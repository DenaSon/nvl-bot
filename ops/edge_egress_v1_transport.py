#!/usr/bin/env python3
"""P1-F: small opt-in, pinned and idempotent dedicated Egress transport.

Only dedicated namespace/interface resources are touched by the stage up.sh.
No customer UID, original wg0, PAM, SSH, SQLite or default host route changes.
This does NOT install a protected-user boot guard or authorize customer cutover.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from ops.edge_egress_provision import EgressSpec

FILES = ("manifest.json", "wg.conf", "up.sh", "down.sh")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")
AGENT = "/opt/nvl-egress/ops/edge_egress_v1_transport.py"


class EgressHold(ValueError):
    pass


def _file(path: Path, directory: bool = False) -> bytes:
    if path.is_symlink():
        raise EgressHold("STAGE_SYMLINK")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & 0o077:
        raise EgressHold("STAGE_PERMISSIONS")
    if directory:
        if not path.is_dir():
            raise EgressHold("STAGE_NOT_DIR")
        return b""
    if not path.is_file() or s.st_size > 16384:
        raise EgressHold("STAGE_BAD_FILE")
    return path.read_bytes()


def stage_hash(stage: Path) -> str:
    if not stage.is_absolute() or not SAFE_PATH.fullmatch(str(stage)) or ".." in stage.parts:
        raise EgressHold("INVALID_STAGE_PATH")
    _file(stage, directory=True)
    digest = hashlib.sha256()
    for name in FILES:
        content = _file(stage / name)
        digest.update(name.encode() + b"\0" + len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def pinned(stage: Path, role: str, digest: str) -> tuple[EgressSpec, str]:
    if role not in ("core", "edge") or not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise EgressHold("MISSING_STAGE_PIN")
    if stage_hash(stage) != digest:
        raise EgressHold("STAGE_HASH_CHANGED")
    try:
        manifest = json.loads(_file(stage / "manifest.json"))
        spec = EgressSpec.from_json(manifest["config"])
        if manifest["role"] != role or manifest["stage_only"] is not True:
            raise EgressHold("STAGE_ROLE_MISMATCH")
        # Reference identity; scripts are pinned by the hash above.
        wg = _file(stage / "wg.conf").decode()
        peer = next(row.partition("=")[2].strip() for row in wg.splitlines()
                    if row.strip().startswith("PublicKey ="))
        if len(peer) != 44:
            raise EgressHold("INVALID_PEER")
    except (ValueError, KeyError, StopIteration, UnicodeError, TypeError) as exc:
        raise EgressHold("STAGE_MANIFEST_INVALID") from exc
    return spec, peer


def _run(*args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressHold("PROBE_UNAVAILABLE") from exc


def _read(*args: str) -> str:
    p = _run(*args)
    if p.returncode != 0:
        raise EgressHold("PROBE_FAILED")
    return p.stdout.strip()


def observe(spec: EgressSpec, role: str, peer: str) -> str:
    """No side effects: ABSENT, UP, or a conservative HOLD."""
    if role == "core":
        namespaces = {line.split()[0] for line in _read("ip", "netns", "list").splitlines()
                      if line.strip()}
        ns = spec.namespace in namespaces
        vh = _run("ip", "link", "show", "dev", spec.veth_root).returncode == 0
        wg = (ns and _run("ip", "netns", "exec", spec.namespace, "ip",
                          "link", "show", "dev", spec.iface).returncode == 0)
        if not (ns or vh or wg):
            return "ABSENT"
        if not (ns and vh and wg):
            raise EgressHold("PARTIAL_CORE_TRANSPORT")
        prefix = ("ip", "netns", "exec", spec.namespace)
        addr = _read(*prefix, "ip", "-4", "-o", "addr", "show", "dev", spec.iface)
        root_addr = _read("ip", "-4", "-o", "addr", "show", "dev", spec.veth_root)
        default = _read(*prefix, "ip", "-4", "route", "show", "default")
        healthy = (f"inet {spec.core_tunnel_ip}/30" in addr
                   and f"inet {spec.root_veth_ip}/30" in root_addr
                   and default.startswith(f"default dev {spec.iface} "))
    else:
        if _run("ip", "link", "show", "dev", spec.iface).returncode != 0:
            return "ABSENT"
        prefix = ()
        addr = _read("ip", "-4", "-o", "addr", "show", "dev", spec.iface)
        port = _read("wg", "show", spec.iface, "listen-port")
        nat = _run("iptables", "-w", "-t", "nat", "-C", "POSTROUTING",
                   "-s", spec.core_tunnel_ip + "/32", "-o", spec.edge_uplink,
                   "-m", "comment", "--comment", "nvl-egress-" + spec.edge_id,
                   "-j", "MASQUERADE")
        healthy = (f"inet {spec.edge_tunnel_ip}/30" in addr
                   and port == str(spec.edge_listen_port)
                   and nat.returncode == 0)
    actual_peer = _read(*prefix, "wg", "show", spec.iface, "peers")
    if not healthy or actual_peer != peer:
        raise EgressHold("FOREIGN_OR_DRIFTED_TRANSPORT")
    return "UP"


def ensure(stage: Path, role: str, digest: str) -> str:
    if os.geteuid() != 0:
        raise EgressHold("ROOT_REQUIRED")
    spec, peer = pinned(stage, role, digest)
    state = observe(spec, role, peer)
    if state == "UP":
        return "EXACT_TRANSPORT_ALREADY_UP"
    if state != "ABSENT":
        raise EgressHold("UNKNOWN_TRANSPORT")
    pinned(stage, role, digest)
    try:
        p = subprocess.run(["/bin/bash", str(stage / "up.sh")],
                           capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressHold("START_UNCERTAIN") from exc
    if p.returncode != 0 or observe(spec, role, peer) != "UP":
        raise EgressHold("START_UNCERTAIN")
    return "TRANSPORT_STARTED"


def render_unit(stage: Path, role: str, digest: str) -> str:
    spec, _ = pinned(stage, role, digest)
    return (
        "[Unit]\n"
        f"Description=NVL dedicated Egress {spec.edge_id} ({role})\n"
        "Wants=network-online.target\nAfter=network-online.target\n\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        "User=root\nGroup=root\nUMask=0077\nTimeoutStartSec=70\nRestart=no\n"
        f"ExecStart=/usr/bin/python3 {AGENT} ensure "
        f"--stage {stage} --role {role} --digest {digest}\n"
        "# No ExecStop: never tear down transport used by SSH sessions.\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("fingerprint", "inspect", "ensure", "render-unit"))
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--role", choices=("core", "edge"), required=True)
    parser.add_argument("--digest")
    args = parser.parse_args(argv)
    try:
        if args.action == "fingerprint":
            print(stage_hash(args.stage))
        elif args.action == "render-unit":
            print(render_unit(args.stage, args.role, args.digest), end="")
        elif args.action == "inspect":
            spec, peer = pinned(args.stage, args.role, args.digest)
            print(observe(spec, args.role, peer))
        else:
            print(ensure(args.stage, args.role, args.digest))
        return 0
    except (EgressHold, OSError) as exc:
        print("HOLD:" + (str(exc) if isinstance(exc, EgressHold)
                          else "FILESYSTEM_UNAVAILABLE"), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
