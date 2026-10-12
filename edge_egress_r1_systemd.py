"""R1 disposable-only, SHA-pinned transport systemd execution boundary.

Opt-in lab bootstrap ONLY. Nothing installs/enables this service or starts
networking when imported. No customer route, PAM, DB, existing wg0, or SSH edit.

Any uncertain start is a HOLD requiring independent operator reconciliation.
Never start/stop/adopt a pre-existing shadow (especially production stg1).
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable

from edge_egress_r1_transport import _stage_owned, inspect_linux
from ops.edge_egress_provision import EgressSpec, preflight

MANIFEST_ROOT = Path("/etc/nvl-egress")
STAGE_ROOT = Path("/root/nvl-egress-staging")
MARKER = MANIFEST_ROOT / "disposable-r1.marker"
MACHINE_ID = Path("/etc/machine-id")
AGENT = Path("/opt/nvl-egress/edge_egress_r1_systemd.py")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HASH_FILES = frozenset(("manifest.json", "wg.conf", "up.sh", "down.sh"))


class R1ServiceUnsafe(ValueError):
    pass


def _owned(path: Path, *, directory: bool = False) -> bool:
    try:
        if path.is_symlink():
            return False
        s = path.stat()
        return (s.st_uid == 0 and not s.st_mode & 0o077
                and (stat.S_ISDIR(s.st_mode) if directory
                     else stat.S_ISREG(s.st_mode)))
    except OSError:
        return False


def _read_checked(path: Path, limit: int) -> bytes:
    if not _owned(path) or not _owned(path.parent, directory=True):
        raise R1ServiceUnsafe("ROOT_OWNED_MATERIAL_REQUIRED")
    if path.stat().st_size > limit:
        raise R1ServiceUnsafe("REVIEWED_MATERIAL_TOO_LARGE")
    # This is not a hostile-root-proof primitive; installation and paths
    # must be immutable to non-root processes. Recheck just before invoking.
    return path.read_bytes()


@dataclass(frozen=True)
class R1BootContract:
    spec: EgressSpec
    role: str
    stage_sha256: dict[str, str]
    machine_id: str
    disposable_marker_sha256: str
    mode: str = "DISPOSABLE_ONLY"

    @classmethod
    def parse(cls, raw: dict) -> "R1BootContract":
        if not isinstance(raw, dict) or set(raw) != {
            "spec", "role", "stage_sha256", "machine_id",
            "disposable_marker_sha256", "mode",
        }:
            raise R1ServiceUnsafe("INVALID_BOOT_CONTRACT_FIELDS")
        try:
            spec = EgressSpec.from_json(raw["spec"])
        except (ValueError, TypeError, KeyError) as exc:
            raise R1ServiceUnsafe("INVALID_BOOT_SPEC") from exc
        hashes = raw["stage_sha256"]
        if (raw["role"] not in ("core", "edge")
            or raw["mode"] != "DISPOSABLE_ONLY"
            or not isinstance(hashes, dict)
            or set(hashes) != _HASH_FILES
            or any(not isinstance(v, str) or not _HEX64.fullmatch(v)
                   for v in hashes.values())
            or not isinstance(raw["machine_id"], str)
            or not _HEX32.fullmatch(raw["machine_id"])
            or not isinstance(raw["disposable_marker_sha256"], str)
            or not _HEX64.fullmatch(raw["disposable_marker_sha256"])):
            raise R1ServiceUnsafe("INVALID_BOOT_CONTRACT")
        return cls(spec, raw["role"], hashes, raw["machine_id"],
                   raw["disposable_marker_sha256"], raw["mode"])

    def filename(self) -> str:
        return f"r1-{self.spec.edge_id}-{self.role}.json"


def read_contract(path: Path, expected_sha256: str) -> R1BootContract:
    if (not isinstance(expected_sha256, str) or
            not _HEX64.fullmatch(expected_sha256) or
            path.parent != MANIFEST_ROOT or
            path.is_symlink()):
        raise R1ServiceUnsafe("UNPINNED_BOOT_CONTRACT")
    raw = _read_checked(path, 8192)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise R1ServiceUnsafe("BOOT_CONTRACT_SHA_CHANGED")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise R1ServiceUnsafe("INVALID_BOOT_CONTRACT_JSON") from exc
    result = R1BootContract.parse(data)
    if path.name != result.filename():
        raise R1ServiceUnsafe("BOOT_CONTRACT_PATH_MISMATCH")
    return result


def render_unit(contract: R1BootContract, manifest_sha256: str,
                agent: Path = AGENT) -> str:
    """Offline text only. Installer and systemctl enable are NOT provided.

    Unit autostart is only for an explicitly prepared disposable lab host:
    its command rechecks the pinned contract and unique machine-id/marker.
    No ExecStop: stopping systemd cannot silently tear down protected routes.
    """
    contract.spec.validate()
    if (not _HEX64.fullmatch(manifest_sha256)
        or agent != AGENT):
        raise R1ServiceUnsafe("UNREVIEWED_UNIT_INPUT")
    path = MANIFEST_ROOT / contract.filename()
    ident = contract.spec.edge_id
    return (
        "[Unit]\n"
        f"Description=NVL R1 disposable transport {ident} ({contract.role})\n"
        "Wants=network-online.target\nAfter=network-online.target\n\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        "User=root\nGroup=root\nUMask=0077\n"
        "Restart=no\nTimeoutStartSec=75\n"
        f"ExecStart=/usr/bin/python3 {agent} "
        f"start --manifest {path} --sha256 {manifest_sha256}\n"
        "# No lifecycle stop/teardown hook; no shared service dependencies.\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def assert_disposable_identity(contract: R1BootContract,
                               *, marker: Path = MARKER,
                               machine_id: Path = MACHINE_ID) -> None:
    raw = _read_checked(marker, 256)
    if hashlib.sha256(raw).hexdigest() != contract.disposable_marker_sha256:
        raise R1ServiceUnsafe("DISPOSABLE_MARKER_MISMATCH")
    try:
        host_id = machine_id.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise R1ServiceUnsafe("MACHINE_ID_UNAVAILABLE") from exc
    if host_id != contract.machine_id or not _HEX32.fullmatch(host_id):
        raise R1ServiceUnsafe("DISPOSABLE_HOST_ID_MISMATCH")


def _no_previous_resources(contract: R1BootContract, *,
                           run: Callable = None) -> None:
    """Read-only preflight; ANY current dedicated resource means HOLD."""
    from ops.edge_egress_provision import preflight as default_preflight
    scan = default_preflight if run is None else run
    try:
        result = scan(contract.spec, contract.role)
    except Exception as exc:
        raise R1ServiceUnsafe("R1_PREFLIGHT_UNKNOWN_HOLD") from exc
    if not result.get("ok") or result.get("issues"):
        raise R1ServiceUnsafe("R1_RESOURCE_COLLISION_OR_PRECHECK_HOLD")
    if contract.role == "edge":
        # Broad catch-all MASQUERADE ahead of our dedicated NAT would mask
        # ownership, as observed on the real Frankfurt edge. Refuse to start.
        p = subprocess.run(["iptables", "-t", "nat", "-S", "POSTROUTING"],
                           capture_output=True, text=True, timeout=8)
        if p.returncode != 0:
            raise R1ServiceUnsafe("NAT_PRECHECK_UNKNOWN_HOLD")
        for line in p.stdout.splitlines():
            if (line.startswith("-A POSTROUTING ") and
                "-j MASQUERADE" in line and
                " -s " not in line and " -o " not in line):
                raise R1ServiceUnsafe("UNSCOPED_LEGACY_NAT_HOLD")


def start_disposable_transport(contract: R1BootContract, *,
                               marker: Path = MARKER,
                               machine_id: Path = MACHINE_ID,
                               stage_root: Path = STAGE_ROOT,
                               executor: Callable | None = None,
                               precheck: Callable | None = None,
                               observe: Callable | None = None) -> str:
    """Explicit lab-only startup; runner cannot elevate Egress user state.

    This invokes the existing independently reviewed staging up.sh; that
    script's own ERR trap may clean up resources it has just created.
    On any uncertain result never invoke down.sh or release a 6G lock.
    """
    if os.geteuid() != 0:
        raise R1ServiceUnsafe("ROOT_REQUIRED")
    assert_disposable_identity(contract, marker=marker, machine_id=machine_id)
    if not _stage_owned(contract.spec, contract.role, stage_root,
                        contract.stage_sha256):
        raise R1ServiceUnsafe("STAGE_SHA_OR_OWNER_MISMATCH")
    if precheck is None:
        _no_previous_resources(contract)
    else:
        _no_previous_resources(contract, run=precheck)
    # Verify the package immediately before calling bash.
    if not _stage_owned(contract.spec, contract.role, stage_root,
                        contract.stage_sha256):
        raise R1ServiceUnsafe("STAGE_CHANGED_BEFORE_EXEC")
    path = stage_root / (contract.spec.edge_id + "-" + contract.role) / "up.sh"
    runner = executor or (
        lambda script: subprocess.run(
            ["/bin/bash", str(script)], capture_output=True, text=True,
            timeout=45, check=False)
    )
    try:
        result = runner(path)
    except Exception as exc:
        raise R1ServiceUnsafe("TRANSPORT_START_UNCERTAIN_HOLD") from exc
    if getattr(result, "returncode", 1) != 0:
        raise R1ServiceUnsafe("TRANSPORT_START_UNCERTAIN_HOLD")

    reader = observe or (
        lambda: inspect_linux(contract.spec, contract.role,
                              stage_root=stage_root,
                              reviewed_stage_sha256=contract.stage_sha256)
    )
    try:
        o = reader()
        complete = (
            o.identity_proven and not o.probe_errors and not o.nat_shadowed
            and o.interface_present and
            ((o.namespace_present and o.veth_present)
             if contract.role == "core" else o.nat_tagged)
        )
    except Exception as exc:
        raise R1ServiceUnsafe("POST_START_IDENTITY_UNCERTAIN_HOLD") from exc
    if not complete:
        raise R1ServiceUnsafe("POST_START_IDENTITY_UNCERTAIN_HOLD")
    return "TRANSPORT_ONLY_NOT_CUSTOMER_READY"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "verify"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        contract = read_contract(args.manifest, args.sha256)
        if os.geteuid() != 0:
            raise R1ServiceUnsafe("ROOT_REQUIRED")
        assert_disposable_identity(contract)
        if not _stage_owned(contract.spec, contract.role, STAGE_ROOT,
                            contract.stage_sha256):
            raise R1ServiceUnsafe("STAGE_SHA_OR_OWNER_MISMATCH")
        if args.action == "start":
            print(start_disposable_transport(contract))
        else:
            print("R1_DISPOSABLE_INPUTS_VERIFIED_ONLY")
    except (R1ServiceUnsafe, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        # No command output, file contents or WG keys in failure messages.
        reason = str(exc) if isinstance(exc, R1ServiceUnsafe) else "R1_UNEXPECTED_HOLD"
        print("ERROR:" + reason, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
