"""Remote half of the NVL Egress lab transport.

The controller streams this module and the existing provisioner over an
authenticated, fingerprint-pinned SSH channel. Neither file is installed on
the target. All WireGuard private material stays on its originating host.
No customer UID routes, DNS, bot accounts or operational wg0 are touched.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from ops.edge_egress_provision import EgressSpec, preflight, stage_files, validated_key

STAGE_ROOT = Path("/root/nvl-egress-staging")
KEY_ROOT = Path("/root/nvl-egress-keys")
TOKEN_RE = re.compile(r"^[a-f0-9]{32,64}$")


def _root_dir(root: Path) -> None:
    if root.is_symlink():
        raise ValueError("UNSAFE_ROOT_SYMLINK")
    if not root.exists():
        root.mkdir(mode=0o700)
    s = root.stat()
    if not root.is_dir() or s.st_uid != 0 or (s.st_mode & 0o077):
        raise ValueError("UNSAFE_ROOT_PERMISSIONS")


def _key_dir(edge_id: str) -> Path:
    _root_dir(KEY_ROOT)
    d = KEY_ROOT / edge_id
    _root_dir(d)
    return d


def _stage_path(spec: EgressSpec, role: str) -> Path:
    return STAGE_ROOT / (spec.edge_id + "-" + role)


def _read_private(spec: EgressSpec) -> str:
    p = _key_dir(spec.edge_id) / "private.key"
    if p.is_symlink() or not p.is_file():
        raise ValueError("HOST_KEY_MISSING")
    s = p.stat()
    if s.st_uid != 0 or s.st_mode & 0o077:
        raise ValueError("UNSAFE_KEY_PERMISSIONS")
    return validated_key(p.read_text().strip(), "private")


def _public_key(spec: EgressSpec, create: bool) -> str:
    p = _key_dir(spec.edge_id) / "private.key"
    if not p.exists():
        if not create:
            raise ValueError("HOST_KEY_MISSING")
        raw = subprocess.run(["wg", "genkey"], text=True, capture_output=True,
                             timeout=8, check=True).stdout.strip()
        raw = validated_key(raw, "generated_private")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(p, flags, 0o600), "w") as f:
            f.write(raw + "\n")
    private = _read_private(spec)
    result = subprocess.run(["wg", "pubkey"], input=private + "\n", text=True,
                            capture_output=True, timeout=8, check=True)
    return validated_key(result.stdout.strip(), "generated_public")


def _owned_stage(spec: EgressSpec, role: str, *, token: str | None = None) -> Path:
    _root_dir(STAGE_ROOT)
    p = _stage_path(spec, role)
    if p.is_symlink() or not p.is_dir():
        raise ValueError("STAGE_NOT_FOUND_OR_UNSAFE")
    s = p.stat()
    if s.st_uid != 0 or s.st_mode & 0o077:
        raise ValueError("STAGE_PERMISSIONS_UNSAFE")
    manifest = p / "manifest.json"
    if manifest.is_symlink():
        raise ValueError("STAGE_MANIFEST_SYMLINK")
    data = json.loads(manifest.read_text())
    if (data.get("config") != vars(spec) or data.get("role") != role
            or data.get("stage_only") is not True):
        raise ValueError("STAGE_OWNERSHIP_MISMATCH")
    if token is not None and data.get("owner_token") != token:
        raise ValueError("STAGE_TOKEN_MISMATCH")
    return p


def _run_script(path: Path, name: str) -> str:
    result = subprocess.run(["/bin/bash", str(path / name)], capture_output=True,
                            text=True, timeout=35, check=False)
    if result.returncode:
        raise ValueError("SHADOW_SCRIPT_FAILED:" + name)
    return result.stdout[-512:].strip()


def execute(action: str, payload: dict) -> dict:
    if os.geteuid() != 0:
        raise ValueError("ROOT_REQUIRED")
    role = payload.get("role")
    if role not in ("core", "edge"):
        raise ValueError("INVALID_ROLE")
    spec = EgressSpec.from_json(payload["spec"])
    if action == "preflight":
        return preflight(spec, role)
    if action == "key":
        return {"public_key": _public_key(spec, create=True)}
    if action == "stage":
        token = payload.get("token")
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise ValueError("INVALID_STAGE_TOKEN")
        peer = validated_key(payload["peer_public_key"], "peer_public_key")
        _root_dir(STAGE_ROOT)
        # Never overwrite an existing stage or take ownership of old files.
        stage_files(spec, role, _stage_path(spec, role), _read_private(spec),
                    peer, owner_token=token)
        return {"state": "STAGED", "network_changed": False}
    if action == "discard":
        token = payload.get("token")
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise ValueError("INVALID_STAGE_TOKEN")
        p = _stage_path(spec, role)
        if not p.exists() and not p.is_symlink():
            return {"state": "ABSENT"}
        p = _owned_stage(spec, role, token=token)
        # Only staged files may be removed. Activation needs a separate stop.
        if (role == "core" and subprocess.run(
                ["ip", "netns", "list"], capture_output=True, text=True,
                timeout=8, check=True).stdout.find(spec.namespace) >= 0):
            raise ValueError("ACTIVE_STAGE_CANNOT_DISCARD")
        if subprocess.run(["ip", "link", "show", "dev", spec.iface],
                          capture_output=True, timeout=8).returncode == 0:
            raise ValueError("ACTIVE_STAGE_CANNOT_DISCARD")
        shutil.rmtree(p)
        return {"state": "DISCARDED"}
    if action == "inspect":
        p = _stage_path(spec, role)
        if not p.exists() and not p.is_symlink():
            return {"state": "ABSENT"}
        _owned_stage(spec, role)
        return {"state": "STAGED", "interface": spec.iface}
    # Network changes are available only through a separate, explicit lab gate.
    if not payload.get("lab_activation") is True:
        raise ValueError("LAB_ACTIVATION_DISABLED")
    if action == "start":
        p = _owned_stage(spec, role)
        return {"state": "SHADOW_STARTED", "detail": _run_script(p, "up.sh")}
    if action == "stop":
        p = _owned_stage(spec, role)
        return {"state": "SHADOW_STOPPED", "detail": _run_script(p, "down.sh")}
    if action == "probe":
        if role != "core":
            raise ValueError("PROBE_CORE_ONLY")
        _owned_stage(spec, role)
        response = subprocess.run(
            ["ip", "netns", "exec", spec.namespace, "curl", "-4", "-fsS",
             "--max-time", "8", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=12, check=True)
        return {"observed_ip": response.stdout.strip()}
    raise ValueError("ACTION_NOT_ALLOWLISTED")


def main() -> int:
    try:
        if len(sys.argv) != 3:
            raise ValueError("INVALID_INVOCATION")
        action = sys.argv[1]
        if action not in {"preflight", "key", "stage", "discard", "inspect",
                          "start", "stop", "probe"}:
            raise ValueError("ACTION_NOT_ALLOWLISTED")
        payload = json.loads(base64.b64decode(sys.argv[2], validate=True))
        if not isinstance(payload, dict):
            raise ValueError("INVALID_PAYLOAD")
        print(json.dumps({"ok": True, "data": execute(action, payload)}))
        return 0
    except Exception as exc:
        # Do not return exception text: subprocess errors can include command
        # arguments or private host material.
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({"ok": False, "error": reason[:128]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
