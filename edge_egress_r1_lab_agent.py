"""Restricted disposable R1 lab host endpoint (transport only).

Invoked via pinned SSH root key from the F2/6G Core coordinator. This endpoint
does NOT grant a lease: caller must hold and recheck the EXISTING Core 6G
transaction and UID guard. Root access on either VPS is inherently privileged.
DO NOT expose as a bot command, public endpoint, systemd autostart or sudo
rule. No automatic cleanup after uncertain transport activation.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from edge_egress_r1_systemd import (
    R1BootContract, _no_previous_resources, assert_disposable_identity,
)
from edge_egress_r1_transport import _stage_owned, inspect_linux
from ops.edge_egress_provision import EgressSpec

_STAGE_ROOT = Path("/root/nvl-egress-staging")


class LabAgentUnsafe(ValueError):
    pass


def _request(encoded: str) -> R1BootContract:
    if len(encoded) > 4096:
        raise LabAgentUnsafe("OVERSIZED_REQUEST")
    try:
        payload = json.loads(base64.b64decode(encoded, validate=True))
    except (ValueError, TypeError) as exc:
        raise LabAgentUnsafe("INVALID_REQUEST") from exc
    if (not isinstance(payload, dict) or set(payload) != {
        "mode", "spec", "role", "machine_id",
        "marker_sha256", "stage_sha256",
    }):
        raise LabAgentUnsafe("INVALID_REQUEST_FIELDS")
    contract = R1BootContract.parse({
        "spec": payload["spec"], "role": payload["role"],
        "machine_id": payload["machine_id"],
        "disposable_marker_sha256": payload["marker_sha256"],
        "stage_sha256": payload["stage_sha256"], "mode": payload["mode"],
    })
    return contract


def _assert_local_host(contract: R1BootContract) -> None:
    if os.geteuid() != 0:
        raise LabAgentUnsafe("ROOT_REQUIRED")
    # An independently prepared root-only marker AND machine-id pin are
    # mandatory; a staging directory alone cannot turn production into a lab.
    assert_disposable_identity(contract)
    role = contract.role
    public = (contract.spec.core_public_ipv4 if role == "core"
              else contract.spec.edge_public_ipv4)
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", "eth0"],
        capture_output=True, text=True, timeout=8, check=True,
    )
    addresses = json.loads(result.stdout)
    local = {entry.get("local") for iface in addresses
             for entry in iface.get("addr_info", [])}
    if public not in local:
        raise LabAgentUnsafe("LAB_HOST_IPV4_MISMATCH")
    if not _stage_owned(contract.spec, role, _STAGE_ROOT,
                        contract.stage_sha256):
        raise LabAgentUnsafe("STAGED_BYTES_UNTRUSTED")


def execute(action: str, encoded: str) -> dict:
    if action not in ("probe", "start"):
        raise LabAgentUnsafe("ACTION_NOT_ALLOWED")
    contract = _request(encoded)
    _assert_local_host(contract)
    # This catches collision, port reuse and legacy unscoped NAT without
    # treating 'not found' or an unknown command failure as permission.
    _no_previous_resources(contract)
    if action == "probe":
        return {"ok": True, "role": contract.role, "state": "OFFLINE_VERIFIED"}

    # The Core F2 bridge must have issued this command over a restricted,
    # host-key pinned SSH channel. This environment check is NOT a substitute
    # for an existing live Core-side 6G lease and fail-closed UID guard.
    if not os.environ.get("SSH_CONNECTION"):
        raise LabAgentUnsafe("SSH_COORDINATOR_REQUIRED")

    stage = _STAGE_ROOT / (contract.spec.edge_id + "-" + contract.role)
    if not _stage_owned(contract.spec, contract.role, _STAGE_ROOT,
                        contract.stage_sha256):
        raise LabAgentUnsafe("STAGE_CHANGED_BEFORE_START")
    try:
        result = subprocess.run(
            ["/bin/bash", str(stage / "up.sh")],
            capture_output=True, text=True, timeout=35, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabAgentUnsafe("START_UNCERTAIN_HOLD") from exc
    if result.returncode:
        raise LabAgentUnsafe("START_UNCERTAIN_HOLD")
    obs = inspect_linux(
        contract.spec, contract.role, stage_root=_STAGE_ROOT,
        reviewed_stage_sha256=contract.stage_sha256,
    )
    healthy = (
        not obs.probe_errors and not obs.nat_shadowed
        and obs.stage_owned and obs.interface_present and obs.identity_proven
        and (obs.namespace_present and obs.veth_present
             if contract.role == "core" else obs.nat_tagged)
    )
    if not healthy:
        raise LabAgentUnsafe("POST_START_IDENTITY_UNCERTAIN_HOLD")
    return {"ok": True, "role": contract.role, "state": "TRANSPORT_VERIFIED"}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print('{"ok":false,"role":null,"state":"HOLD"}')
        return 2
    try:
        result = execute(args[0], args[1])
    except Exception:
        # Error output MUST NOT include stdout of wg/iptables, private keys,
        # the manifest, SSH parameters, or other operator secrets.
        print('{"ok":false,"role":null,"state":"HOLD"}')
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
