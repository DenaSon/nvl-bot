"""Register the already-live, pinned R1 disposable Core/Edge allocation.

Uses the ORIGINAL bot 6G acquire/update callbacks, one SQLite journal and
the existing F1 allocation + F3 readiness stores. Registers only real staged
WireGuard public keys; no fake customer, ingress DNS, READY or RUNNING rows.
Never starts/stops WireGuard, touches SSH/PAM or unlocks UID 1555.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from edge_egress_inventory import reserve_allocation
from edge_egress_f3_readiness import stage_in_existing_6g_transaction
from edge_egress_r1_lab_6g_bootstrap import (
    Lab6GUnsafe, verified_bot_callbacks, lab_host_attested,
    make_lab_db_conn, DEFAULT_SOURCE, DEFAULT_DATABASE,
)
from ops.edge_egress_provision import EgressSpec, validated_key

STAGE = Path("/root/nvl-egress-staging/lab1-core")
CORE_SHA = {
    "manifest.json": "629fa465f68d87274447b6feac585b3108423b0451489131a7bf21ccbf6fb665",
    "wg.conf": "39aec2fa1fd68bd7d4be9cbb4eb7c80db7fc46186c4ce3bc9490d179b2260157",
    "up.sh": "424b32a3048d6a816daf78d9e0697dd94b03b5897dbc393bca51a349570d10f8",
    "down.sh": "57c243bd6614e795bcbfcbfda78dc1c5a2208037779d3361c9dc8616a6a0a389",
}


def readonly_wg_keys(spec: EgressSpec):
    def wg(*arguments):
        result = subprocess.run(
            ["ip", "netns", "exec", spec.namespace, "wg", "show",
             spec.iface, *arguments],
            capture_output=True, text=True, timeout=8, check=True,
        )
        return result.stdout.strip()
    local = validated_key(wg("public-key"), "core_public_key")
    peers = wg("peers").splitlines()
    if len(peers) != 1 or not peers[0].strip():
        raise Lab6GUnsafe("EXACTLY_ONE_LIVE_PEER_REQUIRED")
    remote = validated_key(peers[0].strip(), "edge_public_key")
    if local == remote:
        raise Lab6GUnsafe("WG_PUBLIC_KEYS_MUST_DIFFER")
    return local, remote


def verified_live_stage():
    if not lab_host_attested():
        raise Lab6GUnsafe("LAB_CORE_IDENTITY_MISMATCH")
    if STAGE.is_symlink() or not STAGE.is_dir():
        raise Lab6GUnsafe("STAGE_MISSING")
    for filename, digest in CORE_SHA.items():
        path = STAGE / filename
        if path.is_symlink() or not path.is_file():
            raise Lab6GUnsafe("STAGE_FILE_MISSING:" + filename)
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise Lab6GUnsafe("STAGE_FILE_NOT_ROOT_ONLY:" + filename)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise Lab6GUnsafe("STAGE_FILE_SHA_MISMATCH:" + filename)
    document = json.loads((STAGE / "manifest.json").read_text())
    spec = EgressSpec.from_json(document["config"])
    if (
        spec.edge_id != "lab1"
        or spec.core_public_ipv4 != "107.189.16.36"
        or spec.edge_public_ipv4 != "216.126.229.12"
        or spec.tunnel_network != "10.78.120.0/30"
        or spec.veth_network != "10.78.121.0/30"
        or spec.edge_listen_port != 51852
        or spec.route_table != 1791
        or spec.edge_uplink != "eth0"
    ):
        raise Lab6GUnsafe("LAB_SPEC_CHANGED")
    local, remote = readonly_wg_keys(spec)
    return spec, local, remote


def register_verified_stage() -> None:
    spec, local, remote = verified_live_stage()
    connector = make_lab_db_conn(DEFAULT_DATABASE)
    acquire, update = verified_bot_callbacks(DEFAULT_SOURCE, connector)

    # Start only from the deliberately EMPTY lab journal and registry.
    with connector() as conn:
        required = (
            "failover_operations", "edge_egress_allocations",
            "edge_egress_readiness",
        )
        for name in required:
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone():
                raise Lab6GUnsafe("F1_F3_6G_SCHEMA_MISSING")
            if conn.execute("SELECT COUNT(*) FROM " + name).fetchone()[0] != 0:
                raise Lab6GUnsafe("LAB_JOURNAL_OR_ALLOCATION_NOT_EMPTY")
        # No fake customer/host metadata and no pre-existing protected UID.
        for name in ("edge_egress_uid_runtime", "edge_egress_uid_bindings"):
            if conn.execute("SELECT COUNT(*) FROM " + name).fetchone()[0] != 0:
                raise Lab6GUnsafe("PROTECTED_UID_MAPPING_ALREADY_EXISTS")

    # This acquisition is the exact, SHA-pinned bot callback. We never INSERT
    # a RUNNING row ourselves. A failure after mutation preserves a real 6G
    # HOLD for operator reconciliation.
    operation_id, busy = acquire(spec.core_public_ipv4, spec.edge_public_ipv4)
    if operation_id is None:
        raise Lab6GUnsafe("SHARED_6G_BUSY_OR_HOLD")
    try:
        with connector() as conn:
            conn.execute("BEGIN IMMEDIATE")
            reserve_allocation(
                conn, spec,
                core_public_key=local, edge_public_key=remote,
            )
            conn.execute(
                "UPDATE edge_egress_allocations SET status='STAGED', "
                "updated_at=CURRENT_TIMESTAMP WHERE edge_id=? AND status='RESERVED'",
                (spec.edge_id,),
            )
            stage_in_existing_6g_transaction(
                conn, operation_id,
                source=spec.core_public_ipv4,
                edge_id=spec.edge_id,
                target=spec.edge_public_ipv4,
            )
        update(
            operation_id,
            status="SUCCEEDED", finished=True,
            require_running=True,
            detail={
                "kind": "EGRESS_LAB_ALLOCATION",
                "phase": "STAGED",
                "edge_id": spec.edge_id,
            },
        )
    except Exception as exc:
        # Uncertain commit means keep the *genuine* RUNNING journal for
        # operator review. No automatic 6G unlock or route teardown.
        raise Lab6GUnsafe("LAB_6G_REGISTRY_UNCERTAIN_HOLD") from exc

    print("LAB_6G_OPERATION: ACQUIRED_AND_FINISHED")
    print("EDGE_ALLOCATION: STAGED")
    print("EDGE_READINESS: STAGED_NOT_READY")
    print("SSH_ACCOUNTS: NOT_CREATED")
    print("INGRESS_DNS: NOT_FABRICATED")
    print("PAM_OR_SSH: UNCHANGED")
    print("NETWORK: UNCHANGED")
    print("CUSTOMER_READY: NO")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "register"))
    args = parser.parse_args(argv)
    try:
        spec, local, remote = verified_live_stage()
        if args.action == "preflight":
            print("VERIFIED_LAB_STAGE_AND_WG_PUBLIC_KEYS: PASS")
            print("HOST_MUTATIONS: 0")
        else:
            register_verified_stage()
    except (Lab6GUnsafe, OSError, ValueError, sqlite3.Error,
            subprocess.SubprocessError, TypeError, KeyError) as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
