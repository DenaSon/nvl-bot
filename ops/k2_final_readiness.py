"""Read-only local Core K2 new-Edge release inventory.

Run only after an explicitly approved code deploy, BEFORE attempting any
transfer. No SSH connection, WireGuard start/stop, DB write, service restart,
Cloudflare update or F4 READY promotion is made by this command.

Invocation: python3 -m ops.k2_final_readiness --edge-id <edge_id>
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import stat

from edge_egress_phase2_console import (
    read_dashboard, get_card, transport_check, inspect_local_stage,
)
from edge_egress_k2_final_integration import read_transfer_preview
from edge_egress_v1_console import edge_id_checked


class ReadOnlyInventoryHold(ValueError):
    pass


def _trusted_db(path: Path) -> Path:
    """Don't open a symlink or a writable/untrusted production DB path."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReadOnlyInventoryHold("CORE_DB_UNAVAILABLE") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise ReadOnlyInventoryHold("CORE_DB_OWNERSHIP_NOT_TRUSTED")
    return path


def report(edge_id: str, db_path: Path = Path("/root/master_bot.db")) -> dict:
    eid = edge_id_checked(edge_id)
    if os.geteuid() != 0:
        raise ReadOnlyInventoryHold("ROOT_READONLY_REQUIRED")
    db = _trusted_db(db_path)

    @contextmanager
    def read_db():
        # The URI mode=ro + query_only defense explicitly forbids writes.
        conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only=ON")
            yield conn
        finally:
            conn.close()

    board = read_dashboard(read_db, only_edge=eid)
    card = get_card(board, eid)
    transport = transport_check(card)
    stage = inspect_local_stage(card)
    transfer = read_transfer_preview(read_db, card, transport)
    return {
        "edge_id": eid,
        "edge_public_ipv4": card.ip,
        "trusted_ingress": card.ingress_verified,
        "host_pool_active": card.pool_active,
        "allocation": card.allocation,
        "stage_pin_attested": card.stage_pin is not None,
        "stage_state": stage.stage_state,
        "dedicated_transport": transport.state,
        "f4_current_in_db": card.f4_valid,
        "active_ssh_account_count": transfer.ssh_accounts,
        "transfer_execution_released": transfer.can_execute,
        "transfer_blockers": list(transfer.blockers),
        "operator_note": "READ_ONLY_NO_HOST_CHANGES; NOT_A_PACKET_PROOF",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Core-only K2 read-only VPS preflight")
    parser.add_argument("--edge-id", required=True)
    parser.add_argument("--db", default="/root/master_bot.db")
    args = parser.parse_args(argv)
    try:
        result = report(args.edge_id, Path(args.db))
    except (ReadOnlyInventoryHold, ValueError, sqlite3.Error, OSError) as exc:
        print(json.dumps({
            "status": "HOLD", "reason": str(exc)
            if isinstance(exc, ReadOnlyInventoryHold) else "UNTRUSTED_OR_MISSING_EVIDENCE",
            "changed": False,
        }, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["transfer_execution_released"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
