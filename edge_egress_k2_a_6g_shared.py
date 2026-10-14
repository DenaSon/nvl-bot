"""The ONE existing Phase-6G SQL lease/journal, shared by legacy bot and K2 root.

No parallel operation table, alternate lock or implicit stale protected retry.
The legacy bot keeps its historical stale-lock policy; the K2 root adapter
refuses *every* existing RUNNING lock, including unprotected stale rows.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Callable

from edge_egress_handoff import is_egress_recovery_hold
from safe_failover import (
    FAILOVER_MODE_MANUAL, FAILOVER_STATUS_RUNNING,
    FAILOVER_STATUS_ABORTED_STALE,
)


def acquire_original_6g(
    db_conn: Callable, source_host: str, target_host: str, *,
    mode: str=FAILOVER_MODE_MANUAL, stale_seconds: int,
    parse_datetime: Callable[[str],datetime],
    clock: Callable[[],datetime] = datetime.now,
    allow_legacy_stale_recovery: bool=False,
):
    """Same table and BEGIN IMMEDIATE semantics as original Phase 6G.

    The original bot explicitly opts into legacy stale recovery; K2 root does
    NOT. Never drop or turn an ambiguous P3 RUNNING into an idle lease.
    """
    if not callable(db_conn) or not callable(clock) or not callable(parse_datetime):
        raise ValueError("6G_ORIGINAL_ADAPTER_INVALID")
    now_dt=clock()
    now=now_dt.strftime("%Y-%m-%d %H:%M:%S")
    with db_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row=conn.execute(
            "SELECT id, updated_at, detail_json FROM failover_operations "
            "WHERE status=? ORDER BY id DESC LIMIT 1",
            (FAILOVER_STATUS_RUNNING,),
        ).fetchone()
        if row:
            lock_id,updated_at,detail_json=row
            if (is_egress_recovery_hold(detail_json)
                or not allow_legacy_stale_recovery):
                return None,lock_id
            try:
                age=(now_dt-parse_datetime(updated_at)).total_seconds()
            except Exception:
                age=stale_seconds+1
            if age<=stale_seconds:
                return None,lock_id
            conn.execute(
                "UPDATE failover_operations SET status=?, updated_at=?, finished_at=?, "
                "error=COALESCE(error, 'stale lock recovered by Phase 6G') WHERE id=?",
                (FAILOVER_STATUS_ABORTED_STALE,now,now,lock_id),
            )
        cur=conn.execute(
            "INSERT INTO failover_operations "
            "(mode, source_host, target_host, status, started_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mode,source_host,target_host,FAILOVER_STATUS_RUNNING,now,now),
        )
        return cur.lastrowid,None


def update_original_6g(
    db_conn: Callable, operation_id: int, *,
    status=None, account_count=None, moved_count=None,
    previous_default_host=None, previous_dns_ip=None,
    core_fallback_ip=None, error=None, detail=None,
    finished=False, require_running=False,
    clock: Callable[[],datetime] = datetime.now,
):
    fields=["updated_at=?"]
    values=[clock().strftime("%Y-%m-%d %H:%M:%S")]
    updates={
        "status":status, "account_count":account_count,
        "moved_count":moved_count,
        "previous_default_host":previous_default_host,
        "previous_dns_ip":previous_dns_ip,
        "core_fallback_ip":core_fallback_ip,
        "error":error,
        "detail_json":None if detail is None else json.dumps(detail,ensure_ascii=False),
    }
    for name,value in updates.items():
        if value is not None:
            fields.append(f"{name}=?")
            values.append(value)
    if finished:
        fields.append("finished_at=?")
        values.append(clock().strftime("%Y-%m-%d %H:%M:%S"))
    values.append(operation_id)
    if require_running:
        values.append(FAILOVER_STATUS_RUNNING)
    with db_conn() as conn:
        cur=conn.execute(
            f"UPDATE failover_operations SET {', '.join(fields)} WHERE id=?"
            + (" AND status=?" if require_running else ""),
            values,
        )
        if require_running and cur.rowcount != 1:
            raise RuntimeError("SHARED_6G_LOCK_NO_LONGER_RUNNING")


@dataclass(frozen=True)
class Original6GRootCallbacks:
    """Reviewed production callback adapter, never a second 6G engine."""
    db_conn: Callable

    def acquire(self, source_host: str, target_host: str):
        # For K2, all pre-existing RUNNING operations are busy. No stale
        # recovery and no stop/start of legacy executor from this service.
        return acquire_original_6g(
            self.db_conn,source_host,target_host,
            stale_seconds=0,parse_datetime=datetime.fromisoformat,
            allow_legacy_stale_recovery=False,
        )

    def journal(self, op: int, *, status: str, detail: dict,
                finished: bool, require_running: bool):
        if (type(op) is not int or op<=0 or not isinstance(detail,dict)
            or status not in ("RUNNING","SUCCEEDED")
            or require_running is not True
            or finished != (status=="SUCCEEDED")):
            raise ValueError("6G_ROOT_JOURNAL_SCOPE_NOT_VERIFIED")
        return update_original_6g(
            self.db_conn,op,status=status,detail=detail,
            finished=finished,require_running=True,
        )
