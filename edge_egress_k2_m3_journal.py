"""M3: read-only confirmation of original K2 P3-A / 6G durable UID receipt.

No second migration/lock table, no shadow journal, no SQL writes and no
recovery unlock. A SUCCEEDED label without *exact* action/nonce/scope and
terminal phase is never accepted as migration proof. This observes the
persisted 6G result, NOT an independent packet/F4 acceptance.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import re
import sqlite3
from typing import Callable

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, _scope_digest, INTENT_PHASE,
    RECOVERY_PHASE,
)


class WaveJournalHold(ValueError):
    pass


def confirm_original_6g_commit(
    db_conn: Callable, scope: ExecutionScope,
    ticket: ExecutionTicket, operation_id: int,
) -> bool:
    """Only exact successful original 6G terminal record matches.

    A concurrent pending RUNNING operation means the global failover engine
    remains BUSY: do not dispatch a second customer on this result.
    """
    if (not callable(db_conn) or not isinstance(scope,ExecutionScope)
        or not isinstance(ticket,ExecutionTicket)
        or type(operation_id) is not int or operation_id<=0
        or not isinstance(ticket.nonce,str)
        or not re.fullmatch(r"[a-f0-9]{32}",ticket.nonce)
        or not hmac.compare_digest(ticket.scope_digest,_scope_digest(scope))):
        return False
    digest=sha256(ticket.nonce.encode("ascii")).hexdigest()
    try:
        with db_conn() as conn:
            in_progress=conn.execute(
                "SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING'"
            ).fetchone()
            if (in_progress is None or type(in_progress[0]) is not int
                or in_progress[0]!=0):
                return False
            matches=conn.execute(
                "SELECT id,status,source_host,target_host,detail_json "
                "FROM failover_operations WHERE id=?",
                (operation_id,),
            ).fetchall()
            if len(matches)!=1:
                return False
            op,status,source,target,raw=matches[0]
            if (op!=operation_id or status!="SUCCEEDED"
                or source!=scope.source_host or target!=scope.target_host
                or not isinstance(raw,str) or len(raw)>16384):
                return False
            detail=json.loads(raw)
            if not isinstance(detail,dict):
                return False
            return bool(
                detail.get("kind")=="K2_P3A"
                and detail.get("phase")=="EGRESS_P3_VERIFIED"
                and detail.get("action")==scope.action
                and detail.get("edge_id")==scope.edge_id
                and hmac.compare_digest(
                    str(detail.get("scope_digest","")),_scope_digest(scope))
                and hmac.compare_digest(
                    str(detail.get("nonce_hash","")),digest)
                and not detail.get("manual_recovery",False)
            )
    except (sqlite3.Error, OSError,TypeError,ValueError,KeyError):
        return False
