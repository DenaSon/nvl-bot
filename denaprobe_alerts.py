"""Opt-in DenaProbe R3 alert loop for the existing NVL Telegram bot.

No second poller, no SMTP/HTML fallback, no commands to network, no alert unless
an operator enables this in the *existing* bot after three-phase field tests.
Exactly-once intent; uncertain Telegram delivery is held for manual review.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import secrets
import sqlite3
import time

from cloudzy_rich_transport import RichBotAPI, RichDeliveryHold
from denaprobe_ingest import collector, detector
from denaprobe_rich_admin import render_transition

MAX_PER_TICK = 8


def _reserve(path, recipient_ids, *, now_ms):
    recipients = sorted(set(
        x for x in recipient_ids if type(x) is int and x > 0
    ))[:30]
    if not recipients:
        return []
    with collector.connect_db(Path(path)) as db:
        db.execute("BEGIN IMMEDIATE")
        transitions = db.execute(
            "SELECT id FROM dp3_transitions ORDER BY id DESC LIMIT 80"
        ).fetchall()
        for tr in transitions:
            for recipient in recipients:
                db.execute(
                    "INSERT OR IGNORE INTO dp3_delivery "
                    "(transition_id,recipient_id,status,updated_at) "
                    "VALUES(?,?,'READY',?)",
                    (tr["id"],recipient,now_ms)
                )
        ready = db.execute(
            "SELECT d.transition_id,d.recipient_id,t.incident_id,t.kind,"
            "t.observed_class,t.confidence,t.occurred_at,t.evidence_sequence "
            "FROM dp3_delivery AS d JOIN dp3_transitions AS t "
            "ON t.id=d.transition_id "
            "WHERE d.status='READY' ORDER BY d.transition_id,d.recipient_id LIMIT ?",
            (MAX_PER_TICK,)
        ).fetchall()
        out = []
        for r in ready:
            attempt = secrets.token_hex(12)
            db.execute(
                "UPDATE dp3_delivery SET status='INTENT',attempt=?,"
                "updated_at=? WHERE transition_id=? AND recipient_id=? AND status='READY'",
                (attempt,now_ms,r["transition_id"],r["recipient_id"])
            )
            out.append((dict(r),attempt))
        db.commit()
        return out


def _finish(path, row, attempt, *, status, reason, message_id=None, now_ms):
    with collector.connect_db(Path(path)) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "UPDATE dp3_delivery SET status=?,reason=?,message_id=?,"
            "updated_at=? WHERE transition_id=? AND recipient_id=? "
            "AND status='INTENT' AND attempt=?",
            (status,reason,message_id,now_ms,row["transition_id"],
             row["recipient_id"],attempt)
        )
        db.commit()


async def tick(db_path, recipients, api: RichBotAPI, *, now_ms=None):
    """Explicit single round; caller owns existing async bot scheduling.

    Recovery requires corroborated real samples; never silently recover on
    timeout. Attempt recorded BEFORE Telegram call. An exception cannot
    cause duplicate automatic sends after process restart.
    """
    now = int(time.time()*1000) if now_ms is None else now_ms
    changes = await asyncio.to_thread(detector.evaluate, Path(db_path), now_ms=now)
    reserved = await asyncio.to_thread(_reserve, db_path, recipients, now_ms=now)
    if not reserved:
        return {"changed": len(changes), "sent": 0, "held": 0}
    model = await asyncio.to_thread(detector.read_dashboard, Path(db_path), now_ms=now)
    sent = held = 0
    for row, attempt in reserved:
        try:
            rich = render_transition(model, row)
            message_id = await api.send(chat_id=row["recipient_id"], rich_message=rich)
            if type(message_id) is not int or message_id <= 0:
                raise RichDeliveryHold("INVALID_TELEGRAM_RECEIPT")
            await asyncio.to_thread(
                _finish, db_path, row, attempt, status="SENT",
                reason="ACKNOWLEDGED", message_id=message_id, now_ms=now)
            sent += 1
        except RichDeliveryHold as exc:
            code = str(exc)[:80]
            # Telegram explicitly refused on rate limit, no delivery:
            # safe to retry later; all ambiguous results stay UNCERTAIN.
            status = "READY" if code == "TELEGRAM_RATE_LIMITED" else "UNCERTAIN"
            await asyncio.to_thread(
                _finish, db_path, row, attempt, status=status,
                reason=code, now_ms=now)
            held += 1
        except (OSError, ValueError, sqlite3.Error):
            await asyncio.to_thread(
                _finish, db_path, row, attempt, status="UNCERTAIN",
                reason="DELIVERY_UNCERTAIN", now_ms=now)
            held += 1
    return {"changed": len(changes), "sent": sent, "held": held}
