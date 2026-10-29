"""Atomic native Cloudzy CZ03/CZ06 -> Unified Edge coordinator checkpoints.

Native receipts remain the authority for external effects. This module NEVER
calls a provider, installer, DNS adapter or customer migration worker.

For *new* purchases, creating the native receipt and coordinator registration
is one SQLite transaction. Every later observed checkpoint is committed in the
same transaction as its native receipt transition. Existing historic receipts
are not retroactively modified or adopted without explicit reconciliation.
"""
from __future__ import annotations

import re
import sqlite3
import time

from cloudzy_operation_coordinator import DurableCoordinator, OperationHold

_REF = re.compile(r"[0-9a-f]{32}\Z")

# Safe, bounded, static status mapping: no untrusted provider body or reason
# reaches the coordinator's public code or Telegram Rich card.
_NATIVE_STEPS = {
    "CREATED": ("PROVIDER_WAIT", "WAITING_EXTERNAL", "PROVIDER_RECEIPT_COMMITTED"),
    "WAITING": ("PROVIDER_WAIT", "WAITING_EXTERNAL", "WAITING_FOR_SERVER"),
    "HOLD_WAIT": ("PROVIDER_WAIT", "NEEDS_OPERATOR", "PROVIDER_READ_HOLD"),
    "HOLD_IP": ("PROVIDER_WAIT", "NEEDS_OPERATOR", "PROVIDER_IP_HOLD"),
    "HOLD_SSH": ("SSH_IDENTITY", "NEEDS_ATTESTATION", "SSH_HOST_KEY_REQUIRED"),
    "HOSTKEY_PENDING": ("SSH_IDENTITY", "NEEDS_ATTESTATION", "SSH_HOST_KEY_PENDING"),
    "PROVISIONING": ("EDGE_INSTALL", "WAITING_EXTERNAL", "EDGE_INSTALL_INTENT"),
    "EDGE_READY": ("STANDBY", "NEEDS_ATTESTATION", "EDGE_READY_STANDBY_UNPROVEN"),
    "HOLD_PROVISION": ("EDGE_INSTALL", "NEEDS_OPERATOR", "EDGE_INSTALL_UNCERTAIN"),
    "CREATE_UNCERTAIN": ("PURCHASE", "RECONCILE_REQUIRED", "CREATE_RESULT_UNCERTAIN"),
}

_CZ06_STEPS = {
    "PURCHASING": None,  # native CZ03 receipt is the purchasing authority
    "WAITING_PROVIDER": ("PROVIDER_WAIT", "WAITING_EXTERNAL",
                         "CZ06_WAITING_PROVIDER"),
    "HOSTKEY_PENDING": ("SSH_IDENTITY", "NEEDS_ATTESTATION",
                        "CZ06_SSH_HOST_KEY_PENDING"),
    "INSTALLING": ("EDGE_INSTALL", "WAITING_EXTERNAL",
                   "CZ06_INSTALL_IN_PROGRESS"),
    "EDGE_READY": ("STANDBY", "NEEDS_ATTESTATION",
                   "CZ06_EDGE_READY_STANDBY_UNPROVEN"),
    "STANDBY_VERIFYING": ("STANDBY", "WAITING_EXTERNAL",
                          "CZ06_STANDBY_VERIFYING"),
    "READY": ("CLIENT_E2E", "NEEDS_ATTESTATION",
              "CZ06_STANDBY_READY_AWAITING_CLIENT_E2E"),
    "HOLD": ("STANDBY", "NEEDS_OPERATOR", "CZ06_RECONCILIATION_REQUIRED"),
    "CANCELLED": ("STANDBY", "NEEDS_OPERATOR", "CZ06_CANCELLED_RECONCILE"),
}


class UnifiedLinkHold(RuntimeError):
    pass


def _assert_identity(operation_id, actor=None, chat=None):
    if not isinstance(operation_id, str) or not _REF.fullmatch(operation_id):
        raise UnifiedLinkHold("INVALID_NATIVE_RECEIPT_ID")
    if actor is not None and (
            type(actor) is not int or type(chat) is not int
            or actor <= 0 or chat <= 0):
        raise UnifiedLinkHold("INVALID_NATIVE_OPERATOR_ID")


def _linked(db, operation_id):
    """No implicit repair/adoption of preexisting unrelated native records."""
    # Upgraded Core may still have only historical CZ03 journals; their
    # recovery must work before any first new UO purchase initializes schema.
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='cloudzy_uo_operations'"
    ).fetchone():
        return None
    row = db.execute(
        "SELECT id,actor,chat,version,state,external_intent "
        "FROM cloudzy_uo_operations "
        "WHERE kind='CLOUDZY_NEW' AND source_ref=?",
        ("CZ03:" + operation_id,),
    ).fetchone()
    return row


def register_native_purchase(db: sqlite3.Connection, *, operation_id,
                             actor, chat, now=None):
    """Insert both journals inside caller's BEGIN IMMEDIATE purchase reserve."""
    _assert_identity(operation_id, actor, chat)
    native = db.execute(
        "SELECT actor_id,chat_id,status FROM cloudzy_edge_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    if not native or tuple(native) != (actor, chat, "CREATING"):
        raise UnifiedLinkHold("NATIVE_RESERVATION_IDENTITY_CHANGED")
    DurableCoordinator.initialize(db)
    if _linked(db, operation_id) is not None:
        raise UnifiedLinkHold("UNIFIED_PURCHASE_ALREADY_LINKED")
    ts = int(time.time() if now is None else now)
    db.execute(
        "INSERT INTO cloudzy_uo_operations "
        "(id,kind,source_ref,actor,chat,step,state,version,created_at,updated_at) "
        "VALUES (?,'CLOUDZY_NEW',?, ?,?,'PREFLIGHT','PLANNED',0,?,?)",
        (operation_id, "CZ03:" + operation_id, actor, chat, ts, ts),
    )
    db.execute(
        "INSERT INTO cloudzy_uo_events "
        "(operation_id,version,at,event,state,step,code) "
        "VALUES (?,0,?,'LINK_NATIVE_RECEIPT','PLANNED','PREFLIGHT',"
        "'NATIVE_CZ03_RESERVED')",
        (operation_id, ts),
    )
    return operation_id


def _record(db, operation_id, *, step, state, code, now=None,
            external_intent=False):
    link = _linked(db, operation_id)
    if link is None:
        return False  # historical CZ03 is preserved as-is
    native = db.execute(
        "SELECT actor_id,chat_id FROM cloudzy_edge_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    if not native or tuple(native) != (link[1], link[2]):
        raise UnifiedLinkHold("NATIVE_UNIFIED_OWNER_MISMATCH")
    if link[4] in ("COMPLETED", "CANCELLED_SAFE"):
        raise UnifiedLinkHold("UNIFIED_OPERATION_CLOSED")
    if state == "WAITING_EXTERNAL" and step == "PURCHASE" and not external_intent:
        raise UnifiedLinkHold("PAID_INTENT_MISSING")
    # Duplicate checkpoints are not new events. External intent remains sticky.
    row = DurableCoordinator._row(db, link[0])
    if (row["step"], row["state"], row["code"]) == (step, state, code):
        return False
    coordinator = DurableCoordinator(lambda: None, now=(
        lambda: int(time.time() if now is None else now)
    ))
    coordinator._transition(
        db, row, state=state, step=step, code=code,
        event="NATIVE_RECEIPT_OBSERVED",
        worker=None, deadline=None,
        external_intent=bool(row["external_intent"] or external_intent),
    )
    return True


def mark_paid_intent(db, *, operation_id, now=None):
    """Durable UO intent BEFORE Cloudzy paid POST. No fallback to blind POST."""
    _assert_identity(operation_id)
    native = db.execute(
        "SELECT status FROM cloudzy_edge_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    if not native or tuple(native) != ("CREATING",):
        raise UnifiedLinkHold("NATIVE_PAID_INTENT_STAGE_CHANGED")
    linked = _linked(db, operation_id)
    if linked is None:
        raise UnifiedLinkHold("UNIFIED_PURCHASE_LINK_MISSING")
    if linked[5] or linked[4] != "PLANNED":
        raise UnifiedLinkHold("PAID_INTENT_ALREADY_PENDING")
    return _record(
        db, operation_id, step="PURCHASE", state="WAITING_EXTERNAL",
        code="CLOUDZY_PAID_POST_INTENT", now=now, external_intent=True)


def observe_native_status(db, *, operation_id, status, now=None):
    """Call AFTER native status CAS, BEFORE transaction commit."""
    _assert_identity(operation_id)
    native = db.execute(
        "SELECT status,provider_server_id FROM cloudzy_edge_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    if not native or native[0] != status:
        raise UnifiedLinkHold("NATIVE_STATUS_CAS_NOT_COMMITTED")
    # Existing pre-upgrade receipts must never acquire an invented UO link
    # or new provider-receipt restrictions while being recovered.
    if _linked(db, operation_id) is None:
        return False
    if status == "REJECTED":
        linked = _linked(db, operation_id)
        if linked is None:
            return False
        # A definitive preflight rejection without a paid intent is a safe
        # no-charge end; an intended POST needs independent reconciliation.
        stage = "NEEDS_OPERATOR" if linked[5] else "CANCELLED_SAFE"
        return _record(
            db, operation_id, step="PURCHASE", state=stage,
            code="PROVIDER_POST_REJECTED_REVIEW" if linked[5]
                 else "PURCHASE_PREFLIGHT_REJECTED",
            now=now,
        )
    selected = _NATIVE_STEPS.get(status)
    if selected is None:
        return False
    if status in ("CREATED", "WAITING", "HOLD_SSH", "HOSTKEY_PENDING",
                  "PROVISIONING", "EDGE_READY", "HOLD_PROVISION") and not native[1]:
        raise UnifiedLinkHold("NATIVE_PROVIDER_RECEIPT_UNVERIFIED")
    return _record(db, operation_id, step=selected[0], state=selected[1],
                   code=selected[2], now=now)


def observe_cz06_status(db, *, operation_id, stage, now=None):
    """CZ06 continuation is not proof of the client's ISP or cutover success."""
    # Old CZ06 fixtures and historic receipts may use different native IDs.
    # Validate the new UO ID format ONLY when a UO link actually exists.
    linked = _linked(db, operation_id)
    if linked is None:
        return False
    _assert_identity(operation_id)
    row = db.execute(
        "SELECT stage,actor_id,chat_id FROM cloudzy_cz06_runs WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    if not row or row[0] != stage:
        raise UnifiedLinkHold("NATIVE_CZ06_STATUS_CHANGED")
    if (linked[1], linked[2]) != (row[1], row[2]):
        raise UnifiedLinkHold("NATIVE_CZ06_OWNER_MISMATCH")
    step = _CZ06_STEPS.get(stage)
    if step is None:
        return False
    if stage in ("READY", "STANDBY_VERIFYING", "EDGE_READY"):
        provider = db.execute(
            "SELECT status,provider_server_id,public_ipv4 "
            "FROM cloudzy_edge_operations WHERE id=?", (operation_id,)
        ).fetchone()
        if not provider or provider[0] != "EDGE_READY" or not provider[1] or not provider[2]:
            raise UnifiedLinkHold("CZ06_EDGE_RECEIPT_NOT_READY")
    return _record(
        db, operation_id, step=step[0], state=step[1],
        code=step[2], now=now,
    )


def observe_native_cancellation(db, *, operation_id, uncertain=False, now=None):
    """Mirror operator cancellation inside the native CZ03/CZ06 transaction.

    A paid POST with an unverified outcome is *quarantined*, never presented as
    an independently verified cancellation of a Cloudzy VPS or a settled bill.
    """
    _assert_identity(operation_id)
    row = db.execute(
        "SELECT status FROM cloudzy_edge_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    if row != ("CANCELLED",):
        raise UnifiedLinkHold("NATIVE_CANCELLATION_NOT_COMMITTED")
    link = _linked(db, operation_id)
    if link is None:
        return False  # pre-UO legacy receipt
    if uncertain:
        return _record(
            db, operation_id, step="PURCHASE", state="RECONCILE_REQUIRED",
            code="PROVIDER_PURCHASE_QUARANTINED", now=now,
            external_intent=True,
        )
    # Even a known VPS may remain billable after cancelling local onboarding.
    # A pre-POST cancellation can be marked safe only without paid intent.
    if link[5]:
        return _record(
            db, operation_id, step="PURCHASE", state="RECONCILE_REQUIRED",
            code="PROVIDER_RESOURCE_MAY_REMAIN", now=now,
            external_intent=True,
        )
    return _record(
        db, operation_id, step="PURCHASE", state="CANCELLED_SAFE",
        code="LOCAL_PURCHASE_CANCELLED_NO_PAID_INTENT", now=now,
    )


_CZ07_STATES = frozenset((
    "QUEUED", "ROUTING", "MIGRATING", "PAUSED_SAFE",
    "VERIFYING", "MOVED", "HOLD", "ABORTED", "DONE",
))


def observe_cz07_status(db, *, job_id, expected_status, now=None):
    """Mirror committed CZ07 transitions; never invent provider/user E2E proof.

    This runs inside the *native CZ07 transaction*. For an old source receipt
    lacking a new unified link, simply leave its historical journals alone.
    """
    row = db.execute(
        "SELECT cz06_operation,actor,chat,source,target,provider_id,"
        "status,moved,total FROM cloudzy_cz07_jobs WHERE id=?", (job_id,)
    ).fetchone()
    # Older CZ07 tests and recovery audits append historical events without
    # advancing a native status; do not retroactively impose UO invariants.
    # Only a concrete bound UO row may enforce the stronger stage CAS.
    if not row:
        return False
    origin, actor, chat, _source, target, provider_id, _status, moved, total = row
    link = _linked(db, origin)
    if link is None:
        return False
    if row[6] != expected_status or expected_status not in _CZ07_STATES:
        raise UnifiedLinkHold("CZ07_NATIVE_STATUS_UNVERIFIED")
    _assert_identity(job_id)
    _assert_identity(origin)
    if (actor, chat) != (link[1], link[2]):
        raise UnifiedLinkHold("CZ07_UNIFIED_OWNER_MISMATCH")
    provider = db.execute(
        "SELECT actor_id,chat_id,provider_server_id,public_ipv4 "
        "FROM cloudzy_edge_operations WHERE id=?", (origin,)
    ).fetchone()
    if (not provider or tuple(provider) !=
            (actor, chat, provider_id, target)):
        raise UnifiedLinkHold("CZ07_UNIFIED_PROVIDER_MISMATCH")
    if type(moved) is not int or type(total) is not int or not 0 <= moved <= total:
        raise UnifiedLinkHold("CZ07_UNIFIED_COUNT_INVALID")
    if expected_status == "DONE":
        if moved != total:
            raise UnifiedLinkHold("CZ07_UNIFIED_FINAL_COUNT_MISMATCH")
        if not db.execute(
            "SELECT 1 FROM cloudzy_cz07_acceptance "
            "WHERE job_id=? AND actor=? AND create_ref!='' "
            "AND renew_ref!='' AND client_ref!=''",
            (job_id, actor),
        ).fetchone():
            raise UnifiedLinkHold("CZ07_INDEPENDENT_ACCEPTANCE_REQUIRED")
        step, state, code = (
            "FINAL_VERIFY", "COMPLETED", "CZ07_INDEPENDENT_E2E_ACCEPTED")
    elif expected_status == "MOVED":
        if moved != total:
            raise UnifiedLinkHold("CZ07_TRANSPORT_COMPLETE_PREMATURE")
        step, state, code = (
            "FINAL_VERIFY", "NEEDS_ATTESTATION",
            "CZ07_TRANSPORT_COMPLETE_POSTCHECK_PENDING")
    elif expected_status == "VERIFYING":
        if moved != total:
            raise UnifiedLinkHold("CZ07_FINAL_VERIFICATION_PREMATURE")
        step, state, code = (
            "FINAL_VERIFY", "NEEDS_ATTESTATION", "CZ07_BUSINESS_E2E_REQUIRED")
    elif expected_status == "QUEUED":
        step, state, code = (
            "DNS_CUTOVER", "WAITING_EXTERNAL", "CZ07_ROUTE_APPROVAL_QUEUED")
    elif expected_status == "ROUTING":
        step, state, code = (
            "DNS_CUTOVER", "WAITING_EXTERNAL", "CZ07_DNS_EFFECT_UNCERTAIN")
    elif expected_status == "MIGRATING":
        step, state, code = (
            "CUSTOMER_MIGRATION", "WAITING_EXTERNAL",
            f"CZ07_BATCH_{moved}_OF_{total}")
    elif expected_status == "PAUSED_SAFE":
        step, state, code = (
            "CUSTOMER_MIGRATION", "NEEDS_OPERATOR",
            "CZ07_PAUSED_AT_BATCH_BOUNDARY")
    else:
        step, state, code = (
            "CUSTOMER_MIGRATION" if moved else "DNS_CUTOVER",
            "NEEDS_OPERATOR",
            "CZ07_ORIGINAL_JOURNAL_RECONCILE_REQUIRED")
    # After a CZ07 job has started routing, the effect risk cannot be
    # cleared by a UI event or by an unrelated administrative action.
    return _record(
        db, origin, step=step, state=state, code=code,
        now=now, external_intent=expected_status in (
            "ROUTING", "MIGRATING", "PAUSED_SAFE", "VERIFYING", "MOVED", "DONE"),
    )
