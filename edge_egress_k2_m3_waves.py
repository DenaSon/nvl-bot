"""K2 M3: one guarded UID lifecycle used by SINGLE and bounded BATCH waves.

No Linux/SQL mutation in this module. Every selected account uses a fresh
per-UID M1 preflight, a distinct P3 ticket, the original 6G executor, and
a read-only durable 6G receipt check before the next account may start.

This source interface is NOT registered in Telegram or a root worker.
Default execution is OFF. An inventory preview or synthetic CI proof is
never sufficient to authorize actual customer SSH/SOCKS migration.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
import re
import time
from typing import Awaitable, Callable

from edge_egress_k2_migration_inventory import (
    MigrationInventory, MigrationSelection, UserInventory, select_migration,
)
from edge_egress_p3_executor import (
    ExecutionReceipt, ExecutionScope, ExecutionTicket, _scope_digest,
)

M3_WAVE_EXECUTION_ENABLED = False
# Single verified cross-Edge transfer in unchanged Legacy global mode only.
M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED = False
MAX_WAVE_SIZE = 10
MAX_APPROVAL_AGE_SECONDS = 300


class MigrationWaveHold(ValueError):
    """Fail-closed only; no raw credentials or host tracebacks."""


@dataclass(frozen=True)
class MigrationMember:
    username: str
    uid: int | None
    historical_host: str
    source_edge_id: str
    source_ipv4: str
    source_proven: bool
    target_edge_id: str
    target_ipv4: str
    protected_edge_id: str
    active_sessions: int | None
    blockers: tuple[str, ...]

    @property
    def selectable(self) -> bool:
        return (not self.blockers and self.uid is not None
                and self.source_proven and self.active_sessions == 0)


@dataclass(frozen=True)
class MigrationWavePlan:
    selection: MigrationSelection
    snapshot_digest: str
    target_ipv4: str
    global_blockers: tuple[str, ...]
    members: tuple[MigrationMember, ...]
    wave_size: int
    digest: str

    @property
    def blocked(self) -> tuple[MigrationMember, ...]:
        return tuple(m for m in self.members if not m.selectable)

    @property
    def ready_count(self) -> int:
        return 0 if self.global_blockers else sum(
            m.selectable for m in self.members)

    @property
    def waves(self) -> tuple[tuple[MigrationMember, ...], ...]:
        return tuple(
            self.members[index:index + self.wave_size]
            for index in range(0, len(self.members), self.wave_size)
        )

    @property
    def can_execute(self) -> bool:
        # Explicitly no auto-release even when every field passes preview.
        return False


@dataclass(frozen=True)
class WaveApproval:
    plan_digest: str
    actor_id: int
    chat_id: int
    expires_at: int
    signature: str


@dataclass(frozen=True)
class WaveProgress:
    username: str
    uid: int | None
    status: str  # HOLD, DEFERRED, or VERIFIED
    code: str
    operation_id: int | None = None


@dataclass(frozen=True)
class WaveReport:
    plan_digest: str
    progress: tuple[WaveProgress, ...]
    halted: bool
    halt_reason: str
    all_verified: bool

    @property
    def completed(self) -> int:
        return sum(p.status == "VERIFIED" for p in self.progress)


def _digest_plan(selection: MigrationSelection, snapshot_digest: str,
                 target_ipv4: str, global_blockers: tuple[str, ...],
                 members: tuple[MigrationMember, ...],
                 wave_size: int) -> str:
    payload={
        "mode":selection.mode,"names":selection.usernames,
        "edge":selection.target_edge_id,"target":target_ipv4,
        "inventory":snapshot_digest,"global":global_blockers,
        "wave_size":wave_size,
        "members":[vars(m) for m in members],
    }
    return sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),
                             ensure_ascii=False).encode()).hexdigest()


def _assert_plan(plan: MigrationWavePlan) -> None:
    if (not isinstance(plan,MigrationWavePlan)
        or type(plan.wave_size) is not int
        or not 1 <= plan.wave_size <= MAX_WAVE_SIZE
        or not isinstance(plan.members,tuple)
        or len(plan.members)!=len(plan.selection.usernames)
        or any(not isinstance(m,MigrationMember) for m in plan.members)
        or tuple(m.username for m in plan.members)!=plan.selection.usernames
        or any(m.target_edge_id!=plan.selection.target_edge_id
               or m.target_ipv4!=plan.target_ipv4
               for m in plan.members)
        or select_migration(plan.selection.mode,plan.selection.usernames,
                            plan.selection.target_edge_id)!=plan.selection
        or not isinstance(plan.snapshot_digest,str)
        or not re.fullmatch(r"[0-9a-f]{64}",plan.snapshot_digest)
        or not isinstance(plan.digest,str)
        or not hmac.compare_digest(
            plan.digest,_digest_plan(plan.selection,plan.snapshot_digest,
                    plan.target_ipv4,plan.global_blockers,plan.members,
                    plan.wave_size))):
        raise MigrationWaveHold("WAVE_PLAN_IMMUTABILITY_NOT_ATTESTED")


def split_wave_plan(plan: MigrationWavePlan
                    ) -> tuple[MigrationWavePlan, ...]:
    """Split a broad selected cohort into separately approved <=10 UID waves."""
    _assert_plan(plan)
    result=[]
    for group in plan.waves:
        selection=select_migration(plan.selection.mode,
            tuple(m.username for m in group),plan.selection.target_edge_id)
        digest=_digest_plan(selection,plan.snapshot_digest,plan.target_ipv4,
                            plan.global_blockers,group,plan.wave_size)
        result.append(MigrationWavePlan(
            selection,plan.snapshot_digest,plan.target_ipv4,
            plan.global_blockers,group,plan.wave_size,digest,
        ))
    return tuple(result)


def build_wave_plan(inventory: MigrationInventory, *,
                    wave_size: int = MAX_WAVE_SIZE) -> MigrationWavePlan:
    """Pure explicit-list plan, retaining BLOCKED entries without omission."""
    if not isinstance(inventory, MigrationInventory) or (
        type(wave_size) is not int or not 1 <= wave_size <= MAX_WAVE_SIZE
    ):
        raise MigrationWaveHold("WAVE_INPUT_UNTRUSTED")
    sel=inventory.selection
    if select_migration(sel.mode,sel.usernames,sel.target_edge_id)!=sel:
        raise MigrationWaveHold("WAVE_SELECTION_CHANGED")
    if (not isinstance(inventory.fingerprint,str)
        or len(inventory.fingerprint)!=64
        or not all(c in "0123456789abcdef" for c in inventory.fingerprint)):
        raise MigrationWaveHold("INVENTORY_FINGERPRINT_UNTRUSTED")
    if inventory.selected_total != len(sel.usernames):
        raise MigrationWaveHold("WAVE_SELECTION_COUNT_MISMATCH")
    rows={a.username:a for a in inventory.accounts if a.selected}
    if len(rows)!=len(sel.usernames):
        raise MigrationWaveHold("WAVE_DUPLICATE_OR_MISSING_ACCOUNT")
    if any(not isinstance(rows.get(name),UserInventory) for name in sel.usernames):
        raise MigrationWaveHold("WAVE_SELECTED_ACCOUNT_UNAVAILABLE")
    members=[]
    for name in sel.usernames:
        a=rows[name]
        blockers=list(a.issues)
        if not inventory.target_f4_accepted:
            blockers.append("TARGET_F4_NOT_ACCEPTED")
        if not a.source_proven or not a.source_edge_id or not a.source_ipv4:
            blockers.append("SOURCE_INGRESS_NOT_ATTESTED")
        if a.uid is None:
            blockers.append("ACCOUNT_UID_NOT_ATTESTED")
        if a.active_sessions is None:
            blockers.append("SESSION_STATE_NOT_ATTESTED")
        elif a.active_sessions:
            blockers.append("ACTIVE_SESSIONS_PRESENT")
        if a.protected_edge_id == sel.target_edge_id:
            blockers.append("TARGET_ALREADY_PROTECTED")
        members.append(MigrationMember(
            a.username,a.uid,a.historical_host,a.source_edge_id,
            a.source_ipv4,a.source_proven,sel.target_edge_id,
            inventory.target_ipv4,a.protected_edge_id,a.active_sessions,
            tuple(dict.fromkeys(blockers)),
        ))
    members=tuple(members)
    global_blockers=tuple(inventory.global_issues)
    digest=_digest_plan(sel,inventory.fingerprint,inventory.target_ipv4,
                        global_blockers,members,wave_size)
    result=MigrationWavePlan(sel,inventory.fingerprint,inventory.target_ipv4,
                             global_blockers,members,wave_size,digest)
    _assert_plan(result)
    return result


def m4_same_ingress_reviewed(plan: MigrationWavePlan) -> bool:
    """Pure M4 live factory admission contract, never proof of physical F4.

    Legacy cross-edge UID_ATTACH is valid as a *concept* in original P3,
    but no reviewed M4 host port currently accepts it in mixed Legacy mode.
    The same criterion must be used by both Telegram preview and root PREPARE
    so operators cannot see an executable approval for an impossible move.
    """
    _assert_plan(plan)
    return (
        bool(plan.members) and not plan.global_blockers
        and not plan.blocked
        and all(
            m.source_proven
            and m.source_edge_id == m.target_edge_id
            and m.source_ipv4 == m.target_ipv4
            and m.protected_edge_id == ""
            for m in plan.members
        )
    )


def m4_cross_edge_single_reviewed(plan: MigrationWavePlan) -> bool:
    """One attested ingress->different egress. Not batch/F4 authorisation."""
    _assert_plan(plan)
    return (
        plan.selection.mode == "SINGLE"
        and len(plan.members) == 1
        and not plan.global_blockers and not plan.blocked
        and plan.wave_size >= 1
        and all(
            m.source_proven and m.active_sessions == 0
            and m.source_edge_id != m.target_edge_id
            and m.source_ipv4 != m.target_ipv4
            and m.protected_edge_id == ""
            for m in plan.members
        )
    )


def _approval_message(plan: MigrationWavePlan, actor_id: int,
                      chat_id: int, expires_at: int) -> bytes:
    return json.dumps((plan.digest,actor_id,chat_id,expires_at),
                      separators=(",",":")).encode()


def sign_wave_approval(plan: MigrationWavePlan, *, actor_id: int,
                       chat_id: int, expires_at: int, secret: bytes,
                       now: int | None = None,
                       operator_authorized: bool = False) -> WaveApproval:
    """Root trust service only. Operator authorization is independently checked.

    No bot-facing route in M3; M4 must keep the 32+ byte secret root-only and
    issue this only for an explicitly reviewed exact plan and admin action.
    """
    stamp=int(time.time()) if now is None else now
    _assert_plan(plan)
    if (not isinstance(plan,MigrationWavePlan)
        or not plan.digest or type(actor_id) is not int or actor_id<=0
        or type(chat_id) is not int or chat_id==0
        or type(expires_at) is not int or type(stamp) is not int
        or not stamp < expires_at <= stamp+MAX_APPROVAL_AGE_SECONDS
        or not isinstance(secret,bytes) or len(secret)<32
        or operator_authorized is not True):
        raise MigrationWaveHold("WAVE_OPERATOR_APPROVAL_NOT_ATTESTED")
    sig=hmac.new(secret,_approval_message(plan,actor_id,chat_id,expires_at),
                 "sha256").hexdigest()
    return WaveApproval(plan.digest,actor_id,chat_id,expires_at,sig)


def verify_wave_approval(plan: MigrationWavePlan, approval: WaveApproval, *,
                         actor_id: int,chat_id: int,secret: bytes,
                         now: int) -> None:
    _assert_plan(plan)
    if (not isinstance(plan,MigrationWavePlan)
        or not isinstance(approval,WaveApproval)
        or not isinstance(secret,bytes) or len(secret)<32
        or type(now) is not int or type(actor_id) is not int
        or type(chat_id) is not int
        or approval.plan_digest!=plan.digest
        or approval.actor_id!=actor_id or approval.chat_id!=chat_id
        or type(approval.expires_at) is not int
        or not now < approval.expires_at <= now+MAX_APPROVAL_AGE_SECONDS
        or not isinstance(approval.signature,str)):
        raise MigrationWaveHold("WAVE_APPROVAL_MISSING_EXPIRED_OR_UNBOUND")
    expected=hmac.new(
        secret,_approval_message(plan,actor_id,chat_id,approval.expires_at),
        "sha256").hexdigest()
    if not hmac.compare_digest(approval.signature,expected):
        raise MigrationWaveHold("WAVE_APPROVAL_SIGNATURE_UNTRUSTED")


def _scope(member: MigrationMember) -> ExecutionScope:
    """Same source Edge requires enrollment; changing Edge requires attach."""
    if not member.selectable:
        raise MigrationWaveHold("WAVE_MEMBER_NOT_READY")
    return ExecutionScope(
        "UID_ENROLL_SOURCE" if member.source_ipv4==member.target_ipv4
        else "UID_ATTACH",
        member.target_edge_id,member.source_ipv4,member.target_ipv4,
        username=member.username,uid=member.uid,
    )


def _fresh_member(
    expected: MigrationMember, fresh: MigrationInventory,
) -> bool:
    """Re-read exact UID, source, status, Edge, F4 and session state per UID."""
    if (not isinstance(fresh,MigrationInventory)
        or fresh.selection.mode!="SINGLE"
        or fresh.selection.usernames!=(expected.username,)
        or fresh.selection.target_edge_id!=expected.target_edge_id
        or fresh.target_ipv4!=expected.target_ipv4
        or not fresh.target_f4_accepted or fresh.global_issues):
        return False
    chosen=[x for x in fresh.accounts if x.selected]
    if len(chosen)!=1 or chosen[0].issues:
        return False
    curr=chosen[0]
    return (
        curr.username==expected.username and curr.uid==expected.uid
        and curr.historical_host==expected.historical_host
        and curr.source_edge_id==expected.source_edge_id
        and curr.source_ipv4==expected.source_ipv4
        and curr.source_proven and curr.active_sessions==0
        and curr.protected_edge_id==expected.protected_edge_id
    )


def _as_report(plan: MigrationWavePlan, updates: list[WaveProgress],
               reason: str = "") -> WaveReport:
    ordered=tuple(
        next((r for r in updates if r.username==m.username),
             WaveProgress(m.username,m.uid,"DEFERRED","NOT_STARTED"))
        for m in plan.members
    )
    return WaveReport(plan.digest,ordered,bool(reason),reason,
                      not reason and all(p.status=="VERIFIED" for p in ordered))


async def run_migration_wave(
    plan: MigrationWavePlan,approval: WaveApproval, *,actor_id: int,
    chat_id: int, approval_secret: bytes,
    fresh_inventory: Callable[[MigrationSelection],MigrationInventory],
    issue_single_ticket: Callable[[ExecutionScope,int,int],ExecutionTicket],
    execute_single: Callable[[ExecutionScope,ExecutionTicket,int,int],
                             Awaitable[ExecutionReceipt]],
    committed_6g: Callable[[ExecutionScope,ExecutionTicket,int],bool],
    current_protected_mode: Callable[[], str],
    on_verified: Callable[[str,int,int],None] | None = None,
    release_enabled: bool = False,
    geteuid: Callable[[],int] = os.geteuid,
    clock: Callable[[],int] = lambda: int(time.time()),
) -> WaveReport:
    """Sequential **one UID per original 6G lease**; stop on first HOLD.

    No competing wave-wide lock, shadow journal, 6G unlock, automatic retry,
    manual ip route/uid rule or PAM manipulation. Per-account P3 executors
    remain responsible for deny-first, packet proof and failure fencing.
    """
    if (not M3_WAVE_EXECUTION_ENABLED or release_enabled is not True
        or not isinstance(plan,MigrationWavePlan) or geteuid()!=0
        or not all(callable(fn) for fn in (
            fresh_inventory,issue_single_ticket,execute_single,
            committed_6g,current_protected_mode,clock,
        ))):
        raise MigrationWaveHold("M3_LIVE_EXECUTOR_NOT_RELEASED")
    _assert_plan(plan)
    if len(plan.members)>plan.wave_size:
        raise MigrationWaveHold("WAVE_REQUIRES_EXPLICIT_SUBWAVE_APPROVAL")
    verify_wave_approval(
        plan,approval,actor_id=actor_id,chat_id=chat_id,
        secret=approval_secret,now=clock(),
    )
    if plan.global_blockers:
        return _as_report(plan,[],"WAVE_GLOBAL_HOLD")
    if plan.blocked:
        updates=[
            WaveProgress(m.username,m.uid,"HOLD",
                         m.blockers[0] if m.blockers else "MEMBER_HOLD")
            for m in plan.members if not m.selectable
        ]
        return _as_report(plan,updates,"WAVE_HAS_BLOCKED_USERS")
    seen_tickets=set()
    results=[]
    for member in plan.members:
        # No more than ten accounts, one-at-a-time and no automatic next UID
        # after failed 6G, lost F4, packet hold or cancellation.
        if clock()>=approval.expires_at:
            results.append(WaveProgress(member.username,member.uid,
                                        "HOLD","WAVE_APPROVAL_EXPIRED"))
            return _as_report(plan,results,"WAVE_APPROVAL_EXPIRED")
        try:
            selection=select_migration(
                "SINGLE",(member.username,),member.target_edge_id)
            current=fresh_inventory(selection)
            if not _fresh_member(member,current):
                raise MigrationWaveHold("M3_UID_OR_F4_EVIDENCE_CHANGED")
            scope=_scope(member)
            mode=current_protected_mode()
            if mode not in ("0","1"):
                raise MigrationWaveHold("M3_PROTECTED_MODE_NOT_ATTESTED")
            if (scope.action=="UID_ENROLL_SOURCE" and mode!="0"):
                raise MigrationWaveHold("M3_SAME_EDGE_REQUIRES_LEGACY_MODE")
            if scope.action=="UID_ATTACH" and mode=="0":
                if (not M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED
                    or not m4_cross_edge_single_reviewed(plan)):
                    raise MigrationWaveHold(
                        "M3_CROSS_EDGE_REQUIRES_SEPARATE_PROTECTED_ACCEPTANCE")
            elif scope.action=="UID_ATTACH" and mode!="1":
                raise MigrationWaveHold(
                    "M3_CROSS_EDGE_REQUIRES_SEPARATE_PROTECTED_ACCEPTANCE")
            ticket=issue_single_ticket(scope,actor_id,chat_id)
            if (not isinstance(ticket,ExecutionTicket)
                or ticket.actor_id!=actor_id or ticket.chat_id!=chat_id
                or ticket.scope_digest!=_scope_digest(scope)
                or ticket.nonce in seen_tickets
                or not isinstance(ticket.nonce,str)
                or not re.fullmatch(r"[a-f0-9]{32}",ticket.nonce)
                or clock()>=ticket.expires_at):
                raise MigrationWaveHold("M3_SINGLE_TICKET_NOT_PINNED")
            seen_tickets.add(ticket.nonce)
            receipt=await execute_single(scope,ticket,actor_id,chat_id)
            if (not isinstance(receipt,ExecutionReceipt)
                or receipt.allowed is not True or receipt.result!="SUCCEEDED"
                or type(receipt.operation_id) is not int
                or receipt.operation_id<=0):
                raise MigrationWaveHold("M3_GUARDED_6G_SINGLE_HOLD")
            if committed_6g(scope,ticket,receipt.operation_id) is not True:
                raise MigrationWaveHold("M3_DURABLE_6G_RECEIPT_NOT_ATTESTED")
            # Root M4 checkpoint persists each original-6G VERIFIED
            # terminal receipt before this wave can dispatch the next UID.
            # A checkpoint DB failure stops the wave fail-closed.
            if on_verified is not None:
                if not callable(on_verified):
                    raise MigrationWaveHold("M3_PROGRESS_WITNESS_UNTRUSTED")
                on_verified(member.username,member.uid,receipt.operation_id)
            results.append(WaveProgress(
                member.username,member.uid,"VERIFIED","P3_6G_COMMITTED",
                receipt.operation_id))
        except Exception as exc:
            # Never leak passwords, host logs or raw adapter exception details.
            reason=(str(exc) if isinstance(exc,MigrationWaveHold)
                    else "M3_SINGLE_EXECUTION_UNVERIFIED")
            results.append(WaveProgress(member.username,member.uid,
                                        "HOLD",reason))
            return _as_report(plan,results,reason)
    return _as_report(plan,results)
