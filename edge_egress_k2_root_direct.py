"""K2 Phase 1: single-poller ROOT bot -> original M4 portal in-process.

There is no Unix socket, root daemon, second Telegram poller, or alternate
6G lease here. The existing nvlbot process already runs as root. This
adapter only translates the *existing* M43 request contract to the original
RootMigrationPortal/checkpoint/P3 executor, retaining one-shot authorizations.

No automatic bootstrap: a reviewed RootMigrationPortal with real physical
ports must be explicitly registered by Core startup before execution.
All flags default OFF; missing registration is HOLD, never a fake success.
"""
from __future__ import annotations

from dataclasses import dataclass
import asyncio
import os
import re
import secrets
from typing import Callable

from edge_egress_k2_m43_client import M43ClientHold
from edge_egress_k2_migration_inventory import (
    MigrationSelection, select_migration,
)
from edge_egress_k2_m4_root_portal import PreparedWave, RootMigrationPortal
from edge_egress_k2_core_edge_operations import PreparedActiveEgress

K2_ROOT_DIRECT_ENABLED = False
K2_ROOT_DIRECT_BATCH_ENABLED = False
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class _Pending:
    prepared: PreparedWave | PreparedActiveEgress
    actor_id: int
    chat_id: int
    activate_relay: bool = False


class RootDirectOperatorClient:
    """Owned by ONE existing Telegram application; never constructed per tap."""

    def __init__(self, *, portal: RootMigrationPortal,
                 geteuid: Callable[[], int] = os.geteuid,
                 released: bool = False):
        if (not isinstance(portal, RootMigrationPortal)
            or not callable(geteuid)):
            raise M43ClientHold("K2_ROOT_DIRECT_PORTAL_REQUIRED")
        self.portal = portal
        self.geteuid = geteuid
        self.released = released
        self._pending: dict[str, _Pending] = {}
        self._executing = False
        self._preparing = False
        self._stop = False
        self._review_progress = (0, 0)

    def _gate(self, actor_id: int, chat_id: int) -> None:
        if (not K2_ROOT_DIRECT_ENABLED or self.released is not True
            or self.geteuid() != 0
            or type(actor_id) is not int or actor_id <= 0
            or type(chat_id) is not int or chat_id == 0):
            raise M43ClientHold("K2_ROOT_DIRECT_NOT_RELEASED")
        # Reuse the *real* root portal's role and release checks. The
        # Telegram callback's 'admin' label alone cannot authorize this.
        self.portal._gate(actor_id,chat_id)

    def _prune(self) -> None:
        now=self.portal.clock()
        if type(now) is not int or now <= 0:
            raise M43ClientHold("K2_ROOT_DIRECT_CLOCK_UNTRUSTED")
        for key,item in tuple(self._pending.items()):
            if (not isinstance(item,_Pending)
                or not isinstance(item.prepared,(PreparedWave,PreparedActiveEgress))):
                raise M43ClientHold("K2_ROOT_DIRECT_PENDING_CORRUPT")
            expiry=(item.prepared.expires_at if type(item.prepared) is PreparedActiveEgress
                    else item.prepared.approval.expires_at)
            if type(expiry) is not int:
                raise M43ClientHold("K2_ROOT_DIRECT_PENDING_CORRUPT")
            if expiry <= now:
                del self._pending[key]

    async def _host_task(self,call):
        """Retain single-flight ownership until synchronous host I/O ends."""
        task=asyncio.create_task(asyncio.to_thread(call))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            self._stop=True
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            # Retrieve host exceptions, but cancellation remains the result.
            if task.done() and not task.cancelled():
                task.exception()
            raise

    async def request(self, action: str, *, actor_id: int, chat_id: int,
                      selection: MigrationSelection | None = None,
                      request_id: str | None = None,
                      activate_relay: bool = False,
                      edge_id: str | None = None) -> dict:
        if action not in ("PREPARE","CONFIRM","CANCEL","STATUS","ALL","STOP","RECONCILE"):
            raise M43ClientHold("K2_ROOT_DIRECT_ACTION_DENIED")
        self._gate(actor_id,chat_id)
        if type(activate_relay) is not bool:
            raise M43ClientHold('K2_RELAY_INTENT_INVALID')
        if action=='STOP':
            if self._executing or self._preparing:
                self._stop=True
            return {'state':'STOP_REQUESTED' if self._executing or self._preparing else 'IDLE'}
        if action=='ALL':
            from edge_egress_k2_core_operations import eligible_cohort,CoreOperationalBindings
            if (not K2_ROOT_DIRECT_BATCH_ENABLED or self._executing or self._preparing
                or type(getattr(self.portal.review,'__self__',None)) is not CoreOperationalBindings):
                raise M43ClientHold('K2_ALL_NOT_RELEASED_OR_BUSY')
            from edge_egress_v1_console import edge_id_checked
            edge_id_checked(edge_id)
            self._preparing=True
            self._stop=False
            self._review_progress=(0,0)
            try:
                if activate_relay:
                    with self.portal.checkpoint.db_conn() as db:
                        names=tuple(r[0] for r in db.execute(
                            "SELECT username FROM ssh_accounts WHERE service_type='ssh' "
                            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' ORDER BY username"))
                        on_target=tuple(r[0] for r in db.execute(
                            "SELECT username FROM edge_egress_uid_runtime WHERE edge_id=? "
                            "AND state='PROTECTED' ORDER BY username",(edge_id,)))
                    if names and names==on_target:
                        return {'state':'INVENTORIED','selection':None,
                            'skipped':tuple((n,'TARGET_ALREADY_PROTECTED') for n in names)}
                selected,skipped=await self._host_task(lambda:eligible_cohort(
                    self.portal.checkpoint.db_conn,edge_id,review=self.portal.review,
                    stop_requested=lambda:self._stop,
                    progress=lambda done,total:setattr(self,"_review_progress",(done,total))))
                return {'state':'INVENTORIED','selection':selected,'skipped':skipped}
            finally:
                self._preparing=False
        if action in ("PREPARE","STATUS","RECONCILE"):
            if (not isinstance(selection, MigrationSelection)
                or select_migration(selection.mode, selection.usernames,
                                    selection.target_edge_id) != selection):
                raise M43ClientHold("K2_ROOT_DIRECT_SELECTION_UNTRUSTED")
        else:
            if (type(request_id) is not str
                or _REQUEST_ID.fullmatch(request_id) is None):
                raise M43ClientHold("K2_ROOT_DIRECT_REQUEST_ID_INVALID")

        if action=='RECONCILE':
            from edge_egress_k2_core_recovery import reconcile_settled_cohorts
            if self._executing or self._preparing:
                raise M43ClientHold('K2_RECONCILE_BUSY')
            self._preparing=True
            try:
                return await self._host_task(lambda:reconcile_settled_cohorts(
                    self.portal.execute_single.__self__,selection,actor_id=actor_id,chat_id=chat_id))
            finally:
                self._preparing=False
        if action == "STATUS":
            from edge_egress_k2_m44_recovery import inspect_root_recovery
            from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
            cp=self.portal.checkpoint
            if not isinstance(cp,DurableWaveCheckpoint):
                raise M43ClientHold("K2_ROOT_DIRECT_CHECKPOINT_REQUIRED")
            from edge_egress_k2_m42_bindings import RootM42Bindings
            root=getattr(self.portal.execute_single,'__self__',None)
            providers=({'os_uid':root.ports.os_uid,'clock':root.ports.now}
                       if isinstance(root,RootM42Bindings) else {})
            view=inspect_root_recovery(
                cp.db_conn,selection,actor_id=actor_id,chat_id=chat_id,
                admin_authorized=self.portal.admin_authorized,
                geteuid=self.geteuid,release_enabled=True,
                **providers,
            )
            return {
                "state":"STATUS","edge_id":view.edge_id,
                "wave_state":view.wave_state,"busy":view.original_6g_busy,
                "unresolved":view.unresolved,
                "users":[{"username":u.username,"state":u.state}
                         for u in view.users],
                "note":view.note,
            }
        if action == "PREPARE":
            if (self._executing or self._preparing
                or (selection.mode != "SINGLE"
                    and not K2_ROOT_DIRECT_BATCH_ENABLED)):
                raise M43ClientHold("K2_ROOT_DIRECT_BATCH_OR_INFLIGHT_HOLD")
            self._prune()
            if len(self._pending) >= 20:
                raise M43ClientHold("K2_ROOT_DIRECT_QUEUE_FULL")
            self._preparing=True
            self._stop=False
            try:
                from edge_egress_k2_core_operations import CoreOperationalBindings
                root=getattr(self.portal.execute_single,'__self__',None)
                if type(root) is CoreOperationalBindings:
                    def prepare():
                        if activate_relay:
                            with root.ports.db_conn() as db:
                                names=tuple(r[0] for r in db.execute(
                                    "SELECT username FROM ssh_accounts WHERE service_type='ssh' "
                                    "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' ORDER BY username"))
                                verified=tuple(r[0] for r in db.execute(
                                    "SELECT username FROM edge_egress_uid_runtime WHERE edge_id=? "
                                    "AND state='PROTECTED' ORDER BY username",(selection.target_edge_id,)))
                            if names==tuple(sorted(selection.usernames))==verified:
                                from edge_egress_k2_core_edge_operations import prepare_active_egress
                                return prepare_active_egress(root,selection.target_edge_id,
                                    actor_id=actor_id,chat_id=chat_id)
                        return self.portal.prepare(selection,actor_id=actor_id,chat_id=chat_id)
                    prepared=await self._host_task(prepare)
                    if self._stop:
                        raise M43ClientHold("CORE_REVIEW_STOPPED")
                else:
                    prepared=self.portal.prepare(selection,actor_id=actor_id,chat_id=chat_id)
            finally:
                self._preparing=False
            nonce=secrets.token_hex(16)
            while nonce in self._pending:
                nonce=secrets.token_hex(16)
            self._pending[nonce]=_Pending(prepared,actor_id,chat_id,activate_relay)
            return {
                "state":"PREPARED","request_id":nonce,
                "edge_id":selection.target_edge_id,
                "user_count":len(selection.usernames),
                "expires_at":(prepared.expires_at if type(prepared) is PreparedActiveEgress
                              else prepared.approval.expires_at),
            }

        pending=self._pending.get(request_id)
        if (pending is None or pending.actor_id!=actor_id
            or pending.chat_id!=chat_id):
            raise M43ClientHold("K2_ROOT_DIRECT_APPROVAL_MISSING_OR_FOREIGN")
        # No second tap, retry, or cancellation can reuse the token.
        del self._pending[request_id]
        if action == "CANCEL":
            return {"state":"CANCELLED"}
        if self._executing or self._preparing:
            raise M43ClientHold("K2_ROOT_DIRECT_SINGLE_FLIGHT_HOLD")
        self._executing=True
        self._stop=False
        try:
            from edge_egress_k2_core_operations import CoreOperationalBindings
            if type(pending.prepared) is PreparedActiveEgress:
                from edge_egress_k2_core_edge_operations import execute_active_egress
                root=self.portal.execute_single.__self__
                receipt=await self._host_task(lambda:asyncio.run(execute_active_egress(
                    root,pending.prepared,actor_id=actor_id,chat_id=chat_id)))
                success=receipt.allowed and receipt.result=='SUCCEEDED'
                names=[r[0] for r in pending.prepared.identity[0]]
                return {'state':'COMPLETED' if success else 'HOLD','completed':0,
                    'halted':not success,'relay_state':'VERIFIED' if success else 'HOLD',
                    'accounts':[{'username':n,'state':'VERIFIED' if success else 'HOLD'} for n in names]}
            if type(getattr(self.portal.execute_single,'__self__',None)) is CoreOperationalBindings:
                # Keep the existing Telegram event loop responsive while
                # fixed synchronous OS/SSH measurements run. One temporary
                # thread, no daemon/poller; STOP is observed between UIDs.
                report=await self._host_task(lambda:asyncio.run(self.portal.execute(
                    pending.prepared,actor_id=actor_id,chat_id=chat_id,
                    stop_requested=lambda:self._stop)))
            else:
                report=await self.portal.execute(
                    pending.prepared,actor_id=actor_id,chat_id=chat_id)
            relay_state=None
            if pending.activate_relay and report.all_verified:
                from edge_egress_k2_core_edge_operations import select_active_egress
                root=getattr(self.portal.execute_single,'__self__',None)
                try:
                    receipt=await self._host_task(lambda:asyncio.run(select_active_egress(
                        root,pending.prepared.plan.selection.target_edge_id,
                        actor_id=actor_id,chat_id=chat_id)))
                    relay_state='VERIFIED' if receipt.allowed and receipt.result=='SUCCEEDED' else 'HOLD'
                except (ValueError,OSError):
                    relay_state='HOLD'
            result={
                "state":"COMPLETED" if report.all_verified else "HOLD",
                "completed":report.completed,"halted":report.halted,
                "accounts":[
                    {"username":p.username,"state":p.status}
                    for p in report.progress
                ],
            }
            if pending.activate_relay:
                result['relay_state']=relay_state or 'HOLD'
            return result
        finally:
            self._executing=False


# Process-private root authority MUST NEVER enter application.bot_data or
# PTB PicklePersistence (where HMAC secrets and execution callbacks may leak).
# Registration is explicit at reviewed Core startup; one bot poller only.
_ACTIVE_APPLICATION = None
_ACTIVE_CLIENT: RootDirectOperatorClient | None = None


def register_root_portal(
    application, *, portal: RootMigrationPortal,
    geteuid: Callable[[], int] = os.geteuid,
    released: bool = False,
) -> RootDirectOperatorClient:
    """Bind one reviewed root portal to the existing in-memory bot instance.

    No dynamic import, SSH command, socket, arbitrary Telegram factory, or
    alternate 6G lease. Reject duplicate registration and restart attempts.
    """
    global _ACTIVE_APPLICATION, _ACTIVE_CLIENT
    if (not K2_ROOT_DIRECT_ENABLED or released is not True
        or not callable(geteuid) or geteuid()!=0
        or not isinstance(portal,RootMigrationPortal)
        or portal.release_enabled is not True
        or portal.geteuid()!=0
        or application is None
        or not isinstance(getattr(application,"bot_data",None),dict)
        or _ACTIVE_CLIENT is not None):
        raise M43ClientHold("K2_ROOT_DIRECT_BIND_NOT_ACCEPTED")
    client=RootDirectOperatorClient(
        portal=portal,geteuid=geteuid,released=True,
    )
    _ACTIVE_APPLICATION=application
    _ACTIVE_CLIENT=client
    return client


def bound_root_client(application) -> RootDirectOperatorClient:
    """Only the registered same-process bot may use the reviewed root port."""
    if (not K2_ROOT_DIRECT_ENABLED
        or application is None or application is not _ACTIVE_APPLICATION
        or type(_ACTIVE_CLIENT) is not RootDirectOperatorClient):
        raise M43ClientHold("K2_ROOT_DIRECT_NOT_REGISTERED")
    return _ACTIVE_CLIENT


def native_core_runtime_registered() -> bool:
    """Presentation check; actual handlers still bind the exact application."""
    from edge_egress_k2_core_prerequisites import CoreUIDSnapshotSource
    if (not K2_ROOT_DIRECT_ENABLED or _ACTIVE_APPLICATION is None
        or type(_ACTIVE_CLIENT) is not RootDirectOperatorClient):
        return False
    execute = _ACTIVE_CLIENT.portal.execute_single
    root = getattr(execute, "__self__", None)
    factory = getattr(getattr(root, "ports", None), "port_factory", None)
    return type(getattr(factory, "read_root_snapshot", None)) is CoreUIDSnapshotSource


def native_operations_registered() -> bool:
    from edge_egress_k2_core_operations import CoreOperationalBindings,CORE_OPERATIONS_ENABLED
    return bool(native_core_runtime_registered() and CORE_OPERATIONS_ENABLED
        and type(getattr(_ACTIVE_CLIENT.portal.execute_single,'__self__',None)) is CoreOperationalBindings)


async def native_review(application, selection, *, actor_id,chat_id):
    """Fresh native measurements for existing UI; no synthetic preview fallback."""
    client=bound_root_client(application)
    client._gate(actor_id,chat_id)
    if client._executing or client._preparing:
        raise M43ClientHold('K2_REVIEW_BUSY')
    client._preparing=True
    client._stop=False
    client._review_progress=(0,len(selection.usernames))
    try:
        result=await client._host_task(lambda:client.portal.review(selection))
        if client._stop:
            raise M43ClientHold("CORE_REVIEW_STOPPED")
        client._review_progress=(len(selection.usernames),len(selection.usernames))
        return result
    finally:
        client._preparing=False


async def native_prepare_edge(application,edge_id,*,actor_id,chat_id):
    client=bound_root_client(application)
    client._gate(actor_id,chat_id)
    from edge_egress_k2_core_operations import CoreOperationalBindings
    root=getattr(client.portal.execute_single,'__self__',None)
    if type(root) is not CoreOperationalBindings or client._executing or client._preparing:
        raise M43ClientHold('K2_NATIVE_EDGE_PREPARATION_UNAVAILABLE')
    client._preparing=True
    try:
        from edge_egress_k2_core_edge_operations import prepare_edge
        return await client._host_task(lambda:prepare_edge(root,edge_id,actor_id=actor_id,chat_id=chat_id))
    finally:
        client._preparing=False
