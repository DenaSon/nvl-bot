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
import os
import re
import secrets
from typing import Callable

from edge_egress_k2_m43_client import M43ClientHold
from edge_egress_k2_migration_inventory import (
    MigrationSelection, select_migration,
)
from edge_egress_k2_m4_root_portal import PreparedWave, RootMigrationPortal

K2_ROOT_DIRECT_ENABLED = False
K2_ROOT_DIRECT_BATCH_ENABLED = False
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class _Pending:
    prepared: PreparedWave
    actor_id: int
    chat_id: int


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
                or not isinstance(item.prepared,PreparedWave)
                or type(item.prepared.approval.expires_at) is not int):
                raise M43ClientHold("K2_ROOT_DIRECT_PENDING_CORRUPT")
            if item.prepared.approval.expires_at <= now:
                del self._pending[key]

    async def request(self, action: str, *, actor_id: int, chat_id: int,
                      selection: MigrationSelection | None = None,
                      request_id: str | None = None) -> dict:
        if action not in ("PREPARE","CONFIRM","CANCEL","STATUS"):
            raise M43ClientHold("K2_ROOT_DIRECT_ACTION_DENIED")
        self._gate(actor_id,chat_id)
        if action in ("PREPARE","STATUS"):
            if (not isinstance(selection, MigrationSelection)
                or select_migration(selection.mode, selection.usernames,
                                    selection.target_edge_id) != selection):
                raise M43ClientHold("K2_ROOT_DIRECT_SELECTION_UNTRUSTED")
        else:
            if (type(request_id) is not str
                or _REQUEST_ID.fullmatch(request_id) is None):
                raise M43ClientHold("K2_ROOT_DIRECT_REQUEST_ID_INVALID")

        if action == "STATUS":
            from edge_egress_k2_m44_recovery import inspect_root_recovery
            from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
            cp=self.portal.checkpoint
            if not isinstance(cp,DurableWaveCheckpoint):
                raise M43ClientHold("K2_ROOT_DIRECT_CHECKPOINT_REQUIRED")
            view=inspect_root_recovery(
                cp.db_conn,selection,actor_id=actor_id,chat_id=chat_id,
                admin_authorized=self.portal.admin_authorized,
                geteuid=self.geteuid,release_enabled=True,
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
            if (self._executing
                or (selection.mode != "SINGLE"
                    and not K2_ROOT_DIRECT_BATCH_ENABLED)):
                raise M43ClientHold("K2_ROOT_DIRECT_BATCH_OR_INFLIGHT_HOLD")
            self._prune()
            if len(self._pending) >= 20:
                raise M43ClientHold("K2_ROOT_DIRECT_QUEUE_FULL")
            prepared=self.portal.prepare(
                selection,actor_id=actor_id,chat_id=chat_id,
            )
            nonce=secrets.token_hex(16)
            while nonce in self._pending:
                nonce=secrets.token_hex(16)
            self._pending[nonce]=_Pending(prepared,actor_id,chat_id)
            return {
                "state":"PREPARED","request_id":nonce,
                "edge_id":selection.target_edge_id,
                "user_count":len(selection.usernames),
                "expires_at":prepared.approval.expires_at,
            }

        pending=self._pending.get(request_id)
        if (pending is None or pending.actor_id!=actor_id
            or pending.chat_id!=chat_id):
            raise M43ClientHold("K2_ROOT_DIRECT_APPROVAL_MISSING_OR_FOREIGN")
        # No second tap, retry, or cancellation can reuse the token.
        del self._pending[request_id]
        if action == "CANCEL":
            return {"state":"CANCELLED"}
        if self._executing:
            raise M43ClientHold("K2_ROOT_DIRECT_SINGLE_FLIGHT_HOLD")
        self._executing=True
        try:
            report=await self.portal.execute(
                pending.prepared,actor_id=actor_id,chat_id=chat_id,
            )
            return {
                "state":"COMPLETED" if report.all_verified else "HOLD",
                "completed":report.completed,"halted":report.halted,
                "accounts":[
                    {"username":p.username,"state":p.status}
                    for p in report.progress
                ],
            }
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
