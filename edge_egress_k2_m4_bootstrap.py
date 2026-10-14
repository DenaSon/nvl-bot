"""M4.2: original-6G-scoped M2 first/Nth bootstrap before real P3 UID port.

The P3 root executor acquires original 6G BEFORE calling apply(). Only this
host-port invokes root file/PAM/module staging. A partial stage remains fenced
with original RUNNING 6G, never magically promoted to verified customer egress.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
)
from edge_egress_k2_m3_ingress_port import GuardedVerifiedIngressUIDPort
from edge_egress_k2_m3_waves import MigrationMember
from ops.k2_m2_first_uid import guarded_first_uid_bootstrap
from ops.k2_m2_guard_append import apply_next_uid


class M42BootstrapHold(ValueError):
    pass


@dataclass(frozen=True)
class GuardBootstrap:
    """Immutable reviewed M2 plan; no generic user-command callback.

    Root-owned plan factory supplies exact M2 arguments only. Original M2
    functions independently verify real M2 guards and original 6G before
    each mutation. Missing/partial kwargs always hold.
    """
    scope: ExecutionScope
    ticket: ExecutionTicket
    kind: str
    kwargs: Mapping[str, object]

    def run(self, scope: ExecutionScope, ticket: ExecutionTicket) -> None:
        if (self.scope != scope or self.ticket != ticket
            or self.kind not in ("FIRST_UID", "NEXT_UID")
            or not isinstance(self.kwargs, dict)
            or self.kwargs.get("scope") != scope
            or self.kwargs.get("ticket") != ticket
            or self.kwargs.get("release_enabled") is not True
            or self.kwargs.get("db_conn") is None):
            raise M42BootstrapHold("M42_M2_BOOTSTRAP_NOT_PINNED")
        if self.kind == "FIRST_UID":
            guarded_first_uid_bootstrap(**self.kwargs)
        else:
            # Never silently resume a partially staged UID.
            if self.kwargs.get("resume_partial", False) is not False:
                raise M42BootstrapHold("M42_MANUAL_RECONCILE_REQUIRED")
            apply_next_uid(**self.kwargs)


class DeferredOriginal6GHostPort:
    """P3 GuardedHostPort that stages original M2 then delegates to real M3.

    The deferred type ensures M2 artifacts do not get created during Telegram
    PREPARE, M3 ticket issuance or P3 preflight *before* 6G acquisition.
    """

    def __init__(
        self, *, scope: ExecutionScope, ticket: ExecutionTicket,
        db_conn: Callable,
        bootstrap: GuardBootstrap,
        port_factory: Callable[
            [ExecutionScope, ExecutionTicket], GuardedVerifiedIngressUIDPort,
        ],
    ):
        if (not isinstance(scope, ExecutionScope)
            or not isinstance(ticket, ExecutionTicket)
            or not isinstance(bootstrap, GuardBootstrap)
            or bootstrap.scope != scope or bootstrap.ticket != ticket
            or not callable(db_conn) or not callable(port_factory)
            or bootstrap.kwargs.get("db_conn") is not db_conn):
            raise M42BootstrapHold("M42_DEFERRED_PORT_SCOPE_INVALID")
        self.scope, self.ticket = scope, ticket
        self.db_conn, self.bootstrap = db_conn, bootstrap
        self.port_factory = port_factory
        self._started = False
        self._port = None

    def _locked(self, scope: ExecutionScope):
        if scope != self.scope:
            raise M42BootstrapHold("M42_P3_SCOPE_CHANGED")
        return assert_guarded_6g_intent(self.db_conn, scope, self.ticket)

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise M42BootstrapHold("M42_BOOTSTRAP_ALREADY_ATTEMPTED")
        self._started = True
        self._locked(scope)
        self.bootstrap.run(scope, self.ticket)
        self._locked(scope)
        port = self.port_factory(scope, self.ticket)
        if (not isinstance(port, GuardedVerifiedIngressUIDPort)
            or port.contract.scope != scope or port.ticket != self.ticket
            or port.release_enabled is not True):
            raise M42BootstrapHold("M42_REAL_M3_UID_PORT_REQUIRED")
        self._port = port
        await port.apply(scope)

    async def verify(self, scope: ExecutionScope) -> bool:
        self._locked(scope)
        if self._port is None:
            raise M42BootstrapHold("M42_P3_NOT_APPLIED")
        return await self._port.verify(scope) is True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        self._locked(scope)
        if self._port is None:
            # Existing original 6G remains RUNNING in P3. Never un-fence a
            # possibly half-staged M2 unit or invent success.
            raise M42BootstrapHold("M42_PARTIAL_BOOTSTRAP_HOLD_ORIGINAL_6G")
        await self._port.freeze_or_hold(scope)
