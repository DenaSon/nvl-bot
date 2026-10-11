"""F2: injected shared-6G runtime bridge; no bot/SSH registration.

The existing bot's acquire/update functions remain the ONLY lease authority.
Host ports, gate verification and session-drain checks are REQUIRED injections.
There is intentionally no default live shell, PAM installer or DNS mutator.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable, Protocol

from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime import RuntimeUnsafe, PHASES
from edge_egress_uid_runtime_store import Existing6GUIDRuntimeStore


class RuntimeKernelPort(Protocol):
    def arm(self, request: UIDPolicyRequest, dns_port: int) -> None: ...
    def attach(self, request: UIDPolicyRequest) -> None: ...
    def freeze(self, request: UIDPolicyRequest) -> None: ...
    def assert_frozen(self, request: UIDPolicyRequest) -> None: ...
    def public_ipv4(self, request: UIDPolicyRequest) -> str: ...
    def assert_dns_ipv6(self, request: UIDPolicyRequest) -> None: ...


class RuntimeShadowPort(Protocol):
    async def start(self, request: UIDPolicyRequest) -> None: ...


@dataclass
class Existing6GUIDRuntimeBridge:
    db_conn: Callable
    acquire_fn: Callable
    update_fn: Callable
    os_uid_for_username: Callable
    kernel: RuntimeKernelPort | None = None
    shadow: RuntimeShadowPort | None = None
    session_gate_probe: Callable | None = None
    existing_sessions_probe: Callable | None = None
    store: Existing6GUIDRuntimeStore = field(init=False)
    operation_id: int | None = field(default=None, init=False)
    source: str | None = field(default=None, init=False)
    target: str | None = field(default=None, init=False)

    def __post_init__(self):
        self.store = Existing6GUIDRuntimeStore(self.db_conn,
                                               self.os_uid_for_username)

    def _ports(self):
        if (self.kernel is None or self.shadow is None
                or self.session_gate_probe is None
                or self.existing_sessions_probe is None):
            raise RuntimeUnsafe("EXPLICIT_VERIFIED_RUNTIME_PORTS_REQUIRED")

    async def acquire_6g(self, source, target):
        self._ports()
        if self.operation_id is not None:
            raise RuntimeUnsafe("RUNTIME_BRIDGE_SINGLE_USE")
        op, busy = await asyncio.to_thread(self.acquire_fn, source, target)
        if op is not None:
            self.operation_id, self.source, self.target = op, source, target
        return op, busy

    async def journal(self, operation_id, status, phase, details):
        if operation_id != self.operation_id or (
            status not in {"RUNNING", "SUCCEEDED", "FAILED"}
            or phase not in PHASES
        ):
            raise RuntimeUnsafe("SHARED_JOURNAL_PHASE_OR_LEASE_INVALID")
        if any(
            k in {"token", "password", "secret", "private_key"}
            or type(v) not in (str, int, bool, type(None))
            for k, v in details.items()
        ):
            raise RuntimeUnsafe("UNSAFE_JOURNAL_DETAILS")
        detail = {"kind": "EGRESS_UID_RUNTIME", "phase": phase, **details}
        await asyncio.to_thread(
            self.update_fn, operation_id,
            status=status, detail=detail, finished=status != "RUNNING",
            require_running=True,
        )

    def _identity(self, req: UIDPolicyRequest, source: str):
        if source != self.source or req.spec.edge_public_ipv4 != self.target:
            raise RuntimeUnsafe("SHARED_6G_SOURCE_TARGET_CHANGED")
        if self.os_uid_for_username(req.username) != req.uid:
            raise RuntimeUnsafe("UID_OS_IDENTITY_CHANGED")

    async def check_session_gate(self, req):
        self._identity(req, self.source)
        if not await asyncio.to_thread(self.session_gate_probe, req):
            raise RuntimeUnsafe("PAM_ACCOUNT_GATE_NOT_ATTESTED")

    async def reserve_blocked(self, op, req, source, dns_port):
        self._identity(req, source)
        await asyncio.to_thread(
            self.store.reserve_blocked, op, req, source=source,
            dns_port=dns_port,
        )

    async def assert_frozen_binding(self, op, req, source, dns_port):
        self._identity(req, source)
        await asyncio.to_thread(
            self.store.assert_frozen_binding, op, req,
            source=source, dns_port=dns_port,
        )

    async def check_no_existing_sessions(self, req):
        self._identity(req, self.source)
        if not await asyncio.to_thread(self.existing_sessions_probe, req):
            raise RuntimeUnsafe("EXISTING_USER_PROCESSES_OR_SESSIONS")

    async def arm_boot_guard(self, req, dns_port):
        self._identity(req, self.source)
        await asyncio.to_thread(self.kernel.arm, req, dns_port)

    async def start_edge(self, req):
        self._identity(req, self.source)
        await self.shadow.start(req)

    async def attach_edge(self, req):
        self._identity(req, self.source)
        await asyncio.to_thread(self.kernel.attach, req)

    async def transition(self, op, req, source, before, after):
        self._identity(req, source)
        await asyncio.to_thread(
            self.store.transition, op, req, source=source,
            expected=before, target=after,
        )

    async def prove_ipv4(self, req):
        self._identity(req, self.source)
        return await asyncio.to_thread(self.kernel.public_ipv4, req)

    async def prove_dns_ipv6(self, req):
        self._identity(req, self.source)
        await asyncio.to_thread(self.kernel.assert_dns_ipv6, req)

    async def commit_protected(self, op, req, source):
        self._identity(req, source)
        await asyncio.to_thread(self.store.commit_protected,
                                op, req, source=source)

    async def freeze_edge(self, req):
        self._identity(req, self.source)
        await asyncio.to_thread(self.kernel.freeze, req)

    async def prove_frozen(self, req):
        self._identity(req, self.source)
        await asyncio.to_thread(self.kernel.assert_frozen, req)
