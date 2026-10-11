"""D1-C3B: Phase 6G persistence bridge for a disposable protected-UID canary.

The existing NVL Phase 6G lock/journal callbacks are the ONLY transaction
authority. This adapter is intentionally not imported/registered by bot
handlers, and there is no default kernel/shadow provider. Injected host ports
must be separately reviewed and lab-tested before any opt-in invocation.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import pwd
from typing import Callable, Protocol

from edge_egress_6g_bridge import Existing6GPreparationAdapter
from edge_egress_uid_lifecycle import UIDCanaryUnsafe
from edge_egress_uid_policy import UIDPolicyRequest


class CanaryKernelPort(Protocol):
    async def preflight(self, request: UIDPolicyRequest) -> None: ...
    async def arm_guard(self, request: UIDPolicyRequest) -> None: ...
    async def attach_edge(self, request: UIDPolicyRequest) -> None: ...
    async def public_ip(self, request: UIDPolicyRequest) -> str: ...
    async def check_ipv6_dns(self, request: UIDPolicyRequest) -> None: ...
    async def freeze_uid(self, request: UIDPolicyRequest) -> None: ...
    async def restore(self, request: UIDPolicyRequest) -> None: ...


class CanaryShadowPort(Protocol):
    async def preflight(self, request: UIDPolicyRequest) -> None: ...
    async def start(self, request: UIDPolicyRequest) -> None: ...
    async def stop(self, request: UIDPolicyRequest) -> None: ...


@dataclass
class Existing6GUIDCanaryAdapter:
    """Single-use 6G lease adapter; no extra locks, no direct live host port.

    New instance per test operation. All kernel mutations are delegated and
    require a deliberate, explicit port injection; no default shell executor.
    """
    db_conn: Callable
    acquire_fn: Callable
    update_fn: Callable
    kernel: CanaryKernelPort
    shadow: CanaryShadowPort
    _bridge: Existing6GPreparationAdapter = field(init=False)

    def __post_init__(self):
        if self.kernel is None or self.shadow is None:
            raise UIDCanaryUnsafe("EXPLICIT_HOST_PORTS_REQUIRED")
        self._bridge = Existing6GPreparationAdapter(
            self.db_conn, self.acquire_fn, self.update_fn
        )

    async def acquire_6g_lock(self, source, target):
        return await self._bridge.acquire_existing_6g_lock(source, target)

    async def journal_6g(self, operation_id, status, phase, details):
        if operation_id != self._bridge.operation_id:
            raise UIDCanaryUnsafe("6G_OPERATION_IDENTITY_CHANGED")
        if status not in ("RUNNING", "FAILED", "SUCCEEDED"):
            raise UIDCanaryUnsafe("INVALID_6G_STATUS")
        if not phase.startswith("EGRESS_UID_") or not phase.isupper():
            raise UIDCanaryUnsafe("INVALID_6G_PHASE")
        if any(type(v) not in (str, bool, int, type(None))
               or k in {"token", "secret", "private_key", "password"}
               for k, v in details.items()):
            raise UIDCanaryUnsafe("UNSAFE_JOURNAL_DETAIL")
        detail = {"kind": "EGRESS_UID_CANARY", "phase": phase, **details}
        await asyncio.to_thread(
            self.update_fn, operation_id, status=status, detail=detail,
            finished=(status != "RUNNING"), require_running=True,
        )

    def _assert_uid_sync(self, request: UIDPolicyRequest, source: str):
        request.validate()
        if self._bridge.source_host != source:
            raise UIDCanaryUnsafe("SOURCE_IDENTITY_CHANGED")
        if self._bridge.target_host != request.spec.edge_public_ipv4:
            raise UIDCanaryUnsafe("TARGET_IDENTITY_CHANGED")
        # The existing 6G bridge enforces RUNNING lock and source+target
        # ownership/port/default/DNS invariants, including an account snapshot.
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._bridge._assert_source_and_target_in_db(
                conn, source, request.spec.edge_public_ipv4
            )
            row = conn.execute(
                "SELECT host,service_type,status FROM ssh_accounts "
                "WHERE username=?", (request.username,)
            ).fetchone()
            if not row:
                raise UIDCanaryUnsafe("CUSTOMER_NOT_IN_DB")
            host, service_type, status = row
            if service_type != "ssh" or (host not in (None, "", source)):
                raise UIDCanaryUnsafe("ACCOUNT_SOURCE_MISMATCH")
            if (not isinstance(status, str) or "فعال" not in status
                    or "غیر" in status):
                raise UIDCanaryUnsafe("ACCOUNT_NOT_ACTIVE")
            setting = conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            if setting is not None and setting[0] != "0":
                raise UIDCanaryUnsafe("DISPOSABLE_LAB_NOT_UNPROTECTED")
            # The canary must never silently restore a previously protected
            # user to Core. No other UID policy ownership is inferred here.
        try:
            os_user = pwd.getpwnam(request.username)
        except KeyError as exc:
            raise UIDCanaryUnsafe("OS_ACCOUNT_MISSING") from exc
        if os_user.pw_uid != request.uid:
            raise UIDCanaryUnsafe("UID_OS_DB_BINDING_CHANGED")

    async def assert_ownership_and_uid(self, request, source):
        await asyncio.to_thread(self._assert_uid_sync, request, source)

    async def assert_disposable_lab_ready(self, request):
        await self.kernel.preflight(request)
        await self.shadow.preflight(request)

    async def arm_guard(self, request):
        await self.kernel.arm_guard(request)

    async def start_shadow(self, request):
        await self.shadow.start(request)

    async def attach_edge(self, request):
        await self.kernel.attach_edge(request)

    async def prove_public_edge_ip(self, request):
        return await self.kernel.public_ip(request)

    async def prove_ipv6_dns_blocked(self, request):
        await self.kernel.check_ipv6_dns(request)

    async def freeze_uid(self, request):
        await self.kernel.freeze_uid(request)

    async def stop_shadow(self, request):
        await self.shadow.stop(request)

    async def restore_disposable_canary(self, request):
        await self.kernel.restore(request)
