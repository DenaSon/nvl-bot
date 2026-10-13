"""K2 P3-B: pinned, deny-before-transport provisioning and boot review.

Offline unit/PAM/roster rendering plus a constrained P3-A EDGE_PREPARE host
port. No executable Telegram entry point, installer, systemd start or PAM edit.
A future root-only release adapter must supply independently verified gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable, Protocol

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, ExecutorHold, INTENT_PHASE, _scope_digest,
)
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_systemd import (
    render_ssh_systemd_bundle, verify_bundle,
)
from edge_egress_v1_admission import render_v1_guard_unit, render_pam_review, render_roster
from ops.edge_egress_v1_transport import pinned, render_unit, observe, ensure

# This module cannot be invoked by the Telegram bot; release is independently
# gated at P3-A and every guarded port defaults to disabled.
LIVE_PROVISIONING_ENABLED = False
STAGE_ROLE = "core"
STATUS_UP = "UP"
SUCCESS_RESULTS = frozenset({"EXACT_TRANSPORT_ALREADY_UP", "TRANSPORT_STARTED"})


class BootProvisionHold(ValueError):
    pass


@dataclass(frozen=True)
class StageBootReview:
    stage: Path
    stage_sha256: str
    spec_sha256: str
    edge_id: str
    core_ipv4: str
    edge_ipv4: str
    username: str
    uid: int
    guard_name: str
    dns_name: str
    guard_unit: str
    dns_unit: str
    transport_unit: str
    pam_review: str
    roster_review: str
    digest: str


def _digest_object(payload: dict) -> str:
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()


def _review_payload(review: StageBootReview) -> dict:
    return {
        "stage": str(review.stage), "stage_sha256": review.stage_sha256,
        "spec_sha256": review.spec_sha256,
        "edge": review.edge_id, "edge_ip": review.edge_ipv4,
        "core_ip": review.core_ipv4, "username": review.username,
        "uid": review.uid,
        "guard_name": review.guard_name, "dns_name": review.dns_name,
        "guard_unit": review.guard_unit,
        "dns_unit": review.dns_unit,
        "transport_unit": review.transport_unit, "roster": review.roster_review,
        "pam_review": review.pam_review,
    }


def build_stage_boot_review(stage: Path, stage_sha256: str,
                            manifest: BootGuardManifest, *,
                            stage_reader: Callable = pinned,
                            transport_renderer: Callable = render_unit,
                            roster_manifests: dict[str, bytes]) -> StageBootReview:
    """Pure bundle: no files written, host commands, PAM install or SSH restart.

    roster_manifests must contain the COMPLETE existing protected roster; a
    single member cannot silently overwrite other protected identities.
    """
    if not isinstance(stage, Path) or not stage.is_absolute() or (
            not isinstance(stage_sha256, str) or len(stage_sha256) != 64 or
            any(c not in "0123456789abcdef" for c in stage_sha256)):
        raise BootProvisionHold("PINNED_STAGE_REQUIRED")
    if not isinstance(manifest, BootGuardManifest) or (
            manifest.mode != "PROTECTED_BOOT_GUARD" or not manifest.shared_edge
            or not manifest.ingress_return or manifest.dns_port is None):
        raise BootProvisionHold("PROTECTED_BOOT_GUARD_REQUIRED")
    spec, _peer = stage_reader(stage, STAGE_ROLE, stage_sha256)
    if (spec != manifest.request.spec or
            not manifest.request.username in roster_manifests):
        raise BootProvisionHold("BOOT_SPEC_OR_ROSTER_MISMATCH")
    # Exact raw manifest identity is independently checked by the canonical
    # roster renderer; never trust a separately fabricated username/UID.
    try:
        protected = render_roster(roster_manifests)
        expected = next(
            x for x in json.loads(protected)["protected"]
            if x["username"] == manifest.request.username
        )
        raw = roster_manifests[manifest.request.username]
        if expected["uid"] != manifest.request.uid or (
                BootGuardManifest.parse(json.loads(raw)) != manifest):
            raise BootProvisionHold("GUARD_MANIFEST_IDENTITY_MISMATCH")
        isolated = render_ssh_systemd_bundle(manifest)
        verify_bundle(isolated)
        guard = render_v1_guard_unit(manifest)
        if ("After=local-fs.target wg-quick@wg0.service" not in guard
                or "WantedBy=multi-user.target" not in guard
                or any(tag in guard for tag in (
                    "Requires=ssh.service", "WantedBy=ssh.service",
                    "ExecStop=", "ExecStopPost="))):
            raise BootProvisionHold("BOOT_GUARD_SYSTEMD_SCOPE_VIOLATION")
        transport = transport_renderer(stage, STAGE_ROLE, stage_sha256)
        if (f"--stage {stage} --role core --digest {stage_sha256}" not in transport
                or "ExecStop=" in transport
                or "ssh.service" in transport):
            raise BootProvisionHold("TRANSPORT_SYSTEMD_SCOPE_VIOLATION")
        pam = render_pam_review()
        if "REVIEW" not in pam and "Review" not in pam:
            raise BootProvisionHold("PAM_REVIEW_REQUIRED")
    except (KeyError, TypeError, ValueError, StopIteration) as exc:
        raise BootProvisionHold("INVALID_PROTECTED_BOOT_BUNDLE") from exc
    spec_digest = _digest_object(asdict(spec))
    result = StageBootReview(
        stage, stage_sha256, spec_digest, spec.edge_id, spec.core_public_ipv4,
        spec.edge_public_ipv4, manifest.request.username,
        manifest.request.uid, isolated.guard_name, isolated.dns_name,
        guard, isolated.dns_unit, transport, pam, protected, "",
    )
    return StageBootReview(
        stage, stage_sha256, spec_digest, spec.edge_id, spec.core_public_ipv4,
        spec.edge_public_ipv4, manifest.request.username,
        manifest.request.uid, isolated.guard_name, isolated.dns_name,
        guard, isolated.dns_unit, transport, pam, protected,
        _digest_object(_review_payload(result)),
    )


def assert_shared_6g_intent(db_conn: Callable, scope: ExecutionScope,
                            ticket: ExecutionTicket) -> int:
    """Check the SAME 6G transaction under every P3-B host action.

    The original P3-A journal persists the nonce hash before host mutation.
    Never infer authorization from an unqualified RUNNING row alone.
    """
    if not isinstance(ticket, ExecutionTicket):
        raise BootProvisionHold("TICKET_REQUIRED")
    if not isinstance(scope, ExecutionScope) or scope.action != "EDGE_PREPARE":
        raise BootProvisionHold("EDGE_PREPARE_ONLY")
    expected = hashlib.sha256(ticket.nonce.encode("ascii")).hexdigest()
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id,source_host,target_host,detail_json "
            "FROM failover_operations WHERE status='RUNNING'"
        ).fetchall()
    if len(rows) != 1 or rows[0][1:3] != (
            scope.source_host, scope.target_host):
        raise BootProvisionHold("SHARED_6G_LEASE_NOT_EXCLUSIVE")
    operation_id, _, _, raw = rows[0]
    try:
        detail = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise BootProvisionHold("6G_JOURNAL_NOT_AT_INTENT") from exc
    if not isinstance(detail, dict) or any((
            detail.get("kind") != "K2_P3A",
            detail.get("phase") != INTENT_PHASE,
            detail.get("action") != scope.action,
            detail.get("edge_id") != scope.edge_id,
            detail.get("nonce_hash") != expected,
            detail.get("scope_digest") != _scope_digest(scope))):
        raise BootProvisionHold("6G_INTENT_OR_SCOPE_CHANGED")
    if type(operation_id) is not int or operation_id <= 0:
        raise BootProvisionHold("INVALID_6G_OPERATION")
    return operation_id


class BootSafetyPort(Protocol):
    """Independent real-world checks: implemented after disposable F4 acceptance."""
    def assert_rescue_and_ownership(self, scope: ExecutionScope,
                                    review: StageBootReview) -> None: ...
    def assert_deny_before_transport(self, scope: ExecutionScope,
                                      review: StageBootReview) -> None: ...
    def assert_pam_dns_boot(self, scope: ExecutionScope,
                            review: StageBootReview) -> None: ...
    def freeze_owned_subjects(self, scope: ExecutionScope,
                              review: StageBootReview) -> None: ...


class StageTransportPort(Protocol):
    def ensure(self, stage: Path, role: str, digest: str) -> str: ...
    def observe(self, stage: Path, role: str, digest: str) -> str: ...


class ExistingPinnedTransport:
    """Use existing root-only WireGuard transport logic; no custom shell."""
    def ensure(self, stage: Path, role: str, digest: str) -> str:
        return ensure(stage, role, digest)

    def observe(self, stage: Path, role: str, digest: str) -> str:
        spec, peer = pinned(stage, role, digest)
        return observe(spec, role, peer)


class GuardedStageBootPort:
    """P3-A host-port adapter, bound to one EDGE_PREPARE scope/ticket/review.

    No default enabled instance, mutating shell, PAM install, SSH restart or
    runtime registration. Each stage requires an independently provided
    safety port and exact 6G intent recheck. P3-C owns protected UID attach.
    """
    def __init__(self, *, db_conn: Callable, scope: ExecutionScope,
                 ticket: ExecutionTicket, review: StageBootReview,
                 boot_safety: BootSafetyPort | None = None,
                 transport: StageTransportPort | None = None,
                 stage_reader: Callable = pinned,
                 release_enabled: bool = False):
        if (scope.action != "EDGE_PREPARE" or not isinstance(review, StageBootReview)
                or (review.edge_id, review.core_ipv4, review.edge_ipv4)
                   != (scope.edge_id, scope.source_host, scope.target_host)):
            raise BootProvisionHold("SCOPE_NOT_PINNED_TO_BOOT_PLAN")
        self.db_conn, self.scope, self.ticket = db_conn, scope, ticket
        self.review, self.safety = review, boot_safety
        self.transport, self.stage_reader = transport, stage_reader
        self.release_enabled = release_enabled
        self._applied = False

    def _check(self, scope: ExecutionScope):
        if (not self.release_enabled or self.safety is None or
                self.transport is None or scope != self.scope):
            raise BootProvisionHold("OPERATOR_RELEASE_OR_HOST_PORT_MISSING")
        assert_shared_6g_intent(self.db_conn, scope, self.ticket)
        if self.review.digest != _digest_object(_review_payload(self.review)):
            raise BootProvisionHold("BOOT_REVIEW_FINGERPRINT_CHANGED")
        spec, _ = self.stage_reader(
            self.review.stage, STAGE_ROLE, self.review.stage_sha256)
        if (_digest_object(asdict(spec)) != self.review.spec_sha256 or
                (spec.edge_id, spec.core_public_ipv4, spec.edge_public_ipv4) != (
                self.review.edge_id, self.review.core_ipv4, self.review.edge_ipv4)):
            raise BootProvisionHold("STAGE_IDENTITY_CHANGED")

    async def apply(self, scope: ExecutionScope) -> None:
        if self._applied:
            raise BootProvisionHold("BOOT_PORT_ONE_SHOT")
        self._applied = True
        self._check(scope)
        self.safety.assert_rescue_and_ownership(scope, self.review)
        self._check(scope)
        self.safety.assert_deny_before_transport(scope, self.review)
        self._check(scope)
        self.safety.assert_pam_dns_boot(scope, self.review)
        self._check(scope)
        result = self.transport.ensure(
            self.review.stage, STAGE_ROLE, self.review.stage_sha256)
        if result not in SUCCESS_RESULTS:
            raise BootProvisionHold("TRANSPORT_START_UNCERTAIN")

    async def verify(self, scope: ExecutionScope) -> bool:
        self._check(scope)
        if not self._applied:
            raise BootProvisionHold("PREPARE_NOT_APPLIED")
        self.safety.assert_deny_before_transport(scope, self.review)
        self._check(scope)
        self.safety.assert_pam_dns_boot(scope, self.review)
        self._check(scope)
        return self.transport.observe(
            self.review.stage, STAGE_ROLE, self.review.stage_sha256) == STATUS_UP

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        # Never stop shared SSH or tear down WireGuard on a partial mutation.
        if self.safety is None or scope != self.scope:
            raise BootProvisionHold("CANNOT_RECONCILE_UNOWNED_BOOT")
        self.safety.freeze_owned_subjects(scope, self.review)
