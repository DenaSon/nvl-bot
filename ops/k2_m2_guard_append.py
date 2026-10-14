"""K2 M2: additive, DENY-first protected roster installer for UID #2..N.

This is an **unreleased privileged component**, not a bot callback. It retains
the existing v1 PAM gate and original 6G lease, never writes a new SSH policy,
unfences any UID, restarts sshd, or changes wg0/DNS/other accounts. A crash
after staging may leave this new UID fenced: reconciliation is mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Callable

from edge_egress_uid_boot import BootGuardManifest, BootGuardApplier
from edge_egress_uid_systemd import render_ssh_systemd_bundle
from edge_egress_v1_admission import (
    PAM_LINE, ROSTER, GUARD_DIR, load_roster, render_roster, inspect_pam,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
)
from ops.k2_p3_guard_installer import (
    PAM, UNITS, CODE_DIR, MODULE, RootFilePort, _safe_read, _owned,
)
from edge_egress_f4_pam import verify_installed_gate_digest

M2_APPEND_ENABLED = False


class MultiUIDHold(ValueError):
    pass


@dataclass(frozen=True)
class MultiUIDAppendPlan:
    username: str
    uid: int
    edge_id: str
    edge_ipv4: str
    manifest_bytes: bytes
    current_roster: bytes
    next_roster: bytes
    guard_unit_name: str
    guard_unit: str
    dns_unit_name: str
    dns_unit: str
    pam_digest: str
    module_digest: str

    @property
    def fingerprint(self) -> str:
        pieces = (
            self.username, self.uid, self.edge_id, self.edge_ipv4,
            sha256(self.manifest_bytes).hexdigest(),
            sha256(self.current_roster).hexdigest(),
            sha256(self.next_roster).hexdigest(),
            self.guard_unit_name, sha256(self.guard_unit.encode()).hexdigest(),
            self.dns_unit_name, sha256(self.dns_unit.encode()).hexdigest(),
            self.pam_digest, self.module_digest,
        )
        return sha256(json.dumps(pieces, separators=(",", ":")).encode()).hexdigest()


def plan_next_uid(*, username: str, manifest_bytes: bytes,
                  current_roster: bytes, installed_manifests: dict[str, bytes],
                  pam_bytes: bytes, module_digest: str,
                  os_uid: Callable[[str], int]) -> MultiUIDAppendPlan:
    """Pure append: roster bytes must match every existing root manifest.

    The existing v1 roster is immutable within a plan, including the exact
    previous member hashes. Never replace another protected member.
    """
    if (not isinstance(username, str) or not isinstance(manifest_bytes, bytes)
            or len(manifest_bytes) > 4096
            or not isinstance(current_roster, bytes)
            or not isinstance(pam_bytes, bytes)
            or not isinstance(installed_manifests, dict)
            or not re.fullmatch(r"[a-f0-9]{64}", str(module_digest))
            or not callable(os_uid)):
        raise MultiUIDHold("UNREVIEWED_APPEND_INPUT")
    if not installed_manifests:
        raise MultiUIDHold("FIRST_UID_REQUIRES_BOOTSTRAP")
    if username in installed_manifests:
        raise MultiUIDHold("PROTECTED_MEMBER_ALREADY_EXISTS")
    if (current_roster != render_roster(installed_manifests).encode("utf-8")):
        raise MultiUIDHold("ROSTER_AND_MANIFESTS_NOT_IDENTICAL")
    if len(current_roster) > 262144:
        raise MultiUIDHold("ROSTER_TOO_LARGE")
    if pam_bytes.decode("utf-8", errors="replace").count(PAM_LINE) != 1:
        raise MultiUIDHold("EXISTING_PAM_HOOK_REQUIRED")

    try:
        manifest = BootGuardManifest.parse(json.loads(manifest_bytes))
        req = manifest.request
        uid = os_uid(username)
        if (req.username != username or type(uid) is not int
                or uid != req.uid or uid < 1000
                or not manifest.ingress_return or not manifest.shared_edge
                or manifest.dns_port is None):
            raise MultiUIDHold("NEW_UID_IDENTITY_OR_MANIFEST_INVALID")
        # One Linux rule priority and DNS listener per protected UID.
        # V1 renderer checks UIDs, Edge transport/route-table ownership;
        # it does not reject priority or DNS-port collisions by itself.
        existing_guards = [
            BootGuardManifest.parse(json.loads(raw))
            for raw in installed_manifests.values()
        ]
        if any((x.request.priority == req.priority or
                x.dns_port == manifest.dns_port) for x in existing_guards):
            raise MultiUIDHold("UID_PRIORITY_OR_DNS_PORT_COLLISION")
        merged = dict(installed_manifests)
        merged[username] = manifest_bytes
        updated_roster = render_roster(merged).encode("utf-8")
        bundle = render_ssh_systemd_bundle(manifest)
    except MultiUIDHold:
        raise
    except (ValueError, TypeError, OSError, KeyError, UnicodeError) as exc:
        raise MultiUIDHold("NEW_GUARD_OR_EXISTING_ROSTER_INVALID") from exc
    if len(updated_roster) > 262144:
        raise MultiUIDHold("ROSTER_CAPACITY_EXCEEDED")
    return MultiUIDAppendPlan(
        username, uid, req.spec.edge_id, req.spec.edge_public_ipv4,
        manifest_bytes, current_roster, updated_roster,
        bundle.guard_name, bundle.guard_unit, bundle.dns_name,
        bundle.dns_unit, sha256(pam_bytes).hexdigest(), module_digest,
    )


class CASRootRosterPort(RootFilePort):
    """Fixed path, root-only, exact file compare-and-swap. No chmod of SSH."""

    def replace_roster_exact(self, before: bytes, after: bytes) -> None:
        # Serial 6G ownership is mandatory at the caller. This CAS also
        # detects filesystem drift from another component or operator.
        _owned(ROSTER.parent, directory=True, strict=False)
        if _safe_read(ROSTER) != before:
            raise MultiUIDHold("ROSTER_CONTENT_CAS_LOST")
        fd, temp_path = tempfile.mkstemp(
            prefix=".nvl-protected-roster-", dir=str(ROSTER.parent))
        temp = Path(temp_path)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(after)
                handle.flush()
                os.fsync(handle.fileno())
            if _safe_read(ROSTER) != before:
                raise MultiUIDHold("ROSTER_CONTENT_CAS_LOST")
            os.replace(temp, ROSTER)
            dirfd = os.open(ROSTER.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if temp.exists():
                temp.unlink()


def apply_next_uid(*, plan: MultiUIDAppendPlan, db_conn: Callable,
                   scope: ExecutionScope, ticket: ExecutionTicket,
                   os_uid: Callable[[str], int],
                   port: CASRootRosterPort | None = None,
                   rescue_ok: Callable[[], bool] | None = None,
                   idle_ok: Callable[[str, int], bool] | None = None,
                   independent_f4_ok: Callable[[ExecutionScope], bool] | None = None,
                   legacy_pam_ok: Callable[[], bool] | None = None,
                   sshd_effective: Callable[[], str] | None = None,
                   guard_verify: Callable[[BootGuardManifest], None] | None = None,
                   release_enabled: bool = False,
                   resume_partial: bool = False,
                   geteuid: Callable[[], int] = os.geteuid) -> None:
    """One UID append under an EXISTING 6G RUNNING exact P3 ticket.

    M3 may invoke this once per UID in a bounded cohort; there is no new lock
    or parallel kernel engine. Network/PAM/F4/boot external proof is mandatory.
    """
    if (not M2_APPEND_ENABLED or release_enabled is not True
            or type(resume_partial) is not bool
            or not isinstance(plan, MultiUIDAppendPlan)
            or not isinstance(scope, ExecutionScope)
            or not isinstance(ticket, ExecutionTicket)
            or scope.action not in ("UID_ATTACH", "UID_ENROLL_SOURCE")
            or not callable(db_conn) or port is None or geteuid() != 0
            or not all(callable(c) for c in (
                os_uid, rescue_ok, idle_ok, independent_f4_ok,
                legacy_pam_ok, sshd_effective, guard_verify,
            ))):
        raise MultiUIDHold("M2_ROOT_RELEASE_NOT_ATTESTED")
    if (scope.username != plan.username or scope.uid != plan.uid
            or scope.edge_id != plan.edge_id
            or scope.target_host != plan.edge_ipv4):
        raise MultiUIDHold("M2_SCOPE_OR_EDGE_MISMATCH")
    manifest = BootGuardManifest.parse(json.loads(plan.manifest_bytes))
    if (manifest.request.username != plan.username
            or manifest.request.uid != plan.uid
            or manifest.request.spec.edge_id != scope.edge_id):
        raise MultiUIDHold("M2_MANIFEST_DRIFT")
    if (rescue_ok() is not True or idle_ok(plan.username, plan.uid) is not True
            or independent_f4_ok(scope) is not True
            or legacy_pam_ok() is not True):
        raise MultiUIDHold("INDEPENDENT_RESCUE_F4_OR_MIXED_PAM_HOLD")
    if os_uid(plan.username) != plan.uid:
        raise MultiUIDHold("M2_OS_UID_CHANGED")
    if not verify_installed_gate_digest(plan.module_digest):
        raise MultiUIDHold("M2_CODE_DIGEST_NOT_PINNED")
    # All reads before side effects must be on installed, root-owned objects.
    for d in (ROSTER.parent, GUARD_DIR, UNITS, CODE_DIR):
        _owned(d, directory=True, strict=False)
    pam = _safe_read(PAM, maximum=131072, strict=False)
    if (sha256(pam).hexdigest() != plan.pam_digest
            or not inspect_pam(pam.decode("utf-8"),
                               sshd_effective())):
        raise MultiUIDHold("M2_GLOBAL_PAM_REVIEW_FAILED")
    if _safe_read(ROSTER) != plan.current_roster:
        raise MultiUIDHold("M2_ROSTER_CHANGED_SINCE_PREVIEW")
    # Existing V1 members must agree with ALL their root-owned guards.
    roster = load_roster()
    proposed = json.loads(plan.current_roster)
    if (len(roster) != len(proposed["protected"])
            or any(x["username"] not in roster or
                   x["guard_sha256"] != roster[x["username"]].guard_sha256
                   for x in proposed["protected"])):
        raise MultiUIDHold("M2_EXISTING_ROSTER_INVALID")
    if any(member.uid == plan.uid or member.username == plan.username
           for member in roster.values()):
        raise MultiUIDHold("M2_UID_ALREADY_PROTECTED")
    # Validate *every* pre-existing manifest against its pinned roster hash
    # rather than accepting a syntactically correct but stale roster.
    installed: dict[str, bytes] = {}
    for old_name, old_member in roster.items():
        data = _safe_read(GUARD_DIR / (old_name + ".json"), maximum=4096)
        if sha256(data).hexdigest() != old_member.guard_sha256:
            raise MultiUIDHold("M2_EXISTING_GUARD_DRIFT")
        installed[old_name] = data
    fresh_plan = plan_next_uid(
        username=plan.username, manifest_bytes=plan.manifest_bytes,
        current_roster=plan.current_roster, installed_manifests=installed,
        pam_bytes=pam, module_digest=plan.module_digest, os_uid=os_uid,
    )
    if fresh_plan != plan:
        raise MultiUIDHold("M2_PLAN_CHANGED_OR_FORGED")
    # New guard/unit files must be absent: do not overwrite partial stages.
    paths = (
        GUARD_DIR / (plan.username + ".json"),
        UNITS / plan.guard_unit_name, UNITS / plan.dns_unit_name,
    )
    expected = (
        plan.manifest_bytes, plan.guard_unit.encode(), plan.dns_unit.encode(),
    )
    staged: list[bool] = []
    for path, expected_bytes in zip(paths, expected):
        if path.is_symlink():
            raise MultiUIDHold("M2_STAGED_PATH_SYMLINK")
        if path.exists():
            if not resume_partial:
                raise MultiUIDHold("M2_PARTIAL_STAGE_REQUIRES_RECONCILIATION")
            if _safe_read(path, maximum=65536) != expected_bytes:
                raise MultiUIDHold("M2_PARTIAL_STAGE_BYTES_MISMATCH")
            staged.append(True)
        else:
            staged.append(False)
    # If resuming, old 6G lease is STILL REQUIRED; no fresh lease is minted.
    # The target UID stays denied until M3 commits an independently verified
    # runtime; no old guard, rule, table or roster member is removed.

    # Check the exact original P3/6G lease before *each* privileged step.
    def still_locked():
        return assert_guarded_6g_intent(db_conn, scope, ticket)
    still_locked()
    for path, expected_bytes, already_staged in zip(paths, expected, staged):
        still_locked()
        if not already_staged:
            port.create(path, expected_bytes)
    still_locked()
    port.command("systemctl", "daemon-reload")
    still_locked()
    port.command("systemctl", "enable", "--now", plan.guard_unit_name)
    still_locked()
    guard_verify(manifest)  # BootGuardApplier.verify(..., require_frozen=True)
    still_locked()
    port.command("systemctl", "enable", "--now", plan.dns_unit_name)
    still_locked()
    # Make admission deny this UID as 'rostered but no PROTECTED runtime' only
    # once its on-disk deny/IPv6/DNS guard is independently verified.
    port.replace_roster_exact(plan.current_roster, plan.next_roster)
    if _safe_read(ROSTER) != plan.next_roster:
        raise MultiUIDHold("M2_ROSTER_POST_CAS_UNVERIFIED")
    still_locked()
