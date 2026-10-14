"""M2 read-only interrupted multi-UID stage recovery inspector.

Do not interpret a staged file, a systemd unit or a ROSTERED marker as a
verified user route. Only the guarded original-6G root worker may resume a
byte-exact partial install after independent F4 / idle / rescue checks.
Never delete the guard or remove a roster member to regain connectivity.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ops.k2_m2_guard_append import MultiUIDAppendPlan
from edge_egress_v1_admission import GUARD_DIR, ROSTER
from ops.k2_p3_guard_installer import UNITS, _owned, _safe_read


class StageRecoveryHold(ValueError):
    pass


@dataclass(frozen=True)
class StageRecovery:
    state: str
    may_request_replay: bool
    needs_worker_review: bool
    missing: tuple[str, ...] = ()
    reason: str = ""

    @property
    def customer_ready(self) -> bool:
        # No staged root artifact or PAM review proves egress packet safety.
        return False


def inspect_append_stage(plan: MultiUIDAppendPlan, *,
                         roster_bytes: bytes,
                         staged: Mapping[str, bytes | None],
                         pam_unchanged: bool,
                         original_6g_running: bool) -> StageRecovery:
    """Pure snapshot; no mutations and no automatic replay authorization."""
    if not isinstance(plan, MultiUIDAppendPlan) or not isinstance(staged, Mapping):
        raise StageRecoveryHold("REVIEW_INPUT_UNTRUSTED")
    expected = {
        "guard": plan.manifest_bytes,
        "guard_unit": plan.guard_unit.encode(),
        "dns_unit": plan.dns_unit.encode(),
    }
    if set(staged) != set(expected) or any(
        raw is not None and not isinstance(raw, bytes)
        for raw in staged.values()
    ):
        raise StageRecoveryHold("STAGE_ARTIFACT_SET_INVALID")
    if not pam_unchanged:
        return StageRecovery("HOLD",False,True,reason="GLOBAL_PAM_DRIFT")
    if roster_bytes not in (plan.current_roster,plan.next_roster):
        return StageRecovery("HOLD",False,True,reason="ROSTER_DRIFT")
    if any(raw is not None and raw != expected[name]
           for name,raw in staged.items()):
        return StageRecovery("HOLD",False,True,reason="STAGE_BYTES_MISMATCH")
    missing = tuple(name for name,raw in staged.items() if raw is None)
    if roster_bytes == plan.next_roster:
        if missing:
            return StageRecovery("HOLD",False,True,missing,
                                 "ROSTER_REFERENCES_MISSING_GUARD")
        # Roster committed: the UID remains deny-only until F4 and runtime
        # prove the real path; must not replay a roster CAS or remove it.
        return StageRecovery("ROSTERED_DENY_ONLY",False,True)
    if not original_6g_running:
        return StageRecovery("HOLD",False,True,missing,"ORIGINAL_6G_HOLD_REQUIRED")
    return StageRecovery(
        "PARTIALLY_STAGED" if len(missing)<3 else "NOT_STARTED",
        True,True,missing,
        "INDEPENDENT_RESCUE_IDLE_F4_AND_6G_REVIEW_REQUIRED",
    )


def inspect_root_append_stage(plan: MultiUIDAppendPlan, *,
                              original_6g_running: bool,
                              pam_unchanged: bool) -> StageRecovery:
    """Fixed file read-only observer; noncanonical/symlinked paths HOLD."""
    if not isinstance(plan, MultiUIDAppendPlan):
        raise StageRecoveryHold("PLAN_REQUIRED")
    paths = {
        "guard":GUARD_DIR/(plan.username+".json"),
        "guard_unit":UNITS/plan.guard_unit_name,
        "dns_unit":UNITS/plan.dns_unit_name,
    }
    try:
        for parent in (ROSTER.parent,GUARD_DIR,UNITS):
            _owned(parent,directory=True,strict=False)
        roster=_safe_read(ROSTER)
        staged={}
        for key,path in paths.items():
            # lstat via is_symlink before any open; O_NOFOLLOW must be
            # enforced by the final trusted host-port reader.
            if path.is_symlink():
                raise StageRecoveryHold("STAGED_SYMLINK_UNTRUSTED")
            staged[key]=_safe_read(path,maximum=65536) if path.exists() else None
        return inspect_append_stage(plan,roster_bytes=roster,staged=staged,
            pam_unchanged=pam_unchanged,
            original_6g_running=original_6g_running)
    except (OSError,ValueError) as exc:
        raise StageRecoveryHold("ROOT_STAGE_INSPECTION_FAILED") from exc


def inspect_first_uid_stage(*, plan, pinned_pam_before: bytes,
                            current_pam: bytes,
                            staged: Mapping[str, bytes | None],
                            original_6g_running: bool) -> StageRecovery:
    """First-UID bootstrap may crash before installing the PAM hook.

    Only exact bytes from the reviewed original plan are eligible for
    forward-only continuation; no automatic removal or global SSH edit.
    """
    from ops.k2_p3_guard_installer import GuardInstallPlan
    if (not isinstance(plan, GuardInstallPlan) or not isinstance(staged, Mapping)
        or not isinstance(pinned_pam_before,bytes) or
        __import__("hashlib").sha256(pinned_pam_before).hexdigest() !=
        plan.pam_before_sha256):
        raise StageRecoveryHold("FIRST_PAM_PIN_MISSING")

    expected={
        "roster":plan.roster_bytes,
        "guard":plan.manifest_bytes,
        "pam_backup":None,  # compared to the exact plan-pinned old PAM below
        "guard_unit":plan.guard_unit.encode(),
        "dns_unit":plan.dns_unit.encode(),
    }
    if set(staged)!=set(expected):
        raise StageRecoveryHold("FIRST_STAGE_ARTIFACT_SET_INVALID")
    if any(not isinstance(v,(bytes,type(None))) for v in staged.values()):
        raise StageRecoveryHold("FIRST_STAGE_ARTIFACT_TYPE_INVALID")
    if current_pam == plan.pam_after:
        if any(staged[k] is None for k in staged):
            return StageRecovery("HOLD",False,True,reason="PAM_HOOK_WITH_MISSING_GUARD")
        if any(staged[k] != (pinned_pam_before if k=="pam_backup" else expected[k])
               for k in staged):
            return StageRecovery("HOLD",False,True,reason="PAM_HOOK_STAGE_DRIFT")
        return StageRecovery("ROSTERED_DENY_ONLY",False,True)
    if current_pam != pinned_pam_before:
        return StageRecovery("HOLD",False,True,reason="PAM_CONTENT_UNTRUSTED")
    if any(raw is not None and raw != (
        pinned_pam_before if k=="pam_backup" else expected[k])
        for k,raw in staged.items()):
        return StageRecovery("HOLD",False,True,reason="FIRST_STAGE_BYTES_MISMATCH")
    missing=tuple(k for k,v in staged.items() if v is None)
    if not original_6g_running:
        return StageRecovery("HOLD",False,True,missing,"ORIGINAL_6G_HOLD_REQUIRED")
    return StageRecovery("PARTIALLY_STAGED" if len(missing)<5 else "NOT_STARTED",
                         True,True,missing,
                         "INDEPENDENT_F4_RESCUE_BOOT_DNS_REVIEW_REQUIRED")
