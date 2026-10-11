"""F4 SSH/PAM installation REVIEWER and offline renderer (read-only).

Does not modify /etc/pam.d/sshd, sshd_config, systemd or a host network.
An external operator must keep console recovery and rehearse both PAM auth
and direct-tcpip/SOCKS in a disposable full-system clone. An offline review
passing DOES NOT prove that forwarding actually enters PAM account phase.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


REQUIRED_ACCOUNT_LINE=(
    "account requisite pam_exec.so quiet "
    "/usr/bin/python3 /opt/nvl-egress/edge_egress_uid_admission.py"
)
PAM_PATH="/etc/pam.d/sshd"
MODULE_PATH="/opt/nvl-egress/edge_egress_uid_admission.py"


@dataclass(frozen=True)
class PAMInspection:
    valid: bool
    issues: tuple[str, ...]
    installed: bool = False
    customer_ready: bool = False


def render_pam_change_review() -> str:
    """Proposed exact addition; a human installs it only after recovery proof."""
    return (
        "# REVIEW ONLY — do NOT paste on a live Core without F4 disposable reboot\n"
        "# Place as the FIRST account rule in /etc/pam.d/sshd:\n"
        REQUIRED_ACCOUNT_LINE+"\n"
        "# Confirm UsePAM yes via sshd -T -C user=nvl0557,...\n"
        "# Test emergency console/root AND non-root admins after installation.\n"
        "# No automated edits or ssh.service restart are permitted here.\n"
    )


def inspect_pam_sshd(pam_contents: str, sshd_effective: str, *,
                     protected_username: str = "nvl0557") -> PAMInspection:
    issues=[]
    if not isinstance(pam_contents,str) or not isinstance(sshd_effective,str):
        return PAMInspection(False,("INPUT_UNAVAILABLE",))
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",protected_username):
        return PAMInspection(False,("INVALID_USERNAME",))
    active=[
        " ".join(line.split())
        for line in pam_contents.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    rules=[line for line in active if line.startswith("account ")]
    matching=[line for line in rules if line==REQUIRED_ACCOUNT_LINE]
    installed=len(matching)==1
    if not installed:
        issues.append("EXACT_PAM_ACCOUNT_HOOK_MISSING_OR_DUPLICATED")
    if matching and rules and rules[0]!=REQUIRED_ACCOUNT_LINE:
        issues.append("PAM_HOOK_NOT_FIRST_ACCOUNT_RULE")
    # Unknown PAM account lines using another local script must be reviewed.
    for rule in rules:
        if "pam_exec.so" in rule and rule!=REQUIRED_ACCOUNT_LINE:
            issues.append("UNREVIEWED_PAM_EXEC_ACCOUNT")
            break
    effective=[
        " ".join(line.strip().split()).lower()
        for line in sshd_effective.splitlines() if line.strip()
    ]
    pam=[value.split()[-1] for value in effective if value.startswith("usepam ")]
    if pam!=["yes"]:
        issues.append("SSHD_USEPAM_NOT_ATTESTED_FOR_SELECTED_USER")
    # A PAM account hook may still be skipped for special auth/forwarding
    # paths: only F4 real SSH E2E can prove enforcement.
    return PAMInspection(not issues,tuple(issues),installed=installed)


def inspect_deployment_root(path: str, *, root_owner_uid: int, mode: int,
                            is_symlink: bool) -> bool:
    """Validate root-owned fixed module/manifest directories in preflight."""
    return bool(
        isinstance(path,str) and path.startswith("/opt/nvl-egress/")
        and ".." not in path.split("/")
        and root_owner_uid==0
        and mode & 0o022 == 0
        and is_symlink is False
    )
