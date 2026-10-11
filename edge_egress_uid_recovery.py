"""D1-C3C: read-only post-boot/host-crash reconciliation for one protected UID.

This observer never fixes, unlocks or removes anything. It reports
uncertainty to the operator; a stale 6G RUNNING lock is NOT released.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import subprocess
from typing import Callable

from edge_egress_uid_boot import BootGuardManifest, BootGuardApplier
from edge_egress_uid_dns import DNSError, validate_nss_hosts, plan_transparent_dns
from edge_egress_uid_policy import build_policy_plan


class RecoveryState(str, Enum):
    UNSAFE_GUARD_ABSENT = "UNSAFE_GUARD_ABSENT"
    HOLD_FOR_OPERATOR = "HOLD_FOR_OPERATOR"
    GUARDED_OFFLINE = "GUARDED_OFFLINE"
    ROUTED_UNVERIFIED = "ROUTED_UNVERIFIED"


@dataclass(frozen=True)
class RecoveryEvidence:
    uid_route_rule: bool
    terminal_blackhole: bool
    ipv6_guard: bool
    direct_dns_guard: bool
    udp_tcp_dns_redirect: bool
    nss_hosts_suitable: bool
    edge_route_present: bool
    crash_marker_present: bool
    phase6g_hold: bool
    ssh_required_dependency: bool


@dataclass(frozen=True)
class RecoveryDecision:
    state: RecoveryState
    reason: str
    customer_ready: bool = False


def assess_recovery(observation: RecoveryEvidence) -> RecoveryDecision:
    """Never claim READY. Missing/reordered firewall or guard is unsafe."""
    if not observation.ssh_required_dependency:
        return RecoveryDecision(RecoveryState.UNSAFE_GUARD_ABSENT,
                                "SSH_BOOT_DEPENDENCY_NOT_PROVEN")
    if not observation.uid_route_rule or not observation.terminal_blackhole:
        return RecoveryDecision(RecoveryState.UNSAFE_GUARD_ABSENT,
                                "TERMINAL_UID_GUARD_NOT_PROVEN")
    if not observation.ipv6_guard or not observation.direct_dns_guard:
        return RecoveryDecision(RecoveryState.UNSAFE_GUARD_ABSENT,
                                "IPV6_OR_LOCAL_DNS_GUARD_NOT_PROVEN")
    if not observation.udp_tcp_dns_redirect or not observation.nss_hosts_suitable:
        return RecoveryDecision(RecoveryState.UNSAFE_GUARD_ABSENT,
                                "UID_DNS_PATH_NOT_PROVEN")
    if observation.crash_marker_present or observation.phase6g_hold:
        return RecoveryDecision(RecoveryState.HOLD_FOR_OPERATOR,
                                "RECOVERY_JOURNAL_OR_MARKER_PRESENT")
    if observation.edge_route_present:
        return RecoveryDecision(RecoveryState.ROUTED_UNVERIFIED,
                                "NEEDS_FRESH_IP_DNS_IPV6_PROOF")
    return RecoveryDecision(RecoveryState.GUARDED_OFFLINE,
                            "TERMINAL_GUARD_PRESENT_EDGE_DETACHED")


def has_6g_recovery_hold(rows) -> bool:
    """Takes SELECTed (status, detail_json) rows; never mutates SQLite."""
    # Any shared 6G RUNNING operation can race the protected boot audit.
    # Treat unfamiliar phases as ambiguous, never as authorization.
    return any(status == "RUNNING" for status, _detail in rows)


def _run(*args: str):
    return subprocess.run(list(args), capture_output=True, text=True,
                          timeout=8, check=False)


def inspect_recovery(manifest: BootGuardManifest, *,
                     ssh_unit_name: str,
                     marker_dir: Path = Path("/root/nvl-egress-uid-canary"),
                     run: Callable = _run,
                     read_nss: Callable = lambda: Path("/etc/nsswitch.conf").read_text(),
                     sixg_rows=()) -> RecoveryDecision:
    """Read-only live inspection, no shell, no auto-healing.

    Must run from an authorized Core operator session. A missing required
    ssh.service edge or an ambiguous state always blocks readiness.
    """
    request = manifest.request
    plan = build_policy_plan(request)
    if ssh_unit_name != "nvl-egress-guard-" + request.username + ".service":
        raise ValueError("UNEXPECTED_GUARD_UNIT_IDENTITY")

    def ok(*argv):
        try:
            return run(*argv).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def output(*argv):
        try:
            result = run(*argv)
            return result.stdout if result.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    # Check exact firewall rule identities, not only nonzero counters.
    gate = BootGuardApplier.check_argv
    firewall = [ok(*gate(command.argv)) for command in plan.guard[:3]]
    table = output("ip", "-4", "route", "show", "table", str(plan.table))
    routes = [x.strip() for x in table.splitlines() if x.strip()]
    blackhole = any(x.startswith("blackhole default") for x in routes)
    edge_route = any(x.startswith("default via ") and
                     ("dev " + request.spec.veth_root) in x for x in routes)

    rule_output = output("ip", "-4", "rule", "show")
    rule = any(
        line.strip().startswith(str(request.priority) + ":")
        and "uidrange " + request.uidrange in line
        and "lookup " + str(plan.table) in line
        for line in rule_output.splitlines()
    )
    nat = False
    nss = False
    if manifest.dns_port is not None:
        dns = plan_transparent_dns(request, manifest.dns_port)
        nat = ok(*dns.udp_check.argv) and ok(*dns.tcp_check.argv)
        try:
            validate_nss_hosts(read_nss())
            nss = True
        except (DNSError, OSError):
            pass

    dependency = output("systemctl", "show", "ssh.service", "-p", "Requires",
                        "--value").split()
    # systemd requires list may be space-delimited and reordered.
    required = ssh_unit_name in dependency
    if manifest.dns_port is not None:
        required = required and ("nvl-egress-dns-" + request.username + ".service") in dependency
    marker = marker_dir / (request.username + "-" + request.spec.edge_id + ".json")

    evidence = RecoveryEvidence(
        uid_route_rule=rule,
        terminal_blackhole=blackhole,
        ipv6_guard=firewall[0],
        direct_dns_guard=all(firewall[1:]),
        udp_tcp_dns_redirect=nat,
        nss_hosts_suitable=nss,
        edge_route_present=edge_route,
        crash_marker_present=marker.exists() or marker.is_symlink(),
        phase6g_hold=has_6g_recovery_hold(sixg_rows),
        ssh_required_dependency=required,
    )
    return assess_recovery(evidence)
