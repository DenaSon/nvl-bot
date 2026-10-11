"""D1-C3A: pure, default-off per-UID protected IPv4 route policy.

This is an offline command PLAN, not a command runner or bot integration.
A privileged lifecycle controller must assert UID identity, acquire the
existing 6G lock, prepare the Edge data path, and apply/persist/verify the
policy. No function in this module executes any host command.

The safe construction order is:
  1. reject user IPv6 and localhost DNS stub access;
  2. install a terminal blackhole route BEFORE selecting the table;
  3. select the table for exactly one UID;
  4. only then attach an Edge route that overrides the blackhole.

Detaching the Edge only removes its route: the blackhole remains. Removing
the UID rule is explicitly outside this module to prevent silent Core egress.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from ops.edge_egress_provision import EgressSpec

USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
LOCAL_DNS = "127.0.0.0/8"


class UIDPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Command:
    purpose: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class PolicyPlan:
    uid: int
    username: str
    edge_id: str
    table: int
    priority: int
    guard: tuple[Command, ...]
    attach: tuple[Command, ...]
    fail_closed_detach: tuple[Command, ...]
    verify: tuple[Command, ...]
    customer_ready: bool = False

    def __post_init__(self):
        if self.customer_ready:
            raise UIDPolicyError("OFFLINE_PLAN_NOT_CUSTOMER_READY")


@dataclass(frozen=True)
class UIDPolicyRequest:
    spec: EgressSpec
    username: str
    uid: int
    priority: int = 1780

    def validate(self) -> None:
        self.spec.validate()
        if not isinstance(self.username, str) or not USERNAME.fullmatch(self.username):
            raise UIDPolicyError("INVALID_USERNAME")
        if self.username in {"root", "nobody"}:
            raise UIDPolicyError("FORBIDDEN_ACCOUNT")
        # Guard against accidentally selecting privileged/service-wide identities.
        if type(self.uid) is not int or not 1000 <= self.uid < 60000:
            raise UIDPolicyError("UNSAFE_UID")
        if type(self.priority) is not int or not 1000 <= self.priority < 32000:
            raise UIDPolicyError("INVALID_PRIORITY")
        if self.priority in {7700, 32766, 32767}:
            raise UIDPolicyError("RESERVED_PRIORITY")

    @property
    def uidrange(self) -> str:
        return f"{self.uid}-{self.uid}"


def _cmd(purpose: str, *args: str) -> Command:
    return Command(purpose, tuple(args))


def build_policy_plan(request: UIDPolicyRequest) -> PolicyPlan:
    """Plan only; requires an exclusive table/priority and a verified UID.

    Neither a planner nor Linux UID routing can prove which account owns a
    numeric UID. The future applying controller MUST compare getent/id and
    ensure the route table and rule priority are not in use by another owner.
    """
    request.validate()
    spec, uid, priority = request.spec, str(request.uid), str(request.priority)
    table = str(spec.route_table)
    veth = spec.veth_root

    # Reject direct DNS requests to the local loopback stub so those queries
    # cannot be delegated to systemd-resolved over Core's unprotected route.
    # NSS/DBus resolver traffic and other local proxy paths need separate
    # integration testing: this is NOT a complete DNS leak guarantee.
    guard = (
        _cmd("reject-ipv6", "ip6tables", "-w", "-I", "OUTPUT", "1",
             "-m", "owner", "--uid-owner", uid, "-j", "REJECT"),
        _cmd("block-local-dns-udp", "iptables", "-w", "-I", "OUTPUT", "1",
             "-m", "owner", "--uid-owner", uid, "-d", LOCAL_DNS,
             "-p", "udp", "--dport", "53", "-j", "REJECT"),
        _cmd("block-local-dns-tcp", "iptables", "-w", "-I", "OUTPUT", "1",
             "-m", "owner", "--uid-owner", uid, "-d", LOCAL_DNS,
             "-p", "tcp", "--dport", "53", "-j", "REJECT"),
        _cmd("terminal-blackhole", "ip", "-4", "route", "replace",
             "blackhole", "default", "table", table, "metric", "4096"),
        _cmd("select-uid-only", "ip", "-4", "rule", "add",
             "priority", priority, "uidrange", request.uidrange,
             "lookup", table),
    )
    attach = (
        _cmd("edge-next-hop", "ip", "-4", "route", "replace", "default",
             "via", spec.ns_veth_ip, "dev", veth,
             "src", spec.root_veth_ip, "table", table, "metric", "100"),
    )
    # Important: detach does NOT delete the UID rule or terminal blackhole.
    # ip route del with exact attributes cannot remove unrelated table entries.
    fail_closed_detach = (
        _cmd("remove-edge-next-hop-only", "ip", "-4", "route", "del",
             "default", "via", spec.ns_veth_ip,
             "dev", veth, "table", table, "metric", "100"),
    )
    verify = (
        _cmd("verify-uid-route", "ip", "-4", "route", "get",
             "1.1.1.1", "uid", uid),
        _cmd("verify-rules", "ip", "-4", "rule", "show"),
        _cmd("verify-policy-table", "ip", "-4", "route", "show",
             "table", table),
        _cmd("verify-ipv6-block", "ip6tables", "-w", "-C", "OUTPUT",
             "-m", "owner", "--uid-owner", uid, "-j", "REJECT"),
        _cmd("verify-dns-udp-block", "iptables", "-w", "-C", "OUTPUT",
             "-m", "owner", "--uid-owner", uid, "-d", LOCAL_DNS,
             "-p", "udp", "--dport", "53", "-j", "REJECT"),
        _cmd("verify-dns-tcp-block", "iptables", "-w", "-C", "OUTPUT",
             "-m", "owner", "--uid-owner", uid, "-d", LOCAL_DNS,
             "-p", "tcp", "--dport", "53", "-j", "REJECT"),
    )
    return PolicyPlan(
        uid=request.uid, username=request.username, edge_id=spec.edge_id,
        table=spec.route_table, priority=request.priority,
        guard=guard, attach=attach,
        fail_closed_detach=fail_closed_detach, verify=verify,
    )
