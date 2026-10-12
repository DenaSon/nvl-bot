"""D1-C3C: optional, boot-time *blocking* guard for a protected SSH UID.

This host-local tool neither activates users nor installs systemd units.
The independent per-UID session gate belongs to F2, so this standalone
guard must never be used as permission for a production account cutover.
Explicit apply freezes only its precisely owned Edge route and retains
the terminal blackhole. Full protected mode remains NOT READY.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from edge_egress_uid_dns import plan_transparent_dns, validate_nss_hosts
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
from typing import Callable

from edge_egress_uid_policy import UIDPolicyRequest, build_policy_plan
from edge_egress_uid_route_state import inspect_owned_routes, ProtectedRouteError
from ops.edge_egress_provision import EgressSpec


class BootGuardError(ValueError):
    pass


@dataclass(frozen=True)
class BootGuardManifest:
    request: UIDPolicyRequest
    mode: str
    dns_port: int | None = None
    ingress_return: bool = False
    shared_edge: bool = False

    @classmethod
    def parse(cls, data: dict) -> "BootGuardManifest":
        if not isinstance(data, dict) or (not {"mode", "username", "uid", "priority", "spec"} <= set(data)
            or set(data) - {"mode", "username", "uid", "priority", "spec", "dns_port", "ingress_return", "shared_edge"}):
            raise BootGuardError("INVALID_MANIFEST_FIELDS")
        if data["mode"] != "PROTECTED_BOOT_GUARD":
            raise BootGuardError("PROTECTED_MODE_EXPLICITLY_REQUIRED")
        try:
            spec = EgressSpec.from_json(data["spec"])
            req = UIDPolicyRequest(spec, data["username"],
                                   data["uid"], data["priority"])
            req.validate()
        except (ValueError, TypeError, KeyError) as exc:
            raise BootGuardError("INVALID_UID_POLICY") from exc
        port = data.get("dns_port")
        if port is not None and (type(port) is not int or not 1024 <= port <= 65535):
            raise BootGuardError("INVALID_DNS_PORT")
        ingress = data.get("ingress_return", False)
        if type(ingress) is not bool:
            raise BootGuardError("INVALID_INGRESS_RETURN")
        shared = data.get("shared_edge", False)
        if type(shared) is not bool or (shared and not ingress):
            raise BootGuardError("INVALID_SHARED_EDGE_MODE")
        return cls(req, data["mode"], port, ingress, shared)


def uid_deny_rule(uid: int, action: str = "-C") -> tuple[str, ...]:
    """Exact per-UID IPv4 output fence. Never touches shared routes."""
    if type(uid) is not int or not 1000 <= uid < 60000:
        raise BootGuardError("UNSAFE_UID")
    if action not in ("-C", "-I", "-D"):
        raise BootGuardError("UNSAFE_FENCE_ACTION")
    prefix = ("iptables", "-w", action, "OUTPUT")
    if action == "-I":
        prefix += ("1",)
    return prefix + ("-m", "owner", "--uid-owner", str(uid),
                     "-m", "comment", "--comment", "nvl-egress-uid-" + str(uid),
                     "-j", "REJECT")


def uid_deny_present(run: Callable, uid: int) -> bool:
    result = run(*uid_deny_rule(uid))
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise BootGuardError("UID_DENY_PROBE_FAILED")


def arm_uid_deny(run: Callable, uid: int) -> None:
    """Idempotent per-UID freeze with no table/default deletion."""
    if not uid_deny_present(run, uid):
        result = run(*uid_deny_rule(uid, "-I"))
        if result.returncode != 0:
            raise BootGuardError("UID_DENY_INSERT_FAILED")


def release_uid_deny(run: Callable, uid: int) -> None:
    """Release ONLY an already-verified exact owned per-UID fence."""
    if not uid_deny_present(run, uid):
        raise BootGuardError("UID_DENY_NOT_ARMED")
    result = run(*uid_deny_rule(uid, "-D"))
    if result.returncode != 0:
        raise BootGuardError("UID_DENY_REMOVE_FAILED")
    if uid_deny_present(run, uid):
        raise BootGuardError("UID_DENY_DUPLICATE_HOLD")


def read_root_only_manifest(path: Path) -> BootGuardManifest:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise BootGuardError("UNSAFE_MANIFEST_PATH")
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise BootGuardError("MANIFEST_NOT_ROOT_ONLY")
    if path.stat().st_size > 4096:
        raise BootGuardError("MANIFEST_TOO_LARGE")
    return BootGuardManifest.parse(json.loads(path.read_text(encoding="utf-8")))


def _local_run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True,
                          text=True, timeout=10, check=False)


class BootGuardApplier:
    """Idempotent root-only guard. Does NOT attach an Edge route.

    Commands are predeclared by the policy plan; never executes manifest
    strings as shell. Preflight fails on unknown priority, UID rule, or table
    owner before any mutation. Reboot state is restored as DENY, not READY.
    """
    def __init__(self, run: Callable = _local_run,
                 get_uid: Callable = lambda username: pwd.getpwnam(username).pw_uid,
                 geteuid: Callable = os.geteuid,
                 read_nss: Callable = lambda: Path("/etc/nsswitch.conf").read_text()):
        self.run, self.get_uid, self.geteuid, self.read_nss = run, get_uid, geteuid, read_nss

    def call(self, *argv: str, checked: bool = True) -> str:
        p = self.run(*argv)
        if checked and p.returncode != 0:
            raise BootGuardError("BOOT_GUARD_COMMAND_FAILED")
        return p.stdout

    @staticmethod
    def check_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
        args = list(argv)
        # iptables -w -I OUTPUT 1 ... -> iptables -w -C OUTPUT ...
        if args[0] not in ("iptables", "ip6tables") or args[2:5] != ["-I", "OUTPUT", "1"]:
            raise BootGuardError("UNSUPPORTED_GUARD_COMMAND")
        return tuple(args[:2] + ["-C", "OUTPUT"] + args[5:])

    def preflight(self, manifest: BootGuardManifest):
        if self.geteuid() != 0:
            raise BootGuardError("ROOT_REQUIRED")
        request = manifest.request
        plan = build_policy_plan(request)
        try:
            actual = self.get_uid(request.username)
        except KeyError as exc:
            raise BootGuardError("USER_NOT_FOUND") from exc
        if actual != request.uid:
            raise BootGuardError("UID_CHANGED")

        rules = self.call("ip", "-4", "rule", "show")
        prefix = str(request.priority) + ":"
        match = [" ".join(x.split()) for x in rules.splitlines()
                 if x.strip().startswith(prefix)]
        if len(match) > 1:
            raise BootGuardError("DUPLICATE_PRIORITY")
        expected_rule = (
            f"{request.priority}: from all uidrange "
            f"{request.uidrange} lookup {plan.table}"
        )
        # Exact full-destination UID selection; a stale experimental
        # "to 1.1.1.1/32" rule must NEVER be treated as a protected guard.
        if match and match[0] != expected_rule:
            raise BootGuardError("FOREIGN_PRIORITY")
        # UID must not have ANY overlapping selector, even a broad
        # 1600-1700 range that includes this protected UID. Such a rule can
        # beat the owned route and leak traffic through Core/main.
        for line in rules.splitlines():
            if "uidrange" not in line:
                continue
            selector = re.search(r"\buidrange\s+(\d+)-(\d+)\b", line)
            if not selector:
                raise BootGuardError("UNRECOGNIZED_UID_ROUTING_RULE")
            first, last = map(int, selector.groups())
            if first <= request.uid <= last and " ".join(line.split()) != expected_rule:
                raise BootGuardError("UID_ALREADY_ROUTED_ELSEWHERE")

        if manifest.dns_port is not None:
            try:
                validate_nss_hosts(self.read_nss())
            except (ValueError, OSError) as exc:
                raise BootGuardError("UNSAFE_NSS_CONFIGURATION") from exc
            all_nat = self.call("iptables", "-w", "-t", "nat", "-S", "OUTPUT")
            for line in all_nat.splitlines():
                if (re.search(r"--uid-owner\s+" + re.escape(str(request.uid)) + r"\b", line)
                    and "--dport 53" in line
                    and f"--to-ports {manifest.dns_port}" not in line):
                    raise BootGuardError("FOREIGN_DNS_REDIRECT")
        routes_result = self.run("ip", "-4", "route", "show", "table", str(plan.table))
        if routes_result.returncode:
            # On real iproute2 an unused numeric table can return:
            # "Error: ipv4: FIB table does not exist." rather than empty stdout.
            # Confirm absence from ALL tables instead of treating any command
            # failure as an empty, available table.
            all_routes = self.run("ip", "-j", "-4", "route", "show", "table", "all")
            if all_routes.returncode:
                raise BootGuardError("ROUTE_INVENTORY_UNAVAILABLE")
            try:
                inventory = json.loads(all_routes.stdout)
                if not isinstance(inventory, list):
                    raise ValueError("INVALID_ROUTE_INVENTORY")
            except ValueError as exc:
                raise BootGuardError("INVALID_ROUTE_INVENTORY") from exc
            if any(str(route.get("table", "main")) == str(plan.table)
                   for route in inventory if isinstance(route, dict)):
                raise BootGuardError("ROUTE_TABLE_INVENTORY_CONFLICT")
            routes = ""
        else:
            routes = routes_result.stdout
        try:
            state = inspect_owned_routes(
                routes, next_hop=request.spec.ns_veth_ip,
                device=request.spec.veth_root, source=request.spec.root_veth_ip,
                allow_empty=True, allow_ingress_return=True,
            )
        except ProtectedRouteError as exc:
            raise BootGuardError("FOREIGN_ROUTE_IN_PROTECTED_TABLE") from exc
        if match and not state.terminal_blackhole:
            raise BootGuardError("UID_RULE_WITHOUT_BLACKHOLE")
        return plan, bool(match)

    def apply(self, manifest: BootGuardManifest):
        plan, present = self.preflight(manifest)
        if manifest.shared_edge:
            # FIRST: freeze only this UID. Existing Edge subscribers stay live.
            arm_uid_deny(self.run, manifest.request.uid)
        # First block IPv6/direct local DNS, then arm the terminal IPv4
        # blackhole, and only afterward bind the UID to the table.
        for guard in plan.guard[:3]:
            probe = self.run(*self.check_argv(guard.argv))
            if probe.returncode != 0:
                self.call(*guard.argv)
        if manifest.dns_port is not None:
            dns = plan_transparent_dns(manifest.request, manifest.dns_port)
            for add, verify in ((dns.udp, dns.udp_check), (dns.tcp, dns.tcp_check)):
                if self.run(*verify.argv).returncode != 0:
                    self.call(*add.argv)
        self.call(*plan.guard[3].argv)
        if manifest.ingress_return:
            # Preserve only wg0 inbound SSH replies, before UID selection.
            self.call("ip", "-4", "route", "replace", "10.77.0.0/24",
                      "dev", "wg0", "src", "10.77.0.1", "table", str(plan.table))
        # Boot recovery always returns an owned Edge route to DENY-only.
        # Never delete wg0 or an unknown/default route.
        state = inspect_owned_routes(
            self.call("ip", "-4", "route", "show", "table", str(plan.table)),
            next_hop=manifest.request.spec.ns_veth_ip,
            device=manifest.request.spec.veth_root,
            source=manifest.request.spec.root_veth_ip,
            allow_ingress_return=True,
        )
        if state.edge_attached and not manifest.shared_edge:
            self.call("ip", "-4", "route", "del", "default", "via",
                      manifest.request.spec.ns_veth_ip, "dev",
                      manifest.request.spec.veth_root, "table",
                      str(plan.table), "metric", "100")
        if not present:
            self.call(*plan.guard[4].argv)
        self.verify(manifest, require_frozen=manifest.shared_edge)

    def verify(self, manifest: BootGuardManifest, *, require_frozen: bool = False) -> None:
        plan, present = self.preflight(manifest)
        if not present:
            raise BootGuardError("UID_RULE_NOT_ARMED")
        text = self.call("ip", "-4", "route", "show", "table", str(plan.table))
        if not re.search(r"(?m)^blackhole default\b", text):
            raise BootGuardError("TERMINAL_BLACKHOLE_MISSING")
        if manifest.ingress_return and not re.search(
            r"(?m)^10\.77\.0\.0/24 dev wg0(?: proto kernel)? scope link src 10\.77\.0\.1$",
            text,
        ):
            raise BootGuardError("INGRESS_RETURN_ROUTE_MISSING")
        if require_frozen and manifest.shared_edge and not uid_deny_present(
            self.run, manifest.request.uid
        ):
            raise BootGuardError("SHARED_UID_FENCE_MISSING")
        for guard in plan.guard[:3]:
            if self.run(*self.check_argv(guard.argv)).returncode != 0:
                raise BootGuardError("IPV6_OR_LOCAL_DNS_GUARD_MISSING")
        if manifest.dns_port is not None:
            dns = plan_transparent_dns(manifest.request, manifest.dns_port)
            for command in (dns.udp_check, dns.tcp_check):
                if self.run(*command.argv).returncode != 0:
                    raise BootGuardError("DNS_REDIRECT_NOT_INSTALLED")


def render_ssh_required_unit(manifest: BootGuardManifest,
                             *, module_root: str = "/opt/nvl-egress",
                             config_root: str = "/etc/nvl-egress/protected") -> str:
    """Standalone DENY-only guard artifact, not an SSH unit dependency.

    No protected user may log in until the F2 per-UID session gate is proven.
    """
    req = manifest.request
    name = req.username
    if module_root != "/opt/nvl-egress" or config_root != "/etc/nvl-egress/protected":
        raise BootGuardError("UNREVIEWED_UNIT_PATHS")
    return (
        "[Unit]\n"
        f"Description=NVL fail-closed boot guard for {name} (UID {req.uid})\n"
        "After=local-fs.target\n"
        "\n[Service]\n"
        "Type=oneshot\nRemainAfterExit=yes\n"
        f"ExecStart=/usr/bin/python3 {module_root}/edge_egress_uid_boot.py "
        f"apply --manifest {config_root}/{name}.json --enforce\n"
        "TimeoutStartSec=25\n"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="OFFLINE by default; protected boot guard")
    parser.add_argument("action", choices=("show-unit", "apply", "verify"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--enforce", action="store_true",
                        help="Explicitly authorize host kernel changes")
    args = parser.parse_args(argv)
    try:
        manifest = read_root_only_manifest(args.manifest)
        if args.action == "show-unit":
            print(render_ssh_required_unit(manifest))
        elif args.action == "verify":
            BootGuardApplier().verify(manifest)
            print("GUARD_PRESENT_NOT_CUSTOMER_READY")
        else:
            if not args.enforce:
                raise BootGuardError("EXPLICIT_ENFORCE_REQUIRED")
            BootGuardApplier().apply(manifest)
            print("BOOT_GUARD_ARMED_DENY_ONLY")
    except (BootGuardError, OSError, ValueError, json.JSONDecodeError) as exc:
        # No secret args/logs.
        print("ERROR:" + type(exc).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
