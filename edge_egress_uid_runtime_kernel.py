"""F2: explicit opt-in Core-side UID kernel port, never a default bot adapter.

This port changes only an allocated UID policy table, UID-specific firewall
rules and a dedicated nvl-egress-dns-USERNAME service. It never changes wg0,
main/default routing, ssh.service, DNS records, or legacy account fields.
Use ONLY behind the existing 6G lease, an attested PAM account admission gate,
root-owned manifests, and an idle-account check.

Real PAM/boot/systemd/packet-leak verification remains a F4 release gate.
"""
from __future__ import annotations

import os
import pwd
import re
import subprocess

from edge_egress_uid_boot import BootGuardApplier, BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest, build_policy_plan
from edge_egress_uid_route_state import inspect_owned_routes


class RuntimeKernelUnsafe(ValueError):
    pass


def _run(*args, timeout=15):
    return subprocess.run(list(args), check=False, capture_output=True,
                          text=True, timeout=timeout)


class LocalLinuxProtectedRuntimeKernel:
    def __init__(self, *, explicitly_enabled: bool = False, run=_run,
                 guard_factory=BootGuardApplier):
        self.enabled = explicitly_enabled is True
        self.run = run
        self.guard_factory = guard_factory

    def _assert(self, req):
        req.validate()
        if not self.enabled:
            raise RuntimeKernelUnsafe("LIVE_RUNTIME_DISABLED")
        if os.geteuid() != 0:
            raise RuntimeKernelUnsafe("ROOT_REQUIRED")
        if pwd.getpwnam(req.username).pw_uid != req.uid:
            raise RuntimeKernelUnsafe("UID_CHANGED")

    def _call(self, *args, timeout=15):
        p = self.run(*args, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeKernelUnsafe("OWNED_RUNTIME_COMMAND_FAILED")
        return p.stdout

    def _routes(self, req):
        return inspect_owned_routes(
            self._call("ip", "-4", "route", "show", "table",
                       str(req.spec.route_table)),
            next_hop=req.spec.ns_veth_ip,
            device=req.spec.veth_root, source=req.spec.root_veth_ip,
        )

    def arm(self, req: UIDPolicyRequest, dns_port: int) -> None:
        self._assert(req)
        if type(dns_port) is not int or not 1024 <= dns_port <= 65535:
            raise RuntimeKernelUnsafe("INVALID_DNS_PORT")
        manifest = BootGuardManifest(req, "PROTECTED_BOOT_GUARD", dns_port)
        # If another UID already uses this Edge table, F1 intentionally
        # removes the shared Edge default while arming this account. The
        # shared 6G lease serializes the brief outage; unknown routes fail.
        self.guard_factory().apply(manifest)
        self.guard_factory().verify(manifest)
        self._call("systemctl", "start",
                   "nvl-egress-dns-" + req.username + ".service")
        self._call("systemctl", "is-active", "--quiet",
                   "nvl-egress-dns-" + req.username + ".service")

    def attach(self, req: UIDPolicyRequest) -> None:
        self._assert(req)
        if self._run_link(req.spec.veth_root) is False:
            raise RuntimeKernelUnsafe("EDGE_VETH_MISSING")
        before = self._routes(req)
        if not before.terminal_blackhole:
            raise RuntimeKernelUnsafe("TERMINAL_BLACKHOLE_MISSING")
        if not before.edge_attached:
            plan = build_policy_plan(req)
            for cmd in plan.attach:
                self._call(*cmd.argv)
        if not self._routes(req).edge_attached:
            raise RuntimeKernelUnsafe("OWNED_EDGE_ROUTE_NOT_ATTACHED")

    def _run_link(self, device):
        return self.run("ip", "link", "show", "dev", device).returncode == 0

    def freeze(self, req: UIDPolicyRequest) -> None:
        self._assert(req)
        observed = self._routes(req)
        if observed.edge_attached:
            for cmd in build_policy_plan(req).fail_closed_detach:
                self._call(*cmd.argv)
        self.assert_frozen(req)

    def assert_frozen(self, req: UIDPolicyRequest) -> None:
        self._assert(req)
        routes = self._routes(req)
        if routes.edge_attached or not routes.terminal_blackhole:
            raise RuntimeKernelUnsafe("ROUTE_NOT_FROZEN")
        # Never remove the UID rule, blackhole or per-UID firewall.

    def public_ipv4(self, req: UIDPolicyRequest) -> str:
        self._assert(req)
        if not self._routes(req).edge_attached:
            raise RuntimeKernelUnsafe("EDGE_NOT_ATTACHED")
        process = self.run(
            "runuser", "-u", req.username, "--",
            "env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY",
            "-u", "ALL_PROXY", "-u", "http_proxy", "-u", "https_proxy",
            "-u", "all_proxy",
            "curl", "-4", "-fsS", "--noproxy", "*",
            "--resolve", "one.one.one.one:443:1.1.1.1",
            "--connect-timeout", "5", "--max-time", "15",
            "https://one.one.one.one/cdn-cgi/trace",
            timeout=22,
        )
        if process.returncode != 0:
            raise RuntimeKernelUnsafe("PUBLIC_IP_PROBE_FAILED")
        match = re.search(r"(?m)^ip=(\d{1,3}(?:\.\d{1,3}){3})\s*$",
                          process.stdout)
        if not match:
            raise RuntimeKernelUnsafe("PUBLIC_IP_NOT_OBSERVED")
        return match.group(1)

    def assert_dns_ipv6(self, req: UIDPolicyRequest) -> None:
        self._assert(req)
        for cmd in build_policy_plan(req).verify[3:]:
            self._call(*cmd.argv)
        self._call("systemctl", "is-active", "--quiet",
                   "nvl-egress-dns-" + req.username + ".service")
        # A completed source-IP proof and installed guards are NOT a
        # packet-level guarantee that NSS helpers cannot leak to Core.
        # That negative proof requires F4 packet captures/failure injection.
