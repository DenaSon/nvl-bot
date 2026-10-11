"""D1-C3C: protected boot guard idempotency and SSH startup safety."""
import json
import unittest
from types import SimpleNamespace

from edge_egress_uid_boot import (
    BootGuardApplier, BootGuardError, BootGuardManifest,
    render_ssh_required_unit,
)


def manifest(dns=10553):
    spec = {
        "edge_id": "fra1", "edge_public_ipv4": "216.126.229.12",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": "10.78.100.0/30",
        "veth_network": "10.78.101.0/30",
        "edge_uplink": "eth0", "edge_listen_port": 51832,
        "route_table": 1780, "mode": "relay",
    }
    raw = {"mode": "PROTECTED_BOOT_GUARD", "username": "nvl0557",
           "uid": 1644, "priority": 1780, "spec": spec}
    if dns is not None:
        raw["dns_port"] = dns
    return BootGuardManifest.parse(raw)


class FakeKernel:
    def __init__(self):
        self.priority = False
        self.blackhole = False
        self.edge_attached = False
        self.guards = set()
        self.redirects = set()
        self.log = []
        self.foreign_rule = False
        self.selective_rule = False

    def __call__(self, *args):
        self.log.append(args)
        if args == ("ip", "-4", "rule", "show"):
            content = "0: from all lookup local\n"
            if self.foreign_rule:
                content += "1780: from all uidrange 1644-1644 lookup 9\n"
            elif self.selective_rule:
                content += "1780: from all to 1.1.1.1 uidrange 1644-1644 lookup 1780\n"
            elif self.priority:
                content += "1780: from all uidrange 1644-1644 lookup 1780\n"
            return SimpleNamespace(returncode=0, stdout=content)
        if args == ("ip", "-4", "route", "show", "table", "1780"):
            edge = ("default via " + manifest().request.spec.ns_veth_ip +
                    " dev " + manifest().request.spec.veth_root +
                    " src " + manifest().request.spec.root_veth_ip +
                    " metric 100\n") if self.edge_attached else ""
            blackhole = "blackhole default metric 4096\n" if self.blackhole else ""
            return SimpleNamespace(returncode=0, stdout=edge + blackhole)
        if args == ("iptables", "-w", "-t", "nat", "-S", "OUTPUT"):
            return SimpleNamespace(returncode=0, stdout="")
        if args[0] in ("iptables", "ip6tables"):
            if "-C" in args:
                bag = self.redirects if "-t" in args else self.guards
                canonical = tuple("-I" if part == "-C" else part for part in args)
                if "-t" in args:
                    canonical = canonical[:6] + ("1",) + canonical[6:]
                else:
                    canonical = canonical[:4] + ("1",) + canonical[4:]
                return SimpleNamespace(returncode=0 if canonical in bag else 1,
                                       stdout="")
            if "-I" in args:
                bag = self.redirects if "-t" in args else self.guards
                bag.add(args)
                return SimpleNamespace(returncode=0, stdout="")
        if args[:5] == ("ip", "-4", "route", "replace", "blackhole"):
            self.blackhole = True
        if args[:5] == ("ip", "-4", "route", "del", "default"):
            self.edge_attached = False
        if args[:5] == ("ip", "-4", "rule", "add", "priority"):
            self.priority = True
        return SimpleNamespace(returncode=0, stdout="")


class BootTests(unittest.TestCase):
    def test_missing_explicit_protected_manifest_is_rejected(self):
        x = manifest()
        raw = {"mode": "STAGE_ONLY", "username": x.request.username,
               "uid": 1644, "priority": 1780, "spec": vars(x.request.spec)}
        with self.assertRaisesRegex(BootGuardError, "EXPLICITLY_REQUIRED"):
            BootGuardManifest.parse(raw)
        raw["mode"] = "PROTECTED_BOOT_GUARD"
        raw["dns_port"] = 53
        with self.assertRaisesRegex(BootGuardError, "INVALID_DNS_PORT"):
            BootGuardManifest.parse(raw)

    def test_guard_unit_does_not_kill_shared_ssh(self):
        unit = render_ssh_required_unit(manifest())
        self.assertNotIn("ssh.service", unit)
        self.assertIn("--enforce", unit)
        self.assertNotIn("ExecStop", unit)
        self.assertNotIn("WantedBy=", unit)
        self.assertNotIn("RequiredBy=", unit)

    def test_boot_guard_installs_ipv6_dns_nat_and_blackhole_before_uid(self):
        kernel = FakeKernel()
        manager = BootGuardApplier(
            run=kernel, get_uid=lambda username: 1644,
            geteuid=lambda: 0, read_nss=lambda: "hosts: files dns\n")
        manager.apply(manifest())
        manager.apply(manifest())  # idempotent, no duplicate guard rules
        self.assertTrue(kernel.priority)
        self.assertTrue(kernel.blackhole)
        self.assertEqual(len(kernel.guards), 3)
        self.assertEqual(len(kernel.redirects), 2)
        added = [x for x in kernel.log if
                 ("-I" in x or x[:4] == ("ip", "-4", "route", "replace")
                  or x[:4] == ("ip", "-4", "rule", "add"))]
        # At first apply, UID selection must be the last *mutating* operation.
        first_uid = next(i for i, c in enumerate(added) if "uidrange" in c)
        self.assertIn("blackhole", added[first_uid - 1])
        self.assertEqual(sum(1 for x in added if x[:5] ==
                             ("ip", "-4", "rule", "add", "priority")), 1)

    def test_boot_apply_freezes_exact_owned_edge_route_before_returning(self):
        kernel = FakeKernel()
        kernel.blackhole = True
        kernel.priority = True
        kernel.edge_attached = True
        manager = BootGuardApplier(
            run=kernel, get_uid=lambda _: 1644, geteuid=lambda: 0,
            read_nss=lambda: "hosts: files dns\n",
        )
        manager.apply(manifest())
        self.assertFalse(kernel.edge_attached)
        self.assertTrue(kernel.blackhole)
        self.assertTrue(kernel.priority)
        self.assertEqual(sum(args[:5] == ("ip", "-4", "route", "del", "default")
                             for args in kernel.log), 1)
        self.assertFalse(any("wg0" in args or "flush" in args for args in kernel.log))

    def test_boot_preflight_rejects_foreign_table_route(self):
        kernel = FakeKernel()
        def run(*args):
            if args == ("ip", "-4", "route", "show", "table", "1780"):
                return SimpleNamespace(returncode=0, stdout=(
                    "blackhole default metric 4096\n"
                    "default via 209.200.246.198 dev eth0\n"))
            return kernel(*args)
        manager = BootGuardApplier(run=run, get_uid=lambda _: 1644,
                                   geteuid=lambda: 0,
                                   read_nss=lambda: "hosts: files dns\n")
        with self.assertRaisesRegex(BootGuardError, "FOREIGN_ROUTE"):
            manager.apply(manifest())
        self.assertFalse(kernel.priority)

    def test_real_linux_unused_fib_table_is_not_a_false_collision(self):
        kernel = FakeKernel()
        def run(*args):
            if args == ("ip", "-4", "route", "show", "table", "1780"):
                return SimpleNamespace(returncode=2, stdout="",
                                       stderr="Error: ipv4: FIB table does not exist")
            if args == ("ip", "-j", "-4", "route", "show", "table", "all"):
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return kernel(*args)
        manager = BootGuardApplier(
            run=run, get_uid=lambda username: 1644,
            geteuid=lambda: 0, read_nss=lambda: "hosts: files dns\n",
        )
        result, present = manager.preflight(manifest())
        self.assertEqual(result.table, 1780)
        self.assertFalse(present)

    def test_failed_fib_inventory_cannot_claim_table_is_empty(self):
        kernel = FakeKernel()
        def run(*args):
            if args == ("ip", "-4", "route", "show", "table", "1780"):
                return SimpleNamespace(returncode=2, stdout="")
            if args == ("ip", "-j", "-4", "route", "show", "table", "all"):
                return SimpleNamespace(returncode=1, stdout="")
            return kernel(*args)
        manager = BootGuardApplier(
            run=run, get_uid=lambda username: 1644,
            geteuid=lambda: 0, read_nss=lambda: "hosts: files dns\n",
        )
        with self.assertRaisesRegex(BootGuardError, "INVENTORY_UNAVAILABLE"):
            manager.preflight(manifest())

    def test_wrong_uid_or_priority_collision_never_mutates(self):
        x = manifest()
        for case in ("uid", "priority", "selective", "nss"):
            with self.subTest(case=case):
                kernel = FakeKernel()
                if case == "priority":
                    kernel.foreign_rule = True
                if case == "selective":
                    kernel.selective_rule = True
                manager = BootGuardApplier(
                    run=kernel,
                    get_uid=lambda _: 1645 if case == "uid" else 1644,
                    geteuid=lambda: 0,
                    read_nss=lambda: (
                        "hosts: files resolve [!UNAVAIL=return] dns"
                        if case == "nss" else "hosts: files dns"
                    ))
                with self.assertRaises(BootGuardError):
                    manager.apply(x)
                self.assertFalse(kernel.priority)
                self.assertFalse(kernel.blackhole)
                self.assertFalse(kernel.guards)

    def test_zero_live_operations_during_manifest_parse(self):
        x = manifest(dns=None)
        self.assertEqual(x.request.uid, 1644)
        self.assertIsNone(x.dns_port)


if __name__ == "__main__":
    unittest.main()
