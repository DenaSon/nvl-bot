"""G: focused per-UID shared Egress safety; no host/network access."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_boot import (
    BootGuardApplier, arm_uid_deny, release_uid_deny,
    uid_deny_present, BootGuardError,
)
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from tests.test_edge_egress_v1_f2 import FakeIngressKernel, protected_fixture
from tests.test_edge_egress_uid_runtime_kernel import req


class SharedEdgeTests(unittest.TestCase):
    def test_shared_boot_freezes_only_its_uid_without_route_deletion(self):
        kernel = FakeIngressKernel()
        kernel.priority = True
        kernel.blackhole = True
        kernel.edge_attached = True
        m = protected_fixture()  # shared_edge True from G
        guard = BootGuardApplier(
            run=kernel, get_uid=lambda _: 1644, geteuid=lambda: 0,
            read_nss=lambda: "hosts: files dns\n",
        )
        guard.apply(m)
        guard.apply(m)
        self.assertTrue(kernel.edge_attached)
        self.assertTrue(uid_deny_present(kernel,1644))
        self.assertFalse(any(a[:5] == ("ip","-4","route","del","default")
                             for a in kernel.log))
        self.assertEqual(sum(a[:4] == ("iptables","-w","-I","OUTPUT")
                             and a[-2:] == ("-j","REJECT")
                             and "--dport" not in a for a in kernel.log),1)

    def test_two_uid_fences_are_isolated_and_idempotent(self):
        rules=set()
        commands=[]
        def runner(*args):
            commands.append(args)
            ident = args[args.index("--uid-owner")+1]
            if args[2]=="-C":
                return SimpleNamespace(returncode=0 if ident in rules else 1)
            if args[2]=="-I":
                rules.add(ident)
            if args[2]=="-D":
                rules.remove(ident)
            return SimpleNamespace(returncode=0)
        arm_uid_deny(runner,1644)
        arm_uid_deny(runner,1645)
        arm_uid_deny(runner,1644)
        self.assertEqual(rules,{"1644","1645"})
        release_uid_deny(runner,1644)
        self.assertEqual(rules,{"1645"})
        with self.assertRaisesRegex(BootGuardError,"NOT_ARMED"):
            release_uid_deny(runner,1644)
        self.assertFalse(any("route" in cmd for cmd in commands))

    def test_attach_releases_only_own_fence_and_does_not_replace_shared_default(self):
        denied={"1644"}
        calls=[]
        def runner(*args,timeout=15):
            calls.append(args)
            if args[:5]==("ip","-4","route","show","table"):
                return SimpleNamespace(returncode=0,stdout=(
                    "default via 10.78.101.2 dev vnh-fra1 "
                    "src 10.78.101.1 metric 100\n"
                    "blackhole default metric 4096\n"))
            if args[:4]==("iptables","-w","-C","OUTPUT"):
                return SimpleNamespace(returncode=0 if "1644" in denied else 1,stdout="")
            if args[:4]==("iptables","-w","-D","OUTPUT"):
                denied.remove("1644")
            return SimpleNamespace(returncode=0,stdout="")
        fake_guard=lambda: SimpleNamespace(verify=lambda *a,**kw: None)
        kernel=LocalLinuxProtectedRuntimeKernel(
            explicitly_enabled=True,run=runner,guard_factory=fake_guard)
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=0), \
             patch("edge_egress_uid_runtime_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)):
            kernel.attach(req())
        self.assertEqual(denied,set())
        self.assertFalse(any(a[:5]==("ip","-4","route","del","default")
                             for a in calls))
        self.assertFalse(any(a[:5]==("ip","-4","route","replace","default")
                             for a in calls))


if __name__=="__main__":
    unittest.main()
