"""F2: production kernel port is OFF by default and never targets wg0."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from edge_egress_uid_runtime_kernel import (
    LocalLinuxProtectedRuntimeKernel, RuntimeKernelUnsafe,
)
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def req():
    return UIDPolicyRequest(
        EgressSpec(edge_id="fra1",edge_public_ipv4="216.126.229.12",
                   core_public_ipv4="209.200.246.198",
                   tunnel_network="10.78.100.0/30",
                   veth_network="10.78.101.0/30",
                   edge_uplink="eth0", route_table=1780), "nvl0557",1644,1780)


class KernelTests(unittest.TestCase):
    def test_default_off_even_when_called_as_root(self):
        kernel = LocalLinuxProtectedRuntimeKernel()
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=0):
            with self.assertRaisesRegex(RuntimeKernelUnsafe,"DISABLED"):
                kernel.arm(req(),10553)

    def test_opt_in_requires_root_and_same_real_uid(self):
        kernel = LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True)
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=1000):
            with self.assertRaisesRegex(RuntimeKernelUnsafe,"ROOT_REQUIRED"):
                kernel.freeze(req())
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=0), \
             patch("edge_egress_uid_runtime_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1645)):
            with self.assertRaisesRegex(RuntimeKernelUnsafe,"UID_CHANGED"):
                kernel.freeze(req())

    def test_freeze_keeps_uid_selector_and_terminal_blackhole(self):
        calls=[]
        routes={"edge":True}
        def runner(*args,timeout=15):
            calls.append(args)
            if args[:5] == ("ip","-4","route","show","table"):
                result = ("default via 10.78.101.2 dev vnh-fra1 "
                          "src 10.78.101.1 metric 100\n") if routes["edge"] else ""
                return SimpleNamespace(returncode=0,stdout=result+
                                       "blackhole default metric 4096\n")
            if args[:5] == ("ip","-4","route","del","default"):
                routes["edge"]=False
            return SimpleNamespace(returncode=0,stdout="")
        kernel=LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True,run=runner)
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=0), \
             patch("edge_egress_uid_runtime_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)):
            kernel.freeze(req())
        self.assertFalse(routes["edge"])
        self.assertTrue(any(args[:5]==("ip","-4","route","del","default")
                            for args in calls))
        self.assertFalse(any("wg0" in args or "flush" in args or "ip6tables" in args
                             for args in calls))

    def test_no_silent_core_public_ip_fallback(self):
        def runner(*args,timeout=15):
            if args[:5] == ("ip","-4","route","show","table"):
                return SimpleNamespace(returncode=0,stdout=
                    "default via 10.78.101.2 dev vnh-fra1 "
                    "src 10.78.101.1 metric 100\n"
                    "blackhole default metric 4096\n")
            if "curl" in args:
                return SimpleNamespace(returncode=0,stdout="ip=209.200.246.198\n")
            return SimpleNamespace(returncode=0,stdout="")
        kernel=LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True,run=runner)
        with patch("edge_egress_uid_runtime_kernel.os.geteuid",return_value=0), \
             patch("edge_egress_uid_runtime_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)):
            self.assertEqual(kernel.public_ipv4(req()),"209.200.246.198")
        # The saga must compare this observed result against Edge public IP
        # and HOLD/FREEZE rather than allowing a wrong-route commit.


if __name__=="__main__":
    unittest.main()
