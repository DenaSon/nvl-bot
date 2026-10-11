"""D1-C3B: local Linux port requires opt-in and preserves blackhole ordering."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_kernel import LocalLinuxUIDCanaryKernel, CanaryKernelUnsafe
from edge_egress_uid_policy import UIDPolicyRequest, build_policy_plan
from ops.edge_egress_provision import EgressSpec


def request():
    return UIDPolicyRequest(EgressSpec.from_json({
        "edge_id": "fra1", "edge_public_ipv4": "216.126.229.12",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": "10.78.100.0/30",
        "veth_network": "10.78.101.0/30",
        "edge_uplink": "eth0", "edge_listen_port": 51832,
        "route_table": 1780, "mode": "relay",
    }), "nvl0557", 1644)


class KernelPortTests(unittest.TestCase):
    def test_constructor_does_not_touch_network_and_default_denies(self):
        with patch("edge_egress_uid_kernel._run",
                   side_effect=AssertionError("executed")):
            host = LocalLinuxUIDCanaryKernel()
            with self.assertRaisesRegex(CanaryKernelUnsafe, "DISABLED"):
                host._preflight(request())

    def test_wrong_os_uid_rejected_before_network(self):
        host = LocalLinuxUIDCanaryKernel(explicitly_enabled=True)
        with patch("edge_egress_uid_kernel.os.geteuid", return_value=0), \
             patch("edge_egress_uid_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1645)), \
             patch("edge_egress_uid_kernel._run",
                   side_effect=AssertionError("network accessed")):
            with self.assertRaisesRegex(CanaryKernelUnsafe, "UID_IDENTITY"):
                host._preflight(request())

    def test_preflight_only_read_and_no_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            host = LocalLinuxUIDCanaryKernel(explicitly_enabled=True,
                                             state_dir=directory)
            commands = []
            def fake(*argv, **kwargs):
                commands.append(argv)
                code = 1 if argv[:3] in (
                    ("ip", "link", "show"), ("iptables", "-w", "-C"),
                    ("ip6tables", "-w", "-C")) else 0
                return SimpleNamespace(returncode=code, stdout=(
                    "0: from all lookup local\n7700: from all fwmark 0x77 lookup 77\n"
                    if argv == ("ip", "-4", "rule", "show") else ""
                ))
            with patch("edge_egress_uid_kernel.os.geteuid", return_value=0), \
                 patch("edge_egress_uid_kernel.pwd.getpwnam",
                       return_value=SimpleNamespace(pw_uid=1644)), \
                 patch("edge_egress_uid_kernel._run", side_effect=fake):
                host._preflight(request())
            self.assertTrue(commands)
            self.assertFalse(any("add" in item or "-I" in item
                                 for cmd in commands for item in cmd))

    def test_guard_order_requires_terminal_before_uid_selection(self):
        host = LocalLinuxUIDCanaryKernel(explicitly_enabled=True)
        observed = []
        def fake(*argv, **kwargs):
            observed.append(argv)
            return SimpleNamespace(returncode=0, stdout="")
        with patch("edge_egress_uid_kernel.os.geteuid", return_value=0), \
             patch("edge_egress_uid_kernel.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)), \
             patch.object(host, "_preflight"), \
             patch.object(host, "_record"), \
             patch.object(host, "_check_guards"), \
             patch("edge_egress_uid_kernel._run", side_effect=fake):
            host._arm(request())
        self.assertEqual(observed, [
            command.argv for command in build_policy_plan(request()).guard
        ])
        self.assertIn("blackhole", observed[-2])
        self.assertIn("uidrange", observed[-1])


if __name__ == "__main__":
    unittest.main()
