"""D1-C3A: fail-closed per-user route planning. No live network mutation."""
import unittest

from edge_egress_uid_policy import (
    UIDPolicyError, UIDPolicyRequest, build_policy_plan,
)
from ops.edge_egress_provision import EgressSpec


def sample():
    return EgressSpec.from_json(dict(
        edge_id="fra1", edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30",
        edge_uplink="eth0", edge_listen_port=51832,
        route_table=1780, mode="relay",
    ))


def plan(username="nvl0557", uid=1644, priority=1780):
    return build_policy_plan(
        UIDPolicyRequest(sample(), username, uid, priority)
    )


class UIDPolicyTests(unittest.TestCase):
    def test_plan_is_offline_not_activated(self):
        result = plan()
        self.assertFalse(result.customer_ready)
        self.assertEqual(result.username, "nvl0557")
        self.assertEqual(result.uid, 1644)
        self.assertEqual(result.edge_id, "fra1")
        self.assertEqual(result.table, 1780)
        self.assertEqual(result.priority, 1780)

    def test_guard_installed_before_winning_edge_route(self):
        result = plan()
        names = [c.purpose for c in result.guard]
        self.assertEqual(names, [
            "reject-ipv6", "block-local-dns-udp", "block-local-dns-tcp",
            "terminal-blackhole", "select-uid-only",
        ])
        blackhole = result.guard[3].argv
        self.assertIn("blackhole", blackhole)
        self.assertIn("1780", blackhole)
        self.assertEqual(result.guard[4].argv, (
            "ip", "-4", "rule", "add", "priority", "1780",
            "uidrange", "1644-1644", "lookup", "1780",
        ))
        self.assertEqual(result.attach[0].argv, (
            "ip", "-4", "route", "replace", "default",
            "via", "10.78.101.2", "dev", "vnh-fra1",
            "src", "10.78.101.1", "table", "1780", "metric", "100",
        ))

    def test_fail_closed_detach_keeps_blackhole_and_uid_selection(self):
        result = plan()
        detach = [item.argv for item in result.fail_closed_detach]
        self.assertEqual(len(detach), 1)
        self.assertEqual(detach[0][:5], (
            "ip", "-4", "route", "del", "default",
        ))
        text = " ".join(" ".join(cmd) for cmd in detach)
        self.assertNotIn("rule del", text)
        self.assertNotIn("flush", text)
        self.assertNotIn("blackhole", text)
        self.assertNotIn("wg0", text)

    def test_ipv6_and_stub_dns_fail_closed(self):
        result = plan()
        ipv6, udp, tcp = (x.argv for x in result.guard[:3])
        self.assertEqual(ipv6[:5], ("ip6tables", "-w", "-I", "OUTPUT", "1"))
        self.assertIn("--uid-owner", ipv6)
        self.assertEqual(ipv6[-2:], ("-j", "REJECT"))
        self.assertIn("127.0.0.0/8", udp)
        self.assertIn("127.0.0.0/8", tcp)
        self.assertIn("udp", udp)
        self.assertIn("tcp", tcp)
        self.assertTrue(any(c.purpose == "verify-ipv6-block" for c in result.verify))
        self.assertTrue(any(c.purpose == "verify-dns-udp-block" for c in result.verify))

    def test_no_core_default_or_wg0_changes(self):
        result = plan()
        commands = result.guard + result.attach + result.fail_closed_detach
        for command in commands:
            rendered = " ".join(command.argv)
            self.assertNotIn("wg0", rendered)
            self.assertNotIn("209.200.246.198", rendered)
            self.assertNotIn("flush", command.argv)
            self.assertNotIn("eth0", command.argv)
            self.assertNotIn("nvlbot", rendered)

    def test_reject_unsafe_users_priorities(self):
        cases = [
            ("root", 0, 1780),
            ("nobody", 65534, 1780),
            ("nvl0557", 0, 1780),
            ("nvl0557", 999, 1780),
            ("nvl0557", 60000, 1780),
            ("nvl0557", True, 1780),
            ("nvl0557;rm", 1644, 1780),
            ("nvl0557", 1644, 7700),
            ("nvl0557", 1644, 32766),
            ("nvl0557", 1644, 50),
        ]
        for name, uid, priority in cases:
            with self.subTest(name=name, uid=uid, priority=priority):
                with self.assertRaises(UIDPolicyError):
                    plan(name, uid, priority)

    def test_does_not_execute_host_commands(self):
        import subprocess
        from unittest.mock import patch
        with patch.object(subprocess, "run", side_effect=AssertionError("network IO")):
            with patch.object(subprocess, "check_output", side_effect=AssertionError("host IO")):
                self.assertEqual(plan().uid, 1644)

    def test_guard_against_wrong_uid_name_binding_is_explicit_gate(self):
        # This module cannot attest that a username owns a UID. It is NOT an
        # executor: the higher-level controller must check id/getent and
        # exclusive table/priority ownership before applying commands.
        self.assertFalse(plan().customer_ready)


if __name__ == "__main__":
    unittest.main()
