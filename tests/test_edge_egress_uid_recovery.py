"""D1-C3C: recovery audit never guesses READY or releases a 6G lock."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_recovery import (
    RecoveryEvidence, RecoveryState, assess_recovery, has_6g_recovery_hold,
    inspect_recovery,
)


def evidence(**overrides):
    data = dict(
        uid_route_rule=True, terminal_blackhole=True, ipv6_guard=True,
        direct_dns_guard=True, udp_tcp_dns_redirect=True,
        nss_hosts_suitable=True, edge_route_present=False,
        crash_marker_present=False, phase6g_hold=False,
        ssh_required_dependency=True,
    )
    data.update(overrides)
    return RecoveryEvidence(**data)


def manifest():
    return BootGuardManifest.parse({
        "mode": "PROTECTED_BOOT_GUARD",
        "username": "nvl0557", "uid": 1644, "priority": 1780,
        "dns_port": 10553,
        "spec": {
            "edge_id": "fra1", "edge_public_ipv4": "216.126.229.12",
            "core_public_ipv4": "209.200.246.198",
            "tunnel_network": "10.78.100.0/30",
            "veth_network": "10.78.101.0/30",
            "edge_uplink": "eth0", "edge_listen_port": 51832,
            "route_table": 1780, "mode": "relay",
        },
    })


class RecoveryTests(unittest.TestCase):
    def test_boot_guard_absent_is_unsafe(self):
        for field in ("uid_route_rule", "terminal_blackhole",
                      "ipv6_guard", "direct_dns_guard",
                      "udp_tcp_dns_redirect", "nss_hosts_suitable",
                      "ssh_required_dependency"):
            with self.subTest(field=field):
                result = assess_recovery(evidence(**{field: False}))
                self.assertEqual(result.state, RecoveryState.UNSAFE_GUARD_ABSENT)
                self.assertFalse(result.customer_ready)

    def test_valid_guard_without_edge_is_offline_not_ready(self):
        result = assess_recovery(evidence())
        self.assertEqual(result.state, RecoveryState.GUARDED_OFFLINE)
        self.assertFalse(result.customer_ready)
        result = assess_recovery(evidence(edge_route_present=True))
        self.assertEqual(result.state, RecoveryState.ROUTED_UNVERIFIED)
        self.assertFalse(result.customer_ready)

    def test_crash_marker_or_6g_lock_holds_even_with_route(self):
        for field in ("crash_marker_present", "phase6g_hold"):
            result = assess_recovery(evidence(edge_route_present=True,
                                              **{field: True}))
            self.assertEqual(result.state, RecoveryState.HOLD_FOR_OPERATOR)
            self.assertFalse(result.customer_ready)

    def test_shared_6g_phase_detection(self):
        self.assertTrue(has_6g_recovery_hold([
            ("SUCCEEDED", json.dumps({"phase": "EGRESS_UID_RECOVERY_REQUIRED"})),
            ("RUNNING", json.dumps({"phase": "EGRESS_UID_ARM_GUARD"})),
        ]))
        self.assertFalse(has_6g_recovery_hold([
            ("SUCCEEDED", json.dumps({"phase": "EGRESS_UID_ARM_GUARD"})),
            ("FAILED", "{}"),
        ]))

    def test_actual_audit_read_only_offline(self):
        calls = []
        def run(*args):
            calls.append(args)
            if args == ("ip", "-4", "rule", "show"):
                return SimpleNamespace(returncode=0,
                                       stdout="1780: from all uidrange 1644-1644 lookup 1780\n")
            if args == ("ip", "-4", "route", "show", "table", "1780"):
                return SimpleNamespace(returncode=0, stdout="blackhole default metric 4096\n")
            if args == ("systemctl", "show", "ssh.service", "-p", "Requires",
                        "--value"):
                return SimpleNamespace(returncode=0,
                                       stdout="basic.target nvl-egress-guard-nvl0557.service\n")
            return SimpleNamespace(returncode=0, stdout="")
        with tempfile.TemporaryDirectory() as tmp:
            result = inspect_recovery(
                manifest(), ssh_unit_name="nvl-egress-guard-nvl0557.service",
                marker_dir=Path(tmp), run=run,
                read_nss=lambda: "hosts: files dns\n",
            )
        self.assertEqual(result.state, RecoveryState.GUARDED_OFFLINE)
        self.assertFalse(result.customer_ready)
        self.assertFalse(any("-A" in args or "-I" in args or "add" in args or
                             "del" in args or "replace" in args
                             for args in calls))


if __name__ == "__main__":
    unittest.main()
