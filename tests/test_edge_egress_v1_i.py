"""I: short offline tests for Edge Egress stage/ingress identity.

No SSH, wg0, firewall, database or local root-owned files are modified.
"""
import base64
import json
import unittest
from unittest.mock import patch

from edge_egress_v1_ingress import IngressPeer
from edge_egress_v1_onboarding import (
    OnboardHold, spec_for_new_edge, assert_live_ingress, planned_peer,
    onboard_after_ingress,
)

KEY1 = base64.b64encode(b"a" * 32).decode()
KEY2 = base64.b64encode(b"b" * 32).decode()


class NewEdgeI(unittest.TestCase):
    def test_deterministic_slot_for_new_wg0_edge(self):
        spec = spec_for_new_edge(
            edge_ip="144.172.84.82", core_ip="209.200.246.198",
            ingress_ip="10.77.0.9",
        )
        self.assertEqual(spec.edge_id, "e9")
        self.assertEqual(spec.tunnel_network, "10.79.9.0/30")
        self.assertEqual(spec.veth_network, "10.80.9.0/30")
        self.assertEqual(spec.edge_listen_port, 52009)
        self.assertEqual(spec.route_table, 20009)
        self.assertEqual(spec.iface, "wg-nvl-e9")
        self.assertNotIn("wg0", spec.iface)
        second = spec_for_new_edge(
            edge_ip="144.172.84.76", core_ip="209.200.246.198",
            ingress_ip="10.77.0.8",
        )
        self.assertNotEqual(spec.tunnel_network, second.tunnel_network)
        self.assertNotEqual(spec.route_table, second.route_table)

    def test_reject_unsafe_or_ambiguous_wg0_allocation(self):
        for src in ("10.77.0.1", "10.77.0.255", "10.77.1.8",
                    "192.168.1.2", "invalid", "10.77.0.08"):
            with self.subTest(src=src), self.assertRaises((OnboardHold, ValueError)):
                spec_for_new_edge(edge_ip="144.172.84.82",
                                  core_ip="209.200.246.198",
                                  ingress_ip=src)
        with self.assertRaises(ValueError):
            spec_for_new_edge(edge_ip="10.0.0.2",
                              core_ip="209.200.246.198",
                              ingress_ip="10.77.0.8")

    def test_live_wg0_public_key_and_exact_source(self):
        peer = planned_peer("10.77.0.8", "144.172.84.76", KEY1)
        raw = KEY1 + "\t10.77.0.8/32\n" + KEY2 + "\t10.77.0.6/32\n"
        self.assertEqual(peer.edge_id, "e8")
        assert_live_ingress(peer, raw)
        for bad in (KEY2 + "\t10.77.0.8/32\n",
                    KEY1 + "\t10.77.0.7/32\n",
                    KEY1 + "\t10.77.0.8/32\n"
                    + KEY2 + "\t10.77.0.0/24\n", ""):
            with self.subTest(bad=bad), self.assertRaises(OnboardHold):
                assert_live_ingress(peer, bad)

    def test_registry_entry_rejects_wrong_peer_key(self):
        with self.assertRaises(ValueError):
            planned_peer("10.77.0.8", "144.172.84.76", "invalid")
        with self.assertRaises(ValueError):
            planned_peer("10.77.0.1", "144.172.84.76", KEY1)

    def test_preflight_failure_never_connects_to_remote_or_writes_stage(self):
        with patch("edge_egress_v1_onboarding._checked_ingress_registry",
                   return_value=[]), patch(
            "edge_egress_v1_onboarding.subprocess.run"
        ) as run, patch(
            "edge_egress_v1_onboarding.preflight", return_value={
                "ok": False, "issues": ["ROUTE_TABLE_OCCUPIED"]
            }
        ), patch("edge_egress_v1_onboarding._make_dir") as maker:
            run.return_value.stdout = KEY1 + "\t10.77.0.8/32\n"
            with self.assertRaisesRegex(OnboardHold,"CORE_STAGE_PREFLIGHT_FAILED"):
                onboard_after_ingress(
                    edge_ip="144.172.84.76",core_ip="209.200.246.198",
                    ingress_ip="10.77.0.8",public_key=KEY1,
                    ssh_host_key=None,ssh_port=22,root_password=None
                )
            maker.assert_not_called()

    def test_readiness_never_promoted_by_stage_only(self):
        # This module deliberately must not import or call F3 READY promotion,
        # change host_pool/default, or install any UID route.
        from pathlib import Path
        module = Path(__import__(
            "edge_egress_v1_onboarding"
        ).__file__).read_text()
        self.assertIn("STAGED_NOT_READY", module)
        self.assertNotIn("record_lab_verification(", module)
        self.assertNotIn("mark_ready(", module)
        self.assertNotIn("ip rule add", module)


if __name__ == "__main__":
    unittest.main()
