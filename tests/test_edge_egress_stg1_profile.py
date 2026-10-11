"""D1-D2B stg1 profile is stage-only and distinct from prior fra1 and wg0."""
import json
from pathlib import Path
import unittest

from ops.edge_egress_provision import EgressSpec, plan, core_up_script, edge_up_script

PROFILE = Path(__file__).resolve().parents[1] / "ops/examples/edge_egress_stg1.json"


class Stg1ProfileTests(unittest.TestCase):
    def test_staging_uses_reviewed_core_and_standby_and_new_resources(self):
        spec = EgressSpec.from_json(json.loads(PROFILE.read_text()))
        self.assertEqual(spec.edge_id, "stg1")
        self.assertEqual(spec.core_public_ipv4, "209.200.246.198")
        self.assertEqual(spec.edge_public_ipv4, "216.126.229.12")
        self.assertEqual(spec.edge_uplink, "eth0")
        self.assertEqual(spec.tunnel_network, "10.78.110.0/30")
        self.assertEqual(spec.veth_network, "10.78.111.0/30")
        self.assertEqual(spec.route_table, 1790)
        self.assertEqual(spec.edge_listen_port, 51842)
        self.assertEqual(spec.namespace, "nvl-egress-stg1")
        self.assertEqual(spec.iface, "wg-nvl-stg1")
        self.assertEqual(spec.veth_root, "vnh-stg1")
        self.assertEqual(spec.veth_ns, "vnn-stg1")
        self.assertNotEqual(spec.namespace, "nvl-egress-fra1")
        for role in ("core", "edge"):
            p = plan(spec, role)
            self.assertEqual(p["mode"], "STAGE_ONLY_NO_NETWORK_MUTATION")
            self.assertFalse(p["user_routes_changed"])
            self.assertFalse(p["wg0_changed"])

    def test_generated_scripts_scope_to_stg1_no_root_default_or_legacy_wg0(self):
        spec=EgressSpec.from_json(json.loads(PROFILE.read_text()))
        for text in (core_up_script(spec, Path("/root/nvl-egress-staging/stg1-core")),
                     edge_up_script(spec, Path("/root/nvl-egress-staging/stg1-edge"))):
            self.assertIn("wg-nvl-stg1", text)
            self.assertNotIn("wg0", text)
            self.assertNotIn("nvlbot", text)
            self.assertNotIn("ip rule add", text)
            self.assertNotIn("ip route replace default", text)
            self.assertNotIn("systemctl restart", text)
            self.assertNotIn("ssh.service", text)

if __name__ == "__main__":
    unittest.main()
