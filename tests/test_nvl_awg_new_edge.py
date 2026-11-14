"""Hermetic AWG 3.1 new-Edge planning and installer contract tests."""
import pathlib
import subprocess
import unittest

from nvl_awg_new_edge import (
    AWGPlanHold, AWGCoreProfile, allocated_edge_ip, render_new_edge_conf,
    expected_peer_block,
)
from nvl_awg_core_peer import plan_core_peer, verify_core_peer_plan

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY_CORE = "A" * 43 + "="
KEY_EDGE = "B" * 43 + "="
KEY_PRIVATE = "C" * 43 + "="
HPK = "D" * 43 + "="
CORE_IP = "10.231.55.1"
EDGE_IP = "10.231.55.2"
HOST = "8.8.4.4"  # test-only public IPv4, no network calls

CORE_CONF = f"""\
[Interface]
Address = {CORE_IP}/32
ListenPort = 42372
MTU = 1320
PrivateKey = {KEY_PRIVATE}
Jc = 3
Jmin = 64
Jmax = 128
S1 = 24
S2 = 20
S3 = 16
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {HPK}
ContentPaddingAddition = 16-32

[Peer]
# original test peer
PublicKey = {KEY_CORE}
AllowedIPs = {EDGE_IP}/32
"""


class NewEdgePlanTests(unittest.TestCase):
    def test_profile_and_address_allocated_away_from_live_peer(self):
        profile = AWGCoreProfile.parse(CORE_CONF)
        self.assertEqual(profile.core_tunnel_ip, CORE_IP)
        self.assertEqual(profile.core_listen_port, 42372)
        live = KEY_CORE + f" {EDGE_IP}/32\n"
        self.assertEqual(
            allocated_edge_ip(CORE_CONF, core_tunnel_ip=CORE_IP,
                              live_allowed_ips=live), "10.231.55.3",
        )
        rendered = render_new_edge_conf(
            profile, edge_private_key=KEY_PRIVATE, core_public_key=KEY_CORE,
            core_public_ip="8.8.8.8", edge_tunnel_ip="10.231.55.3",
            edge_port=42371,
        )
        self.assertIn("Address = 10.231.55.3/32", rendered)
        self.assertIn("AllowedIPs = 10.231.55.1/32", rendered)
        self.assertIn("Endpoint = 8.8.8.8:42372", rendered)
        self.assertIn("PersistentKeepalive = 25", rendered)
        self.assertIn("HeaderProtectionKey = " + HPK, rendered)
        self.assertNotIn("10.77.0.1", rendered)

    def test_missing_or_mismatched_obfuscation_holds(self):
        for config in (
            CORE_CONF.replace("HeaderProtectionKey =", "HeaderKey ="),
            CORE_CONF.replace("S4 = 12", "S4 = 8"),
            CORE_CONF.replace("H2 = 2", "H2 = 99"),
            CORE_CONF.replace("MTU = 1320", "MTU = 9000"),
            CORE_CONF.replace("S1 = 24", "S1 = 24\nS1 = 25"),
        ):
            with self.subTest(config=config[:90]):
                with self.assertRaises(AWGPlanHold):
                    AWGCoreProfile.parse(config)

    def test_registered_and_live_addresses_cannot_collide(self):
        self.assertEqual(
            allocated_edge_ip(CORE_CONF, core_tunnel_ip=CORE_IP,
                              registered_ips=("10.231.55.3",),
                              live_allowed_ips=KEY_CORE + f" {EDGE_IP}/32"),
            "10.231.55.4",
        )
        self.assertEqual(
            allocated_edge_ip(CORE_CONF, core_tunnel_ip=CORE_IP,
                              live_allowed_ips=KEY_CORE + " 10.231.55.0/28"),
            "10.231.55.16",
        )

    def test_new_core_peer_plan_never_replaces_existing_peer(self):
        live = KEY_CORE + f" {EDGE_IP}/32"
        planned = plan_core_peer(CORE_CONF, live,
                                 edge_host=HOST, edge_udp_port=42371,
                                 edge_public_key=KEY_EDGE)
        self.assertEqual(planned.edge_tunnel_ip, "10.231.55.3")
        self.assertIn(KEY_CORE, planned.after_conf)
        self.assertIn(KEY_EDGE, planned.after_conf)
        self.assertIn("Endpoint = " + HOST + ":42371", planned.after_conf)
        self.assertEqual(planned.apply_argv[:3], ("awg", "set", "awg0"))
        verify_core_peer_plan(planned, current_conf=CORE_CONF,
                              current_live_allowed=live)
        with self.assertRaisesRegex(AWGPlanHold, "CONFIG_CHANGED"):
            verify_core_peer_plan(planned, current_conf=CORE_CONF + "\n",
                                  current_live_allowed=live)

    def test_duplicate_peer_not_added(self):
        with self.assertRaisesRegex(AWGPlanHold, "ALREADY_CONFIGURED"):
            plan_core_peer(CORE_CONF, KEY_CORE + f" {EDGE_IP}/32",
                           edge_host=HOST, edge_udp_port=42371,
                           edge_public_key=KEY_CORE)

    def test_shell_is_not_core_installer_or_existing_tunnel_reset(self):
        text = (ROOT / "setup_edge_awg_relay.sh").read_text()
        completed = subprocess.run(
            ["bash", "-n"], input=text, text=True,
            capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for dangerous in (
            "systemctl restart awg-quick@awg0", "systemctl restart wg-quick@wg0",
            "iptables -F", "iptables -t nat -F", "wg syncconf wg0",
        ):
            self.assertNotIn(dangerous, text)
        for guard in ("EXISTING_AWG_CONFIG", "EXISTING_AWG_LINK",
                      "EXISTING_WG_LINK", "AWG_31_MODULE_REQUIRED"):
            self.assertIn(guard, text)
        self.assertNotIn("149.104.110.", text)


if __name__ == "__main__":
    unittest.main()
