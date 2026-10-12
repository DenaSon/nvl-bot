"""Structural integration tests for the existing, not duplicated, bot callbacks.

This test reads source only: never imports/starts the Telegram bot, creates
systemd services, changes SQLite, touches firewall or calls Cloudflare.
"""
from pathlib import Path
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase2CallbackContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")
        begin = cls.source.index('    elif d == "hpeg_status":')
        end = cls.source.index('    elif d == "flt_radar"', begin)
        cls.handler = cls.source[begin:end]

    def test_existing_single_dashboard_is_entry_point(self):
        self.assertEqual(self.source.count('    elif d == "hpeg_status":'), 1)
        self.assertIn('await asyncio.to_thread(read_egress_dashboard, db_conn)',
                      self.handler)
        self.assertIn('egress_dashboard_html(board)', self.handler)
        self.assertIn('callback_data="hp_addedge"', self.handler)
        self.assertIn('callback_data="hpeg_status"', self.handler)

    def test_all_phase2_inspection_callbacks_are_admin_only(self):
        self.assertIn('d.startswith("hpeg_edge_")', self.handler)
        self.assertIn('d.startswith("hpeg_health_")', self.handler)
        self.assertIn('d.startswith("hpeg_actions_")', self.handler)
        self.assertIn('d.startswith("hpeg_probe_")', self.handler)
        self.assertGreaterEqual(
            self.handler.count("if role != 'admin':"), 3
        )
        self.assertIn('edge_id_checked(edge_id)', self.handler)

    def test_no_activation_or_mutation_in_phase2_handler(self):
        forbidden = (
            "_db_set_default_host", "_cf_update_dns_record_sync",
            "_db_update_setting", "iptables ", "wg syncconf",
            "systemctl restart", "edge_egress_handoff",
            "onboard_after_ingress", "ensure(", "down.sh",
            "assign_user", "mark_ready", "edge_egress_v1_onboard_enabled",
        )
        for bad in forbidden:
            with self.subTest(forbidden=bad):
                self.assertNotIn(bad, self.handler)
        self.assertIn("egress_actions_html(card, result)", self.handler)
        self.assertIn("inspect_egress_transport, card", self.handler)


if __name__ == "__main__":
    unittest.main()
