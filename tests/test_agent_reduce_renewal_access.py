"""Regression contract: agents may reduce time only on their own subscriptions.

The production bot is not imported, because it performs runtime initialization.
"""
import ast
from pathlib import Path
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class AgentReduceRenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_ssh_reduce_allows_agent_but_checks_account_ownership(self):
        region = self.source.split('elif d.startswith("uact_rd_")', 1)[1].split(
            'elif d.startswith("rdd_custom_")', 1
        )[0]
        self.assertIn("role in ('admin', 'agent')", region.split("\n", 1)[0])
        self.assertIn("_can_manage_user(role, ag_id, cur[5])", region)
        self.assertIn("cur[7] == 'tls'", region)

    def test_v2_unlimited_reduce_visible_to_owning_agent(self):
        detail = self.source.split("async def _show_v2ray_user_detail(", 1)[1].split(
            "# ==========================================", 1
        )[0]
        self.assertIn("if not is_vol:", detail)
        self.assertIn("if role in ('admin', 'agent'):", detail)
        self.assertIn('callback_data=f"v2act_rd_{username}"', detail)

    def test_v2_reduce_entry_and_commit_recheck_ownership(self):
        handler = self.source.split("async def callback_handler(", 1)[1]
        entry = handler.split('elif d.startswith("v2act_rd_")', 1)[1].split(
            'elif d.startswith("v2rnd_custom_")', 1
        )[0]
        self.assertIn("role in ('admin', 'agent')", entry.split("\n", 1)[0])
        self.assertIn("_can_manage_user(role, ag_id, cur[5])", entry)
        commit = handler.split('elif d in ("v2rnyes", "v2rn_emergency_yes"):', 1)[1].split(
            'elif ', 1
        )[0]
        self.assertIn("_can_manage_user(role, ag_id, cur[5])", commit)

    def test_v2_time_callbacks_reject_volumetric_services(self):
        handler = self.source.split("async def callback_handler(", 1)[1]
        for marker in ('elif d.startswith("v2act_rn_"):', 'elif d.startswith("v2act_rd_")',
                       'elif d in ("v2rnyes", "v2rn_emergency_yes"):'):
            with self.subTest(marker=marker):
                region = handler.split(marker, 1)[1].split("elif ", 1)[0]
                self.assertIn("_db_get_user_service_type", region)
                self.assertIn("_can_manage_user(role, ag_id, cur[5])", region)

    def test_both_reduce_paths_keep_no_past_expiry_and_refund(self):
        self.assertIn("if mode == 'reduce' and new_exp_dt <= datetime.now():", self.source)
        self.assertIn("nvl_daily_business.refund_purchase(conn, ag_id, cost)", self.source)


if __name__ == "__main__":
    unittest.main()
