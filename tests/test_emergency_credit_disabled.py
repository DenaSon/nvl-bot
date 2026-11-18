"""Emergency credit is OFF, without changing historical debt repayment."""
import ast
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text(
    encoding="utf-8"
)
TREE = ast.parse(SOURCE)


def standalone_function(name, globals_dict):
    node = next(n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    scope = dict(globals_dict)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<nvl-isolated>", "exec"), scope)
    return scope[name]


class EmergencyCreditOffTests(unittest.TestCase):
    def test_default_deny_and_all_previous_debt_preserved(self):
        self.assertIn("EMERGENCY_CREDIT_ENABLED = False", SOURCE)
        self.assertIn("def _apply_emergency_repayment(", SOURCE)
        self.assertIn("def _db_agent_register_emergency_use(", SOURCE)

    def test_no_new_emergency_credit_offer(self):
        check = standalone_function("_check_emergency_option", {
            "EMERGENCY_CREDIT_ENABLED": False,
            "EMERGENCY_CREDIT_LIMIT": 1000000,
            "EMERGENCY_MAX_CONSECUTIVE_REQUESTS": 2,
        })
        agent = [None] * 14
        agent[2], agent[12], agent[13] = 100, 0, 0
        eligible, *_ = check(agent, 200)
        self.assertFalse(eligible)

    def test_stale_approval_is_rejected_for_callback_and_text(self):
        callback = SOURCE.split("async def callback_handler(", 1)[1].split(
            "# Finance V1", 1
        )[0]
        text = SOURCE.split("async def text_handler(", 1)[1].split(
            "# Native manual Edge intake", 1
        )[0]
        self.assertIn("context.user_data.pop('emergency_approved', None)", callback)
        self.assertIn("context.user_data.pop('emergency_approved', None)", text)
        for action in (
            'uinc_emergency_yes', 'buy_emergency_yes', 'v2rn_emergency_yes',
            'v2addvol_emergency_yes', 'v2_vol_buy_emergency_yes',
            'v2_buy_emergency_yes', 'rnyes_emergency',
        ):
            self.assertIn(repr(action), callback)

    def test_emergency_counter_cannot_increase(self):
        ns = {
            "EMERGENCY_CREDIT_ENABLED": False,
            "db_conn": lambda: self.fail("DB should not be touched"),
        }
        register = standalone_function("_db_agent_register_emergency_use", ns)
        with self.assertRaisesRegex(RuntimeError, "EMERGENCY_CREDIT_DISABLED"):
            register(1, 100)

    def test_old_emergency_eligibility_short_circuits(self):
        can_use = standalone_function("_agent_can_use_emergency_credit", {
            "EMERGENCY_CREDIT_ENABLED": False,
            "EMERGENCY_MIN_ACTIVE_ACCOUNTS": 50,
            "_get_active_account_count_by_agent": lambda _: self.fail("no DB scan"),
        })
        self.assertEqual(can_use(1), (False, 0))


if __name__ == "__main__":
    unittest.main()
