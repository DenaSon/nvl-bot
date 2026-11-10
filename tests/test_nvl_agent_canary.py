"""Canary rollout contract for NVL reseller lifecycle screens (no bot import)."""
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import patch


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class AgentLifecycleCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ast.parse(BOT.read_text(encoding="utf-8"))
        functions = [node for node in source.body
                     if isinstance(node, ast.FunctionDef)
                     and node.name == "_agent_lifecycle_access"]
        if len(functions) != 1:
            raise AssertionError("missing central canary gate")
        cls.fn_globals = {"os": os, "NVL_AGENT_LIFECYCLE_R1_ENABLED": True}
        exec(compile(ast.Module(body=functions, type_ignores=[]),
                     str(BOT), "exec"), cls.fn_globals)
        cls.allowed = staticmethod(cls.fn_globals["_agent_lifecycle_access"])

    def test_disabled_flag_denies_everyone(self):
        self.fn_globals["NVL_AGENT_LIFECYCLE_R1_ENABLED"] = False
        try:
            with patch.dict(os.environ, {"NVL_AGENT_LIFECYCLE_ALLOWED_AGENT_IDS": ""}):
                self.assertFalse(self.allowed(1))
        finally:
            self.fn_globals["NVL_AGENT_LIFECYCLE_R1_ENABLED"] = True

    def test_canary_only_allows_selected_resellers(self):
        with patch.dict(os.environ, {"NVL_AGENT_LIFECYCLE_ALLOWED_AGENT_IDS": "3,7"}):
            self.assertTrue(self.allowed(3))
            self.assertTrue(self.allowed(7))
            self.assertFalse(self.allowed(6))
            self.assertFalse(self.allowed(0))

    def test_malformed_canary_configuration_fails_closed(self):
        with patch.dict(os.environ, {"NVL_AGENT_LIFECYCLE_ALLOWED_AGENT_IDS": "3,bad"}):
            self.assertFalse(self.allowed(3))

    def test_phase2_requires_independent_switch(self):
        with patch.dict(os.environ, {"NVL_AGENT_LIFECYCLE_ALLOWED_AGENT_IDS": "3",
                                     "NVL_AGENT_LIFECYCLE_R2_ENABLED": "0"}):
            self.assertFalse(self.allowed(3, r2=True))
        with patch.dict(os.environ, {"NVL_AGENT_LIFECYCLE_ALLOWED_AGENT_IDS": "3",
                                     "NVL_AGENT_LIFECYCLE_R2_ENABLED": "1"}):
            self.assertTrue(self.allowed(3, r2=True))


if __name__ == "__main__":
    unittest.main()
