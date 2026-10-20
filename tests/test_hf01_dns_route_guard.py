"""HF01 regression: disabled unrelated Edge must not rewrite customer DNS."""
import ast
import json
import pathlib
import types
import unittest
import urllib.request
from dns_route_guard import DNSDecision, RelayCandidate, plan_host_retirement_dns

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT = ROOT / "bot_final_v49-2.py"


class RouteDecisionTests(unittest.TestCase):
    def test_unrelated_host_never_switches(self):
        self.assertEqual(plan_host_retirement_dns("104.194.153.100", "172.86.92.41", "91.107.170.239", ()).action, "UNCHANGED")

    def test_core_first_in_database_must_not_be_selected(self):
        options = [
            RelayCandidate("91.107.170.239", True, True),
            RelayCandidate("153.75.93.185", False, True),
            RelayCandidate("172.86.92.41", False, False),
        ]
        d = plan_host_retirement_dns("172.86.92.41", "172.86.92.41", "91.107.170.239", options)
        self.assertEqual((d.action, d.target), ("SWITCH", "153.75.93.185"))

    def test_unverified_relay_does_not_trigger_switch(self):
        d = plan_host_retirement_dns("172.86.92.41", "172.86.92.41", "91.107.170.239", [
            RelayCandidate("153.75.93.185", True, False)
        ])
        self.assertEqual(d.action, "BLOCKED")

    def test_standby_is_not_a_live_candidate(self):
        d = plan_host_retirement_dns("172.86.92.41", "172.86.92.41", "91.107.170.239", [
            RelayCandidate("153.75.93.185", True, True, True)
        ])
        self.assertEqual(d.action, "BLOCKED")

    def test_missing_core_identity_blocks(self):
        d = plan_host_retirement_dns("172.86.92.41", "172.86.92.41", "", [])
        self.assertEqual(d.action, "BLOCKED")

    def test_default_relay_preferred_over_ip_sort(self):
        d = plan_host_retirement_dns("172.86.92.41", "172.86.92.41", "91.107.170.239", [
            RelayCandidate("100.1.1.1", False, True),
            RelayCandidate("153.75.93.185", True, True),
        ])
        self.assertEqual(d.target, "153.75.93.185")

    def test_core_host_cannot_be_retired_implicitly(self):
        d = plan_host_retirement_dns("91.107.170.239", "91.107.170.239", "91.107.170.239", [])
        self.assertEqual(d.action, "BLOCKED")


class BotWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def region(self, before, after):
        x = self.source.index(before)
        return self.source[x:self.source.index(after, x)]

    def test_guard_precedes_automatic_host_mutation(self):
        sec = self.region("async def _host_health_tick(app):", "async def _host_health_loop(app):")
        self.assertLess(sec.index("decision = await _hf01_plan_host_deactivation(host)"),
                        sec.index("_db_set_host_active,"))
        self.assertNotIn("remaining_active[0]", sec)

    def test_guard_precedes_manual_host_mutation(self):
        sec = self.region('elif d.startswith("hpblk_")', 'elif d.startswith("hpact_")')
        self.assertLess(sec.index("decision = await _hf01_plan_host_deactivation(host)"),
                        sec.index('_db_set_host_active,'))
        self.assertNotIn("remaining_active[0]", sec)

    def test_cloudflare_reader_uses_get_and_validates_records(self):
        reader = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "_cf_read_public_domain_ip_sync")
        source = ast.get_source_segment(self.source, reader)
        self.assertIn('method="GET"', source)
        self.assertIn("PUBLIC_A_RECORD_AMBIGUOUS", source)
        self.assertIn("PUBLIC_A_RECORD_INVALID", source)

    def test_actual_reader_accepts_exact_record(self):
        node = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == "_cf_read_public_domain_ip_sync")
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self):
                return json.dumps({"success": True, "result": [
                    {"type":"A","name":"n1.nvlsup.com","content":"172.86.92.41"}]}).encode()
        request = types.SimpleNamespace(Request=urllib.request.Request, urlopen=lambda *a, **k:Response())
        env = {"_cf_get_config":lambda:{"zone":"zone","public_domain":"n1.nvlsup.com","token":"t","email":""},
               "_cf_configured":lambda cfg:True, "urllib":types.SimpleNamespace(request=request), "json":json}
        exec(compile(ast.Module(body=[node],type_ignores=[]), "<hf01>", "exec"), env)
        self.assertEqual(env["_cf_read_public_domain_ip_sync"](), ("172.86.92.41", None))
