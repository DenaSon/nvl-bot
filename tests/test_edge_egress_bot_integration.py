"""D1-C1: protection gates on actual NVL bot callbacks and shared 6G/6H.

The giant Telegram bot is NOT imported in tests: importing would require
production-only dependencies/credentials. Each named function is extracted with
AST and executed against mocks, ensuring zero network/DB/Telegram mutations.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import sys
import types
import unittest

from edge_egress_lifecycle import (
    LEGACY_FAILOVER_UNSAFE,
    EDGE_PROVISION_UNSAFE,
    UNKNOWN_MODE,
    PROTECTED_SETTING_KEY,
    legacy_failover_gate,
    legacy_new_edge_gate,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_FILE = ROOT / "bot_final_v49-2.py"


def source_tree():
    return ast.parse(BOT_FILE.read_text(encoding="utf-8"), filename=str(BOT_FILE))


def get_function(name, extra=None):
    matches = [
        node for node in source_tree().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"missing or duplicate bot function: {name}")
    ns = {"asyncio": asyncio, "PROTECTED_SETTING_KEY": PROTECTED_SETTING_KEY,
          "PROTECTED_SETTING_DEFAULT": "0",
          "legacy_failover_gate": legacy_failover_gate,
          "legacy_new_edge_gate": legacy_new_edge_gate,
          "any_protected_bindings": lambda _db: False,
          "db_conn": lambda: None}
    ns.update(extra or {})
    module = ast.Module(body=[matches[0]], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(BOT_FILE), "exec"), ns, ns)
    return ns[name]


class PureLifecycleCompatibilityTests(unittest.TestCase):
    def test_disabled_mode_preserves_legacy_behavior(self):
        for value in (None, "0"):
            self.assertTrue(legacy_failover_gate(value).allowed)
            self.assertTrue(legacy_new_edge_gate(value).allowed)

    def test_protected_mode_rejects_all_legacy_handoffs_and_onboarding(self):
        self.assertEqual(legacy_failover_gate("1").reason, LEGACY_FAILOVER_UNSAFE)
        self.assertEqual(legacy_new_edge_gate("1").reason, EDGE_PROVISION_UNSAFE)
        self.assertFalse(legacy_failover_gate("1").allowed)
        self.assertFalse(legacy_new_edge_gate("1").allowed)

    def test_invalid_mode_fails_closed(self):
        for value in ("true", "off", "", "2", " 0 "):
            with self.subTest(value=value):
                self.assertEqual(legacy_failover_gate(value).reason, UNKNOWN_MODE)
                self.assertFalse(legacy_new_edge_gate(value).allowed)


@unittest.skipIf(sys.version_info < (3, 12), 'NVL bot baseline uses Python 3.12 f-string syntax')
class BotPreflightIntegrationTests(unittest.TestCase):
    def test_protected_manual_and_auto_preflights_return_before_any_network(self):
        calls = []
        def config(key, default):
            calls.append(("setting", key, default))
            return "1"
        def unexpected(*args, **kwargs):
            raise AssertionError("preflight attempted network/DB after protected denial")
        gate = get_function("_safe_manual_failover_preflight", {
            "_db_get_setting": config,
            "_is_current_core_host": unexpected,
            "_db_get_failover_host_meta": unexpected,
        })
        for requires_clear in (False, True):
            outcome = asyncio.run(gate(
                "172.86.94.174", "216.126.229.12",
                require_clear_filter=requires_clear
            ))
            self.assertFalse(outcome["ok"])
            self.assertEqual(outcome["errors"], [LEGACY_FAILOVER_UNSAFE])
            self.assertEqual(outcome["egress_gate"], LEGACY_FAILOVER_UNSAFE)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(x[1] == PROTECTED_SETTING_KEY for x in calls))

    def test_invalid_flag_blocks_without_lookup_of_hosts(self):
        gate = get_function("_safe_manual_failover_preflight", {
            "_db_get_setting": lambda *args: "garbage",
            "_is_current_core_host": lambda *args: self.fail("unexpected host check"),
        })
        result = asyncio.run(gate("source", "target"))
        self.assertEqual(result["errors"], [UNKNOWN_MODE])

    def test_disabled_mode_continues_existing_real_preflight_shape(self):
        async def tcp_ok(*args, **kwargs):
            return True, None
        async def admin_ok(*args, **kwargs):
            return True, None
        call_count = []
        def config(key, default):
            call_count.append(key)
            return "0"
        def target_meta(host):
            return {"active": True, "is_standby": host == "216.126.229.12",
                    "service_port": 2252, "admin_ssh_port": 22}
        ns = {
            "_db_get_setting": config,
            "_is_current_core_host": lambda h: False,
            "_db_get_failover_host_meta": target_meta,
            "_db_get_default_host": lambda: "172.86.94.174",
            "_db_get_failover_accounts": lambda h: ["nvl0557"],
            "_db_count_other_explicit_active_ssh_hosts": lambda h: 0,
            "_get_core_public_ip_cached": lambda: "209.200.246.198",
            "_cf_get_config": lambda: {"dns_current_ip": "172.86.94.174"},
            "_cf_configured": lambda cfg: True,
            "is_transparent_dns_handoff_safe": lambda **kwargs: (True, "OK"),
            "_db_get_host_port_health_map": lambda: {
                "216.126.229.12": {"filter_state": "CLEAR",
                                  "regional_state_updated_at": "today"}
            },
            "evidence_age_seconds": lambda *args: 0,
            "_tcp_health_check": tcp_ok,
            "_check_ssh_reachable": admin_ok,
            "_probe_wireguard_edge_sync": lambda h: {
                "wg_peer_ok": True, "core_path_ok": True
            },
            "EDGE_OBSERVABILITY_PROBE_TIMEOUT_SECONDS": 5,
            "FILTER_STATE_UNKNOWN": "UNKNOWN",
            "FILTER_STATE_CLEAR": "CLEAR",
            "FILTER_STATE_POSSIBLE": "POSSIBLE",
            "FILTER_STATE_LIKELY": "LIKELY",
            "STANDBY_REGIONAL_EVIDENCE_MAX_AGE_SECONDS": 120,
            "normalize_probe_error": lambda x: "OK",
            "datetime": __import__("datetime").datetime,
        }
        gate = get_function("_safe_manual_failover_preflight", ns)
        result = asyncio.run(gate("172.86.94.174", "216.126.229.12"))
        self.assertTrue(result["ok"], result.get("errors"))
        self.assertEqual(result["accounts"], ["nvl0557"])
        self.assertEqual(call_count, [PROTECTED_SETTING_KEY])

    def test_existing_protected_mapping_blocks_6g_even_with_global_mode_off(self):
        fn = get_function("_safe_manual_failover_preflight", {
            "_db_get_setting": lambda *args: "0",
            "any_protected_bindings": lambda _db: True,
            "_is_current_core_host": lambda _: self.fail("unsafe host lookup"),
        })
        result = asyncio.run(fn("172.86.94.174", "216.126.229.12"))
        self.assertEqual(result["errors"], ["EGRESS_PROTECTED_BINDINGS_LEGACY_MUTATION_UNSAFE"])

    def test_6g_engine_keeps_lock_preflight_before_dns_and_accounts(self):
        tree = source_tree()
        fn = next(x for x in tree.body if isinstance(x, ast.AsyncFunctionDef)
                  and x.name == "_safe_manual_failover")
        all_calls = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    all_calls.append((node.lineno, node.func.id))
                elif isinstance(node.func, ast.Attribute):
                    all_calls.append((node.lineno, node.func.attr))
        preflight = min(i for i, name in all_calls if name == "_safe_manual_failover_preflight")
        dns = min(i for i, name in all_calls if name == "_cf_switch_public_domain")
        rebuild = min(i for i, name in all_calls if name == "_run_phase6g_rebuild_helper")
        # The lock function is passed to asyncio.to_thread, not called directly.
        lock = min(node.lineno for node in ast.walk(fn)
                   if isinstance(node, ast.Name) and node.id == "_db_acquire_failover_lock")
        self.assertLess(lock, preflight)
        self.assertLess(preflight, dns)
        self.assertLess(preflight, rebuild)


@unittest.skipIf(sys.version_info < (3, 12), 'NVL bot baseline uses Python 3.12 f-string syntax')
class OnboardingAndDnsIntegrationTests(unittest.TestCase):
    def test_protected_onboarding_does_not_launch_remote_installer(self):
        sent = []
        async def send_message(chat_id, text, **kwargs):
            sent.append((chat_id, text))
        app = types.SimpleNamespace(bot=types.SimpleNamespace(send_message=send_message))
        def unexpected(*args, **kwargs):
            raise AssertionError("Remote Edge provisioning unexpectedly started")
        onboard = get_function("_provision_new_edge", {
            "_db_get_setting": lambda *args: "1",
            "_provision_new_edge_sync": unexpected,
            "esc": lambda s: s,
        })
        outcome = asyncio.run(onboard(
            "172.86.94.174", "SECRET", 2252, "test", 123, app
        ))
        self.assertEqual(outcome, (False, None, None))
        self.assertEqual(len(sent), 1)
        self.assertIn(EDGE_PROVISION_UNSAFE, sent[0][1])

    def test_protected_dns_mutation_returns_denial_without_cf_read(self):
        fn = get_function("_cf_update_dns_record_sync", {
            "_db_get_setting": lambda *args: "1",
            "_cf_get_config": lambda: self.fail("CF read after protected denial"),
        })
        ok, reason = fn("209.200.246.198")
        self.assertFalse(ok)
        self.assertEqual(reason, LEGACY_FAILOVER_UNSAFE)

    def test_disabled_dns_keeps_existing_missing_config_response(self):
        fn = get_function("_cf_update_dns_record_sync", {
            "_db_get_setting": lambda *args: "0",
            "_cf_get_config": lambda: {"token": "", "zone": ""},
        })
        ok, reason = fn("172.86.94.174")
        self.assertFalse(ok)
        self.assertIn("Cloudflare", reason)

    def test_protected_mapping_blocks_legacy_dns_without_global_mode(self):
        fn = get_function("_cf_update_dns_record_sync", {
            "_db_get_setting": lambda *args: "0",
            "any_protected_bindings": lambda _db: True,
            "LEGACY_PROTECTED_BINDINGS_BLOCKED":
                "EGRESS_PROTECTED_BINDINGS_LEGACY_MUTATION_UNSAFE",
            "_cf_get_config": lambda: self.fail("CF consulted after protected fence"),
        })
        self.assertEqual(fn("209.200.246.198"),
                         (False, "EGRESS_PROTECTED_BINDINGS_LEGACY_MUTATION_UNSAFE"))

    def test_protected_mapping_blocks_edge_remote_provision(self):
        sent = []
        async def send_message(chat_id, text, **kwargs):
            sent.append((chat_id, text))
        app = types.SimpleNamespace(bot=types.SimpleNamespace(send_message=send_message))
        fn = get_function("_provision_new_edge", {
            "_db_get_setting": lambda *args: "0",
            "any_protected_bindings": lambda _db: True,
            "_provision_new_edge_sync": lambda *args: self.fail("remote installer started"),
        })
        self.assertEqual(asyncio.run(fn("172.86.94.174", "SECRET",
                                        2252, "test", 123, app)),
                         (False, None, None))
        self.assertEqual(len(sent), 1)

    def test_setting_defaults_to_off_and_no_protected_mode_ui_toggle(self):
        src = BOT_FILE.read_text(encoding="utf-8")
        self.assertIn("('edge_egress_protected_mode', '0')", src)
        self.assertNotIn("callback_data='edge_egress_enable'", src)
        self.assertNotIn('callback_data="edge_egress_enable"', src)


if __name__ == "__main__":
    unittest.main()
