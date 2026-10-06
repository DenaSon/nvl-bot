import copy
import pathlib
import unittest
from unittest.mock import AsyncMock

import marzban_admin


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


def _inbounds(*tags):
    protocol_by_tag = {
        "Shadowsocks TCP": "shadowsocks",
        "VLESS TCP REALITY": "vless",
        "VLESS TCP REALITY DIRECT": "vless",
        "Trojan WS": "trojan",
        "VMess WS": "vmess",
    }
    payload = {}
    for tag in tags:
        protocol = protocol_by_tag[tag]
        payload.setdefault(protocol, []).append({
            "tag": tag,
            "protocol": protocol,
        })
    return payload


class V123B2RepairPlanningTests(unittest.TestCase):
    def setUp(self):
        self.node = {
            "id": 1,
            "name": "Pingo✅",
            "address": "172.86.72.203",
            "port": 62050,
            "api_port": 62051,
            "usage_coefficient": 1.0,
        }
        self.public = "argus.nvlsup.xyz"
        self.generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public,
        )

    def _legacy(self, label):
        host = copy.deepcopy(self.generated)
        host["remark"] = (
            f"{label} ({{USERNAME}}) [{{PROTOCOL}} - {{TRANSPORT}}]"
        )
        return host

    def test_real_argus_legacy_shape_is_repairable_and_manual_hosts_are_preserved(self):
        manual_ss = copy.deepcopy(self.generated)
        manual_ss["remark"] = "Manual SS"
        manual_ss["address"] = "manual.example"

        manual_extra = copy.deepcopy(self.generated)
        manual_extra["remark"] = "Manual VMess"
        manual_extra["address"] = "manual-vmess.example"

        hosts = {
            "Shadowsocks TCP": [manual_ss, self._legacy("arGuS")],
            "VLESS TCP REALITY": [],
            "VLESS TCP REALITY DIRECT": [self._legacy("Pingo")],
            "Trojan WS": [self._legacy("ArGuS")],
            "VMess WS": [manual_extra],
        }

        plan = marzban_admin.plan_node_public_host_repair(
            hosts,
            self.node,
            public_address=self.public,
        )

        self.assertTrue(plan["repairable"])
        self.assertEqual(plan["added_tags"], ["VLESS TCP REALITY"])
        self.assertCountEqual(
            plan["normalized_tags"],
            ["Shadowsocks TCP", "VLESS TCP REALITY DIRECT", "Trojan WS"],
        )
        self.assertCountEqual(
            plan["claimed_legacy_tags"],
            ["Shadowsocks TCP", "VLESS TCP REALITY DIRECT", "Trojan WS"],
        )
        self.assertEqual(plan["removed_unexpected_tags"], {})
        self.assertCountEqual(
            plan["changed_tags"],
            [
                "Shadowsocks TCP",
                "VLESS TCP REALITY",
                "VLESS TCP REALITY DIRECT",
                "Trojan WS",
            ],
        )

        repaired = copy.deepcopy(hosts)
        for tag, desired in plan["desired_by_tag"].items():
            repaired[tag] = copy.deepcopy(desired)

        self.assertIn(manual_ss, repaired["Shadowsocks TCP"])
        self.assertIn(manual_extra, repaired["VMess WS"])
        self.assertEqual(repaired["VLESS TCP REALITY"], [self.generated])
        self.assertEqual(
            repaired["VLESS TCP REALITY DIRECT"],
            [self.generated],
        )

        verified = marzban_admin.inspect_node_public_host_profile(
            repaired,
            self.node,
            public_address=self.public,
        )
        self.assertTrue(verified["adoptable"])

    def test_manual_host_on_requested_endpoint_is_ambiguous_and_fails_closed(self):
        manual = copy.deepcopy(self.generated)
        manual["remark"] = "My custom endpoint"

        hosts = {
            "Shadowsocks TCP": [manual],
            "VLESS TCP REALITY": [],
            "Trojan WS": [],
        }
        plan = marzban_admin.plan_node_public_host_repair(
            hosts,
            self.node,
            public_address=self.public,
        )

        self.assertFalse(plan["repairable"])
        self.assertIn("Shadowsocks TCP", plan["ambiguous_tags"])
        self.assertNotIn("Shadowsocks TCP", plan["desired_by_tag"])

    def test_current_node_generated_remark_is_strong_ownership_even_on_wrong_address(self):
        drifted = copy.deepcopy(self.generated)
        drifted["address"] = "old.example"

        hosts = {
            "Shadowsocks TCP": [drifted],
            "VLESS TCP REALITY": [copy.deepcopy(self.generated)],
            "Trojan WS": [copy.deepcopy(self.generated)],
        }
        plan = marzban_admin.plan_node_public_host_repair(
            hosts,
            self.node,
            public_address=self.public,
        )

        self.assertTrue(plan["repairable"])
        self.assertIn("Shadowsocks TCP", plan["normalized_tags"])
        self.assertEqual(
            plan["desired_by_tag"]["Shadowsocks TCP"],
            [self.generated],
        )

    def test_generated_host_outside_managed_profile_is_removed_but_manual_is_preserved(self):
        manual = copy.deepcopy(self.generated)
        manual["remark"] = "Manual VMess"
        manual["address"] = "manual-vmess.example"

        hosts = {
            tag: [copy.deepcopy(self.generated)]
            for tag in marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        }
        hosts["VMess WS"] = [manual, self._legacy("Old Node")]

        plan = marzban_admin.plan_node_public_host_repair(
            hosts,
            self.node,
            public_address=self.public,
        )

        self.assertTrue(plan["repairable"])
        self.assertEqual(plan["removed_unexpected_tags"], {"VMess WS": 1})
        self.assertEqual(plan["desired_by_tag"]["VMess WS"], [manual])

    def test_duplicate_owned_hosts_are_deduplicated(self):
        hosts = {
            tag: [copy.deepcopy(self.generated)]
            for tag in marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        }
        hosts["Trojan WS"].append(copy.deepcopy(self.generated))

        plan = marzban_admin.plan_node_public_host_repair(
            hosts,
            self.node,
            public_address=self.public,
        )

        self.assertTrue(plan["repairable"])
        self.assertEqual(plan["deduplicated_tags"], {"Trojan WS": 1})
        self.assertEqual(
            plan["desired_by_tag"]["Trojan WS"],
            [self.generated],
        )


class V123B2RepairServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.node = {
            "id": 1,
            "name": "Pingo✅",
            "address": "172.86.72.203",
            "port": 62050,
            "api_port": 62051,
            "usage_coefficient": 1.0,
        }
        self.public = "argus.nvlsup.xyz"
        self.generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public,
        )
        self.inbounds = _inbounds(
            *marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS,
            "VMess WS",
        )

    def _legacy(self, label):
        host = copy.deepcopy(self.generated)
        host["remark"] = (
            f"{label} ({{USERNAME}}) [{{PROTOCOL}} - {{TRANSPORT}}]"
        )
        return host

    def _legacy_state(self):
        return {
            "Shadowsocks TCP": [self._legacy("arGuS")],
            "VLESS TCP REALITY": [],
            "VLESS TCP REALITY DIRECT": [self._legacy("Pingo")],
            "Trojan WS": [self._legacy("ArGuS")],
            "VMess WS": [],
        }

    async def test_preview_is_get_only(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        state = self._legacy_state()

        async def request(method, endpoint, *, json_data=None, params=None):
            self.assertEqual(method, "GET")
            self.assertIsNone(json_data)
            if endpoint == "/api/node/1":
                return True, copy.deepcopy(self.node)
            if endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if endpoint == "/api/hosts":
                return True, copy.deepcopy(state)
            self.fail(f"unexpected endpoint: {endpoint}")

        service.request = AsyncMock(side_effect=request)

        ok, plan = await service.preview_node_public_profile_repair(
            1,
            self.public,
        )

        self.assertTrue(ok)
        self.assertTrue(plan["read_only"])
        self.assertTrue(plan["repairable"])
        self.assertEqual(service.request.await_count, 3)

    async def test_stale_fingerprint_refuses_all_puts(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        plan = marzban_admin.plan_node_public_host_repair(
            self._legacy_state(),
            self.node,
            public_address=self.public,
        )
        plan.update({
            "node_id": 1,
            "node": copy.deepcopy(self.node),
            "public_address": self.public,
            "stage": "repair_preview",
            "read_only": True,
        })
        service.preview_node_public_profile_repair = AsyncMock(
            return_value=(True, plan)
        )
        service.request = AsyncMock()

        ok, result = await service.repair_node_public_profile(
            1,
            self.public,
            expected_fingerprint="stale-preview",
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "repair_stale")
        service.request.assert_not_awaited()

    async def test_repair_is_verified_and_retry_is_idempotent(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        state = self._legacy_state()
        put_tags = []

        async def request(method, endpoint, *, json_data=None, params=None):
            if method == "GET" and endpoint == "/api/node/1":
                return True, copy.deepcopy(self.node)
            if method == "GET" and endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if method == "GET" and endpoint == "/api/hosts":
                return True, copy.deepcopy(state)
            if method == "PUT" and endpoint == "/api/hosts":
                self.assertIsInstance(json_data, dict)
                self.assertEqual(len(json_data), 1)
                tag, desired = next(iter(json_data.items()))
                put_tags.append(tag)
                state[tag] = copy.deepcopy(desired)
                return True, {"ok": True}
            self.fail(f"unexpected request: {method} {endpoint}")

        service.request = AsyncMock(side_effect=request)

        initial_plan = marzban_admin.plan_node_public_host_repair(
            state,
            self.node,
            public_address=self.public,
        )
        ok, result = await service.repair_node_public_profile(
            1,
            self.public,
            expected_fingerprint=initial_plan["fingerprint"],
        )

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertCountEqual(
            put_tags,
            [
                "Shadowsocks TCP",
                "VLESS TCP REALITY",
                "VLESS TCP REALITY DIRECT",
                "Trojan WS",
            ],
        )
        verified = marzban_admin.inspect_node_public_host_profile(
            state,
            self.node,
            public_address=self.public,
        )
        self.assertTrue(verified["adoptable"])

        put_count = len(put_tags)
        retry_plan = marzban_admin.plan_node_public_host_repair(
            state,
            self.node,
            public_address=self.public,
        )
        ok, retry = await service.repair_node_public_profile(
            1,
            self.public,
            expected_fingerprint=retry_plan["fingerprint"],
        )

        self.assertTrue(ok)
        self.assertTrue(retry["verified"])
        self.assertEqual(retry["changed_tags"], [])
        self.assertEqual(len(put_tags), put_count)


class V123B2RepairUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_version_and_node_detail_expose_repair(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V124-2026-10-07-critical-only-regional-notifications"',
            self.source,
        )
        region = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("🛠 Repair Public Endpoint", region)
        self.assertIn('callback_data=f"mza_nrepair_{node_id}"', region)

    def test_preview_and_confirm_are_stale_safe_and_pending_precedes_put(self):
        self.assertIn("MZA_NODE_REPAIR_PUBLIC_INPUT", self.source)
        region = self._region(
            "elif d.startswith('mza_nrepair_confirm_'):",
            "elif d.startswith('mza_nadopt_confirm_'):",
        )
        preview_pos = region.index("service.preview_node_public_profile_repair(")
        dns_pos = region.index("preflight_public_endpoint")
        pending_pos = region.index(
            "_db_upsert_marzban_node_public_profile"
        )
        repair_pos = region.index("service.repair_node_public_profile(")
        verified_pos = region.rindex(
            "_db_upsert_marzban_node_public_profile"
        )
        self.assertLess(preview_pos, pending_pos)
        self.assertLess(dns_pos, pending_pos)
        self.assertLess(pending_pos, repair_pos)
        self.assertLess(repair_pos, verified_pos)
        self.assertIn("stale_identity", region)
        self.assertIn("stale_plan", region)
        self.assertIn('"pending"', region)
        self.assertIn('"verified"', region)

    def test_node_detail_navigation_clears_stale_node_text_input(self):
        nav = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn(
            "if (not starters or d.startswith('mza_node_')) and input_state in (",
            nav,
        )
        self.assertIn("'MZA_NODE_ADDRESS_INPUT'", nav)

    def test_cancel_command_is_registered_as_persistent_state_escape_hatch(self):
        self.assertIn("async def cmd_cancel(", self.source)
        self.assertIn('CommandHandler("cancel", cmd_cancel)', self.source)
        cancel_region = self._region(
            "async def cmd_cancel(",
            "# ==========================================\n# 🎯 توابع رابط‌های گرافیکی",
        )
        self.assertIn("safe_clear_context(context)", cancel_region)
        self.assertIn("_mig_cancel_session(chat_id)", cancel_region)
        self.assertIn("marzban_node_bootstrap.cancel_session(chat_id)", cancel_region)

    def test_failure_keeps_pending_and_navigation_clears_repair_draft(self):
        confirm = self._region(
            "elif d.startswith('mza_nrepair_confirm_'):",
            "elif d.startswith('mza_nadopt_confirm_'):",
        )
        self.assertIn("mapping محلی عمداً <code>pending</code> باقی ماند", confirm)

        nav = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("node_repair_starter", nav)
        self.assertIn("MZA_NODE_REPAIR_PUBLIC_INPUT", nav)
        self.assertIn("_mza_clear_node_repair(context)", nav)


if __name__ == "__main__":
    unittest.main()
