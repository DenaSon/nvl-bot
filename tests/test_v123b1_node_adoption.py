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


class V123B1AdoptionInspectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.node = {
            "id": 9,
            "name": "Argus",
            "address": "172.86.72.203",
            "port": 62050,
            "api_port": 62051,
            "usage_coefficient": 1.0,
        }
        self.public_address = "argus.nvlsup.xyz"
        self.generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public_address,
        )

    def _healthy_hosts(self):
        state = {
            tag: [copy.deepcopy(self.generated)]
            for tag in marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        }
        manual = copy.deepcopy(self.generated)
        manual["remark"] = "Manual Host"
        state["VMess WS"] = [manual]
        return state

    def test_exact_existing_profile_is_adoptable_without_touching_manual_hosts(self):
        report = marzban_admin.inspect_node_public_host_profile(
            self._healthy_hosts(),
            self.node,
            public_address=self.public_address,
        )

        self.assertTrue(report["adoptable"])
        self.assertTrue(report["verified"])
        self.assertEqual(report["matched_hosts"], 3)
        self.assertEqual(report["missing_tags"], [])
        self.assertEqual(report["duplicate_tags"], {})
        self.assertEqual(report["unexpected_tags"], {})
        self.assertEqual(report["remark_conflicts"], [])
        self.assertEqual(report["drifted_tags"], [])

    def test_missing_duplicate_unexpected_conflict_and_payload_drift_fail_closed(self):
        missing = self._healthy_hosts()
        missing["Trojan WS"] = []
        report = marzban_admin.inspect_node_public_host_profile(
            missing,
            self.node,
            public_address=self.public_address,
        )
        self.assertFalse(report["adoptable"])
        self.assertIn("Trojan WS", report["missing_tags"])

        duplicate = self._healthy_hosts()
        duplicate["VLESS TCP REALITY"].append(copy.deepcopy(self.generated))
        report = marzban_admin.inspect_node_public_host_profile(
            duplicate,
            self.node,
            public_address=self.public_address,
        )
        self.assertFalse(report["adoptable"])
        self.assertEqual(report["duplicate_tags"]["VLESS TCP REALITY"], 2)

        unexpected = self._healthy_hosts()
        unexpected["VMess WS"].append(copy.deepcopy(self.generated))
        report = marzban_admin.inspect_node_public_host_profile(
            unexpected,
            self.node,
            public_address=self.public_address,
        )
        self.assertFalse(report["adoptable"])
        self.assertEqual(report["unexpected_tags"]["VMess WS"], 1)

        conflict = self._healthy_hosts()
        wrong = copy.deepcopy(self.generated)
        wrong["address"] = "legacy.nvlsup.xyz"
        conflict["VMess WS"].append(wrong)
        report = marzban_admin.inspect_node_public_host_profile(
            conflict,
            self.node,
            public_address=self.public_address,
        )
        self.assertFalse(report["adoptable"])
        self.assertEqual(len(report["remark_conflicts"]), 1)

        drifted = self._healthy_hosts()
        drifted["Shadowsocks TCP"][0]["mux_enable"] = True
        report = marzban_admin.inspect_node_public_host_profile(
            drifted,
            self.node,
            public_address=self.public_address,
        )
        self.assertFalse(report["adoptable"])
        self.assertIn("Shadowsocks TCP", report["drifted_tags"])

    async def test_service_inspection_is_get_only(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        hosts = self._healthy_hosts()
        inbounds = _inbounds(
            *marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS,
            "VMess WS",
        )

        async def request(method, endpoint, *, json_data=None, params=None):
            self.assertEqual(method, "GET")
            self.assertIsNone(json_data)
            if endpoint == "/api/node/9":
                return True, copy.deepcopy(self.node)
            if endpoint == "/api/inbounds":
                return True, copy.deepcopy(inbounds)
            if endpoint == "/api/hosts":
                return True, copy.deepcopy(hosts)
            self.fail(f"unexpected endpoint: {endpoint}")

        service.request = AsyncMock(side_effect=request)

        ok, report = await service.inspect_node_public_profile(
            9,
            self.public_address,
        )

        self.assertTrue(ok)
        self.assertTrue(report["read_only"])
        self.assertTrue(report["adoptable"])
        self.assertEqual(service.request.await_count, 3)

    async def test_missing_required_inbound_is_reported_without_host_write_or_host_get(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        service.get_node = AsyncMock(return_value=(True, copy.deepcopy(self.node)))
        service.get_inbounds = AsyncMock(return_value=(
            True,
            _inbounds("Shadowsocks TCP", "VLESS TCP REALITY"),
        ))
        service.get_hosts = AsyncMock()

        ok, report = await service.inspect_node_public_profile(
            9,
            self.public_address,
        )

        self.assertTrue(ok)
        self.assertFalse(report["adoptable"])
        self.assertIn("Trojan WS", report["missing_inbounds"])
        service.get_hosts.assert_not_awaited()


class V123B1AdoptionUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_version_and_node_detail_expose_adoption_state(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B2-2026-10-06-repair-public-endpoint"',
            self.source,
        )
        region = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("_db_get_marzban_node_public_profile", region)
        self.assertIn("Stable Public Endpoint", region)
        self.assertIn("Mapping  <code>not adopted</code>", region)
        self.assertIn("🔗 Adopt Public Endpoint", region)
        self.assertIn('callback_data=f"mza_nadopt_{node_id}"', region)

    def test_adopt_input_and_confirm_reinspect_before_local_mapping(self):
        self.assertIn("MZA_NODE_ADOPT_PUBLIC_INPUT", self.source)
        region = self._region(
            "elif d.startswith('mza_nadopt_confirm_'):",
            "elif d.startswith('mza_nedit_name_'):",
        )
        inspect_pos = region.index("service.inspect_node_public_profile(")
        dns_pos = region.index("preflight_public_endpoint")
        persist_pos = region.index("_db_upsert_marzban_node_public_profile")
        self.assertLess(inspect_pos, persist_pos)
        self.assertLess(dns_pos, persist_pos)
        self.assertIn("stale_identity", region)
        self.assertIn('"verified"', region)

    def test_adoption_callback_never_calls_remote_mutators(self):
        region = self._region(
            "elif d.startswith('mza_nadopt_confirm_'):",
            "elif d.startswith('mza_nedit_name_'):",
        )
        for forbidden in (
            "reconcile_node_public_hosts(",
            "update_node_settings(",
            "update_host(",
            "delete_host(",
            "delete_node(",
            "modify_node(",
        ):
            self.assertNotIn(forbidden, region)
        self.assertIn("inspect کاملاً read-only", self.source.lower())

    def test_navigation_clears_abandoned_adopt_draft(self):
        region = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("node_adopt_starter", region)
        self.assertIn("MZA_NODE_ADOPT_PUBLIC_INPUT", region)
        self.assertIn("_mza_clear_node_adopt(context)", region)


if __name__ == "__main__":
    unittest.main()
