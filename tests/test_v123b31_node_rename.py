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


class V123B31RenameServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.node = {
            "id": 1,
            "name": "Pingo✅",
            "address": "172.86.72.203",
            "port": 62050,
            "api_port": 62051,
            "usage_coefficient": 1.0,
            "status": "connected",
        }
        self.public = "argus.nvlsup.xyz"
        self.tags = marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        self.inbounds = _inbounds(*self.tags, "VMess WS")
        generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public,
        )
        self.hosts = {
            tag: [copy.deepcopy(generated)]
            for tag in self.tags
        }
        manual = copy.deepcopy(generated)
        manual["remark"] = "Manual VMess"
        manual["address"] = "manual.example"
        self.hosts["VMess WS"] = [manual]

    async def test_preview_is_get_only_and_requires_canonical_profile(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )

        async def request(method, endpoint, *, json_data=None, params=None):
            self.assertEqual(method, "GET")
            self.assertIsNone(json_data)
            if endpoint == "/api/node/1":
                return True, copy.deepcopy(self.node)
            if endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if endpoint == "/api/hosts":
                return True, copy.deepcopy(self.hosts)
            if endpoint == "/api/nodes":
                return True, [copy.deepcopy(self.node)]
            self.fail(f"unexpected endpoint: {endpoint}")

        service.request = AsyncMock(side_effect=request)
        ok, plan = await service.preview_node_public_profile_rename(
            1,
            "Argus Edge",
            self.public,
        )

        self.assertTrue(ok)
        self.assertTrue(plan["read_only"])
        self.assertTrue(plan["renameable"])
        self.assertFalse(plan["no_change"])
        self.assertEqual(plan["old_name"], "Pingo✅")
        self.assertEqual(plan["new_name"], "Argus Edge")
        self.assertEqual(plan["public_address"], self.public)
        self.assertCountEqual(plan["changed_tags"], self.tags)
        self.assertNotEqual(
            plan["old_managed_remark"],
            plan["new_managed_remark"],
        )
        self.assertEqual(service.request.await_count, 4)

    async def test_stale_fingerprint_refuses_node_and_host_writes(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        preview = {
            "renameable": True,
            "no_change": False,
            "fingerprint": "current",
            "node_id": 1,
            "node": copy.deepcopy(self.node),
            "old_name": "Pingo✅",
            "new_name": "Argus Edge",
            "public_address": self.public,
            "old_managed_remark": "old",
            "new_managed_remark": "new",
            "managed_tags": list(self.tags),
        }
        service.preview_node_public_profile_rename = AsyncMock(
            return_value=(True, preview)
        )
        service.update_node_settings = AsyncMock()

        ok, result = await service.rename_node_public_profile(
            1,
            "Argus Edge",
            self.public,
            expected_fingerprint="stale",
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "rename_stale")
        self.assertFalse(result["renamed"])
        service.update_node_settings.assert_not_awaited()

    async def test_rename_syncs_four_managed_remarks_preserves_manual_and_is_idempotent(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        node = copy.deepcopy(self.node)
        hosts = copy.deepcopy(self.hosts)
        node_puts = []
        host_puts = []

        async def request(method, endpoint, *, json_data=None, params=None):
            if method == "GET" and endpoint == "/api/node/1":
                return True, copy.deepcopy(node)
            if method == "GET" and endpoint == "/api/nodes":
                return True, [copy.deepcopy(node)]
            if method == "GET" and endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if method == "GET" and endpoint == "/api/hosts":
                return True, copy.deepcopy(hosts)
            if method == "PUT" and endpoint == "/api/node/1":
                node_puts.append(copy.deepcopy(json_data))
                if "name" in json_data:
                    node["name"] = json_data["name"]
                if "status" in json_data:
                    node["status"] = json_data["status"]
                return True, copy.deepcopy(node)
            if method == "PUT" and endpoint == "/api/hosts":
                self.assertEqual(len(json_data), 1)
                tag, desired = next(iter(json_data.items()))
                host_puts.append(tag)
                hosts[tag] = copy.deepcopy(desired)
                return True, {"ok": True}
            self.fail(f"unexpected request: {method} {endpoint}")

        service.request = AsyncMock(side_effect=request)

        ok_preview, preview = await service.preview_node_public_profile_rename(
            1,
            "Argus Edge",
            self.public,
        )
        self.assertTrue(ok_preview)
        self.assertTrue(preview["renameable"])

        ok, result = await service.rename_node_public_profile(
            1,
            "Argus Edge",
            self.public,
            expected_fingerprint=preview["fingerprint"],
        )

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertTrue(result["renamed"])
        self.assertEqual(node["name"], "Argus Edge")
        self.assertEqual(node["address"], self.node["address"])
        self.assertEqual(len(node_puts), 1)
        self.assertCountEqual(host_puts, self.tags)

        expected = marzban_admin.node_generated_host_payload(
            node,
            public_address=self.public,
        )
        for tag in self.tags:
            self.assertEqual(hosts[tag], [expected])
        self.assertEqual(hosts["VMess WS"], self.hosts["VMess WS"])

        put_count = len(node_puts) + len(host_puts)
        ok_retry_preview, retry_preview = (
            await service.preview_node_public_profile_rename(
                1,
                "Argus Edge",
                self.public,
            )
        )
        self.assertTrue(ok_retry_preview)
        self.assertTrue(retry_preview["renameable"])
        self.assertTrue(retry_preview["no_change"])

        ok_retry, retry = await service.rename_node_public_profile(
            1,
            "Argus Edge",
            self.public,
            expected_fingerprint=retry_preview["fingerprint"],
        )
        self.assertTrue(ok_retry)
        self.assertTrue(retry["verified"])
        self.assertFalse(retry["renamed"])
        self.assertEqual(len(node_puts) + len(host_puts), put_count)

    async def test_duplicate_target_name_fails_closed(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        other = {
            **copy.deepcopy(self.node),
            "id": 2,
            "name": "Argus Edge",
            "address": "203.0.113.20",
        }

        async def request(method, endpoint, *, json_data=None, params=None):
            self.assertEqual(method, "GET")
            if endpoint == "/api/node/1":
                return True, copy.deepcopy(self.node)
            if endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if endpoint == "/api/hosts":
                return True, copy.deepcopy(self.hosts)
            if endpoint == "/api/nodes":
                return True, [copy.deepcopy(self.node), other]
            self.fail(f"unexpected endpoint: {endpoint}")

        service.request = AsyncMock(side_effect=request)
        ok, plan = await service.preview_node_public_profile_rename(
            1,
            "Argus Edge",
            self.public,
        )

        self.assertTrue(ok)
        self.assertFalse(plan["renameable"])
        self.assertTrue(any("already exists" in issue for issue in plan["issues"]))


class V123B31RenameUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker_and_preview_exist(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V124-2026-10-07-critical-only-regional-notifications"',
            self.source,
        )
        preview = self._region(
            "async def _mza_show_node_edit_confirm",
            "def _db_get_marzban_node_public_profile",
        )
        self.assertIn("V123B.3.1 · Rename Preview", preview)
        self.assertIn("preview_node_public_profile_rename", preview)
        self.assertIn("preflight_public_endpoint", preview)
        self.assertIn("mza_nrename_confirm_", preview)
        self.assertIn("Hostهای دستی دست‌نخورده می‌مانند", preview)

    def test_confirm_is_stale_safe_and_pending_precedes_remote_rename(self):
        confirm = self._region(
            "elif d.startswith('mza_nrename_confirm_'):",
            "elif d.startswith('mza_nedit_confirm_'):",
        )
        preview_pos = confirm.index("service.preview_node_public_profile_rename(")
        dns_pos = confirm.index("preflight_public_endpoint")
        pending_pos = confirm.index("_db_upsert_marzban_node_public_profile")
        rename_pos = confirm.index("service.rename_node_public_profile(")
        verified_pos = confirm.rindex("_db_upsert_marzban_node_public_profile")
        self.assertLess(preview_pos, pending_pos)
        self.assertLess(dns_pos, pending_pos)
        self.assertLess(pending_pos, rename_pos)
        self.assertLess(rename_pos, verified_pos)
        self.assertIn('"pending"', confirm)
        self.assertIn('"verified"', confirm)
        self.assertIn("fingerprint", confirm)
        self.assertIn("nonce", confirm)

    def test_address_lifecycle_is_delegated_to_v123b32_safe_move(self):
        address = self._region(
            "elif d.startswith('mza_nedit_address_'):",
            "elif d.startswith('mza_nedit_ports_'):",
        )
        self.assertIn("V123B.3.2 · Safe Node Move / Change IP", address)
        self.assertIn("MZA_NODE_MOVE_ADDRESS_INPUT", address)
        self.assertIn("mza_nmove_cancel_", address)

    def test_partial_rename_keeps_pending_and_offers_repair(self):
        confirm = self._region(
            "elif d.startswith('mza_nrename_confirm_'):",
            "elif d.startswith('mza_nedit_confirm_'):",
        )
        self.assertIn("mapping عمداً <code>pending</code> باقی مانده است", confirm)
        self.assertIn("🛠 Repair Public Endpoint", confirm)


if __name__ == "__main__":
    unittest.main()
