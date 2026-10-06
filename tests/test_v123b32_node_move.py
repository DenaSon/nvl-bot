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


class V123B32MoveServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.node = {
            "id": 1,
            "name": "Argus",
            "address": "172.86.72.203",
            "port": 62050,
            "api_port": 62051,
            "usage_coefficient": 1.0,
            "status": "connected",
        }
        self.public = "argus.nvlsup.xyz"
        self.new_address = "203.0.113.22"
        self.tags = marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        self.inbounds = _inbounds(*self.tags)
        generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public,
        )
        self.hosts = {
            tag: [copy.deepcopy(generated)]
            for tag in self.tags
        }

    async def test_preview_is_get_only_and_keeps_public_profile_stable(self):
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
        ok, plan = await service.preview_node_public_profile_move(
            1,
            self.new_address,
            self.public,
        )

        self.assertTrue(ok)
        self.assertTrue(plan["read_only"])
        self.assertTrue(plan["moveable"])
        self.assertFalse(plan["no_change"])
        self.assertEqual(plan["old_address"], self.node["address"])
        self.assertEqual(plan["new_address"], self.new_address)
        self.assertEqual(plan["public_address"], self.public)
        self.assertEqual(plan["managed_tags"], list(self.tags))
        self.assertEqual(service.request.await_count, 4)

    async def test_stale_fingerprint_refuses_address_write(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        plan = {
            "moveable": True,
            "no_change": False,
            "fingerprint": "current",
            "node_id": 1,
            "node": copy.deepcopy(self.node),
            "old_address": self.node["address"],
            "new_address": self.new_address,
            "public_address": self.public,
            "managed_remark": marzban_admin.node_generated_host_remark("Argus"),
            "managed_tags": list(self.tags),
        }
        service.preview_node_public_profile_move = AsyncMock(
            return_value=(True, plan)
        )
        service.update_node_settings = AsyncMock()

        ok, result = await service.move_node_public_profile(
            1,
            self.new_address,
            self.public,
            expected_fingerprint="stale",
            connect_timeout=1,
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "move_stale")
        self.assertFalse(result["moved"])
        service.update_node_settings.assert_not_awaited()

    async def test_move_changes_only_node_address_and_verifies_connected(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        node = copy.deepcopy(self.node)
        hosts = copy.deepcopy(self.hosts)
        writes = []

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
                writes.append(("node", copy.deepcopy(json_data)))
                node["address"] = json_data["address"]
                node["status"] = "connecting"
                return True, copy.deepcopy(node)
            if method == "POST" and endpoint == "/api/node/1/reconnect":
                writes.append(("reconnect", None))
                node["status"] = "connected"
                return True, {"ok": True}
            self.fail(f"unexpected request: {method} {endpoint}")

        service.request = AsyncMock(side_effect=request)
        ok_preview, preview = await service.preview_node_public_profile_move(
            1,
            self.new_address,
            self.public,
        )
        self.assertTrue(ok_preview)
        before_hosts = copy.deepcopy(hosts)

        ok, result = await service.move_node_public_profile(
            1,
            self.new_address,
            self.public,
            expected_fingerprint=preview["fingerprint"],
            connect_timeout=1,
        )

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertTrue(result["connected"])
        self.assertTrue(result["moved"])
        self.assertFalse(result["rolled_back"])
        self.assertEqual(node["id"], 1)
        self.assertEqual(node["address"], self.new_address)
        self.assertEqual(hosts, before_hosts)
        self.assertEqual(
            [kind for kind, _ in writes].count("node"),
            1,
        )

    async def test_connect_failure_rolls_back_old_address(self):
        service = marzban_admin.MarzbanAdminService(
            "https://marzban.example", "admin", "secret"
        )
        node = copy.deepcopy(self.node)
        hosts = copy.deepcopy(self.hosts)
        reconnects = 0

        async def request(method, endpoint, *, json_data=None, params=None):
            nonlocal reconnects
            if method == "GET" and endpoint == "/api/node/1":
                return True, copy.deepcopy(node)
            if method == "GET" and endpoint == "/api/nodes":
                return True, [copy.deepcopy(node)]
            if method == "GET" and endpoint == "/api/inbounds":
                return True, copy.deepcopy(self.inbounds)
            if method == "GET" and endpoint == "/api/hosts":
                return True, copy.deepcopy(hosts)
            if method == "PUT" and endpoint == "/api/node/1":
                node["address"] = json_data["address"]
                node["status"] = "connecting"
                return True, copy.deepcopy(node)
            if method == "POST" and endpoint == "/api/node/1/reconnect":
                reconnects += 1
                if node["address"] == self.node["address"]:
                    node["status"] = "connected"
                else:
                    node["status"] = "error"
                return True, {"ok": True}
            self.fail(f"unexpected request: {method} {endpoint}")

        service.request = AsyncMock(side_effect=request)
        ok_preview, preview = await service.preview_node_public_profile_move(
            1,
            self.new_address,
            self.public,
        )
        self.assertTrue(ok_preview)

        ok, result = await service.move_node_public_profile(
            1,
            self.new_address,
            self.public,
            expected_fingerprint=preview["fingerprint"],
            connect_timeout=1,
            rollback_timeout=1,
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "move_connect_rollback")
        self.assertTrue(result["rolled_back"])
        self.assertTrue(result["rollback_connected"])
        self.assertEqual(node["address"], self.node["address"])
        self.assertGreaterEqual(reconnects, 2)


class V123B32MoveUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker_and_managed_address_route_use_safe_move(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B32M-2026-10-06-safe-node-move"',
            self.source,
        )
        region = self._region(
            "elif d.startswith('mza_nedit_address_'):",
            "elif d.startswith('mza_nedit_ports_'):",
        )
        self.assertIn("V123B.3.2 · Safe Node Move / Change IP", region)
        self.assertIn("MZA_NODE_MOVE_ADDRESS_INPUT", region)
        self.assertIn("mza_nmove_cancel_", region)

    def test_destination_install_uses_current_marzban_certificate_without_cutover(self):
        region = self._region(
            "# 🌐 V123B.3.2 Safe Node Move input.",
            "# 🚀 Marzban Node bootstrap Phase 6 input.",
        )
        self.assertIn("service.get_node_settings()", region)
        self.assertIn("marzban_node_install.run_install", region)
        self.assertIn('certificate=str(settings_payload.get("certificate") or "")', region)
        self.assertIn("هنوز Node.address و DNS تغییر نمی‌کنند", region)
        self.assertIn('"destination_ready"] = True', region)

    def test_cutover_preview_preserves_node_id_public_endpoint_and_hosts(self):
        region = self._region(
            "elif d.startswith('mza_nmove_cutover_'):",
            "elif d.startswith('mza_nmove_confirm_'):",
        )
        self.assertIn("preview_node_public_profile_move", region)
        self.assertIn("preflight_public_endpoint", region)
        self.assertIn("Node ID", region)
        self.assertIn("unchanged", region)
        self.assertIn("Managed Hosts", region)
        self.assertIn("rollback", region.lower())

    def test_confirm_persists_pending_before_remote_move_and_keeps_pending_until_dns_finalize(self):
        region = self._region(
            "elif d.startswith('mza_nmove_confirm_'):",
            "elif d.startswith('mza_nmove_finalize_'):",
        )
        pending_pos = region.index("_db_upsert_marzban_node_public_profile")
        move_pos = region.index("service.move_node_public_profile(")
        self.assertLess(pending_pos, move_pos)
        self.assertIn('"pending"', region)
        self.assertIn("control_plane_ready", region)
        self.assertIn("DNS Public Endpoint", region)

    def test_finalize_requires_new_dns_connected_node_and_canonical_hosts(self):
        region = self._region(
            "elif d.startswith('mza_nmove_finalize_'):",
            "elif d.startswith('mza_nedit_name_'):",
        )
        self.assertIn("preflight_public_endpoint", region)
        self.assertIn('"connected"', region)
        self.assertIn("preview_node_public_profile_repair", region)
        self.assertIn('"verified"', region)
        self.assertIn("_mza_clear_node_move", region)


if __name__ == "__main__":
    unittest.main()
