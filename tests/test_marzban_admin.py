import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import marzban_admin


class AuthorizationTests(unittest.TestCase):
    def test_admin_can_manage_any_account(self):
        self.assertTrue(marzban_admin.can_manage_v2ray_account("admin", 0, 99))

    def test_agent_can_manage_only_own_account(self):
        self.assertTrue(marzban_admin.can_manage_v2ray_account("agent", 7, 7))
        self.assertFalse(marzban_admin.can_manage_v2ray_account("agent", 7, 8))

    def test_unknown_role_is_denied(self):
        self.assertFalse(marzban_admin.can_manage_v2ray_account(None, 0, 0))


class SubscriptionNameTests(unittest.TestCase):
    def test_name_is_normalized(self):
        self.assertEqual(
            marzban_admin.normalize_subscription_name("  My   VPN\n"),
            "My VPN",
        )

    def test_blank_name_becomes_none(self):
        self.assertIsNone(marzban_admin.normalize_subscription_name("   "))

    def test_name_length_is_validated(self):
        with self.assertRaises(ValueError):
            marzban_admin.normalize_subscription_name("x")
        with self.assertRaises(ValueError):
            marzban_admin.normalize_subscription_name("x" * 31)


class NodeValidationTests(unittest.TestCase):
    def test_node_id_must_be_positive(self):
        self.assertEqual(marzban_admin.normalize_node_id("7"), 7)
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_id(0)
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_id("nope")

    def test_node_settings_are_normalized(self):
        self.assertEqual(
            marzban_admin.normalize_node_changes({
                "name": "  DE   Node ",
                "address": "node.example.com",
                "port": "62050",
                "api_port": 62051,
                "usage_coefficient": "1.5",
            }),
            {
                "name": "DE Node",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.5,
            },
        )

    def test_node_settings_reject_unsafe_values(self):
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes({"address": "https://node.example.com"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes({"port": 70000})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes({"usage_coefficient": 0})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes({"status": "connected"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes({"unknown": "x"})

    def test_settings_update_cannot_directly_mutate_status(self):
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_changes(
                {"status": "disabled"},
                allow_status=False,
            )


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )

    async def test_list_users_uses_v084_query_contract(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"users": [], "total": 0})
            ok, payload = await self.service.list_users(
                offset=8,
                limit=8,
                search="hamid",
                status="active",
            )

        self.assertTrue(ok)
        self.assertEqual(payload["total"], 0)
        request.assert_awaited_once_with(
            "GET",
            "/api/users",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params={
                "offset": 8,
                "limit": 8,
                "search": "hamid",
                "status": "active",
            },
        )

    async def test_get_nodes_uses_read_only_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, [])
            ok, payload = await self.service.get_nodes()

        self.assertTrue(ok)
        self.assertEqual(payload, [])
        request.assert_awaited_once_with(
            "GET",
            "/api/nodes",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_get_node_uses_detail_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"id": 4, "status": "connected"})
            ok, payload = await self.service.get_node(4)

        self.assertTrue(ok)
        self.assertEqual(payload["id"], 4)
        request.assert_awaited_once_with(
            "GET",
            "/api/node/4",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_disable_node_uses_node_modify_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"id": 4, "status": "disabled"})
            ok, payload = await self.service.set_node_enabled(4, False)

        self.assertTrue(ok)
        self.assertEqual(payload["status"], "disabled")
        request.assert_awaited_once_with(
            "PUT",
            "/api/node/4",
            "https://marzban.example",
            "admin",
            "secret",
            json_data={"status": "disabled"},
            params=None,
        )

    async def test_enable_node_uses_connecting_state(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"id": 4, "status": "connecting"})
            ok, payload = await self.service.set_node_enabled(4, True)

        self.assertTrue(ok)
        self.assertEqual(payload["status"], "connecting")
        request.assert_awaited_once_with(
            "PUT",
            "/api/node/4",
            "https://marzban.example",
            "admin",
            "secret",
            json_data={"status": "connecting"},
            params=None,
        )

    async def test_settings_edit_preserves_disabled_node(self):
        self.service.get_node = AsyncMock(
            return_value=(True, {"id": 4, "status": "disabled"})
        )
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (
                True,
                {"id": 4, "status": "disabled", "usage_coefficient": 2.0},
            )
            ok, payload = await self.service.update_node_settings(
                4,
                usage_coefficient=2,
            )

        self.assertTrue(ok)
        self.assertEqual(payload["status"], "disabled")
        request.assert_awaited_once_with(
            "PUT",
            "/api/node/4",
            "https://marzban.example",
            "admin",
            "secret",
            json_data={"usage_coefficient": 2.0, "status": "disabled"},
            params=None,
        )

    async def test_reconnect_node_uses_reconnect_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"detail": "Reconnection task scheduled"})
            ok, payload = await self.service.reconnect_node(4)

        self.assertTrue(ok)
        self.assertIn("Reconnection", payload["detail"])
        request.assert_awaited_once_with(
            "POST",
            "/api/node/4/reconnect",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_node_usage_uses_usage_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"usages": []})
            ok, payload = await self.service.get_nodes_usage()

        self.assertTrue(ok)
        self.assertEqual(payload["usages"], [])
        request.assert_awaited_once_with(
            "GET",
            "/api/nodes/usage",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_reset_user_usage_uses_reset_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"username": "hamid"})
            ok, payload = await self.service.reset_user_usage("hamid")

        self.assertTrue(ok)
        self.assertEqual(payload["username"], "hamid")
        request.assert_awaited_once_with(
            "POST",
            "/api/user/hamid/reset",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_set_user_status_updates_remote_status(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"username": "hamid", "status": "disabled"})
            ok, payload = await self.service.set_user_status("hamid", "disabled")

        self.assertTrue(ok)
        self.assertEqual(payload["status"], "disabled")
        request.assert_awaited_once_with(
            "PUT",
            "/api/user/hamid",
            "https://marzban.example",
            "admin",
            "secret",
            json_data={"status": "disabled"},
            params=None,
        )

    async def test_delete_user_uses_delete_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, None)
            ok, payload = await self.service.delete_user("hamid")

        self.assertTrue(ok)
        self.assertIsNone(payload)
        request.assert_awaited_once_with(
            "DELETE",
            "/api/user/hamid",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_modify_user_supports_expiry_extension_payload(self):
        new_expire = 1793577600
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"username": "hamid", "expire": new_expire})
            ok, payload = await self.service.modify_user("hamid", expire=new_expire)

        self.assertTrue(ok)
        self.assertEqual(payload["expire"], new_expire)
        request.assert_awaited_once_with(
            "PUT",
            "/api/user/hamid",
            "https://marzban.example",
            "admin",
            "secret",
            json_data={"expire": new_expire},
            params=None,
        )

    async def test_subscription_url_is_made_absolute(self):
        self.service.get_user = AsyncMock(
            return_value=(True, {"subscription_url": "/sub/token"})
        )
        ok, url = await self.service.get_subscription_url("hamid")

        self.assertTrue(ok)
        self.assertEqual(url, "https://marzban.example/sub/token")

    async def test_subscription_url_rejects_empty_value(self):
        self.service.get_user = AsyncMock(
            return_value=(True, {"subscription_url": ""})
        )
        ok, error = await self.service.get_subscription_url("hamid")

        self.assertFalse(ok)
        self.assertIn("empty", error.lower())

    async def test_online_users_filters_to_recent_active_users(self):
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(seconds=30)).isoformat()
        old = (now - timedelta(minutes=15)).isoformat()
        users = [
            {"username": "recent", "status": "active", "online_at": recent},
            {"username": "old", "status": "active", "online_at": old},
            {"username": "disabled", "status": "disabled", "online_at": recent},
            {"username": "never", "status": "active", "online_at": None},
        ]

        self.service.list_users = AsyncMock(
            return_value=(True, {"users": users, "total": len(users)})
        )
        ok, payload = await self.service.list_online_users(window_seconds=300)

        self.assertTrue(ok)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["users"][0]["username"], "recent")


if __name__ == "__main__":
    unittest.main()
