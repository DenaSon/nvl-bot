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
