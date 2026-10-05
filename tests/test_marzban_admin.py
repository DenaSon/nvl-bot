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


    def test_node_create_uses_marzban_defaults_and_normalizes(self):
        self.assertEqual(
            marzban_admin.normalize_node_create(
                "  USA   Node ",
                "node.example.com",
            ),
            {
                "name": "USA Node",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "add_as_new_host": True,
            },
        )

    def test_node_create_normalizes_custom_values(self):
        self.assertEqual(
            marzban_admin.normalize_node_create(
                "USA-2",
                "144.172.105.187",
                port="62060",
                api_port=62061,
                usage_coefficient="1.5",
                add_as_new_host="false",
            ),
            {
                "name": "USA-2",
                "address": "144.172.105.187",
                "port": 62060,
                "api_port": 62061,
                "usage_coefficient": 1.5,
                "add_as_new_host": False,
            },
        )

    def test_node_create_rejects_invalid_boolean_and_fields(self):
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_create(
                "USA-2",
                "node.example.com",
                add_as_new_host="maybe",
            )
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_create("", "node.example.com")
        with self.assertRaises(ValueError):
            marzban_admin.normalize_node_create(
                "USA-2",
                "https://node.example.com",
            )


    def test_duplicate_node_lookup_is_case_insensitive(self):
        nodes = [
            {"id": 4, "name": "  USA   Node  ", "address": "1.2.3.4"},
            {"id": 5, "name": "DE Node", "address": "5.6.7.8"},
        ]
        duplicate = marzban_admin.find_duplicate_node(nodes, "usa node")
        self.assertIsNotNone(duplicate)
        self.assertEqual(duplicate["id"], 4)
        self.assertIsNone(marzban_admin.find_duplicate_node(nodes, "FR Node"))


class HostValidationTests(unittest.TestCase):
    def test_inbound_tag_and_index_are_normalized(self):
        self.assertEqual(
            marzban_admin.normalize_inbound_tag(" VLESS TCP REALITY "),
            "VLESS TCP REALITY",
        )
        self.assertEqual(marzban_admin.normalize_host_index("0"), 0)
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_index(-1)
        with self.assertRaises(ValueError):
            marzban_admin.normalize_inbound_tag("")

    def test_host_settings_are_normalized(self):
        self.assertEqual(
            marzban_admin.normalize_host_changes({
                "remark": "  Germany   Edge ",
                "address": "de.example.com",
                "port": "443",
                "sni": "cdn.example.com",
                "host": "-",
                "path": "/ws",
                "security": "TLS",
                "alpn": "h2,http/1.1",
                "fingerprint": "Chrome",
                "allowinsecure": "false",
                "is_disabled": "true",
            }),
            {
                "remark": "Germany Edge",
                "address": "de.example.com",
                "port": 443,
                "sni": "cdn.example.com",
                "host": None,
                "path": "/ws",
                "security": "tls",
                "alpn": "h2,http/1.1",
                "fingerprint": "chrome",
                "allowinsecure": False,
                "is_disabled": True,
            },
        )

    def test_host_settings_reject_unsafe_values(self):
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"address": "https://example.com"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"port": 70000})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"security": "reality"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"alpn": "bogus"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"unknown": "x"})

    def test_official_fragment_and_noise_formats_are_validated(self):
        self.assertEqual(
            marzban_admin.normalize_host_changes({
                "fragment_setting": "10-100,100-200,tlshello",
                "noise_setting": "rand:10-20,100-200",
            }),
            {
                "fragment_setting": "10-100,100-200,tlshello",
                "noise_setting": "rand:10-20,100-200",
            },
        )
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"fragment_setting": "bad"})
        with self.assertRaises(ValueError):
            marzban_admin.normalize_host_changes({"noise_setting": "bad"})



class UserCreateValidationTests(unittest.TestCase):
    def test_username_uses_safe_nvl_subset(self):
        self.assertEqual(
            marzban_admin.normalize_user_create_username(" Lumixo_01 "),
            "Lumixo_01",
        )
        for value in ("ab", "name with space", "user@example.com", "x" * 33):
            with self.assertRaises(ValueError):
                marzban_admin.normalize_user_create_username(value)

    def test_dynamic_inbounds_group_all_supported_protocols(self):
        payload = {
            "vless": [
                {"tag": "VLESS Reality", "protocol": "vless"},
                {"tag": "VLESS HTTP", "protocol": "vless"},
            ],
            "vmess": [{"tag": "VMess WS", "protocol": "vmess"}],
            "other": [{"tag": "Ignored", "protocol": "socks"}],
        }
        self.assertEqual(
            marzban_admin.build_user_inbounds(payload),
            {
                "vless": ["VLESS Reality", "VLESS HTTP"],
                "vmess": ["VMess WS"],
            },
        )

    def test_selected_inbounds_are_revalidated_against_current_config(self):
        payload = {
            "vless": [{"tag": "A", "protocol": "vless"}],
            "trojan": [{"tag": "B", "protocol": "trojan"}],
        }
        self.assertEqual(
            marzban_admin.build_user_inbounds(payload, ["B"]),
            {"trojan": ["B"]},
        )
        with self.assertRaises(ValueError):
            marzban_admin.build_user_inbounds(payload, ["Removed Tag"])


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

    async def test_get_node_settings_fetches_certificate_endpoint(self):
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (
                True,
                {
                    "min_node_version": "v0.4.4",
                    "certificate": "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----",
                },
            )
            ok, payload = await self.service.get_node_settings()

        self.assertTrue(ok)
        self.assertEqual(payload["min_node_version"], "v0.4.4")
        self.assertIn("BEGIN CERTIFICATE", payload["certificate"])
        request.assert_awaited_once_with(
            "GET",
            "/api/node/settings",
            "https://marzban.example",
            "admin",
            "secret",
            json_data=None,
            params=None,
        )

    async def test_get_node_settings_rejects_missing_certificate(self):
        self.service.request = AsyncMock(return_value=(True, {"min_node_version": "v0.4.4"}))
        ok, error = await self.service.get_node_settings()
        self.assertFalse(ok)
        self.assertIn("certificate", error)

    async def test_create_node_posts_node_create_contract_and_verifies(self):
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        created = {
            "id": 9,
            "name": "USA-2",
            "address": "144.172.105.187",
            "port": 62060,
            "api_port": 62061,
            "usage_coefficient": 1.5,
            "status": "connecting",
        }
        verified = dict(created, status="connected")
        self.service.request = AsyncMock(return_value=(True, created))
        self.service.get_node = AsyncMock(return_value=(True, verified))

        ok, payload = await self.service.create_node(
            " USA-2 ",
            "144.172.105.187",
            port="62060",
            api_port=62061,
            usage_coefficient="1.5",
            add_as_new_host=False,
        )

        self.assertTrue(ok)
        self.assertEqual(payload, verified)
        self.service.request.assert_awaited_once_with(
            "POST",
            "/api/node",
            json_data={
                "name": "USA-2",
                "address": "144.172.105.187",
                "port": 62060,
                "api_port": 62061,
                "usage_coefficient": 1.5,
                "add_as_new_host": False,
            },
        )
        self.service.get_node.assert_awaited_once_with(9)

    async def test_create_node_validation_failure_never_posts(self):
        self.service.request = AsyncMock()

        ok, error = await self.service.create_node(
            "USA-2",
            "https://node.example.com",
        )

        self.assertFalse(ok)
        self.assertIn("URL scheme", error)
        self.service.request.assert_not_awaited()

    async def test_create_node_duplicate_precheck_blocks_post(self):
        self.service.get_nodes = AsyncMock(return_value=(
            True,
            [{"id": 7, "name": "usa-2", "address": "old.example.com"}],
        ))
        self.service.request = AsyncMock()
        self.service.get_node = AsyncMock()

        ok, result = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "precheck")
        self.assertFalse(result["created"])
        self.assertTrue(result["duplicate"])
        self.assertEqual(result["node_id"], 7)
        self.service.request.assert_not_awaited()
        self.service.get_node.assert_not_awaited()

    async def test_create_node_precheck_failure_blocks_post(self):
        self.service.get_nodes = AsyncMock(return_value=(False, "Network Error"))
        self.service.request = AsyncMock()

        ok, result = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "precheck")
        self.assertFalse(result["created"])
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["error"], "Network Error")
        self.service.request.assert_not_awaited()

    async def test_create_node_post_failure_is_returned_without_verify(self):
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        self.service.request = AsyncMock(
            return_value=(False, {"status": 409, "detail": 'Node "USA-2" already exists'})
        )
        self.service.get_node = AsyncMock()

        ok, error = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertEqual(error["status"], 409)
        self.service.get_node.assert_not_awaited()

    async def test_create_node_reports_post_success_verify_failure_without_retry(self):
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        self.service.request = AsyncMock(return_value=(
            True,
            {
                "id": 9,
                "name": "USA-2",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "status": "connecting",
            },
        ))
        self.service.get_node = AsyncMock(return_value=(False, "Network Error"))

        ok, result = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertTrue(result["created"])
        self.assertEqual(result["stage"], "verify")
        self.assertEqual(result["node_id"], 9)
        self.assertEqual(result["error"], "Network Error")
        self.service.request.assert_awaited_once()
        self.service.get_node.assert_awaited_once_with(9)

    async def test_create_node_rejects_invalid_verified_node_id(self):
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        self.service.request = AsyncMock(return_value=(
            True,
            {
                "id": 9,
                "name": "USA-2",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "status": "connecting",
            },
        ))
        self.service.get_node = AsyncMock(return_value=(
            True,
            {
                "id": "not-an-id",
                "name": "USA-2",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "status": "connected",
            },
        ))

        ok, result = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertTrue(result["created"])
        self.assertEqual(result["node_id"], 9)
        self.assertIn("invalid node id", result["error"])


    async def test_create_node_rejects_mismatched_verified_identity(self):
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        self.service.request = AsyncMock(return_value=(
            True,
            {
                "id": 9,
                "name": "USA-2",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "status": "connecting",
            },
        ))
        self.service.get_node = AsyncMock(return_value=(
            True,
            {
                "id": 9,
                "name": "Different Node",
                "address": "node.example.com",
                "port": 62050,
                "api_port": 62051,
                "usage_coefficient": 1.0,
                "status": "connected",
            },
        ))

        ok, result = await self.service.create_node(
            "USA-2",
            "node.example.com",
        )

        self.assertFalse(ok)
        self.assertTrue(result["created"])
        self.assertEqual(result["node_id"], 9)
        self.assertIn("different name", result["error"])


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

    async def test_create_user_posts_dynamic_inbounds_and_verifies(self):
        current_inbounds = {
            "vless": [
                {"tag": "VLESS Reality", "protocol": "vless"},
                {"tag": "VLESS HTTP", "protocol": "vless"},
            ],
            "vmess": [{"tag": "VMess WS", "protocol": "vmess"}],
        }
        self.service.get_inbounds = AsyncMock(return_value=(True, current_inbounds))
        self.service.get_user = AsyncMock(return_value=(
            True,
            {
                "username": "nvl_demo01",
                "status": "active",
                "data_limit": 5 * 1024**3,
                "expire": 1234567890,
            },
        ))
        self.service.request = AsyncMock(return_value=(True, {"username": "nvl_demo01"}))

        ok, user = await self.service.create_user(
            "nvl_demo01",
            data_limit_bytes=5 * 1024**3,
            expire=1234567890,
        )

        self.assertTrue(ok)
        self.assertEqual(user["username"], "nvl_demo01")
        self.service.request.assert_awaited_once()
        args = self.service.request.await_args
        self.assertEqual(args.args[:2], ("POST", "/api/user"))
        payload = args.kwargs["json_data"]
        self.assertEqual(payload["data_limit"], 5 * 1024**3)
        self.assertEqual(payload["data_limit_reset_strategy"], "no_reset")
        self.assertEqual(
            payload["inbounds"],
            {
                "vless": ["VLESS Reality", "VLESS HTTP"],
                "vmess": ["VMess WS"],
            },
        )
        self.assertEqual(set(payload["proxies"]), {"vless", "vmess"})
        self.service.get_user.assert_awaited_once_with("nvl_demo01")

    async def test_create_on_hold_uses_duration_and_zero_absolute_expire(self):
        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            {"vless": [{"tag": "VLESS Reality", "protocol": "vless"}]},
        ))
        self.service.get_user = AsyncMock(return_value=(
            True,
            {"username": "holduser", "status": "on_hold"},
        ))
        self.service.request = AsyncMock(return_value=(True, {"username": "holduser"}))

        ok, _ = await self.service.create_user(
            "holduser",
            data_limit_bytes=0,
            expire=0,
            status="on_hold",
            on_hold_expire_duration=30 * 86400,
        )

        self.assertTrue(ok)
        payload = self.service.request.await_args.kwargs["json_data"]
        self.assertEqual(payload["status"], "on_hold")
        self.assertEqual(payload["expire"], 0)
        self.assertEqual(payload["on_hold_expire_duration"], 30 * 86400)

    async def test_create_user_reports_post_success_verify_failure_without_retry(self):
        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            {"vless": [{"tag": "VLESS Reality", "protocol": "vless"}]},
        ))
        self.service.get_user = AsyncMock(return_value=(False, "temporary verify error"))
        self.service.request = AsyncMock(return_value=(True, {"username": "nvl_demo02"}))

        ok, result = await self.service.create_user(
            "nvl_demo02",
            data_limit_bytes=1024**3,
            expire=0,
        )

        self.assertFalse(ok)
        self.assertTrue(result["created"])
        self.assertEqual(result["stage"], "verify")
        self.service.request.assert_awaited_once()

    async def test_create_user_rejects_removed_selected_inbound_before_post(self):
        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            {"vless": [{"tag": "Current", "protocol": "vless"}]},
        ))
        self.service.request = AsyncMock()

        ok, error = await self.service.create_user(
            "nvl_demo03",
            data_limit_bytes=1024**3,
            selected_inbound_tags=["Old Removed Tag"],
        )

        self.assertFalse(ok)
        self.assertIn("no longer exists", str(error))
        self.service.request.assert_not_awaited()

    async def test_update_host_uses_bulk_hosts_contract_for_target_tag(self):
        current = {
            "VLESS TCP REALITY": [
                {
                    "remark": "DE",
                    "address": "de.example.com",
                    "port": 443,
                    "sni": None,
                    "host": None,
                    "path": None,
                    "security": "inbound_default",
                    "alpn": "",
                    "fingerprint": "",
                    "allowinsecure": None,
                    "is_disabled": False,
                    "mux_enable": None,
                    "fragment_setting": None,
                    "noise_setting": None,
                    "random_user_agent": None,
                    "use_sni_as_host": None,
                },
                {
                    "remark": "FI",
                    "address": "fi.example.com",
                    "port": 443,
                },
            ],
            "VMess WS": [
                {"remark": "WS", "address": "ws.example.com", "port": 443},
            ],
        }
        self.service.get_hosts = AsyncMock(return_value=(True, current))
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            request.return_value = (True, {"VLESS TCP REALITY": []})
            ok, _ = await self.service.update_host(
                "VLESS TCP REALITY",
                0,
                expected_host=current["VLESS TCP REALITY"][0],
                address="new.example.com",
                port="8443",
            )

        self.assertTrue(ok)
        sent = request.await_args.kwargs["json_data"]
        self.assertEqual(set(sent), {"VLESS TCP REALITY"})
        self.assertEqual(sent["VLESS TCP REALITY"][0]["address"], "new.example.com")
        self.assertEqual(sent["VLESS TCP REALITY"][0]["port"], 8443)
        self.assertEqual(sent["VLESS TCP REALITY"][1]["remark"], "FI")
        request.assert_awaited_once()
        self.assertEqual(request.await_args.args[:2], ("PUT", "/api/hosts"))

    async def test_update_host_rejects_stale_confirmation_without_put(self):
        expected = {
            "remark": "DE",
            "address": "old.example.com",
            "port": 443,
        }
        current = {
            "VLESS TCP REALITY": [
                {
                    "remark": "DE",
                    "address": "changed-elsewhere.example.com",
                    "port": 443,
                }
            ]
        }
        self.service.get_hosts = AsyncMock(return_value=(True, current))
        with patch("v2ray_engine.api_request", new_callable=AsyncMock) as request:
            ok, error = await self.service.update_host(
                "VLESS TCP REALITY",
                0,
                expected_host=expected,
                address="new.example.com",
            )

        self.assertFalse(ok)
        self.assertIn("changed since confirmation", error)
        request.assert_not_awaited()

    async def test_disable_host_routes_through_safe_host_update(self):
        host = {"remark": "DE", "address": "de.example.com", "port": 443}
        self.service.update_host = AsyncMock(return_value=(True, {}))

        ok, _ = await self.service.set_host_disabled(
            "VLESS TCP REALITY",
            0,
            True,
            expected_host=host,
        )

        self.assertTrue(ok)
        self.service.update_host.assert_awaited_once_with(
            "VLESS TCP REALITY",
            0,
            expected_host=host,
            is_disabled=True,
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