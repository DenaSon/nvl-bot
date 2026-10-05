import copy
import unittest
from unittest.mock import AsyncMock

import marzban_admin


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


class ManagedNodePublicHostTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        self.node = {
            "id": 9,
            "name": "Pingo✅",
            "address": "172.86.72.203",
        }

    async def test_reconcile_keeps_only_nvl_profile_and_preserves_manual_hosts(self):
        generated = marzban_admin.node_generated_host_payload(self.node)
        manual = dict(generated)
        manual["remark"] = "Manual Host"

        state = {
            "Shadowsocks TCP": [],
            "VLESS TCP REALITY": [],
            "Trojan WS": [],
            "VMess WS": [dict(generated), manual],
        }

        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            _inbounds(
                "Shadowsocks TCP",
                "VLESS TCP REALITY",
                "Trojan WS",
                "VMess WS",
            ),
        ))

        async def get_hosts():
            return True, copy.deepcopy(state)

        async def request(method, endpoint, *, json_data=None, params=None):
            self.assertEqual(method, "PUT")
            self.assertEqual(endpoint, "/api/hosts")
            self.assertIsNone(params)
            self.assertEqual(len(json_data), 1)
            tag, hosts = next(iter(json_data.items()))
            state[tag] = copy.deepcopy(hosts)
            return True, {"ok": True}

        self.service.get_hosts = AsyncMock(side_effect=get_hosts)
        self.service.request = AsyncMock(side_effect=request)

        ok, result = await self.service.reconcile_node_public_hosts(self.node)

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertEqual(
            tuple(result["managed_tags"]),
            marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS,
        )

        for tag in marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS:
            matches = [
                host for host in state[tag]
                if host["remark"] == generated["remark"]
                and host["address"] == generated["address"]
            ]
            self.assertEqual(len(matches), 1, tag)

        generated_on_vmess = [
            host for host in state["VMess WS"]
            if host["remark"] == generated["remark"]
            and host["address"] == generated["address"]
        ]
        self.assertEqual(generated_on_vmess, [])
        self.assertEqual(
            [host["remark"] for host in state["VMess WS"]],
            ["Manual Host"],
        )

    async def test_reconcile_is_idempotent(self):
        generated = marzban_admin.node_generated_host_payload(self.node)
        state = {
            tag: [copy.deepcopy(generated)]
            for tag in marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        }

        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            _inbounds(*marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS),
        ))

        async def get_hosts():
            return True, copy.deepcopy(state)

        self.service.get_hosts = AsyncMock(side_effect=get_hosts)
        self.service.request = AsyncMock()

        ok, result = await self.service.reconcile_node_public_hosts(self.node)

        self.assertTrue(ok)
        self.assertEqual(result["changed_tags"], [])
        self.service.request.assert_not_awaited()

    async def test_missing_required_inbound_fails_closed_before_writes(self):
        self.service.get_inbounds = AsyncMock(return_value=(
            True,
            _inbounds("Shadowsocks TCP", "VLESS TCP REALITY"),
        ))
        self.service.get_hosts = AsyncMock()
        self.service.request = AsyncMock()

        ok, result = await self.service.reconcile_node_public_hosts(self.node)

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "host_profile_precheck")
        self.assertIn("Trojan WS", result["error"])
        self.service.get_hosts.assert_not_awaited()
        self.service.request.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
