import copy
import pathlib
import unittest
from unittest.mock import AsyncMock

import marzban_admin


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class V123B33DnsGuardTests(unittest.TestCase):
    def test_detached_guard_blocks_any_node_ip_overlap(self):
        resolver = lambda host: {
            "argus.nvlsup.xyz": ["45.61.149.116"],
            "mixed.nvlsup.xyz": ["45.61.149.116", "203.0.113.9"],
        }.get(host, [])

        attached = marzban_admin.preflight_public_endpoint_detached(
            "45.61.149.116",
            "argus.nvlsup.xyz",
            resolver=resolver,
        )
        mixed = marzban_admin.preflight_public_endpoint_detached(
            "45.61.149.116",
            "mixed.nvlsup.xyz",
            resolver=resolver,
        )
        detached = marzban_admin.preflight_public_endpoint_detached(
            "45.61.149.116",
            "new.nvlsup.xyz",
            resolver=lambda host: {
                "new.nvlsup.xyz": ["203.0.113.9"],
            }.get(host, []),
        )

        self.assertFalse(attached["ok"])
        self.assertFalse(mixed["ok"])
        self.assertEqual(attached["matched_ips"], ("45.61.149.116",))
        self.assertTrue(detached["ok"])
        self.assertTrue(detached["detached"])
        self.assertEqual(detached["matched_ips"], ())


class V123B33ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = marzban_admin.MarzbanAdminService(
            "https://marzban.example",
            "admin",
            "secret",
        )
        self.node = {
            "id": 1,
            "name": "Argus",
            "address": "45.61.149.116",
            "port": 62050,
            "api_port": 62051,
            "status": "connected",
        }
        self.public = "argus.nvlsup.xyz"
        self.remark = marzban_admin.node_generated_host_remark("Argus")
        self.tags = marzban_admin.NVL_NODE_PUBLIC_HOST_TAGS
        self.generated = marzban_admin.node_generated_host_payload(
            self.node,
            public_address=self.public,
        )

    async def test_preview_is_get_only_and_preserves_manual_same_endpoint_host(self):
        manual = copy.deepcopy(self.generated)
        manual["remark"] = "Manual customer host"
        hosts = {
            tag: [copy.deepcopy(self.generated)]
            for tag in self.tags
        }
        hosts[self.tags[0]].append(manual)

        self.service.get_node = AsyncMock(return_value=(True, copy.deepcopy(self.node)))
        self.service.get_hosts = AsyncMock(return_value=(True, copy.deepcopy(hosts)))
        self.service.request = AsyncMock()

        ok, plan = await self.service.preview_node_public_profile_delete(
            1,
            self.public,
            self.remark,
            self.tags,
        )

        self.assertTrue(ok)
        self.assertTrue(plan["read_only"])
        self.assertTrue(plan["deletable"])
        self.assertEqual(plan["managed_host_count"], len(self.tags))
        self.assertGreaterEqual(plan["manual_hosts_preserved"], 1)
        self.assertTrue(plan["fingerprint"])
        self.service.request.assert_not_awaited()

    async def test_stale_fingerprint_refuses_delete_before_remote_write(self):
        preview = {
            "stage": "managed_delete_preview",
            "read_only": True,
            "deleted": False,
            "deletable": True,
            "fingerprint": "current",
            "node": copy.deepcopy(self.node),
            "host_candidates": [],
        }
        self.service.preview_node_public_profile_delete = AsyncMock(
            return_value=(True, preview)
        )
        self.service.request = AsyncMock()

        ok, result = await self.service.delete_node_public_profile(
            1,
            self.public,
            self.remark,
            self.tags,
            expected_fingerprint="stale",
        )

        self.assertFalse(ok)
        self.assertEqual(result["stage"], "managed_delete_stale")
        self.assertFalse(result["deleted"])
        self.service.request.assert_not_awaited()

    async def test_verified_delete_removes_node_then_managed_hosts(self):
        candidates = [
            {"tag": tag, "index": 0, "host": copy.deepcopy(self.generated)}
            for tag in self.tags
        ]
        preview = {
            "stage": "managed_delete_preview",
            "read_only": True,
            "deleted": False,
            "deletable": True,
            "fingerprint": "fp",
            "node": copy.deepcopy(self.node),
            "host_candidates": candidates,
            "managed_host_count": len(candidates),
        }
        events = []

        self.service.preview_node_public_profile_delete = AsyncMock(
            return_value=(True, preview)
        )

        async def request(method, endpoint, *, json_data=None, params=None):
            events.append((method, endpoint))
            self.assertEqual((method, endpoint), ("DELETE", "/api/node/1"))
            return True, {"ok": True}

        self.service.request = AsyncMock(side_effect=request)
        self.service.get_nodes = AsyncMock(return_value=(True, []))
        self.service.delete_node_generated_hosts = AsyncMock(
            return_value=(True, {"deleted_count": len(candidates)})
        )
        self.service.get_hosts = AsyncMock(return_value=(True, {}))

        ok, result = await self.service.delete_node_public_profile(
            1,
            self.public,
            self.remark,
            self.tags,
            expected_fingerprint="fp",
        )

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertTrue(result["node_verified_absent"])
        self.assertEqual(result["hosts_deleted"], len(candidates))
        self.assertEqual(events, [("DELETE", "/api/node/1")])
        self.service.delete_node_generated_hosts.assert_awaited_once_with(candidates)

    async def test_cleanup_recovery_is_idempotent_when_hosts_are_already_gone(self):
        self.service.get_hosts = AsyncMock(side_effect=[
            (True, {}),
            (True, {}),
        ])
        self.service.delete_node_generated_hosts = AsyncMock()

        ok, result = await self.service.cleanup_managed_public_hosts(
            self.public,
            self.remark,
            self.tags,
        )

        self.assertTrue(ok)
        self.assertTrue(result["verified"])
        self.assertEqual(result["deleted_count"], 0)
        self.service.delete_node_generated_hosts.assert_not_awaited()


class V123B33UiRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker_and_safe_delete_preview_are_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V124-2026-10-07-critical-only-regional-notifications"',
            self.source,
        )
        starter = self._region(
            "elif d.startswith('mza_ndelete_'):",
            "elif d.startswith('mza_nreconnect_'):",
        )
        self.assertIn("V123B.3.3 · Safe Delete Preview", starter)
        self.assertIn("preflight_public_endpoint_detached", starter)
        self.assertIn("DNS Detached", starter)
        self.assertIn("preview_node_public_profile_delete", starter)
        self.assertIn("Other/Manual Hosts preserved", starter)

    def test_confirm_marks_deleting_before_first_remote_delete(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_ndelete_'):",
        )
        pending_pos = region.index("_db_upsert_marzban_node_public_profile")
        remote_pos = region.index("service.delete_node_public_profile(")
        self.assertLess(pending_pos, remote_pos)
        self.assertIn('"deleting"', region)
        self.assertIn("preflight_public_endpoint_detached", region)
        self.assertIn("fingerprint", region)
        self.assertIn("_db_delete_marzban_node_public_profile", region)

    def test_recovery_never_blindly_redeletes_absent_node(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_cleanup_'):",
            "elif d.startswith('mza_ndelete_confirm_'):",
        )
        self.assertIn("service.get_nodes()", region)
        self.assertIn("cleanup_managed_public_hosts", region)
        self.assertIn('profile_state") or "").lower() != "deleting"', region)
        self.assertNotIn("service.delete_node_public_profile(", region)
        self.assertNotIn("service.delete_node(", region)

    def test_legacy_unmanaged_delete_path_remains_available(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_ndelete_'):",
        )
        self.assertIn("Legacy / unmanaged Node path", region)
        self.assertIn("ok_delete, result = await service.delete_node(node_id)", region)

    def test_db_profile_state_supports_deleting_and_guarded_removal(self):
        self.assertIn('{"pending", "verified", "deleting"}', self.source)
        self.assertIn("def _db_delete_marzban_node_public_profile(", self.source)
        self.assertIn("expected_public_address", self.source)
        self.assertIn("expected_state", self.source)


if __name__ == "__main__":
    unittest.main()
