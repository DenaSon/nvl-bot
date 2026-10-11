"""D1-C3B: the UID canary reuses actual Phase 6G DB lock/journal APIs."""
import asyncio
import json
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_6g_bridge import Existing6GUIDCanaryAdapter
from edge_egress_uid_lifecycle import run_disposable_uid_canary
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def request(uid=1644):
    return UIDPolicyRequest(EgressSpec.from_json({
        "edge_id": "fra1",
        "edge_public_ipv4": "216.126.229.12",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": "10.78.100.0/30",
        "veth_network": "10.78.101.0/30",
        "edge_uplink": "eth0",
        "edge_listen_port": 51832,
        "route_table": 1780,
        "mode": "relay",
    }), "nvl0557", uid)


class FakeKernel:
    def __init__(self):
        self.events = []

    async def preflight(self, request):
        self.events.append("preflight")
    async def arm_guard(self, request):
        self.events.append("arm")
    async def attach_edge(self, request):
        self.events.append("attach")
    async def public_ip(self, request):
        self.events.append("proof")
        return "216.126.229.12"
    async def check_ipv6_dns(self, request):
        self.events.append("ipv6_dns")
    async def freeze_uid(self, request):
        self.events.append("freeze")
    async def restore(self, request):
        self.events.append("restore")


class FakeShadow:
    async def preflight(self, request): pass
    async def start(self, request): pass
    async def stop(self, request): pass


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE failover_operations(
              id INTEGER PRIMARY KEY, status TEXT,
              source_host TEXT, target_host TEXT, detail_json TEXT);
            INSERT INTO failover_operations(id,status,source_host,target_host)
              VALUES(14,'RUNNING','172.86.94.174','216.126.229.12');
            CREATE TABLE host_pool(
              host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
              is_standby INTEGER,service_port INTEGER);
            INSERT INTO host_pool VALUES ('172.86.94.174',1,1,0,2252);
            INSERT INTO host_pool VALUES ('216.126.229.12',1,0,1,2252);
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('dns_current_ip','172.86.94.174');
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE ssh_accounts(
              username TEXT,host TEXT,service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts
              VALUES('nvl0557','172.86.94.174','ssh','فعال');
        """)
        self.db.commit()
        self.kernel = FakeKernel()
        self.updates = []

    def tearDown(self):
        self.db.close()

    def acquire(self, src, dst):
        return 14, None

    def update(self, operation_id, *, status, detail, finished, require_running):
        self.assertTrue(require_running)
        old = self.db.execute("SELECT status FROM failover_operations WHERE id=?",
                              (operation_id,)).fetchone()
        if old != ("RUNNING",):
            raise RuntimeError("CAS failed")
        self.updates.append((status, detail["phase"]))
        self.db.execute("UPDATE failover_operations SET status=?,detail_json=? WHERE id=?",
                        (status, json.dumps(detail), operation_id))
        self.db.commit()

    def adapter(self):
        return Existing6GUIDCanaryAdapter(
            lambda: self.db, self.acquire, self.update,
            self.kernel, FakeShadow()
        )

    def test_lock_and_real_db_account_recheck_allow_disposable_canary(self):
        with patch("edge_egress_uid_6g_bridge.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)):
            result = asyncio.run(run_disposable_uid_canary(
                self.adapter(), request(), source_edge="172.86.94.174",
                explicitly_authorized=True))
        self.assertTrue(result.ok, result)
        self.assertEqual(self.db.execute(
            "SELECT status FROM failover_operations WHERE id=14"
        ).fetchone(), ("SUCCEEDED",))
        self.assertEqual(self.kernel.events,
                         ["preflight", "arm", "attach", "proof",
                          "ipv6_dns", "freeze", "restore"])

    def test_os_account_identity_change_blocks_before_mutation(self):
        with patch("edge_egress_uid_6g_bridge.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1645)):
            result = asyncio.run(run_disposable_uid_canary(
                self.adapter(), request(), source_edge="172.86.94.174",
                explicitly_authorized=True))
        self.assertFalse(result.ok)
        self.assertNotIn("arm", self.kernel.events)
        self.assertEqual(self.updates[-1][0], "FAILED")

    def test_protected_mode_is_never_restored_to_unprotected(self):
        self.db.execute(
            "UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'")
        self.db.commit()
        with patch("edge_egress_uid_6g_bridge.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)):
            result = asyncio.run(run_disposable_uid_canary(
                self.adapter(), request(), source_edge="172.86.94.174",
                explicitly_authorized=True))
        self.assertFalse(result.ok)
        self.assertNotIn("arm", self.kernel.events)
        self.assertEqual(self.updates[-1][0], "FAILED")


if __name__ == "__main__":
    unittest.main()
