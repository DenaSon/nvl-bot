"""Offline K2: bind SSH account host ONLY after protected UID route proof.

Synthetic F4 rows here are fixtures. These tests never attest production safety.
"""
from __future__ import annotations

import asyncio
import json
from hashlib import sha256
import sqlite3
import time
import unittest

from edge_egress_k2_customer_move import (
    K2_LIVE_HOST_BINDING_ENABLED, CustomerBindingHold,
    GuardedCustomerIngressBindingPort,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, _scope_digest, INTENT_PHASE,
)


class FakeUIDPort:
    def __init__(self, db):
        self.db = db
        self.healthy = True
        self.calls = []

    async def apply(self, scope):
        self.calls.append("apply")
        with self.db() as c:
            c.execute("INSERT INTO edge_egress_uid_runtime VALUES(?,?,?,?,?)",
                      (scope.username, scope.uid, scope.edge_id, scope.target_host,
                       "PROTECTED"))
            c.execute("INSERT INTO edge_egress_uid_bindings VALUES(?,?,?,?,?)",
                      (scope.username, scope.uid, scope.edge_id, scope.target_host,
                       "PROTECTED"))

    async def verify(self, scope):
        self.calls.append("verify")
        return self.healthy

    async def freeze_or_hold(self, scope):
        self.calls.append("freeze")
        with self.db() as c:
            c.execute("UPDATE edge_egress_uid_runtime SET state='HOLD' WHERE username=?",
                      (scope.username,))


class GuardedCustomerBindingTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(":memory:")
        self.addCleanup(self.c.close)
        self.db = lambda: self.c
        self.scope = ExecutionScope(
            "UID_ATTACH", "fra1", "104.194.144.195", "216.126.229.12",
            username="canary", uid=1655,
        )
        self.ticket = ExecutionTicket(123, 456, "b"*32, 2**40,
                                      _scope_digest(self.scope), "a"*64)
        self.c.executescript("""
        CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
        INSERT INTO settings VALUES('edge_egress_protected_mode','1');
        CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                                  service_type TEXT,status TEXT);
        INSERT INTO ssh_accounts VALUES
          ('canary','104.194.144.195','ssh','🟢 فعال'),
          ('other','104.194.144.195','ssh','🟢 فعال');
        CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER);
        INSERT INTO host_pool VALUES('216.126.229.12',1);
        CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT,
          source_host TEXT,target_host TEXT,detail_json TEXT);
        CREATE TABLE edge_egress_allocations(edge_id TEXT,
          edge_public_ipv4 TEXT,status TEXT);
        INSERT INTO edge_egress_allocations VALUES(
          'fra1','216.126.229.12','STAGED');
        CREATE TABLE edge_egress_readiness(
          edge_id TEXT,edge_ipv4 TEXT,state TEXT,observed_ipv4 TEXT,
          witness TEXT,probed_at INTEGER,expires_at INTEGER,
          generation INTEGER,last_operation_id INTEGER);
        CREATE TABLE edge_egress_uid_runtime(
          username TEXT,uid INTEGER,edge_id TEXT,edge_ipv4 TEXT,state TEXT);
        CREATE TABLE edge_egress_uid_bindings(
          username TEXT,uid INTEGER,edge_id TEXT,edge_ipv4 TEXT,status TEXT);
        """)
        now = int(time.time())
        self.c.execute("INSERT INTO edge_egress_readiness VALUES(?,?,?,?,?,?,?,?,?)",
                       ("fra1", "216.126.229.12", "READY",
                        "216.126.229.12", "F4_PRODUCTION_ACCEPTANCE",
                        now - 5, now + 200, 1, 17))
        detail = {
            "phase": INTENT_PHASE, "kind": "K2_P3A",
            "nonce_hash": sha256(self.ticket.nonce.encode()).hexdigest(),
            "scope_digest": _scope_digest(self.scope),
        }
        self.c.execute("INSERT INTO failover_operations VALUES(?,?,?,?,?)",
                       (17, "RUNNING", self.scope.source_host,
                        self.scope.target_host, json.dumps(detail)))
        self.uid = FakeUIDPort(self.db)

    def make(self, **options):
        return GuardedCustomerIngressBindingPort(
            db_conn=self.db,scope=self.scope,ticket=self.ticket,
            uid_port=self.uid, independent_ingress_proof=lambda _: True,
            **options,
        )

    def host(self, user="canary"):
        return self.c.execute(
            "SELECT host FROM ssh_accounts WHERE username=?", (user,)
        ).fetchone()[0]

    def test_default_is_release_disabled_without_any_write(self):
        self.assertFalse(K2_LIVE_HOST_BINDING_ENABLED)
        p = self.make()
        with self.assertRaisesRegex(CustomerBindingHold, "NOT_RELEASED"):
            asyncio.run(p.apply(self.scope))
        self.assertEqual(self.host(),self.scope.source_host)
        self.assertEqual(self.uid.calls,[])

    def test_verified_uid_route_then_exact_host_cas(self):
        p = self.make(release_enabled=True)
        asyncio.run(p.apply(self.scope))
        self.assertTrue(asyncio.run(p.verify(self.scope)))
        self.assertEqual(self.host(),self.scope.target_host)
        self.assertEqual(self.host("other"),self.scope.source_host)
        self.assertEqual(self.uid.calls,["apply","verify","verify"])
        with self.assertRaisesRegex(CustomerBindingHold,"ONE_SHOT"):
            asyncio.run(p.apply(self.scope))

    def test_bad_independent_ingress_never_moves_host(self):
        p = GuardedCustomerIngressBindingPort(
            db_conn=self.db,scope=self.scope,ticket=self.ticket,
            uid_port=self.uid,independent_ingress_proof=lambda _:False,
            release_enabled=True,
        )
        with self.assertRaisesRegex(CustomerBindingHold,"INGRESS_NOT_ATTESTED"):
            asyncio.run(p.apply(self.scope))
        self.assertEqual(self.host(),self.scope.source_host)
        asyncio.run(p.freeze_or_hold(self.scope))
        self.assertIn("freeze",self.uid.calls)

    def test_readiness_expiry_prevents_host_commit(self):
        self.c.execute(
            "UPDATE edge_egress_readiness SET expires_at=?",
            (int(time.time()) - 10,),
        )
        p=self.make(release_enabled=True)
        with self.assertRaisesRegex(CustomerBindingHold,"F4_ACCEPTANCE"):
            asyncio.run(p.apply(self.scope))
        self.assertEqual(self.host(),self.scope.source_host)

    def test_lock_loss_prevents_host_commit(self):
        old_apply = self.uid.apply
        async def unstable(scope):
            await old_apply(scope)
            self.c.execute("UPDATE failover_operations SET status='FAILED'")
        self.uid.apply=unstable
        p=self.make(release_enabled=True)
        with self.assertRaises(Exception):
            asyncio.run(p.apply(self.scope))
        self.assertEqual(self.host(),self.scope.source_host)

    def test_host_drift_prevents_any_uid_mutation(self):
        self.c.execute("UPDATE ssh_accounts SET host='198.51.100.3' "
                       "WHERE username='canary'")
        p=self.make(release_enabled=True)
        with self.assertRaisesRegex(CustomerBindingHold,"OLD_ACCOUNT_HOST_CHANGED"):
            asyncio.run(p.apply(self.scope))
        self.assertEqual(self.uid.calls,[])


if __name__ == "__main__":
    unittest.main()
