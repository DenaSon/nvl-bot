"""F2: durable UID runtime persistence under existing 6G lock."""
from contextlib import contextmanager
import sqlite3
import tempfile
import unittest
from pathlib import Path

from edge_egress_inventory import ensure_schema
from edge_egress_legacy_fence import has_protected_bindings
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_uid_runtime_store import (
    Existing6GUIDRuntimeStore, RuntimeStoreUnsafe, install_runtime_schema,
    read_binding,
)
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec

SOURCE = "172.86.94.174"
TARGET = "216.126.229.12"
CORE = "209.200.246.198"


def spec():
    return EgressSpec(
        edge_id="fra1", edge_public_ipv4=TARGET,
        core_public_ipv4=CORE, tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30", edge_uplink="eth0",
        edge_listen_port=51832, route_table=1780,
    )


def req(name="nvl0557", uid=1644, priority=1780):
    return UIDPolicyRequest(spec(), name, uid, priority)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "core.db")
        with self.conn() as c:
            c.executescript("""
                CREATE TABLE failover_operations(
                  id INTEGER PRIMARY KEY, status TEXT,
                  source_host TEXT, target_host TEXT);
                INSERT INTO failover_operations VALUES
                  (42,'RUNNING','172.86.94.174','216.126.229.12');
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('dns_current_ip','172.86.94.174');
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,
                  active INTEGER,is_default INTEGER);
                INSERT INTO host_pool VALUES('172.86.94.174',1,1);
                CREATE TABLE ssh_accounts(
                  username TEXT PRIMARY KEY,host TEXT,
                  service_type TEXT,status TEXT);
                INSERT INTO ssh_accounts VALUES
                  ('nvl0557','172.86.94.174','ssh','🟢 فعال'),
                  ('nvl0558','172.86.94.174','ssh','🟢 فعال');
            """)
            ensure_schema(c)
            install_protected_mapping_schema(c)
            install_runtime_schema(c)
            c.execute("""
                INSERT INTO edge_egress_allocations (
                    edge_id, edge_public_ipv4,core_public_ipv4,
                    tunnel_network,veth_network,route_table,
                    edge_listen_port,edge_uplink,core_public_key,
                    edge_public_key,status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, ("fra1", TARGET, CORE, "10.78.100.0/30",
                  "10.78.101.0/30",1780,51832,"eth0",
                  "unused-public-core-key","unused-public-edge-key","STAGED"))
        self.store = Existing6GUIDRuntimeStore(
            self.conn, lambda name: {"nvl0557":1644,"nvl0558":1645}[name]
        )

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_blocked_intent_fences_legacy_before_kernel_mutation(self):
        row = self.store.reserve_blocked(42, req(), source=SOURCE,
                                         dns_port=10553)
        self.assertEqual(row.state, "BLOCKED")
        with self.conn() as c:
            self.assertTrue(has_protected_bindings(c))
            self.assertIsNone(c.execute(
                "SELECT username FROM edge_egress_uid_bindings"
            ).fetchone())

    def test_proof_cas_preserves_legacy_ssh_host_and_dns(self):
        self.store.reserve_blocked(42, req(), source=SOURCE, dns_port=10553)
        r = self.store.transition(42, req(), source=SOURCE,
                                  expected="BLOCKED", target="ROUTED_UNVERIFIED")
        self.assertEqual(r.state, "ROUTED_UNVERIFIED")
        protected = self.store.commit_protected(42, req(), source=SOURCE)
        self.assertEqual(protected.state, "PROTECTED")
        self.assertEqual(protected.generation, 3)
        with self.conn() as c:
            self.assertEqual(c.execute(
                "SELECT status FROM edge_egress_uid_bindings WHERE username='nvl0557'"
            ).fetchone(), ("PROTECTED",))
            self.assertEqual(c.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
            ).fetchone(), (SOURCE,))
            self.assertEqual(c.execute(
                "SELECT status FROM failover_operations WHERE id=42"
            ).fetchone(), ("RUNNING",))
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "STALE"):
            self.store.commit_protected(42, req(), source=SOURCE)

    def test_multiple_users_share_edge_table_but_priority_and_port_unique(self):
        self.store.reserve_blocked(42, req(), source=SOURCE, dns_port=10553)
        user2 = req("nvl0558", 1645, 1781)
        other = self.store.reserve_blocked(42, user2, source=SOURCE,
                                           dns_port=10554)
        self.assertEqual(other.route_table, 1780)
        self.assertEqual(other.priority, 1781)
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "ALREADY_EXISTS"):
            self.store.reserve_blocked(42, req(), source=SOURCE, dns_port=10555)

    def test_resource_collision_is_denied_transactionally(self):
        self.store.reserve_blocked(42, req(), source=SOURCE, dns_port=10553)
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "COLLISION"):
            self.store.reserve_blocked(42, req("nvl0558",1645,1780),
                                       source=SOURCE,dns_port=10554)
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "COLLISION"):
            self.store.reserve_blocked(42, req("nvl0558",1645,1781),
                                       source=SOURCE,dns_port=10553)
        with self.conn() as c:
            self.assertIsNone(read_binding(c, "nvl0558"))

    def test_lock_loss_is_fail_closed_without_unprotected_fallback(self):
        with self.conn() as c:
            c.execute("UPDATE failover_operations SET status='FAILED' WHERE id=42")
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "LOCK_NOT_CURRENT"):
            self.store.reserve_blocked(42, req(), source=SOURCE, dns_port=10553)
        with self.conn() as c:
            self.assertIsNone(read_binding(c, "nvl0557"))

    def test_freeze_and_hold_keep_protected_mapping(self):
        self.store.reserve_blocked(42, req(), source=SOURCE,dns_port=10553)
        self.store.transition(42,req(),source=SOURCE,expected="BLOCKED",
                              target="ROUTED_UNVERIFIED")
        self.store.commit_protected(42,req(),source=SOURCE)
        r = self.store.transition(42,req(),source=SOURCE,expected="PROTECTED",
                                  target="FROZEN")
        self.assertEqual(r.state, "FROZEN")
        with self.conn() as c:
            self.assertTrue(has_protected_bindings(c))
            self.assertIsNotNone(c.execute(
                "SELECT 1 FROM edge_egress_uid_bindings WHERE username='nvl0557'"
            ).fetchone())
        self.store.transition(42,req(),source=SOURCE,expected="FROZEN",
                              target="HOLD")

    def test_wrong_source_default_or_dns_prevents_binding(self):
        for statement in (
            "UPDATE host_pool SET is_default=0",
            "UPDATE settings SET value='209.200.246.198' WHERE key='dns_current_ip'",
        ):
            with self.subTest(statement=statement):
                with self.conn() as c:
                    c.execute(statement)
                with self.assertRaises(RuntimeStoreUnsafe):
                    self.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)
                with self.conn() as c:
                    c.execute("UPDATE host_pool SET is_default=1")
                    c.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                              (SOURCE,))

    def test_only_valid_frozen_protected_binding_can_resume(self):
        self.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "FROZEN_BINDING"):
            self.store.assert_frozen_binding(42,req(),source=SOURCE)
        self.store.transition(42,req(),source=SOURCE,expected="BLOCKED",
                              target="ROUTED_UNVERIFIED")
        self.store.commit_protected(42,req(),source=SOURCE)
        self.store.transition(42,req(),source=SOURCE,expected="PROTECTED",
                              target="FROZEN")
        self.assertEqual(self.store.assert_frozen_binding(
            42,req(),source=SOURCE).state,"FROZEN")
        with self.conn() as c:
            c.execute("DELETE FROM edge_egress_uid_bindings")
        with self.assertRaisesRegex(RuntimeStoreUnsafe,"FROZEN_PROTECTED"):
            self.store.assert_frozen_binding(42,req(),source=SOURCE)

    def test_foreign_edge_allocation_cannot_be_bound(self):
        with self.conn() as c:
            c.execute("UPDATE edge_egress_allocations SET status='RETIRED'")
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "STAGED_EDGE"):
            self.store.reserve_blocked(42, req(), source=SOURCE,dns_port=10553)


if __name__ == "__main__":
    unittest.main()
