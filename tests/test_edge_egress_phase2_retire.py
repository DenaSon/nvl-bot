"""Offline safety contracts for Phase 2 K2 Edge retirement."""
import base64
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edge_egress_v1_ingress import parse_registry
from edge_egress_phase2_retire import (
    RetireHold, issue_ticket, legacy_delete_managed, plan_retirement,
    plan_html, retire_metadata,
)


class Phase2RetireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.db = self.base / "nvl.db"
        self.registry = self.base / "ingress.json"
        self.stage = self.base / "stage"
        self.stage.mkdir()
        self.registry.write_text(json.dumps({
            "version": 1, "peers": [{
                "edge_id": "e7", "edge_ipv4": "172.86.105.67",
                "ingress_ipv4": "10.77.0.7",
                "wg_public_key": base64.b64encode(b"\x03" * 32).decode(),
            }],
        }))
        with self.conn() as db:
            db.executescript("""
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,is_default INT);
                CREATE TABLE ssh_accounts(username TEXT,host TEXT);
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE failover_operations(status TEXT);
                CREATE TABLE edge_egress_f3_ingress_candidates(edge_ipv4 TEXT PRIMARY KEY,state TEXT);
                CREATE TABLE edge_egress_allocations(edge_id TEXT,edge_public_ipv4 TEXT);
                CREATE TABLE edge_egress_readiness(edge_id TEXT,edge_ipv4 TEXT);
                CREATE TABLE edge_egress_uid_bindings(edge_id TEXT,edge_ipv4 TEXT);
                CREATE TABLE edge_egress_uid_runtime(edge_id TEXT,edge_ipv4 TEXT);
                INSERT INTO settings VALUES('edge_egress_protected_mode','0');
                INSERT INTO settings VALUES('dns_current_ip','144.172.84.82');
                INSERT INTO edge_egress_f3_ingress_candidates VALUES('172.86.105.67','INGRESS_ONLY');
            """)
        self.read_registry = lambda: parse_registry(self.registry.read_bytes())
        self.probe = lambda eid, src, pubkey: ()

    def conn(self):
        return sqlite3.connect(str(self.db))

    def plan(self):
        return plan_retirement(self.conn, "e7", registry_path=self.registry,
                               registry_loader=self.read_registry,
                               runtime_probe=self.probe, stage_root=self.stage)

    def test_clean_inactive_ingress_candidate_is_eligible_for_metadata_only(self):
        p = self.plan()
        self.assertTrue(p.allowed)
        self.assertEqual(p.edge_ipv4, "172.86.105.67")
        self.assertIn("قابل حذف", plan_html(p))

    def test_blocks_dns_default_and_active_pool(self):
        with self.conn() as db:
            db.execute("UPDATE settings SET value='172.86.105.67' WHERE key='dns_current_ip'")
            db.execute("INSERT INTO host_pool VALUES('172.86.105.67',1,1)")
        p = self.plan()
        self.assertIn("EDGE_IS_PUBLIC_DNS", p.blockers)
        self.assertIn("HOST_POOL_ACTIVE_OR_DEFAULT", p.blockers)

    def test_blocks_even_one_ssh_user(self):
        with self.conn() as db:
            db.execute("INSERT INTO ssh_accounts VALUES('client','172.86.105.67')")
        self.assertIn("SSH_ACCOUNT_DEPENDENCY", self.plan().blockers)

    def test_running_6g_holds(self):
        with self.conn() as db:
            db.execute("INSERT INTO failover_operations VALUES('RUNNING')")
        self.assertIn("6G_RUNNING", self.plan().blockers)

    def test_live_kernel_routes_hold(self):
        self.probe = lambda edge, src, pubkey: ("EGRESS_POLICY_RULE_PRESENT",)
        self.assertIn("EGRESS_POLICY_RULE_PRESENT", self.plan().blockers)

    def test_kernel_probe_failure_never_allows_delete(self):
        def fail(*args):
            raise RetireHold("missing sudo privilege")
        self.probe = fail
        self.assertIn("KERNEL_AUDIT_HOLD", self.plan().blockers)

    def test_local_stage_holds_even_if_db_has_no_allocation(self):
        (self.stage / "core-e7").mkdir()
        self.assertIn("LOCAL_STAGE_PRESENT", self.plan().blockers)

    def test_protected_uid_row_blocks_without_ssh_host_match(self):
        with self.conn() as db:
            db.execute("INSERT INTO edge_egress_uid_runtime VALUES('e7','172.86.105.67')")
        self.assertIn("EDGE_EGRESS_UID_RUNTIME_DEPENDENCY", self.plan().blockers)

    def test_protected_mode_holds(self):
        with self.conn() as db:
            db.execute("UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'")
        self.assertIn("PROTECTED_MODE_NOT_LEGACY", self.plan().blockers)

    def test_f3_conflicting_state_holds(self):
        with self.conn() as db:
            db.execute("UPDATE edge_egress_f3_ingress_candidates SET state='READY'")
        self.assertIn("F3_CANDIDATE_CONFLICT", self.plan().blockers)

    def test_old_hostpool_delete_cannot_bypass_k2_even_mode_zero(self):
        self.assertTrue(legacy_delete_managed(self.conn, "172.86.105.67",
                                               registry_loader=self.read_registry))
        self.assertFalse(legacy_delete_managed(self.conn, "203.0.113.20",
                                                registry_loader=self.read_registry))

    def test_ticket_binds_actor_chat_edge_and_expiry(self):
        p = self.plan()
        t = issue_ticket(p, actor_id=42, chat_id=72, now=lambda: 100)
        self.assertEqual((t.actor_id,t.chat_id,t.edge_id,t.expiry), (42,72,"e7",220))
        with self.assertRaises(RetireHold):
            issue_ticket(type(p)("e7",p.edge_ipv4,p.fingerprint,("HOLD",),False),42,72)
        with self.assertRaises(RetireHold):
            retire_metadata(self.conn, t, actor_id=43, chat_id=72, edge_id="e7",
                            now=lambda: 101, registry_path=self.registry,
                            registry_loader=self.read_registry, geteuid=lambda: 0)
        with self.assertRaises(RetireHold):
            retire_metadata(self.conn, t, actor_id=42, chat_id=72, edge_id="e7",
                            now=lambda: 220, registry_path=self.registry,
                            registry_loader=self.read_registry, geteuid=lambda: 0)


if __name__ == "__main__":
    unittest.main()
