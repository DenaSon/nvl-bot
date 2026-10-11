"""F3 readiness: no lab proof may be promoted to customer-ready."""
from contextlib import contextmanager
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from edge_egress_f3_readiness import (
    Existing6GReadinessStore, ReadinessUnsafe, admission_eligible,
    assignment_preview, install_readiness_schema, read_readiness,
    stage_in_existing_6g_transaction,
)

SOURCE="172.86.94.174"
EDGE="216.126.229.12"


class F3ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.temp.name)/"fake.db")
        with self.conn() as c:
            c.executescript("""
                CREATE TABLE failover_operations (
                  id INTEGER PRIMARY KEY, status TEXT, source_host TEXT,
                  target_host TEXT);
                INSERT INTO failover_operations VALUES
                  (42,'RUNNING','172.86.94.174','216.126.229.12');
                CREATE TABLE edge_egress_allocations (
                  edge_id TEXT PRIMARY KEY,edge_public_ipv4 TEXT,
                  status TEXT);
                INSERT INTO edge_egress_allocations VALUES
                  ('fra1','216.126.229.12','STAGED');
                CREATE TABLE ssh_accounts (
                  username TEXT,service_type TEXT,status TEXT);
                INSERT INTO ssh_accounts VALUES('nvl0557','ssh','🟢 فعال');
            """)
            install_readiness_schema(c)
        self.store=Existing6GReadinessStore(self.conn)

    @contextmanager
    def conn(self):
        c=sqlite3.connect(self.path)
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def tearDown(self):
        self.temp.cleanup()

    def stage(self):
        return self.store.mark_staged(42,source=SOURCE,edge_id="fra1",target=EDGE)

    def test_stage_is_not_customer_ready(self):
        row=self.stage()
        self.assertEqual(row.state,"STAGED")
        self.assertFalse(admission_eligible(row))
        with self.conn() as c:
            self.assertEqual(
                assignment_preview(c,"nvl0557","fra1")["reason"],
                "F4_PRODUCTION_EVIDENCE_REQUIRED")

    def test_verified_namespace_ip_is_only_a_lab_witness(self):
        self.stage()
        now=int(time.time())
        result=self.store.record_lab_verification(
            42,source=SOURCE,edge_id="fra1",target=EDGE,
            observed_ip=EDGE,now=now)
        self.assertEqual(result.state,"VERIFIED_LAB")
        self.assertEqual(result.witness,"PINNED_SHADOW_NAMESPACE")
        self.assertFalse(admission_eligible(result,now=now+1))
        with self.conn() as c:
            self.assertEqual(
                assignment_preview(c,"nvl0557","fra1")["reason"],
                "LAB_PROOF_NOT_CUSTOMER_READY")

    def test_wrong_public_ip_missing_stage_or_bad_ttl_refused(self):
        self.stage()
        for ip in ("209.200.246.198","not-an-ip","127.0.0.1"):
            with self.subTest(ip=ip):
                with self.assertRaises(ReadinessUnsafe):
                    self.store.record_lab_verification(
                        42,source=SOURCE,edge_id="fra1",
                        target=EDGE,observed_ip=ip)
        with self.assertRaisesRegex(ReadinessUnsafe,"TTL"):
            self.store.record_lab_verification(
                42,source=SOURCE,edge_id="fra1",target=EDGE,
                observed_ip=EDGE,ttl_seconds=1)
        with self.conn() as c:
            self.assertEqual(read_readiness(c,"fra1").state,"STAGED")

    def test_lost_6g_lock_blocks_verification_and_stage(self):
        self.stage()
        with self.conn() as c:
            c.execute("UPDATE failover_operations SET status='FAILED'")
        with self.assertRaisesRegex(ReadinessUnsafe,"LEASE_NOT_CURRENT"):
            self.store.record_lab_verification(
                42,source=SOURCE,edge_id="fra1",target=EDGE,
                observed_ip=EDGE)
        with self.assertRaisesRegex(ReadinessUnsafe,"LEASE_NOT_CURRENT"):
            self.stage()

    def test_incomplete_cleanup_hold_revokes_prior_evidence(self):
        self.stage()
        self.store.record_lab_verification(
            42,source=SOURCE,edge_id="fra1",target=EDGE,
            observed_ip=EDGE)
        held=self.store.hold(42,source=SOURCE,edge_id="fra1",target=EDGE)
        self.assertEqual(held.state,"HOLD")
        self.assertIsNone(held.observed_ipv4)
        self.assertFalse(admission_eligible(held))
        with self.assertRaisesRegex(ReadinessUnsafe,"UNSAFE_READINESS"):
            self.store.record_lab_verification(
                42,source=SOURCE,edge_id="fra1",
                target=EDGE,observed_ip=EDGE)

    def test_stage_atomic_hook_requires_existing_6g_transaction(self):
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            stage_in_existing_6g_transaction(
                c,42,source=SOURCE,edge_id="fra1",target=EDGE)
        with self.conn() as c:
            self.assertEqual(read_readiness(c,"fra1").state,"STAGED")
            c.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(ReadinessUnsafe,"EXISTING_READINESS"):
                stage_in_existing_6g_transaction(
                    c,42,source=SOURCE,edge_id="fra1",target=EDGE)

    def test_absence_of_f3_migration_keeps_legacy_staging_only(self):
        with self.conn() as c:
            c.execute("DROP TABLE edge_egress_readiness")
            c.execute("BEGIN IMMEDIATE")
            stage_in_existing_6g_transaction(
                c,42,source=SOURCE,edge_id="fra1",target=EDGE)
            tables=c.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name='edge_egress_readiness'").fetchall()
            self.assertEqual(tables,[])

    def test_future_f4_witness_still_expires(self):
        self.stage()
        with self.conn() as c:
            c.execute(
                "UPDATE edge_egress_readiness "
                "SET state='READY',witness='F4_PRODUCTION_ACCEPTANCE',"
                "observed_ipv4=?,probed_at=1000,expires_at=1050",
                (EDGE,),
            )
            row=read_readiness(c,"fra1")
        self.assertTrue(admission_eligible(row,now=1020))
        self.assertFalse(admission_eligible(row,now=1050))
        self.assertFalse(admission_eligible(row,now=1060))

if __name__=="__main__":
    unittest.main()
