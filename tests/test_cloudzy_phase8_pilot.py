"""Phase 8 live-pilot preflight: isolated DB; all production probes are read-only."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

from cloudzy_phase8_pilot import evaluate_pilot, open_core_readonly, main

SRC, DST = "203.0.113.11", "203.0.113.12"
DNS_SRC = [{"name": "n1.test", "id": "record-1", "ip": SRC, "ttl": 60}]
DNS_DST = [{"name": "n1.test", "id": "record-1", "ip": DST, "ttl": 60}]


class PilotReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "test.db"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.executescript("""
          CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
          CREATE TABLE host_pool(
            host TEXT,active INTEGER,is_default INTEGER,is_standby INTEGER,
            provider TEXT,provider_instance_id TEXT);
          CREATE TABLE ssh_accounts(username TEXT,host TEXT,status TEXT,service_type TEXT);
          CREATE TABLE failover_operations(status TEXT);
          CREATE TABLE cloudzy_cz04a_actions(status TEXT);
          CREATE TABLE cloudzy_cz04b_operations(status TEXT);
          CREATE TABLE cloudzy_edge_operations(
            id TEXT,status TEXT,public_ipv4 TEXT,provider_server_id TEXT);
          CREATE TABLE cloudzy_cz06_runs(
            operation_id TEXT,stage TEXT,actor_id INTEGER,chat_id INTEGER,
            updated_at INTEGER);
          CREATE TABLE cloudzy_cz07_jobs(
            id TEXT,status TEXT,source TEXT,target TEXT,moved INTEGER,
            total INTEGER,actor INTEGER,started_at INTEGER);
          CREATE TABLE cloudzy_cz07_acceptance(
            job_id TEXT,actor INTEGER,create_ref TEXT,renew_ref TEXT,client_ref TEXT);
        """)
        self.db.executemany("INSERT INTO settings VALUES (?,?)", [
            ("hosts", SRC),("dns_current_ip",SRC),
            ("core_wg_public_ip","203.0.113.10")])
        self.db.executemany("INSERT INTO host_pool VALUES (?,?,?,?,?,?)", [
            (SRC,1,1,0,"legacy",""),
            (DST,1,0,1,"cloudzy","provider-1")])
        self.db.executemany("INSERT INTO ssh_accounts VALUES (?,?,?,?)",
                            [(f"user{i}",SRC,"🟢 فعال","ssh") for i in range(4)])
        self.db.execute("INSERT INTO cloudzy_edge_operations VALUES (?,?,?,?)",
                        ("p1","EDGE_READY",DST,"provider-1"))
        self.db.execute("INSERT INTO cloudzy_cz06_runs VALUES (?,?,?,?,?)",
                        ("p1","READY",7,7,10))
        self.db.commit()

    def inspect(self, phase, **kwargs):
        return evaluate_pilot(self.db, phase=phase, **kwargs)

    def test_purchase_ready_does_not_prove_charge_or_migrate(self):
        r=self.inspect("purchase")
        self.assertEqual(r.verdict,"READY_FOR_PURCHASE_TEST")
        self.assertFalse(r.blockers)
        self.assertIn("AUTHORIZE_ONE_CHARGEABLE_CZ03_ORDER", r.next_checks)
        self.assertEqual(r.cohort,4)

    def test_paid_unknown_order_blocks_double_purchase(self):
        self.db.execute("INSERT INTO cloudzy_edge_operations VALUES (?,?,?,?)",
                        ("pending","CREATE_UNCERTAIN",None,None))
        self.assertIn("UNSETTLED_CLOUDZY_PURCHASE",
                      self.inspect("purchase").blockers)

    def test_exact_live_dns_and_independent_client_proof_are_distinct(self):
        r=self.inspect("cutover",expected_target=DST,max_accounts=4)
        self.assertEqual(r.verdict,"READY_FOR_LIVE_DNS_TEST")
        self.assertIn("RUN_CLOUDFLARE_LIVE_GET",r.next_checks)
        r=self.inspect("cutover",expected_target=DST,max_accounts=4,
                       live_dns=DNS_SRC)
        self.assertEqual(r.verdict,"READY_FOR_CLIENT_TEST")
        self.assertIn("VERIFY_REAL_CLIENT_FROM_AFFECTED_ISP",r.next_checks)
        r=self.inspect("cutover",expected_target=DST,max_accounts=4,
                       live_dns=DNS_SRC,client_witness=lambda s,t:True)
        self.assertEqual(r.verdict,"READY_FOR_CONTROLLED_CUTOVER")
        self.assertFalse(r.blockers)

    def test_operator_text_and_false_witness_never_grant_cutover(self):
        for value in ("yes",False,None,0):
            with self.subTest(value=value):
                report=self.inspect(
                    "cutover",expected_target=DST,max_accounts=4,
                    live_dns=DNS_SRC,client_witness=lambda s,t:value)
                self.assertNotEqual(report.verdict,"READY_FOR_CONTROLLED_CUTOVER")
        r=self.inspect("cutover",expected_target=DST,max_accounts=4,
                       live_dns=DNS_SRC,client_witness="operator_says_ok")
        self.assertNotEqual(r.verdict,"READY_FOR_CONTROLLED_CUTOVER")

    def test_full_production_cohort_cannot_be_called_a_small_pilot(self):
        self.db.executemany(
            "INSERT INTO ssh_accounts VALUES (?,?,?,?)",
            [(f"extra{i}",SRC,"🟢 فعال","ssh") for i in range(6)])
        r=self.inspect("cutover", max_accounts=5,live_dns=DNS_SRC,
                       client_witness=lambda *_:True)
        self.assertIn("PILOT_COHORT_EXCEEDS_EXPLICIT_LIMIT",r.blockers)

    def test_route_drift_lease_and_no_verified_standby_block(self):
        self.db.execute("INSERT INTO failover_operations VALUES ('RUNNING')")
        self.assertIn("ORIGINAL_6G_LEASE_BUSY",
                      self.inspect("cutover",max_accounts=4).blockers)
        self.db.execute("DELETE FROM failover_operations")
        self.db.execute("UPDATE settings SET value=? WHERE key='hosts'",(DST,))
        self.assertIn("LEGACY_HOSTS_ORDER_MISMATCH",
                      self.inspect("cutover",max_accounts=4).blockers)
        self.db.execute("UPDATE settings SET value=? WHERE key='hosts'",(SRC,))
        self.db.execute("UPDATE cloudzy_cz06_runs SET stage='HOLD'")
        self.assertIn("NO_VERIFIED_CZ06_STANDBY",
                      self.inspect("cutover",max_accounts=4).blockers)

    def test_dns_identity_drift_blocks_cutover(self):
        r=self.inspect("cutover",max_accounts=4,
                       live_dns=DNS_DST,client_witness=lambda *_:True)
        self.assertIn("LIVE_DNS_SOURCE_CHANGED",r.blockers)

    def test_final_requires_done_and_three_business_receipts(self):
        self.db.execute("UPDATE host_pool SET is_default=0 WHERE host=?",(SRC,))
        self.db.execute("UPDATE host_pool SET is_default=1,is_standby=0 "
                        "WHERE host=?",(DST,))
        self.db.execute("UPDATE settings SET value=? WHERE key='hosts'",(DST,))
        self.db.execute("UPDATE settings SET value=? "
                        "WHERE key='dns_current_ip'",(DST,))
        self.db.execute("UPDATE ssh_accounts SET host=?",(DST,))
        self.db.execute("INSERT INTO cloudzy_cz07_jobs VALUES "
                        "('j1','VERIFYING',?,?,4,4,7,20)",(SRC,DST))
        report=self.inspect("final",expected_target=DST,live_dns=DNS_DST)
        self.assertIn("CZ07_NOT_BUSINESS_ACCEPTED",report.blockers)
        self.db.execute("UPDATE cloudzy_cz07_jobs SET status='DONE'")
        report=self.inspect("final",expected_target=DST,live_dns=DNS_DST)
        self.assertIn("INDEPENDENT_CREATE_RENEW_CLIENT_PROOF_MISSING",
                      report.blockers)
        self.db.execute("INSERT INTO cloudzy_cz07_acceptance VALUES "
                        "('j1',7,'create-evidence','renew-evidence','isp-evidence')")
        report=self.inspect("final",expected_target=DST,live_dns=DNS_DST)
        self.assertEqual(report.verdict,"FINAL_AUDIT_PASS")
        self.assertFalse(report.blockers)

    def test_readonly_cli_never_initializes_schema(self):
        self.db.commit()
        db=open_core_readonly(self.path)
        try:
            report=evaluate_pilot(db,phase="purchase")
            self.assertEqual(report.verdict,"READY_FOR_PURCHASE_TEST")
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM ssh_accounts")
        finally:
            db.close()
        self.assertEqual(main(["--db",str(self.path),"--phase","purchase"]),0)

    def test_live_dns_probe_must_explicitly_use_get_config(self):
        from cloudzy_phase8_pilot import live_cloudflare_get
        with patch.dict("os.environ",{},clear=True):
            with self.assertRaisesRegex(Exception,
                                        "PHASE8_CLOUDFLARE_GET_CONFIG_MISSING"):
                live_cloudflare_get()


if __name__ == "__main__":
    unittest.main()
