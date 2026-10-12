"""F4 production preflight requires exact staged allocation and safe host state."""
import sqlite3
import unittest

from edge_egress_f4_preflight import examine_core, sshd_connection_spec
from edge_egress_f4_pam import REQUIRED_ACCOUNT_LINE


class F4CorePreflightTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(":memory:")
        self.c.executescript("""
            CREATE TABLE ssh_accounts(username TEXT,host TEXT,
                                      service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES
              ('nvl0557','172.86.94.174','ssh','🟢 فعال');
            CREATE TABLE host_pool(host TEXT,active INTEGER,is_default INTEGER);
            INSERT INTO host_pool VALUES('172.86.94.174',1,1);
            CREATE TABLE settings(key TEXT,value TEXT);
            INSERT INTO settings VALUES('dns_current_ip','172.86.94.174');
            CREATE TABLE failover_operations(status TEXT);
            CREATE TABLE edge_egress_allocations(edge_id TEXT,
                                                 edge_public_ipv4 TEXT,status TEXT);
            INSERT INTO edge_egress_allocations
              VALUES('fra1','216.126.229.12','STAGED');
            CREATE TABLE edge_egress_readiness(
              edge_id TEXT,edge_ipv4 TEXT,state TEXT);
            INSERT INTO edge_egress_readiness
              VALUES('fra1','216.126.229.12','VERIFIED_LAB');
            CREATE TABLE edge_egress_uid_runtime(username TEXT,uid INTEGER);
            CREATE TABLE edge_egress_uid_bindings(username TEXT,uid INTEGER);
        """)

    def tearDown(self): self.c.close()

    def check(self,**kwargs):
        params=dict(
            conn=self.c,username="nvl0557",uid=1644,
            os_uid=1644,source_ip="172.86.94.174",
            edge_id="fra1",expected_edge_ip="216.126.229.12",
            pam_text=REQUIRED_ACCOUNT_LINE+"\n",
            sshd_effective="usepam yes\n",ssh_active=True,bot_active=True,
            gate_digest_verified=True,
        )
        params.update(kwargs)
        return examine_core(**params)

    def test_match_localport_and_ingress_context_are_explicit(self):
        actual = sshd_connection_spec(
            username="nvl0557",local_addr="10.77.0.1",
            remote_addr="10.77.0.7",local_port=2252,
        )
        self.assertEqual(
            actual,
            "user=nvl0557,host=localhost,addr=10.77.0.7,"
            "laddr=10.77.0.1,lport=2252",
        )
        for invalid in (
            {"local_port": 0}, {"local_port": True},
            {"local_addr": "bad-address"},
            {"remote_addr": "10.77.0.7,host=evil"},
            {"username": "root; invalid"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                sshd_connection_spec(**{
                    "username": "nvl0557", "local_addr": "10.77.0.1",
                    "remote_addr": "10.77.0.7", "local_port": 2252,
                    **invalid,
                })

    def test_clean_mock_host_is_preflight_candidate_not_customer_ready(self):
        p=self.check()
        self.assertTrue(p.safe_to_consider)
        self.assertFalse(p.customer_ready)

    def test_reviewed_root_owned_pam_hook_digest_is_required(self):
        decision=self.check(gate_digest_verified=False)
        self.assertFalse(decision.safe_to_consider)
        self.assertIn("PAM_GATE_SHA256_OR_ROOT_OWNERSHIP_UNVERIFIED",
                      decision.blockers)

    def test_missing_pam_or_wrong_uid_or_down_service_blocks(self):
        for kw in ({"pam_text":""},{"uid":1645},{"ssh_active":False},
                   {"bot_active":False},{"sshd_effective":"usepam no\n"}):
            with self.subTest(kw=kw):
                self.assertFalse(self.check(**kw).safe_to_consider)

    def test_existing_protected_intent_or_running_6g_blocks(self):
        self.c.execute("INSERT INTO edge_egress_uid_runtime VALUES('nvl0557',1644)")
        self.assertIn("EXISTING_PROTECTED_OR_HOLD_INTENT",self.check().blockers)
        self.c.execute("DELETE FROM edge_egress_uid_runtime")
        self.c.execute("INSERT INTO failover_operations VALUES('RUNNING')")
        self.assertIn("6G_RECOVERY_OR_OPERATION_ACTIVE",self.check().blockers)

    def test_stale_edge_and_dns_and_schema_block(self):
        self.c.execute("UPDATE edge_egress_readiness SET state='HOLD'")
        self.assertIn("EDGE_NOT_IN_F4_PREACCEPTANCE_STATE",self.check().blockers)
        self.c.execute("UPDATE settings SET value='209.200.246.198'")
        self.assertIn("INGRESS_DNS_MISMATCH",self.check().blockers)
        self.c.execute("DROP TABLE edge_egress_uid_runtime")
        self.assertIn("MISSING_REQUIRED_DB_TABLES",self.check().blockers)


if __name__=="__main__":
    unittest.main()
