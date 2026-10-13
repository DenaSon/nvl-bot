"""P3-D: fake Cloudflare + real SQLite 6G/CAS, zero network calls."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import urllib.parse
import unittest

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_v1_cloudflare import ProtectedCloudflareDNS, DnsHold
from edge_egress_p3_dns_cutover import (
    P3D_INGRESS_DNS_EXECUTOR_ENABLED, GuardedIngressCloudflarePort,
    DnsHandoffAuthorization, ProtectedDnsHandoffHold, DNS_CUTOVER_PHASE,
)

SOURCE = "172.86.94.174"
TARGET = "216.126.229.12"
CORE = "209.200.246.198"
NAMES = ("vpn.example.com", "tls.example.com")
USERS = (("nvl0557", 1644), ("nvl0558", 1645))


class FakeCloudflare(ProtectedCloudflareDNS):
    def __init__(self):
        self.cfg = {
            "zone": "a" * 32, "token": "never-publish-token",
            "public_domain": NAMES[0], "tls_domain": NAMES[1],
            "tls_passthrough": "1",
        }
        self.records = {
            n: {"id": f"{i+1:032x}", "type": "A", "name": n,
                "content": SOURCE, "ttl": 1, "proxied": False,
                "modified_on": "version-1"}
            for i,n in enumerate(NAMES)
        }
        self.aaaa = set()
        self.calls = []
        self.on_patch = None
        super().__init__(lambda: self.cfg)

    def _request(self, cfg, path, method="GET", payload=None):
        self.calls.append((method,path))
        if method == "GET":
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            name, kind = params["name"][0], params["type"][0]
            if kind == "AAAA":
                return ([{"type":"AAAA","name":name}]
                        if name in self.aaaa else [])
            return [deepcopy(self.records[name])]
        rid = path.rsplit("/",1)[-1]
        name = next((name for name,rec in self.records.items()
                     if rec["id"] == rid),None)
        if method != "PATCH" or name is None:
            raise DnsHold("FAKE_PROVIDER_INVALID_WRITE")
        rec=self.records[name]
        rec["content"]=payload["content"]
        rec["modified_on"]="version-2"
        if self.on_patch is not None:
            callback=self.on_patch
            self.on_patch=None
            callback(name)
        return deepcopy(rec)

    @property
    def writes(self):
        return [x for x in self.calls if x[0] == "PATCH"]


class P3DTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dbpath=Path(self.tmp.name)/"db.sqlite"
        self.dbconn=self.db
        self.cf=FakeCloudflare()
        self.safe=True
        self.euid=0
        self.independent_calls=[]
        with self.db() as c:
            c.executescript(f"""
                CREATE TABLE failover_operations(
                  id INTEGER PRIMARY KEY,status TEXT,source_host TEXT,
                  target_host TEXT,detail_json TEXT);
                INSERT INTO failover_operations VALUES(
                  42,'RUNNING','{SOURCE}','{TARGET}',
                  '{{"phase":"{DNS_CUTOVER_PHASE}","kind":"PROTECTED_EGRESS_J"}}');
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('edge_egress_protected_mode','1');
                INSERT INTO settings VALUES('dns_current_ip','{SOURCE}');
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
                    is_default INTEGER,is_standby INTEGER);
                INSERT INTO host_pool VALUES('{SOURCE}',1,1,0);
                INSERT INTO host_pool VALUES('{TARGET}',1,0,1);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                    service_type TEXT,status TEXT);
                CREATE TABLE edge_egress_allocations(edge_id TEXT PRIMARY KEY,
                    edge_public_ipv4 TEXT,core_public_ipv4 TEXT,status TEXT);
                INSERT INTO edge_egress_allocations VALUES(
                    'fra1','{TARGET}','{CORE}','STAGED');
                CREATE TABLE edge_egress_uid_runtime(
                    username TEXT PRIMARY KEY,uid INTEGER,edge_ipv4 TEXT,state TEXT);
                CREATE TABLE edge_egress_uid_bindings(
                    username TEXT PRIMARY KEY,uid INTEGER,edge_ipv4 TEXT,status TEXT);
            """)
            install_readiness_schema(c)
            now=int(time.time())
            c.execute(
                "INSERT INTO edge_egress_readiness "
                "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
                "expires_at,last_operation_id) VALUES("
                "?,?,'READY',?,'F4_PRODUCTION_ACCEPTANCE',?,?,42)",
                ("fra1",TARGET,TARGET,now-5,now+1800),
            )
            for user,uid in USERS:
                c.execute("INSERT INTO ssh_accounts VALUES(?,?,'ssh','🟢 فعال')",
                          (user,TARGET))
                c.execute("INSERT INTO edge_egress_uid_runtime VALUES(?,?,?,'FROZEN')",
                          (user,uid,TARGET))
                c.execute("INSERT INTO edge_egress_uid_bindings VALUES(?,?,?,'PROTECTED')",
                          (user,uid,TARGET))

    @contextmanager
    def db(self):
        c=sqlite3.connect(str(self.dbpath),timeout=5)
        try:
            with c: yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def independent(self, source,target,uids):
        self.independent_calls.append((source,target,uids))
        return self.safe

    def auth(self):
        return DnsHandoffAuthorization(
            42,self.cf.preview_edge_to_edge(SOURCE,TARGET),USERS,
        )

    def gate(self,authorization=None,release=True):
        return GuardedIngressCloudflarePort(
            db_conn=self.dbconn,authorization=authorization or self.auth(),
            cloudflare=self.cf,independent_proof=self.independent,
            release_enabled=release,geteuid=lambda:self.euid,
        )

    def test_default_disabled_and_unreleased_port_never_puts_dns(self):
        self.assertIs(P3D_INGRESS_DNS_EXECUTOR_ENABLED,False)
        p=self.gate(release=False)
        with self.assertRaisesRegex(ProtectedDnsHandoffHold,"RELEASE"):
            p.cutover()
        self.assertEqual(len(self.cf.writes),0)

    def test_positive_pinned_two_record_dns_cas_under_6g(self):
        p=self.gate()
        p.cutover()
        p.verify_provider_target()
        self.assertEqual(tuple(rec["content"] for rec in self.cf.records.values()),
                         (TARGET,TARGET))
        self.assertEqual(len(self.cf.writes),2)
        self.assertGreaterEqual(len(self.independent_calls),4)
        with self.db() as c:
            self.assertEqual(c.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone(),(SOURCE,))
            self.assertEqual(c.execute(
                "SELECT status FROM failover_operations"
            ).fetchone(),("RUNNING",))

    def test_no_cutover_when_protected_mode_or_phase_missing(self):
        for query in (
            "UPDATE settings SET value='0' WHERE key='edge_egress_protected_mode'",
            "UPDATE failover_operations SET detail_json='{}'",
        ):
            with self.subTest(query=query):
                with self.db() as c:
                    c.execute(query)
                with self.assertRaises(ProtectedDnsHandoffHold):
                    self.gate().cutover()
                self.assertEqual(len(self.cf.writes),0)
                with self.db() as c:
                    c.execute(
                        "UPDATE settings SET value='1' "
                        "WHERE key='edge_egress_protected_mode'"
                    )
                    c.execute("UPDATE failover_operations SET detail_json=?",
                        (json.dumps({"phase":DNS_CUTOVER_PHASE,
                                     "kind":"PROTECTED_EGRESS_J"}),))

    def test_6h_egress_only_phase_never_calls_cloudflare(self):
        with self.db() as c:
            c.execute("UPDATE failover_operations SET detail_json=?",
                      (json.dumps({"phase":"EDGE_ONLY_PROTECTED_DNS_CUTOVER",
                                   "kind":"PROTECTED_EGRESS_SWITCH"}),))
        with self.assertRaises(ProtectedDnsHandoffHold):
            self.gate().cutover()
        self.assertFalse(self.cf.writes)

    def test_deny_if_protected_uid_not_frozen_or_mapping_missing(self):
        with self.db() as c:
            c.execute("UPDATE edge_egress_uid_runtime SET state='PROTECTED' "
                      "WHERE username='nvl0557'")
        with self.assertRaisesRegex(ProtectedDnsHandoffHold,"UID_REPIN"):
            self.gate().cutover()
        self.assertFalse(self.cf.writes)

    def test_6g_lease_lost_between_provider_writes_holds_partial_dns(self):
        gate=self.gate()
        def drop(_):
            with self.db() as c:
                c.execute("UPDATE failover_operations SET status='SUCCEEDED' WHERE id=42")
        self.cf.on_patch=drop
        with self.assertRaises(ProtectedDnsHandoffHold):
            gate.cutover()
        self.assertEqual(len(self.cf.writes),1)
        self.assertEqual(self.cf.records[NAMES[0]]["content"],TARGET)
        self.assertEqual(self.cf.records[NAMES[1]]["content"],SOURCE)

    def test_concurrent_record_mutation_blocks_before_any_provider_write(self):
        auth=self.auth()
        self.cf.records[NAMES[0]]["modified_on"]="concurrent-writer"
        with self.assertRaisesRegex(DnsHold,"CAS"):
            self.gate(auth).cutover()
        self.assertFalse(self.cf.writes)

    def test_concurrent_change_after_first_record_blocks_remaining(self):
        gate=self.gate()
        def concurrent(_):
            self.cf.records[NAMES[1]]["modified_on"]="elsewhere"
        self.cf.on_patch=concurrent
        with self.assertRaisesRegex(DnsHold,"CAS"):
            gate.cutover()
        self.assertEqual(len(self.cf.writes),1)
        self.assertEqual(self.cf.records[NAMES[1]]["content"],SOURCE)

    def test_aaaa_record_prevents_dns_write(self):
        self.cf.aaaa.add(NAMES[1])
        with self.assertRaisesRegex(DnsHold,"AAAA"):
            self.cf.preview_edge_to_edge(SOURCE,TARGET)
        self.assertEqual(len(self.cf.writes),0)

    def test_external_proof_missing_prevents_dns_write(self):
        self.safe=False
        with self.assertRaisesRegex(ProtectedDnsHandoffHold,"INDEPENDENT"):
            self.gate().cutover()
        self.assertFalse(self.cf.writes)

    def test_6g_busy_or_foreign_target_prevents_dns_write(self):
        with self.db() as c:
            c.execute("INSERT INTO failover_operations VALUES("
                      "43,'RUNNING','8.8.8.8','1.1.1.1','{}')")
        with self.assertRaisesRegex(ProtectedDnsHandoffHold,"LOCK|LEASE"):
            self.gate().cutover()
        self.assertFalse(self.cf.writes)

    def test_account_membership_drift_blocks_cutover(self):
        with self.db() as c:
            c.execute("INSERT INTO ssh_accounts VALUES("
                      "'nvl0559',?,'ssh','🟢 فعال')",(TARGET,))
        with self.assertRaisesRegex(ProtectedDnsHandoffHold,"ACCOUNT_SET_CHANGED"):
            self.gate().cutover()
        self.assertFalse(self.cf.writes)

    def test_cannot_switch_to_core_or_private_address(self):
        for target in (CORE,SOURCE,"10.0.0.1"):
            with self.subTest(target=target):
                if target == SOURCE or target=="10.0.0.1":
                    with self.assertRaises(DnsHold):
                        self.cf.preview_edge_to_edge(SOURCE,target)
                else:
                    # Core IP may be a globally routable IP, so a separate
                    # explicit 6G host-pool/target-ownership gate must deny.
                    with self.assertRaises(ProtectedDnsHandoffHold):
                        a=DnsHandoffAuthorization(42,
                            self.cf.preview_edge_to_edge(SOURCE,target),USERS)
                        self.gate(a).cutover()


if __name__=="__main__":
    unittest.main()
