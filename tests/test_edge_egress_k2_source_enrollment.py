"""K2 Phase2 source enrollment: SQLite/6G/PAM boundary with fake kernel."""
from __future__ import annotations
import asyncio
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import sqlite3
import tempfile
import time
from pathlib import Path
import unittest

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_inventory import ensure_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_uid_runtime_store import install_runtime_schema, read_binding, RuntimeStoreUnsafe
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_p3_executor import (
    ExecutionScope, ExecutorHold, FreshEvidence, BASE_GATES, ATTACH_GATES,
    SOURCE_ENROLL_GATES, issue_execution_ticket, Existing6GGuardedExecutor,
)
from edge_egress_k2_source_enrollment import (
    SourceEnrollmentHold, SOURCE_ENROLLMENT_RELEASED,
    SameEdge6GUIDRuntimeStore, GuardedSourceEnrollmentPort,
    plan_source_enrollment,
)
from tests.test_edge_egress_p3_uid import FakePerUIDKernel, FakeIndependentSafety
from edge_egress_v1_admission import Member
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET, CORE, req


class SameEdgeEnrollmentTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "db.sqlite"
        self.uid = 1644
        self.conn_factory = self.db
        self.request = UIDPolicyRequest(
            replace(req().spec, edge_id="src1", edge_public_ipv4=SOURCE),
            "nvl0557", self.uid, priority=1780,
        )
        self.manifest = BootGuardManifest(
            self.request, "PROTECTED_BOOT_GUARD", 10553,
            ingress_return=True, shared_edge=True,
        )
        self.roster = {"nvl0557":Member("nvl0557",self.uid,"a"*64)}
        self.lookup=lambda name: {"nvl0557":self.uid}[name]
        self.kernel=FakePerUIDKernel()
        self.kernel.ip=SOURCE
        self.safety=FakeIndependentSafety()
        self.journal_events=[]
        self.now=int(time.time())
        with self.db() as c:
            c.executescript(f"""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('dns_current_ip','{SOURCE}');
                INSERT INTO settings VALUES('edge_egress_protected_mode','0');
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
                    is_default INTEGER,service_port INTEGER);
                INSERT INTO host_pool VALUES('{SOURCE}',1,1,2252);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                    service_type TEXT,status TEXT);
                INSERT INTO ssh_accounts VALUES(
                    'nvl0557','{SOURCE}','ssh','🟢 فعال');
                CREATE TABLE failover_operations(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_host TEXT,target_host TEXT,status TEXT,detail_json TEXT);
            """)
            ensure_schema(c)
            install_runtime_schema(c)
            install_protected_mapping_schema(c)
            install_readiness_schema(c)
            for edge,ip,table in (("src1",SOURCE,1780),("dst1",TARGET,1781)):
                c.execute(
                    "INSERT INTO edge_egress_allocations("
                    "edge_id,edge_public_ipv4,core_public_ipv4,tunnel_network,"
                    "veth_network,route_table,edge_listen_port,edge_uplink,"
                    "core_public_key,edge_public_key,status)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (edge,ip,CORE,"10.78.100.0/30" if edge=="src1" else "10.78.110.0/30",
                     "10.78.101.0/30" if edge=="src1" else "10.78.111.0/30",
                     table,51832 if edge=="src1" else 51833,"eth0",
                     "core-public-"+edge,"edge-public-"+edge,"STAGED"),
                )
                c.execute(
                    "INSERT INTO edge_egress_readiness("
                    "edge_id,edge_ipv4,state,observed_ipv4,witness,"
                    "probed_at,expires_at,last_operation_id) "
                    "VALUES(?,?,'READY',?,'F4_PRODUCTION_ACCEPTANCE',?,?,42)",
                    (edge,ip,ip,self.now-5,self.now+3600),
                )

    @contextmanager
    def db(self):
        conn=sqlite3.connect(self.path,timeout=5)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def prepare(self):
        return plan_source_enrollment(
            self.db,"dst1",self.request,dns_port=10553,
            roster_loader=lambda:self.roster,guard_loader=lambda _:self.manifest,
            os_uid_for_username=self.lookup,
        )

    def acquire(self,source,target):
        with self.db() as c:
            busy=c.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchone()
            if busy:
                return None,busy[0]
            cur=c.execute(
                "INSERT INTO failover_operations(source_host,target_host,status,"
                "detail_json) VALUES(?,?,'RUNNING','{}')", (source,target),
            )
            return cur.lastrowid,None

    def journal(self,op,*,status,detail,finished,require_running):
        self.journal_events.append((status,detail.get("phase")))
        with self.db() as c:
            changed=c.execute(
                "UPDATE failover_operations SET status=?,detail_json=? "
                "WHERE id=? AND status='RUNNING'",
                (status,json.dumps(detail),op),
            ).rowcount
            if changed!=1:
                raise RuntimeError("6G_CAS_FAILURE")

    def engine(self, *, wrong_ip=False, safety_failure=None,
               fake_gate=False, release=True):
        plan=self.prepare()
        evidence=FreshEvidence(
            sha256(b"independent lab attestation").hexdigest(),
            1000, BASE_GATES | ATTACH_GATES |
            (frozenset() if fake_gate else SOURCE_ENROLL_GATES),
        )
        if not fake_gate:
            ticket=issue_execution_ticket(
                plan.scope,evidence,actor_id=12,chat_id=30,now=1000,
            )
        else:
            return plan,evidence,None,None
        store=SameEdge6GUIDRuntimeStore(
            self.conn_factory,self.lookup,scope=plan.scope,ticket=ticket,
            shared_edge_enabled=True,
        )
        self.kernel.ip=TARGET if wrong_ip else SOURCE
        self.safety.error_on=safety_failure
        uid_port=GuardedProtectedUIDPort(
            db_conn=self.conn_factory,plan=plan.uid_plan,ticket=ticket,store=store,
            kernel=self.kernel,safety=self.safety,
            roster_loader=lambda:self.roster,guard_loader=lambda _:self.manifest,
            os_uid_for_username=self.lookup,release_enabled=release,
        )
        port=GuardedSourceEnrollmentPort(
            db_conn=self.conn_factory,plan=plan,ticket=ticket,uid_port=uid_port,
            os_uid_for_username=self.lookup,release_enabled=release,
        )
        engine=Existing6GGuardedExecutor(
            db_conn=self.conn_factory,acquire_fn=self.acquire,journal_fn=self.journal,
            review_fn=lambda _:evidence,host_port=port,
            release_enabled=True,geteuid=lambda:0,clock=lambda:1000,
        )
        return plan,ticket,engine,store

    def execute(self,plan,ticket,engine):
        return asyncio.run(engine.execute(
            plan.scope,ticket,actor_id=12,chat_id=30,
        ))

    def state(self):
        with self.db() as c:
            rt=read_binding(c,"nvl0557")
            mapping=c.execute("SELECT uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings WHERE username='nvl0557'").fetchone()
            host=c.execute("SELECT host FROM ssh_accounts "
                           "WHERE username='nvl0557'").fetchone()
            dns=c.execute("SELECT value FROM settings "
                          "WHERE key='dns_current_ip'").fetchone()
            mode=c.execute("SELECT value FROM settings "
                           "WHERE key='edge_egress_protected_mode'").fetchone()
            journal=c.execute("SELECT status,detail_json FROM failover_operations "
                              "ORDER BY id DESC LIMIT 1").fetchone()
            return rt,mapping,host,dns,mode,journal

    def test_default_off_no_live_registration(self):
        self.assertIs(SOURCE_ENROLLMENT_RELEASED,False)
        plan,ticket,engine,_=self.engine(release=False)
        receipt=self.execute(plan,ticket,engine)
        self.assertFalse(receipt.allowed)
        self.assertEqual(self.kernel.events,[])
        self.assertIsNone(self.state()[0])

    def test_same_edge_legacy_enroll_cas_no_host_dns_or_mode_change(self):
        plan,ticket,engine,_=self.engine()
        self.assertEqual(plan.scope.source_host,plan.scope.target_host)
        result=self.execute(plan,ticket,engine)
        self.assertTrue(result.allowed,result)
        row,mapping,host,dns,mode,journal=self.state()
        self.assertEqual(row.state,"PROTECTED")
        self.assertEqual((row.edge_id,row.edge_ipv4),("src1",SOURCE))
        self.assertEqual(mapping,(1644,"src1",SOURCE,"PROTECTED"))
        self.assertEqual(host,(SOURCE,))
        self.assertEqual(dns,(SOURCE,))
        self.assertEqual(mode,("0",))
        self.assertEqual(journal[0],"SUCCEEDED")
        self.assertEqual(self.kernel.events[:4],[
            "arm","assert_frozen","attach","ipv4"])
        self.assertIn("packet",self.safety.events)
        with self.assertRaises(SourceEnrollmentHold):
            self.prepare()

    def test_wrong_ip_keeps_deny_and_6g_recovery(self):
        plan,ticket,engine,_=self.engine(wrong_ip=True)
        result=self.execute(plan,ticket,engine)
        self.assertFalse(result.allowed)
        self.assertTrue(result.manual_recovery)
        row,mapping,_,_,mode,journal=self.state()
        self.assertIsNotNone(row)
        self.assertEqual(row.state,"HOLD")
        self.assertIsNone(mapping)
        self.assertTrue(self.kernel.deny)
        self.assertEqual(journal[0],"RUNNING")
        self.assertEqual(json.loads(journal[1])["phase"],
                         "EGRESS_P3_RECOVERY_REQUIRED")
        self.assertEqual(mode,("0",))

    def test_missing_independent_packet_proof_keeps_frozen(self):
        plan,ticket,engine,_=self.engine(safety_failure="packet")
        result=self.execute(plan,ticket,engine)
        self.assertFalse(result.allowed)
        self.assertEqual(self.state()[0].state,"HOLD")
        self.assertTrue(self.kernel.deny)

    def test_drift_after_preview_does_not_mutate_kernel(self):
        plan,ticket,engine,_=self.engine()
        with self.db() as c:
            c.execute("UPDATE ssh_accounts SET host=? WHERE username='nvl0557'",
                      (TARGET,))
        result=self.execute(plan,ticket,engine)
        self.assertFalse(result.allowed)
        self.assertEqual(self.kernel.events,[])
        self.assertIsNone(self.state()[0])
        self.assertEqual(self.state()[-1][0],"RUNNING")

    def test_missing_source_f4_blocks_even_pre_plan(self):
        with self.db() as c:
            c.execute("UPDATE edge_egress_readiness SET expires_at=1 "
                      "WHERE edge_id='src1'")
        with self.assertRaises(SourceEnrollmentHold):
            self.prepare()

    def test_cross_edge_old_attach_still_denied_in_legacy_mode(self):
        scope=ExecutionScope(
            "UID_ATTACH","dst1",SOURCE,TARGET,username="nvl0557",uid=1644)
        with self.assertRaises(ExecutorHold):
            ExecutionScope("UID_ATTACH","src1",SOURCE,SOURCE,
                           username="nvl0557",uid=1644)
        with self.assertRaises(ExecutorHold):
            ExecutionScope("UID_ENROLL_SOURCE","dst1",SOURCE,TARGET,
                           username="nvl0557",uid=1644)
        self.assertEqual(scope.target_host,TARGET)

    def test_ticket_must_add_distinct_same_edge_gates(self):
        plan,evidence,_,_=self.engine(fake_gate=True)
        with self.assertRaisesRegex(ExecutorHold,"MISSING_ACCEPTANCE_GATES"):
            issue_execution_ticket(
                plan.scope,evidence,actor_id=12,chat_id=30,now=1000,
            )

    def test_lease_has_to_be_nonce_bound(self):
        plan,ticket,engine,store=self.engine()
        with self.db() as c:
            c.execute("INSERT INTO failover_operations("
                      "source_host,target_host,status,detail_json) "
                      "VALUES(?,?,'RUNNING',?)",
                      (SOURCE,SOURCE,json.dumps({
                          "kind":"K2_P3A","phase":"EGRESS_P3_EXECUTE_INTENT",
                          "action":"UID_ATTACH","nonce_hash":"0"*64,
                          "scope_digest":ticket.scope_digest,
                      })))
        with self.db() as c, self.assertRaises(RuntimeStoreUnsafe):
            store.reserve_blocked(1,self.request,source=SOURCE,dns_port=10553)

    def test_user_uid_drift_before_apply_forces_hold(self):
        plan,ticket,engine,_=self.engine()
        self.uid=1655
        result=self.execute(plan,ticket,engine)
        self.assertFalse(result.allowed)
        self.assertEqual(self.kernel.events,[])


if __name__=="__main__":
    unittest.main()
