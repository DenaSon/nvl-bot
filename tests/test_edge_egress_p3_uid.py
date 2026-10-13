"""P3-C UID lifecycle safety tests: real SQLite F2 CAS, fake privileged ports.

Never mutates Linux users, routes, SSH, WireGuard, PAM, or DNS.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_inventory import ensure_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_p3_executor import (
    ATTACH_GATES, BASE_GATES, ExecutionScope, FreshEvidence,
    Existing6GGuardedExecutor, issue_execution_ticket,
)
from edge_egress_p3_uid import (
    FREEZE, NEW, RESUME, UID_LIFECYCLE_ENABLED, GuardedProtectedUIDPort,
    ProtectedUIDHold, review_protected_uid,
)
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_runtime_store import (
    Existing6GUIDRuntimeStore, install_runtime_schema, read_binding,
)
from edge_egress_v1_admission import Member
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET, CORE, req


class FakePerUIDKernel:
    def __init__(self):
        self.events=[]
        self.deny=False
        self.attached=False
        self.ip=TARGET
        self.failed_step=None
        self.failed_freeze=False

    def _step(self,name):
        self.events.append(name)
        if self.failed_step==name:
            raise RuntimeError("simulated private credentials")
    def arm(self,r,port):
        self._step("arm")
        self.deny=True
    def attach(self,r):
        self._step("attach")
        if not self.deny:
            raise RuntimeError("ATTACH_WITHOUT_DENY")
        self.attached=True
        self.deny=False
    def freeze(self,r):
        self._step("freeze")
        if self.failed_freeze:
            raise RuntimeError("freeze failure")
        self.deny=True
    def assert_frozen(self,r):
        self._step("assert_frozen")
        if not self.deny:
            raise RuntimeError("UNFENCED")
    def public_ipv4(self,r):
        self._step("ipv4")
        return self.ip
    def assert_dns_ipv6(self,r):
        self._step("dns_ipv6")


class FakeIndependentSafety:
    def __init__(self):
        self.events=[]
        self.error_on=None
        self.lease_effect=None
    def _check(self,name):
        self.events.append(name)
        if self.lease_effect is not None:
            callback=self.lease_effect
            self.lease_effect=None
            callback()
        if self.error_on==name:
            raise RuntimeError("independent attestation unavailable")
    def assert_account_idle(self,r): self._check("idle")
    def assert_pam_ingress_boot(self,r): self._check("pam_boot")
    def assert_multi_uid_isolation(self,r): self._check("multi_uid")
    def assert_packet_dns_ipv6_no_core_leak(self,r): self._check("packet")


class P3CUIDTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dbpath=Path(self.tmp.name)/"db.sqlite"
        self.conn_factory=self.db
        self.uid_req=req()
        self.guard=BootGuardManifest(
            self.uid_req,"PROTECTED_BOOT_GUARD",10553,
            ingress_return=True,shared_edge=True,
        )
        raw=json.dumps({
            "mode":self.guard.mode,"username":self.uid_req.username,
            "uid":self.uid_req.uid,"priority":self.uid_req.priority,
            "dns_port":10553,"ingress_return":True,"shared_edge":True,
            "spec":self.uid_req.spec.__dict__,
        },sort_keys=True).encode()
        self.roster={self.uid_req.username:Member(
            self.uid_req.username,self.uid_req.uid,sha256(raw).hexdigest())}
        self.roster_loader=lambda:self.roster
        self.guard_loader=lambda member:self.guard
        self.unix_lookup=lambda username:{"nvl0557":1644}[username]
        self.store=Existing6GUIDRuntimeStore(
            self.conn_factory,self.unix_lookup,shared_edge_enabled=True)
        self.kernel=FakePerUIDKernel()
        self.safety=FakeIndependentSafety()
        self.clock=1000
        self.journal_events=[]
        with self.db() as c:
            c.executescript(f"""
                CREATE TABLE failover_operations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT,source_host TEXT,target_host TEXT,detail_json TEXT);
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('dns_current_ip','{SOURCE}');
                INSERT INTO settings VALUES('edge_egress_protected_mode','1');
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,
                    active INTEGER,is_default INTEGER);
                INSERT INTO host_pool VALUES('{SOURCE}',1,1);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,
                    host TEXT,service_type TEXT,status TEXT);
                INSERT INTO ssh_accounts VALUES(
                    'nvl0557','{SOURCE}','ssh','🟢 فعال');
            """)
            ensure_schema(c)
            install_protected_mapping_schema(c)
            install_runtime_schema(c)
            install_readiness_schema(c)
            c.execute(
                "INSERT INTO edge_egress_allocations("
                "edge_id,edge_public_ipv4,core_public_ipv4,"
                "tunnel_network,veth_network,route_table,edge_listen_port,"
                "edge_uplink,core_public_key,edge_public_key,status)"
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("fra1",TARGET,CORE,"10.78.100.0/30","10.78.101.0/30",
                 1780,51832,"eth0","core-public","edge-public","STAGED"),
            )
            now=int(time.time())
            c.execute(
                "INSERT INTO edge_egress_readiness("
                "edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
                "expires_at,last_operation_id) VALUES("
                "?,?,'READY',?,'F4_PRODUCTION_ACCEPTANCE',?,?,42)",
                ("fra1",TARGET,TARGET,now-5,now+3600),
            )

    @contextmanager
    def db(self):
        c=sqlite3.connect(str(self.dbpath),timeout=5)
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def plan(self,purpose=NEW):
        action="UID_FREEZE" if purpose==FREEZE else "UID_ATTACH"
        scope=ExecutionScope(action,"fra1",SOURCE,TARGET,
                             username="nvl0557",uid=1644)
        return review_protected_uid(
            self.conn_factory,scope,self.uid_req,dns_port=10553,
            purpose=purpose,roster_loader=self.roster_loader,
            guard_loader=self.guard_loader,
            os_uid_for_username=self.unix_lookup,
        )

    def setup_action(self,purpose=NEW,release=True,preexisting=None):
        if preexisting:
            self.make_binding(preexisting)
        plan=self.plan(purpose)
        evidence=FreshEvidence(
            sha256(b"Operator witnessed protected UID preflight").hexdigest(),
            1000, BASE_GATES | (ATTACH_GATES if purpose!=FREEZE else frozenset()),
        )
        ticket=issue_execution_ticket(
            plan.scope,evidence,actor_id=18,chat_id=30,now=self.clock,
        )
        port=GuardedProtectedUIDPort(
            db_conn=self.conn_factory,plan=plan,ticket=ticket,
            store=self.store,kernel=self.kernel,safety=self.safety,
            roster_loader=self.roster_loader,guard_loader=self.guard_loader,
            os_uid_for_username=self.unix_lookup,release_enabled=release,
        )
        engine=Existing6GGuardedExecutor(
            db_conn=self.conn_factory,acquire_fn=self.acquire,
            journal_fn=self.journal,
            review_fn=lambda scope:evidence,host_port=port,
            release_enabled=True,geteuid=lambda:0,clock=lambda:1000,
        )
        return plan,port,engine,ticket

    def acquire(self,source,target):
        with self.db() as c:
            busy=c.execute("SELECT id FROM failover_operations "
                           "WHERE status='RUNNING'").fetchone()
            if busy: return None,busy[0]
            cursor=c.execute(
                "INSERT INTO failover_operations("
                "status,source_host,target_host,detail_json)"
                "VALUES('RUNNING',?,?,'{}')",
                (source,target),
            )
            return cursor.lastrowid,None

    def journal(self,op,*,status,detail,finished,require_running):
        self.journal_events.append((status,detail.get("phase")))
        with self.db() as c:
            changed=c.execute(
                "UPDATE failover_operations SET status=?, detail_json=? "
                "WHERE id=? AND status='RUNNING'",
                (status,json.dumps(detail),op),
            ).rowcount
            if changed!=1:
                raise RuntimeError("6G_CAS_LOST")

    def execute(self,engine,plan,ticket):
        return asyncio.run(engine.execute(
            plan.scope,ticket,actor_id=18,chat_id=30,
        ))

    def make_binding(self,state):
        # Exact real store operations under a simulated existing 6G lease.
        with self.db() as c:
            c.execute("INSERT INTO failover_operations "
                      "(status,source_host,target_host,detail_json) "
                      "VALUES('RUNNING',?,?,?)",
                      (SOURCE,TARGET,json.dumps({"phase":"OLD_TEST_FIXTURE"})))
        with self.db() as c:
            op=c.execute("SELECT id FROM failover_operations "
                         "WHERE status='RUNNING'").fetchone()[0]
        self.store.reserve_blocked(op,self.uid_req,source=SOURCE,dns_port=10553)
        if state in ("PROTECTED","FROZEN"):
            self.store.transition(op,self.uid_req,source=SOURCE,
                                  expected="BLOCKED",target="ROUTED_UNVERIFIED")
            self.store.commit_protected(op,self.uid_req,source=SOURCE)
        if state=="FROZEN":
            self.store.transition(op,self.uid_req,source=SOURCE,
                                  expected="PROTECTED",target="FROZEN")
            self.kernel.deny=True
        with self.db() as c:
            c.execute("UPDATE failover_operations SET status='SUCCEEDED' WHERE id=?", (op,))

    def binding(self):
        with self.db() as c:
            return read_binding(c,"nvl0557")

    def mapping(self):
        with self.db() as c:
            return c.execute(
                "SELECT uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings WHERE username='nvl0557'"
            ).fetchone()

    def journal_final(self):
        with self.db() as c:
            return c.execute(
                "SELECT status,detail_json FROM failover_operations "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()

    def test_source_never_defaults_to_live_release(self):
        self.assertIs(UID_LIFECYCLE_ENABLED,False)
        plan,port,engine,ticket=self.setup_action(release=False)
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertIsNone(self.binding())
        self.assertEqual(self.kernel.events,[])

    def test_new_attach_uses_blocked_before_kernel_then_commits_protected(self):
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.allowed)
        self.assertEqual(result.result,"SUCCEEDED")
        self.assertEqual(self.binding().state,"PROTECTED")
        self.assertEqual(self.mapping(),(1644,"fra1",TARGET,"PROTECTED"))
        self.assertEqual(self.kernel.events[:4],[
            "arm","assert_frozen","attach","ipv4"])
        self.assertIn("packet",self.safety.events)
        self.assertFalse(self.kernel.deny)
        self.assertEqual(self.journal_final()[0],"SUCCEEDED")
        with self.db() as c:
            self.assertEqual(c.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
            ).fetchone(),(SOURCE,))
            self.assertEqual(c.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone(),(SOURCE,))

    def test_protected_new_enrollment_is_not_reentrant(self):
        self.make_binding("PROTECTED")
        with self.assertRaises(ProtectedUIDHold):
            self.plan(NEW)
        self.assertEqual(self.binding().state,"PROTECTED")

    def test_freeze_does_not_require_idle_dns_pam_or_healthy_edge(self):
        self.make_binding("PROTECTED")
        self.safety.error_on="pam_boot"
        plan,port,engine,ticket=self.setup_action(FREEZE)
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.allowed)
        self.assertEqual(self.binding().state,"FROZEN")
        self.assertEqual(self.mapping(),(1644,"fra1",TARGET,"PROTECTED"))
        self.assertTrue(self.kernel.deny)
        self.assertNotIn("pam_boot",self.safety.events)
        self.assertNotIn("idle",self.safety.events)
        self.assertNotIn("packet",self.safety.events)

    def test_freeze_succeeds_with_missing_optional_safety_provider(self):
        self.make_binding("PROTECTED")
        plan,port,engine,ticket=self.setup_action(FREEZE)
        port.safety=None
        receipt=self.execute(engine,plan,ticket)
        self.assertTrue(receipt.allowed)
        self.assertTrue(self.kernel.deny)
        self.assertEqual(self.binding().state,"FROZEN")

    def test_shared_edge_second_protected_uid_is_never_mutated(self):
        second=Member("nvl0558",1645,"b"*64)
        self.roster["nvl0558"]=second
        with self.db() as c:
            c.execute(
                "INSERT INTO edge_egress_uid_runtime "
                "(username,uid,edge_id,edge_ipv4,route_table,priority,"
                "dns_port,state,last_operation_id) "
                "VALUES('nvl0558',1645,'fra1',?,1780,1781,10554,'PROTECTED',33)",
                (TARGET,),
            )
            c.execute(
                "INSERT INTO edge_egress_uid_bindings"
                "(username,uid,edge_id,edge_ipv4,status)"
                "VALUES('nvl0558',1645,'fra1',?,'PROTECTED')",
                (TARGET,),
            )
        plan,port,engine,ticket=self.setup_action()
        receipt=self.execute(engine,plan,ticket)
        self.assertTrue(receipt.allowed)
        with self.db() as c:
            row=read_binding(c,"nvl0558")
            mapping=c.execute(
                "SELECT status FROM edge_egress_uid_bindings "
                "WHERE username='nvl0558'",
            ).fetchone()
        self.assertEqual((row.uid,row.state,row.generation), (1645,"PROTECTED",1))
        self.assertEqual(mapping,("PROTECTED",))
        self.assertEqual(self.binding().state,"PROTECTED")

    def test_stale_generation_after_preview_is_denied(self):
        self.make_binding("FROZEN")
        plan,port,engine,ticket=self.setup_action(RESUME)
        with self.db() as c:
            c.execute(
                "UPDATE edge_egress_uid_runtime SET generation=generation+1 "
                "WHERE username='nvl0557'"
            )
        receipt=self.execute(engine,plan,ticket)
        self.assertTrue(receipt.manual_recovery)
        self.assertEqual(self.binding().state,"FROZEN")
        self.assertEqual(self.mapping(),(1644,"fra1",TARGET,"PROTECTED"))

    def test_resume_from_frozen_requires_new_proofs_and_keeps_mapping(self):
        self.make_binding("FROZEN")
        plan,port,engine,ticket=self.setup_action(RESUME)
        r=self.execute(engine,plan,ticket)
        self.assertTrue(r.allowed)
        self.assertEqual(self.binding().state,"PROTECTED")
        self.assertEqual(self.mapping(),(1644,"fra1",TARGET,"PROTECTED"))
        self.assertFalse(self.kernel.deny)

    def test_resume_denied_if_existing_protected_mapping_missing(self):
        self.make_binding("FROZEN")
        with self.db() as c:
            c.execute("DELETE FROM edge_egress_uid_bindings")
        with self.assertRaises(ProtectedUIDHold):
            self.plan(RESUME)

    def test_roster_missing_target_or_conflicting_os_uid_holds(self):
        self.roster={}
        with self.assertRaises(ProtectedUIDHold):
            self.plan()
        self.roster={"nvl0557":Member("nvl0557",1644,"a"*64)}
        self.unix_lookup=lambda name:1645
        with self.assertRaises(ProtectedUIDHold):
            self.plan()

    def test_readonly_review_rejects_any_preexisting_unrostered_account(self):
        with self.db() as c:
            c.execute("INSERT INTO edge_egress_uid_runtime("
                      "username,uid,edge_id,edge_ipv4,route_table,priority,"
                      "dns_port,state,last_operation_id)"
                      "VALUES('nvl0999',1999,'fra1',?,1780,1999,10555,'HOLD',44)",
                      (TARGET,))
        with self.assertRaisesRegex(ProtectedUIDHold,"INCOMPLETE_PROTECTED_ROSTER"):
            self.plan()

    def test_session_or_pam_failure_has_no_unprotected_fallback(self):
        for fail in ("idle","pam_boot","multi_uid"):
            with self.subTest(fail=fail):
                self.safety.error_on=fail
                plan,port,engine,ticket=self.setup_action()
                result=self.execute(engine,plan,ticket)
                self.assertTrue(result.manual_recovery)
                self.assertIsNone(self.binding())
                self.assertEqual(self.kernel.events,[])
                self.assertEqual(self.journal_final()[0],"RUNNING")
                # Remove only fixture 6G journal for independent scenario.
                with self.db() as c:
                    c.execute("DELETE FROM failover_operations")
                self.safety.error_on=None

    def test_wrong_observed_ip_remains_frozen_and_journal_hold(self):
        self.kernel.ip="144.172.84.82"
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.binding().state,"HOLD")
        self.assertTrue(self.kernel.deny)
        self.assertIsNone(self.mapping())
        self.assertEqual(self.journal_final()[0],"RUNNING")

    def test_missing_packet_level_dns_ipv6_proof_forces_hold(self):
        self.safety.error_on="packet"
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.binding().state,"HOLD")
        self.assertTrue(self.kernel.deny)

    def test_kernel_attach_partial_failure_retains_fence_and_hold(self):
        self.kernel.failed_step="attach"
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.binding().state,"HOLD")
        self.assertTrue(self.kernel.deny)
        self.assertNotIn("password",self.journal_final()[1])

    def test_lease_loss_mid_operation_does_not_clobber_new_owner(self):
        def lose():
            with self.db() as c:
                c.execute("UPDATE failover_operations SET status='SUCCEEDED' "
                          "WHERE status='RUNNING'")
        self.safety.lease_effect=lose
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.kernel.events,[])
        self.assertIsNone(self.binding())

    def test_roster_changes_mid_operation_holds_without_legacy_release(self):
        def drift():
            self.roster={"nvl0557":Member("nvl0557",1644,"b"*64)}
        self.safety.lease_effect=drift
        plan,port,engine,ticket=self.setup_action()
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.kernel.events,[])
        self.assertIsNone(self.binding())

    def test_resume_failure_keeps_per_uid_fence_and_previous_mapping(self):
        self.make_binding("FROZEN")
        self.kernel.failed_step="attach"
        plan,port,engine,ticket=self.setup_action(RESUME)
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.binding().state,"HOLD")
        self.assertEqual(self.mapping(),(1644,"fra1",TARGET,"PROTECTED"))
        self.assertTrue(self.kernel.deny)

    def test_freeze_after_route_loss_still_fences_one_uid(self):
        self.make_binding("PROTECTED")
        self.kernel.failed_step="assert_frozen"
        plan,port,engine,ticket=self.setup_action(FREEZE)
        result=self.execute(engine,plan,ticket)
        self.assertTrue(result.manual_recovery)
        self.assertTrue(self.kernel.deny)
        self.assertEqual(self.journal_final()[0],"RUNNING")


if __name__=="__main__":
    unittest.main()
