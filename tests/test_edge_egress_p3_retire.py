"""P3-E: real SQLite existing-6G + fake bounded kernel inventory; no host writes."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edge_egress_p3_executor import (
    BASE_GATES, RETIRE_GATES, ExecutionScope, FreshEvidence,
    Existing6GGuardedExecutor, issue_execution_ticket, ExecutorHold,
)
from edge_egress_p3_retire import (
    P3E_RETIRE_EXECUTOR_ENABLED, EdgeRetireHold, GuardedOrphanRetirePort,
    OwnedKernelSnapshot, RetiredUIDFence, plan_orphan_cleanup,
)
from ops.edge_egress_provision import EgressSpec

CORE = "209.200.246.198"
EDGE = "172.86.105.67"
DEFAULT = "144.172.84.82"
SPEC = EgressSpec.from_json({
    "edge_id": "e7", "edge_public_ipv4": EDGE, "core_public_ipv4": CORE,
    "tunnel_network": "10.81.7.0/30", "veth_network": "10.80.7.0/30",
    "edge_uplink": "eth0", "edge_listen_port": 51832,
    "route_table": 20007, "mode": "relay",
})
USER = RetiredUIDFence("nvl0557",1644,1782,20007,True,True,True,True,
                       True,True,0)


class FakeOwnedHost:
    def __init__(self):
        self.snapshot = OwnedKernelSnapshot(
            namespace_present=True, veth_present=True,
            dedicated_wg_present=True, units_enabled=True,
            units_running=False,
            wg0_runtime_reference=False,wg0_persistent_reference=False,
            foreign_references=(),owned_uid_fences=(USER,),
            audit_complete=True,
        )
        self.events=[]
        self.fail=None
        self.on_action=None

    def inspect(self,spec):
        if spec!=SPEC: raise AssertionError("foreign spec")
        return self.snapshot

    def _mark(self,step):
        self.events.append(step)
        if self.on_action is not None:
            f=self.on_action
            self.on_action=None
            f(step)
        if self.fail==step:
            raise RuntimeError("fake host failure contains no credentials")

    def disable_exact_owned_units(self,spec):
        self._mark("disable")
        self.snapshot=replace(self.snapshot,units_enabled=False,units_running=False)

    def remove_exact_owned_next_hop(self,spec,fence):
        self._mark("remove-next-hop")
        if fence != USER: raise AssertionError("unowned UID")
        self.snapshot=replace(self.snapshot,owned_uid_fences=(
            replace(self.snapshot.owned_uid_fences[0],preferred_edge_route=False),
        ))

    def remove_exact_dedicated_transport(self,spec):
        self._mark("retire-transport")
        if any(x.preferred_edge_route for x in self.snapshot.owned_uid_fences):
            raise AssertionError("MUTATED_WHILE_ROUTE_PRESENT")
        self.snapshot=replace(
            self.snapshot,namespace_present=False,veth_present=False,
            dedicated_wg_present=False,
        )

    def reaffirm_uid_fences(self,spec,fences):
        self.events.append("refence")
        if not all(f.uid==1644 for f in fences):
            raise AssertionError("wrong UID")
        self.snapshot=replace(self.snapshot,owned_uid_fences=tuple(
            replace(x,ipv4_reject=True,ipv6_reject=True,
                    terminal_blackhole=True)
            for x in self.snapshot.owned_uid_fences
        ))


class P3ERetirementTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"db.sqlite"
        self.scope=ExecutionScope("EDGE_RETIRE","e7",CORE,EDGE)
        self.stage=Path("/root/nvl-egress-v1/core-e7")
        self.pin="a"*64
        self.host=FakeOwnedHost()
        self.reg=()
        self.stage_spec=SPEC
        self.stage_reader=lambda path,role,digest:(self.stage_spec,"peer")
        self.registry_loader=lambda:self.reg
        self.now=1000
        self.events=[]
        with self.db() as c:
            c.executescript(f"""
                CREATE TABLE failover_operations(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT,
                  source_host TEXT,target_host TEXT,detail_json TEXT);
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER);
                INSERT INTO host_pool VALUES('{DEFAULT}',1,1);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT);
                INSERT INTO ssh_accounts VALUES('nvl0557','104.194.144.195');
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('dns_current_ip','{DEFAULT}');
                INSERT INTO settings VALUES('edge_egress_protected_mode','0');
                CREATE TABLE edge_egress_f3_ingress_candidates(edge_ipv4 TEXT);
                CREATE TABLE edge_egress_allocations(edge_id TEXT,edge_public_ipv4 TEXT);
                CREATE TABLE edge_egress_readiness(edge_id TEXT,edge_ipv4 TEXT);
                CREATE TABLE edge_egress_uid_bindings(edge_id TEXT,edge_ipv4 TEXT);
                CREATE TABLE edge_egress_uid_runtime(edge_id TEXT,edge_ipv4 TEXT);
            """)

    @contextmanager
    def db(self):
        conn=sqlite3.connect(str(self.path),timeout=5)
        try:
            with conn: yield conn
        finally: conn.close()

    def preview(self):
        return plan_orphan_cleanup(
            self.db,self.scope,stage=self.stage,stage_sha256=self.pin,
            host=self.host,registry_loader=self.registry_loader,
            stage_reader=self.stage_reader,
        )

    def execute_retire(self,release=True,plan=None,evidence_gates=None):
        plan=plan or self.preview()
        proof=FreshEvidence(
            plan.fingerprint,self.now,
            BASE_GATES|RETIRE_GATES if evidence_gates is None else evidence_gates,
        )
        ticket=issue_execution_ticket(
            self.scope,proof,actor_id=99,chat_id=88,now=self.now)
        port=GuardedOrphanRetirePort(
            db_conn=self.db,plan=plan,ticket=ticket,host=self.host,
            stage_reader=self.stage_reader,registry_loader=self.registry_loader,
            release_enabled=release)
        runner=Existing6GGuardedExecutor(
            db_conn=self.db,acquire_fn=self.acquire,journal_fn=self.journal,
            review_fn=lambda scope:proof,host_port=port,
            release_enabled=True,geteuid=lambda:0,clock=lambda:self.now,
        )
        return asyncio.run(runner.execute(
            self.scope,ticket,actor_id=99,chat_id=88))

    def acquire(self,source,target):
        with self.db() as c:
            busy=c.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchone()
            if busy: return None,busy[0]
            r=c.execute(
                "INSERT INTO failover_operations(status,source_host,target_host,detail_json)"
                "VALUES('RUNNING',?,?,'{}')",(source,target))
            return r.lastrowid,None

    def journal(self,op,*,status,detail,finished,require_running):
        import json
        self.events.append((status,detail["phase"]))
        with self.db() as c:
            r=c.execute("UPDATE failover_operations SET status=?,detail_json=? "
                        "WHERE id=? AND status='RUNNING'",
                        (status,json.dumps(detail),op))
            if r.rowcount!=1: raise RuntimeError("6G_CAS_FAILED")

    def journal_status(self):
        with self.db() as c:
            return c.execute(
                "SELECT status,detail_json FROM failover_operations "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()

    def test_plan_is_read_only_for_retired_e7_metadata_and_uid1644(self):
        self.assertIs(P3E_RETIRE_EXECUTOR_ENABLED,False)
        p=self.preview()
        self.assertEqual(p.detached_uids,("nvl0557",))
        self.assertEqual(p.spec.route_table,20007)
        self.assertFalse(p.registry_has_edge)
        self.assertEqual(self.host.events,[])
        self.assertEqual(self.journal_status(),None)

    def test_success_preserves_uid_reject_blackhole_and_original_ssh(self):
        r=self.execute_retire()
        self.assertTrue(r.allowed)
        self.assertEqual(self.host.events,[
            "disable","remove-next-hop","retire-transport"])
        f=self.host.snapshot.owned_uid_fences[0]
        self.assertTrue(f.selector_exact and f.terminal_blackhole)
        self.assertTrue(f.ipv4_reject and f.ipv6_reject)
        self.assertFalse(f.preferred_edge_route)
        self.assertEqual(self.journal_status()[0],"SUCCEEDED")
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
            ).fetchone(),("104.194.144.195",))
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone(),(DEFAULT,))
            self.assertEqual(db.execute(
                "SELECT active,is_default FROM host_pool WHERE host=?",
                (DEFAULT,)
            ).fetchone(),(1,1))

    def test_not_released_no_mutation_but_6g_recovery_hold(self):
        res=self.execute_retire(release=False)
        self.assertTrue(res.manual_recovery)
        self.assertEqual(self.host.events,[])
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_retire_never_allowed_without_all_specific_6g_evidence(self):
        for gate in RETIRE_GATES:
            with self.subTest(gate=gate):
                evidence=BASE_GATES | (RETIRE_GATES - {gate})
                with self.assertRaises(ExecutorHold):
                    self.execute_retire(evidence_gates=evidence)
                self.assertEqual(self.host.events,[])

    def test_block_foreign_rule_missing_fence_and_sessions(self):
        for variant in (
            replace(USER,ipv4_reject=False),
            replace(USER,ipv6_reject=False),
            replace(USER,terminal_blackhole=False),
            replace(USER,selector_exact=False),
            replace(USER,unix_owner_matches=False),
            replace(USER,active_sessions=1),
            replace(USER,table=20008),
        ):
            with self.subTest(variant=variant):
                self.host.snapshot=replace(
                    self.host.snapshot,owned_uid_fences=(variant,))
                with self.assertRaises(EdgeRetireHold):
                    self.preview()
                self.assertEqual(self.host.events,[])
        self.host.snapshot=replace(self.host.snapshot,owned_uid_fences=(USER,))

    def test_block_other_user_or_global_resource_reference(self):
        self.host.snapshot=replace(
            self.host.snapshot,foreign_references=("other-uid-rule",))
        with self.assertRaises(EdgeRetireHold):
            self.preview()
        self.host.snapshot=replace(
            self.host.snapshot,foreign_references=(),
            wg0_persistent_reference=True)
        with self.assertRaises(EdgeRetireHold):
            self.preview()

    def test_block_metadata_active_or_client_dependent(self):
        checks=[
            (f"UPDATE settings SET value='{EDGE}' "
             "WHERE key='dns_current_ip'", "DNS"),
            (f"INSERT INTO edge_egress_uid_bindings VALUES('e7','{EDGE}')",
             "METADATA"),
            (f"INSERT INTO host_pool VALUES('{EDGE}',1,0)","HOST"),
            (f"UPDATE ssh_accounts SET host='{EDGE}'", "SSH"),
        ]
        for sql,label in checks:
            with self.subTest(label=label):
                with self.db() as c: c.execute(sql)
                with self.assertRaises(EdgeRetireHold):
                    self.preview()
                with self.db() as c:
                    c.execute(f"UPDATE settings SET value='{DEFAULT}' "
                              "WHERE key='dns_current_ip'")
                    c.execute("DELETE FROM edge_egress_uid_bindings")
                    c.execute(f"DELETE FROM host_pool WHERE host='{EDGE}'")
                    c.execute("UPDATE ssh_accounts SET host='104.194.144.195'")

    def test_another_running_6g_blocks_preview_without_host_mutation(self):
        with self.db() as c:
            c.execute(
                "INSERT INTO failover_operations"
                "(status,source_host,target_host,detail_json) "
                "VALUES('RUNNING',?,?,?)",(CORE,EDGE,'{}'))
        with self.assertRaisesRegex(EdgeRetireHold,"6G_ALREADY_RUNNING"):
            self.preview()
        self.assertEqual(self.host.events,[])

    def test_stage_changed_between_preview_and_execution_is_held(self):
        plan=self.preview()
        self.stage_spec=replace(SPEC,route_table=20008)
        receipt=self.execute_retire(plan=plan)
        self.assertTrue(receipt.manual_recovery)
        self.assertEqual(self.host.events,[])
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_registry_changed_between_preview_and_action_holds(self):
        from edge_egress_v1_ingress import IngressPeer
        plan=self.preview()
        self.reg=(IngressPeer("e7",EDGE,"10.77.0.7","A"*44),)
        r=self.execute_retire(plan=plan)
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.events,[])

    def test_systemd_disable_uncertain_does_not_touch_uid_next_hop(self):
        self.host.fail="disable"
        r=self.execute_retire()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.events,["disable","refence"])
        self.assertTrue(self.host.snapshot.owned_uid_fences[0].preferred_edge_route)
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_failure_after_next_hop_never_tears_down_transport(self):
        self.host.fail="remove-next-hop"
        r=self.execute_retire()
        self.assertTrue(r.manual_recovery)
        self.assertNotIn("retire-transport",self.host.events)
        self.assertIn("refence",self.host.events)
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_missing_fence_after_detach_rejects_transport_teardown(self):
        def leak(step):
            if step=="remove-next-hop":
                self.host.snapshot=replace(
                    self.host.snapshot,owned_uid_fences=(
                        replace(USER,ipv4_reject=False),
                    ))
        self.host.on_action=leak
        r=self.execute_retire()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.events.count("retire-transport"),0)
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_partial_transport_failure_keeps_shared_6g_hold(self):
        self.host.fail="retire-transport"
        r=self.execute_retire()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.journal_status()[0],"RUNNING")
        self.assertTrue(self.host.snapshot.owned_uid_fences[0].ipv4_reject)

    def test_transport_must_disappear_before_verified_terminal_success(self):
        def fail_to_remove(step):
            if step=="retire-transport":
                self.host.snapshot=replace(
                    self.host.snapshot,namespace_present=True)
        # fail_to_remove is called pre-mutation in this fake, so fake still
        # removes later. Model silent no-op explicitly instead.
        orig=self.host.remove_exact_dedicated_transport
        self.host.remove_exact_dedicated_transport=lambda spec:self.host.events.append("noop")
        r=self.execute_retire()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.journal_status()[0],"RUNNING")

    def test_same_or_foreign_core_edge_not_allowlisted(self):
        with self.assertRaises(ExecutorHold):
            ExecutionScope("EDGE_RETIRE","e7",CORE,CORE)
        with self.assertRaises(ExecutorHold):
            ExecutionScope("DELETE_ALL","e7",CORE,EDGE)


if __name__=="__main__":
    unittest.main()
