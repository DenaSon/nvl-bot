"""K2 P3-B offline safety contract; never starts WireGuard, sshd or PAM."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edge_egress_p3_boot import (
    LIVE_PROVISIONING_ENABLED, BootProvisionHold, ExistingPinnedTransport,
    GuardedStageBootPort, assert_shared_6g_intent, build_stage_boot_review,
)
from edge_egress_p3_executor import (
    BASE_GATES, ExecutionScope, Existing6GGuardedExecutor, FreshEvidence,
    INTENT_PHASE, RECOVERY_PHASE, _scope_digest, issue_execution_ticket,
)
from edge_egress_uid_boot import BootGuardManifest
from ops.edge_egress_provision import EgressSpec


def sample():
    spec = {
        "edge_id": "fra1", "edge_public_ipv4": "216.126.229.12",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": "10.78.100.0/30", "veth_network": "10.78.101.0/30",
        "edge_uplink": "eth0", "edge_listen_port": 51832,
        "route_table": 1780, "mode": "relay",
    }
    raw = {
        "mode": "PROTECTED_BOOT_GUARD", "username": "nvl0557",
        "uid": 1644, "priority": 1780, "dns_port": 10553,
        "ingress_return": True, "shared_edge": True, "spec": spec,
    }
    return BootGuardManifest.parse(raw), json.dumps(raw,sort_keys=True).encode()


class FakeTransport:
    def __init__(self):
        self.ensure_count=0
        self.observe_count=0
        self.state="ABSENT"
        self.on_ensure=None

    def ensure(self, stage, role, digest):
        self.ensure_count+=1
        if self.on_ensure is not None:
            self.on_ensure()
        self.state="UP"
        return "TRANSPORT_STARTED"

    def observe(self, stage, role, digest):
        self.observe_count+=1
        return self.state


class FakeSafety:
    def __init__(self):
        self.log=[]
        self.on_deny=None
        self.fail_pam=False
        self.fail_freeze=False

    def assert_rescue_and_ownership(self, scope, review):
        self.log.append("RESCUE")

    def assert_deny_before_transport(self, scope, review):
        self.log.append("DENY")
        if self.on_deny:
            self.on_deny()

    def assert_pam_dns_boot(self, scope, review):
        self.log.append("PAM_BOOT_DNS")
        if self.fail_pam:
            raise BootProvisionHold("NO_PAM_PROOF")

    def freeze_owned_subjects(self, scope, review):
        self.log.append("FREEZE")
        if self.fail_freeze:
            raise BootProvisionHold("FREEZE_FAILURE")


class BootProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path=Path(self.temp.name)/"db.sqlite"
        self.scope=ExecutionScope(
            "EDGE_PREPARE", "fra1", "209.200.246.198", "216.126.229.12",
        )
        self.manifest,self.raw=sample()
        self.stage=Path("/root/nvl-egress-v1/core-fra1")
        self.stage_sha="a"*64
        self.actual_spec=self.manifest.request.spec
        self.stage_reader=lambda path, role, digest: (self.actual_spec,"peer")
        def renderer(path,role,digest):
            return ("[Unit]\nDescription=NVL dedicated\n[Service]\n"
                    "Type=oneshot\nRemainAfterExit=yes\n"
                    "ExecStart=/usr/bin/python3 -m ops.edge_egress_v1_transport "
                    f"ensure --stage {path} --role {role} --digest {digest}\n"
                    "# No ExecStop\n")
        self.renderer=renderer
        self.review=self.plan()
        with self.db() as db:
            db.execute("CREATE TABLE failover_operations("
                       "id INTEGER PRIMARY KEY AUTOINCREMENT,status TEXT,"
                       "source_host TEXT,target_host TEXT,detail_json TEXT)")
            db.execute("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT)")
            db.execute("INSERT INTO settings VALUES('edge_egress_protected_mode','0')")
        self.safety=FakeSafety()
        self.transport=FakeTransport()
        self.clock=1000
        self.evidence=FreshEvidence(sha256(self.review.digest.encode()).hexdigest(),
                                    self.clock,BASE_GATES)
        self.ticket=issue_execution_ticket(self.scope,self.evidence,
                                            actor_id=123,chat_id=456,now=self.clock)
        self.journal_events=[]

    @contextmanager
    def db(self):
        c=sqlite3.connect(str(self.db_path),timeout=4)
        try:
            with c: yield c
        finally: c.close()

    def plan(self, **kwargs):
        return build_stage_boot_review(
            self.stage,self.stage_sha,self.manifest,stage_reader=self.stage_reader,
            transport_renderer=self.renderer,
            roster_manifests={"nvl0557":self.raw},**kwargs,
        )

    def port(self, **kwargs):
        return GuardedStageBootPort(
            db_conn=self.db, scope=self.scope, ticket=self.ticket,
            review=self.review, boot_safety=self.safety,
            transport=self.transport, stage_reader=self.stage_reader,
            **kwargs,
        )

    def insert_intent(self):
        from hashlib import sha256
        detail={"kind":"K2_P3A","phase":INTENT_PHASE,"action":self.scope.action,
                "edge_id":self.scope.edge_id,
                "nonce_hash":sha256(self.ticket.nonce.encode()).hexdigest(),
                "scope_digest":_scope_digest(self.scope)}
        with self.db() as db:
            cur=db.execute("INSERT INTO failover_operations "
                           "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                           ("RUNNING",self.scope.source_host,
                            self.scope.target_host,json.dumps(detail)))
            return cur.lastrowid

    def acquire(self,source,target):
        with self.db() as db:
            row=db.execute("SELECT id FROM failover_operations WHERE status='RUNNING'").fetchone()
            if row: return None,row[0]
            cur=db.execute("INSERT INTO failover_operations "
                           "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                           ("RUNNING",source,target,'{"phase":"LOCKED"}'))
            return cur.lastrowid,None

    def journal(self,op,*,status,detail,finished,require_running):
        self.journal_events.append((status,detail["phase"]))
        with self.db() as db:
            rc=db.execute("UPDATE failover_operations SET status=?,detail_json=? "
                          "WHERE id=? AND status='RUNNING'",
                          (status,json.dumps(detail),op)).rowcount
            if rc!=1: raise RuntimeError("6G_LEASE_CAS_LOST")

    def executor(self,port):
        return Existing6GGuardedExecutor(
            db_conn=self.db,acquire_fn=self.acquire,journal_fn=self.journal,
            review_fn=lambda scope:self.evidence, host_port=port,
            release_enabled=True,geteuid=lambda:0,clock=lambda:self.clock,
        )

    def test_no_production_activation_and_legacy_components_reused(self):
        self.assertIs(LIVE_PROVISIONING_ENABLED,False)
        self.assertIsNotNone(ExistingPinnedTransport)
        self.assertIn("wg-quick@wg0.service",self.review.guard_unit)
        self.assertIn("Type=notify",self.review.dns_unit)
        self.assertIn("Requires="+self.review.guard_name,self.review.dns_unit)
        self.assertIn("REVIEW",self.review.pam_review.upper())
        self.assertNotIn("ExecStop=",self.review.transport_unit)
        self.assertNotIn("ssh.service",self.review.guard_unit+self.review.dns_unit)
        self.assertEqual(self.review.stage_sha256,self.stage_sha)

    def test_plan_is_deterministic_and_digest_changes_with_pin(self):
        self.assertEqual(self.plan().digest,self.review.digest)
        other=build_stage_boot_review(
            self.stage,"b"*64,self.manifest,stage_reader=self.stage_reader,
            transport_renderer=self.renderer,roster_manifests={"nvl0557":self.raw})
        self.assertNotEqual(other.digest,self.review.digest)

    def test_missing_shared_ingress_or_dns_is_hold(self):
        for change in (
            {"shared_edge":False}, {"ingress_return":False}, {"dns_port":None},
        ):
            raw=json.loads(self.raw)
            raw.update(change)
            try: other=BootGuardManifest.parse(raw)
            except ValueError: continue
            with self.subTest(change=change), self.assertRaises(BootProvisionHold):
                build_stage_boot_review(
                    self.stage,self.stage_sha,other,stage_reader=self.stage_reader,
                    transport_renderer=self.renderer,
                    roster_manifests={"nvl0557":json.dumps(raw).encode()})

    def test_plan_fails_on_wrong_stage_and_other_uid_roster(self):
        self.actual_spec=replace(self.actual_spec,edge_public_ipv4="144.172.84.82")
        with self.assertRaises(BootProvisionHold):
            self.plan()
        self.actual_spec=self.manifest.request.spec
        with self.assertRaises(BootProvisionHold):
            build_stage_boot_review(
                self.stage,self.stage_sha,self.manifest,stage_reader=self.stage_reader,
                transport_renderer=self.renderer,roster_manifests={})

    def test_plan_rejects_global_ssh_coupling(self):
        def unsafe(path,role,digest):
            return self.renderer(path,role,digest)+"ExecStop=/bin/true\n"
        with self.assertRaises(BootProvisionHold):
            build_stage_boot_review(
                self.stage,self.stage_sha,self.manifest,stage_reader=self.stage_reader,
                transport_renderer=unsafe,roster_manifests={"nvl0557":self.raw})

    def test_zero_shared_6g_intent_cannot_stage(self):
        with self.assertRaises(BootProvisionHold):
            assert_shared_6g_intent(self.db,self.scope,self.ticket)
        port=self.port(release_enabled=True)
        with self.assertRaises(BootProvisionHold):
            asyncio.run(port.apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_old_or_foreign_intent_cannot_stage(self):
        id=self.insert_intent()
        with self.db() as db:
            db.execute("UPDATE failover_operations SET detail_json=? WHERE id=?",
                       ('{"phase":"LOCKED"}',id))
        with self.assertRaises(BootProvisionHold):
            asyncio.run(self.port(release_enabled=True).apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_second_running_lease_holds(self):
        self.insert_intent()
        with self.db() as db:
            db.execute("INSERT INTO failover_operations "
                       "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                       ("RUNNING","1.1.1.1","8.8.8.8",'{"phase":"OTHER"}'))
        with self.assertRaises(BootProvisionHold):
            asyncio.run(self.port(release_enabled=True).apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_without_release_no_host_operation(self):
        self.insert_intent()
        with self.assertRaises(BootProvisionHold):
            asyncio.run(self.port(release_enabled=False).apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_allowlisted_port_rechecks_lease_before_each_step(self):
        self.insert_intent()
        p=self.port(release_enabled=True)
        asyncio.run(p.apply(self.scope))
        self.assertEqual(self.safety.log[:3],["RESCUE","DENY","PAM_BOOT_DNS"])
        self.assertEqual(self.transport.ensure_count,1)
        self.assertTrue(asyncio.run(p.verify(self.scope)))
        self.assertEqual(self.transport.observe_count,1)
        with self.assertRaises(BootProvisionHold):
            asyncio.run(p.apply(self.scope))

    def test_live_drift_between_guard_and_transport_blocks_start(self):
        op=self.insert_intent()
        def drop():
            self.safety.on_deny=None
            with self.db() as db:
                db.execute("UPDATE failover_operations SET status='ABORTED_STALE' WHERE id=?", (op,))
        self.safety.on_deny=drop
        with self.assertRaises(BootProvisionHold):
            asyncio.run(self.port(release_enabled=True).apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_post_review_stage_spec_drift_holds_before_transport(self):
        self.insert_intent()
        self.actual_spec=replace(self.actual_spec,route_table=1781)
        with self.assertRaisesRegex(BootProvisionHold,"STAGE_IDENTITY_CHANGED"):
            asyncio.run(self.port(release_enabled=True).apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_tampered_review_unit_names_are_rejected_before_transport(self):
        self.insert_intent()
        for change in (
            {"guard_unit":"tampered"}, {"dns_name":"ssh.service"},
            {"roster_review":'{"protected":[]}'},
        ):
            with self.subTest(change=change):
                forged=replace(self.review,**change)
                port=GuardedStageBootPort(
                    db_conn=self.db,scope=self.scope,ticket=self.ticket,
                    review=forged,boot_safety=self.safety,
                    transport=self.transport,stage_reader=self.stage_reader,
                    release_enabled=True)
                with self.assertRaisesRegex(BootProvisionHold,"FINGERPRINT_CHANGED"):
                    asyncio.run(port.apply(self.scope))
        self.assertEqual(self.transport.ensure_count,0)

    def test_end_to_end_p3a_before_transport_intent_and_success(self):
        p=self.port(release_enabled=True)
        receipt=asyncio.run(self.executor(p).execute(
            self.scope,self.ticket,actor_id=123,chat_id=456))
        self.assertTrue(receipt.allowed)
        self.assertEqual(self.journal_events,[
            ("RUNNING",INTENT_PHASE),("SUCCEEDED","EGRESS_P3_VERIFIED")])
        self.assertEqual(self.transport.ensure_count,1)
        self.assertIn("PAM_BOOT_DNS",self.safety.log)
        self.assertNotIn("FREEZE",self.safety.log)

    def test_end_to_end_lost_pam_evidence_is_frozen_under_6g(self):
        self.safety.fail_pam=True
        p=self.port(release_enabled=True)
        receipt=asyncio.run(self.executor(p).execute(
            self.scope,self.ticket,actor_id=123,chat_id=456))
        self.assertTrue(receipt.manual_recovery)
        self.assertEqual(self.transport.ensure_count,0)
        self.assertIn("FREEZE",self.safety.log)
        with self.db() as db:
            status,details=db.execute(
                "SELECT status,detail_json FROM failover_operations").fetchone()
        self.assertEqual(status,"RUNNING")
        self.assertEqual(json.loads(details)["phase"],RECOVERY_PHASE)

    def test_end_to_end_failed_verify_is_frozen(self):
        self.transport.state="ABSENT"
        self.transport.observe=lambda *args:"ABSENT"
        p=self.port(release_enabled=True)
        receipt=asyncio.run(self.executor(p).execute(
            self.scope,self.ticket,actor_id=123,chat_id=456))
        self.assertTrue(receipt.manual_recovery)
        self.assertEqual(self.transport.ensure_count,1)
        self.assertIn("FREEZE",self.safety.log)

    def test_ports_cannot_run_uid_attach_or_wrong_scope(self):
        attach=ExecutionScope("UID_ATTACH","fra1",
                              self.scope.source_host,self.scope.target_host,
                              username="nvl0557",uid=1644)
        with self.assertRaises(BootProvisionHold):
            GuardedStageBootPort(
                db_conn=self.db,scope=attach,ticket=self.ticket,review=self.review,
                boot_safety=self.safety,transport=self.transport,release_enabled=True)
        self.insert_intent()
        with self.assertRaises(BootProvisionHold):
            asyncio.run(self.port(release_enabled=True).apply(attach))


if __name__=="__main__":
    unittest.main()
