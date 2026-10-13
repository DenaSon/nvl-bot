"""P3-A offline tests; no production commands or mutation ports are imported."""
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

from edge_egress_handoff import is_egress_recovery_hold
from edge_egress_p3_executor import (
    ALLOWED_ACTIONS, ATTACH_GATES, BASE_GATES, EXECUTOR_ENABLED,
    INTENT_PHASE, RECOVERY_PHASE, ExecutionScope, ExecutorHold,
    Existing6GGuardedExecutor, FreshEvidence, issue_execution_ticket,
)


class FakeHost:
    def __init__(self, test):
        self.test = test
        self.applied = 0
        self.verified = 0
        self.frozen = 0
        self.fail_apply = False
        self.fail_verify = False
        self.fail_freeze = False
        self.observe_phase = None

    async def apply(self, scope):
        self.applied += 1
        with self.test.conn() as c:
            entry = c.execute("SELECT status,detail_json FROM failover_operations "
                              "WHERE status='RUNNING'").fetchone()
            self.observe_phase = json.loads(entry[1]).get("phase")
        if self.fail_apply:
            raise RuntimeError("private password=not-for-journal")

    async def verify(self, scope):
        self.verified += 1
        return not self.fail_verify

    async def freeze_or_hold(self, scope):
        self.frozen += 1
        if self.fail_freeze:
            raise RuntimeError("freeze failed")


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "db.sqlite"
        with self.conn() as db:
            db.execute("""CREATE TABLE failover_operations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT, source_host TEXT, target_host TEXT, detail_json TEXT
            )""")
        self.now = 1000
        self.scope = ExecutionScope(
            action="EDGE_PREPARE", edge_id="e7",
            source_host="209.200.246.198", target_host="172.86.105.67",
        )
        self.digest = sha256(b"pinned F4/host/Stage snapshot").hexdigest()
        self.evidence = FreshEvidence(self.digest, 1000, BASE_GATES)
        self.host = FakeHost(self)
        self.acquire_count = 0
        self.journal_count = 0

    @contextmanager
    def conn(self):
        con = sqlite3.connect(str(self.path), timeout=3)
        try:
            with con:
                yield con
        finally:
            con.close()

    def acquire(self, source, target):
        self.acquire_count += 1
        with self.conn() as db:
            running = db.execute("SELECT id FROM failover_operations "
                                 "WHERE status='RUNNING'").fetchone()
            if running:
                return None, running[0]
            cur = db.execute(
                "INSERT INTO failover_operations "
                "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                ("RUNNING",source,target,json.dumps({"phase":"LOCKED"})),
            )
            return cur.lastrowid, None

    def journal(self, op, *, status, detail, finished, require_running):
        self.journal_count += 1
        self.assertTrue(require_running)
        self.assertEqual(finished, status == "SUCCEEDED")
        with self.conn() as db:
            updated = db.execute(
                "UPDATE failover_operations SET status=?,detail_json=? "
                "WHERE id=? AND status='RUNNING'",
                (status,json.dumps(detail),op),
            )
            if updated.rowcount != 1:
                raise RuntimeError("6G_STATUS_CAS_FAILED")

    def engine(self, *, reviewer=None, enabled=True, root=True, host=True,
               journal=None):
        return Existing6GGuardedExecutor(
            db_conn=self.conn, acquire_fn=self.acquire,
            journal_fn=journal or self.journal,
            review_fn=reviewer or (lambda scope: self.evidence),
            host_port=self.host if host else None,
            release_enabled=enabled, geteuid=lambda: 0 if root else 1000,
            clock=lambda: self.now,
        )

    def ticket(self, scope=None, evidence=None):
        return issue_execution_ticket(
            scope or self.scope, evidence or self.evidence,
            actor_id=18, chat_id=35, now=self.now,
        )

    def run_exec(self, engine=None, ticket=None, scope=None):
        return asyncio.run((engine or self.engine()).execute(
            scope or self.scope, ticket or self.ticket(),
            actor_id=18, chat_id=35,
        ))

    def only(self):
        with self.conn() as db:
            row = db.execute("SELECT id,status,detail_json FROM failover_operations").fetchone()
        return row[0], row[1], json.loads(row[2])

    def test_global_source_default_off_and_requires_explicit_gate(self):
        self.assertIs(EXECUTOR_ENABLED, False)
        for enabled,root,host in ((False,True,True),(True,False,True),(True,True,False)):
            with self.subTest(enabled=enabled,root=root,host=host):
                with self.assertRaises(ExecutorHold):
                    self.run_exec(engine=self.engine(enabled=enabled,root=root,host=host))
        self.assertEqual(self.acquire_count,0)
        self.assertEqual(self.host.applied,0)

    def test_allowlist_and_uid_identity_rejected_before_acquire(self):
        self.assertEqual(ALLOWED_ACTIONS, {"EDGE_PREPARE","UID_ATTACH","UID_FREEZE"})
        for data in (
            dict(action="DELETE_ALL"), dict(edge_id="../e7"),
            dict(action="UID_ATTACH",username="",uid=None),
            dict(action="EDGE_PREPARE",username="root",uid=0),
        ):
            with self.subTest(data=data), self.assertRaises(ExecutorHold):
                ExecutionScope(**{**vars(self.scope),**data})

    def test_ticket_bound_actor_chat_scope_expiry(self):
        ticket=self.ticket()
        for a,c,ts in ((19,35,1000),(18,99,1000),(18,35,1120)):
            self.now=ts
            with self.subTest(actor=a,chat=c,now=ts):
                with self.assertRaises(ExecutorHold):
                    asyncio.run(self.engine().execute(self.scope,ticket,
                                                      actor_id=a,chat_id=c))
        self.assertEqual(self.acquire_count,0)

    def test_required_attestation_gates(self):
        for missing in BASE_GATES:
            with self.subTest(missing=missing),self.assertRaises(ExecutorHold):
                self.ticket(evidence=replace(self.evidence,gates=BASE_GATES-{missing}))
        attach=ExecutionScope(action="UID_ATTACH",edge_id="e7",
            source_host=self.scope.source_host,target_host=self.scope.target_host,
            username="nvl0557",uid=1644)
        with self.assertRaises(ExecutorHold):
            self.ticket(scope=attach)
        valid=replace(self.evidence,gates=BASE_GATES|ATTACH_GATES)
        self.assertEqual(self.ticket(scope=attach,evidence=valid).evidence_digest,self.digest)

    def test_success_has_protected_intent_before_first_mutation_and_terminal_cas(self):
        result=self.run_exec()
        self.assertTrue(result.allowed)
        self.assertEqual(result.result,"SUCCEEDED")
        self.assertEqual(self.host.observe_phase,INTENT_PHASE)
        self.assertEqual((self.host.applied,self.host.verified,self.host.frozen),(1,1,0))
        _,status,detail=self.only()
        self.assertEqual(status,"SUCCEEDED")
        self.assertEqual(detail["kind"],"K2_P3A")
        self.assertNotIn("password",json.dumps(detail).lower())

    def test_replay_blocked_with_durable_original_journal(self):
        ticket=self.ticket()
        first=self.run_exec(ticket=ticket)
        self.assertTrue(first.allowed)
        with self.assertRaisesRegex(ExecutorHold,"TICKET_REPLAY"):
            self.run_exec(ticket=ticket)
        self.assertEqual(self.acquire_count,1)
        self.assertEqual(self.host.applied,1)

    def test_same_executor_instance_cannot_run_twice(self):
        engine=self.engine()
        ticket=self.ticket()
        self.assertTrue(self.run_exec(engine=engine,ticket=ticket).allowed)
        with self.assertRaisesRegex(ExecutorHold,"EXECUTOR_ONE_SHOT"):
            self.run_exec(engine=engine,ticket=self.ticket())

    def test_shared_running_lock_refuses_second_mutation(self):
        with self.conn() as db:
            db.execute("INSERT INTO failover_operations "
                       "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                       ("RUNNING","9.9.9.9","8.8.8.8",'{"phase":"EGRESS_RECOVERY_REQUIRED"}'))
        r=self.run_exec()
        self.assertEqual(r.result,"SHARED_6G_BUSY")
        self.assertEqual(self.host.applied,0)

    def test_changed_preview_before_lock_does_not_acquire(self):
        original=self.ticket()
        self.evidence=replace(self.evidence,digest=sha256(b"changed").hexdigest())
        with self.assertRaisesRegex(ExecutorHold,"PREVIEW_STALE"):
            self.run_exec(ticket=original)
        self.assertEqual(self.acquire_count,0)

    def test_changed_inside_lock_leaves_durable_protected_recovery_marker(self):
        original=self.ticket()
        count=[0]
        def review(scope):
            count[0]+=1
            if count[0] >= 2:
                return replace(self.evidence,digest=sha256(b"changed after lock").hexdigest())
            return self.evidence
        r=self.run_exec(engine=self.engine(reviewer=review),ticket=original)
        self.assertFalse(r.allowed)
        self.assertTrue(r.manual_recovery)
        _,status,detail=self.only()
        self.assertEqual(status,"RUNNING")
        self.assertEqual(detail["phase"],RECOVERY_PHASE)
        self.assertTrue(is_egress_recovery_hold(json.dumps(detail)))
        self.assertEqual(self.host.applied,0)

    def test_partial_host_write_freezes_holds_and_sanitizes(self):
        self.host.fail_apply=True
        r=self.run_exec()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.applied,1)
        self.assertEqual(self.host.frozen,1)
        _,status,d=self.only()
        self.assertEqual((status,d["phase"]),("RUNNING",RECOVERY_PHASE))
        self.assertTrue(d["frozen"])
        self.assertTrue(is_egress_recovery_hold(json.dumps(d)))
        self.assertNotIn("private",json.dumps(d))
        self.assertNotIn("password",json.dumps(d))

    def test_post_action_validation_failure_remains_locked(self):
        self.host.fail_verify=True
        r=self.run_exec()
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.frozen,1)
        self.assertEqual(self.only()[1],"RUNNING")

    def test_failed_freeze_never_unlocks_6g(self):
        self.host.fail_apply=True
        self.host.fail_freeze=True
        r=self.run_exec()
        self.assertTrue(r.manual_recovery)
        self.assertFalse(self.only()[2]["frozen"])
        self.assertEqual(self.only()[1],"RUNNING")

    def test_failed_success_journal_recovers_without_failed_unlock(self):
        ticket=self.ticket()
        def journal(op, *, status, detail, finished, require_running):
            if status=="SUCCEEDED":
                raise RuntimeError("simulated persistent commit error")
            return self.journal(op,status=status,detail=detail,
                                finished=finished,require_running=require_running)
        r=self.run_exec(engine=self.engine(journal=journal),ticket=ticket)
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.frozen,1)
        self.assertEqual(self.only()[2]["phase"],RECOVERY_PHASE)

    def test_intent_persisted_on_failure_before_host_write(self):
        def journal(op, *, status, detail, finished, require_running):
            if detail["phase"]==INTENT_PHASE:
                raise RuntimeError("journal outage")
            return self.journal(op,status=status,detail=detail,
                                finished=finished,require_running=require_running)
        r=self.run_exec(engine=self.engine(journal=journal))
        self.assertTrue(r.manual_recovery)
        self.assertEqual(self.host.applied,0)
        self.assertEqual(self.only()[1],"RUNNING")

    def test_recovery_phase_never_stale_unlocked(self):
        for p in (INTENT_PHASE, RECOVERY_PHASE):
            self.assertTrue(is_egress_recovery_hold(json.dumps({"phase":p})))
        self.assertFalse(is_egress_recovery_hold(json.dumps({"phase":"EGRESS_P3_VERIFIED"})))


if __name__ == "__main__":
    unittest.main()
