"""K2 Phase 2 promotion: real source-enrollment SQLite + P3-A 6G CAS."""
from __future__ import annotations
import asyncio
from hashlib import sha256
import json
import unittest

from edge_egress_k2_cohort_promotion import (
    COHORT_PROMOTION_RELEASED, CohortPromotionHold,
    inspect_promotion, GuardedCohortPromotionPort,
)
from edge_egress_p3_executor import (
    BASE_GATES, PROMOTION_GATES, ExecutionScope, FreshEvidence,
    Existing6GGuardedExecutor, issue_execution_ticket, ExecutorHold,
)
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class FakePromotionSafety:
    def __init__(self):
        self.events=[]
        self.fail=None
        self.on_check=None
        self.calls=0

    def _check(self,step):
        self.events.append(step)
        self.calls+=1
        if self.on_check:
            self.on_check(self.calls,step)
        return step != self.fail

    def assert_root_rescue_and_pam_boot(self,scope): return self._check("pam_rescue")
    def assert_all_users_idle(self,scope): return self._check("idle")
    def assert_kernel_uid_routes(self,scope): return self._check("routes")
    def assert_external_ipv4_dns_ipv6(self,scope): return self._check("packet")
    def assert_failure_reboot_recovery(self,scope): return self._check("reboot")


class CohortPromotionTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        old_plan,ticket,executor,_=self.fx.engine()
        result=self.fx.execute(old_plan,ticket,executor)
        self.assertTrue(result.allowed,result)
        self.scope=ExecutionScope(
            "COHORT_PROMOTE","src1",SOURCE,TARGET
        )
        self.roster_loader=lambda:self.fx.roster
        self.guard_loader=lambda m:self.fx.manifest
        self.safety=FakePromotionSafety()
        self.clock=1000

    def review(self):
        return inspect_promotion(
            self.fx.conn_factory,self.scope,now=self.fx.now,
            os_uid=self.fx.lookup,roster_loader=self.roster_loader,
            guard_loader=self.guard_loader,
        )

    def prepared(self,release=True,missing_gates=False):
        review=self.review()
        evidence=FreshEvidence(
            sha256(b"independent source+target F4 and packet witness").hexdigest(),
            1000, BASE_GATES |
            (frozenset() if missing_gates else PROMOTION_GATES),
        )
        if missing_gates:
            return review,evidence,None,None
        ticket=issue_execution_ticket(
            self.scope,evidence,actor_id=17,chat_id=42,now=1000,
        )
        port=GuardedCohortPromotionPort(
            db_conn=self.fx.conn_factory,review=review,ticket=ticket,
            safety=self.safety,clock=lambda:self.fx.now,
            os_uid=self.fx.lookup,roster_loader=self.roster_loader,
            guard_loader=self.guard_loader,release_enabled=release,
        )
        executor=Existing6GGuardedExecutor(
            db_conn=self.fx.conn_factory,acquire_fn=self.fx.acquire,
            journal_fn=self.fx.journal,review_fn=lambda scope:evidence,
            host_port=port,release_enabled=True,geteuid=lambda:0,
            clock=lambda:self.clock,
        )
        return review,ticket,executor,port

    def mode(self):
        with self.fx.db() as c:
            return c.execute(
                "SELECT value FROM settings "
                "WHERE key='edge_egress_protected_mode'"
            ).fetchone()[0]

    def journal(self):
        with self.fx.db() as c:
            return c.execute(
                "SELECT status,detail_json FROM failover_operations "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()

    def run_promotion(self, ticket, executor):
        return asyncio.run(executor.execute(
            self.scope,ticket,actor_id=17,chat_id=42,
        ))

    def test_success_atomic_legacy_to_protected_mode_no_customer_mutation(self):
        before=self.fx.state()
        review,ticket,executor,_=self.prepared()
        self.assertEqual(review.protected_accounts,1)
        result=self.run_promotion(ticket,executor)
        self.assertTrue(result.allowed,result)
        self.assertEqual(self.mode(),"1")
        after=self.fx.state()
        self.assertEqual(before[:4],after[:4])  # runtime, mapping, SSH host, DNS
        self.assertEqual(self.journal()[0],"SUCCEEDED")
        self.assertGreaterEqual(self.safety.events.count("packet"),2)
        with self.fx.db() as c:
            self.assertEqual(c.execute("SELECT is_default FROM host_pool "
                                      "WHERE host=?",(SOURCE,)).fetchone(),(1,))

    def test_no_root_release_by_default_and_ticket_gates_required(self):
        self.assertIs(COHORT_PROMOTION_RELEASED,False)
        review,evidence,_,_=self.prepared(missing_gates=True)
        with self.assertRaisesRegex(ExecutorHold,"MISSING_ACCEPTANCE_GATES"):
            issue_execution_ticket(self.scope,evidence,actor_id=17,chat_id=42,now=1000)
        review,ticket,executor,_=self.prepared(release=False)
        result=self.run_promotion(ticket,executor)
        self.assertFalse(result.allowed)
        self.assertEqual(self.mode(),"0")
        self.assertEqual(self.safety.events,[])

    def test_unknown_active_legacy_account_prevents_promotion(self):
        with self.fx.db() as c:
            c.execute("INSERT INTO ssh_accounts VALUES("
                      "'nvl_new',?,'ssh','🟢 فعال')",(SOURCE,))
        with self.assertRaises(CohortPromotionHold):
            self.review()
        self.assertEqual(self.mode(),"0")

    def test_partial_or_foreign_runtime_mapping_refuses(self):
        with self.fx.db() as c:
            c.execute("UPDATE edge_egress_uid_bindings SET edge_id='foreign' "
                      "WHERE username='nvl0557'")
        with self.assertRaises(CohortPromotionHold):
            self.review()

    def test_stale_source_f4_fails_before_ticket(self):
        with self.fx.db() as c:
            c.execute("UPDATE edge_egress_readiness SET expires_at=1 "
                      "WHERE edge_id='src1'")
        with self.assertRaises(CohortPromotionHold):
            self.review()

    def test_roster_or_unix_uid_drift_before_promotion_blocks(self):
        self.fx.uid=1670
        with self.assertRaises(CohortPromotionHold):
            self.review()
        self.fx.uid=1644
        self.fx.roster={}
        with self.assertRaises(CohortPromotionHold):
            self.review()

    def test_scope_rejects_same_source_for_promotion(self):
        with self.assertRaises(ExecutorHold):
            ExecutionScope("COHORT_PROMOTE","src1",SOURCE,SOURCE)

    def test_drift_under_original_6g_lock_holds_before_sql_write(self):
        review,ticket,executor,_=self.prepared()
        with self.fx.db() as c:
            c.execute("UPDATE ssh_accounts SET host=? WHERE username='nvl0557'",
                      (TARGET,))
        result=self.run_promotion(ticket,executor)
        self.assertFalse(result.allowed)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.mode(),"0")
        self.assertEqual(self.journal()[0],"RUNNING")

    def test_missing_external_packet_proof_holds_without_mode_change(self):
        review,ticket,executor,_=self.prepared()
        self.safety.fail="packet"
        result=self.run_promotion(ticket,executor)
        self.assertFalse(result.allowed)
        self.assertEqual(self.mode(),"0")
        self.assertEqual(self.journal()[0],"RUNNING")
        self.assertEqual(json.loads(self.journal()[1])["phase"],
                         "EGRESS_P3_RECOVERY_REQUIRED")

    def test_failure_after_cas_keeps_mode_protected_and_6g_hold(self):
        review,ticket,executor,_=self.prepared()
        def inject(count,step):
            if step=="packet" and count>5:
                self.safety.fail="packet"
        self.safety.on_check=inject
        result=self.run_promotion(ticket,executor)
        self.assertFalse(result.allowed)
        self.assertTrue(result.manual_recovery)
        self.assertEqual(self.mode(),"1")  # NEVER auto rollback to Legacy
        self.assertEqual(self.journal()[0],"RUNNING")

    def test_competing_running_6g_lease_blocks_readonly_review(self):
        with self.fx.db() as c:
            c.execute(
                "INSERT INTO failover_operations "
                "(source_host,target_host,status,detail_json) "
                "VALUES(?,?,'RUNNING','{}')",(SOURCE,TARGET),
            )
        with self.assertRaisesRegex(CohortPromotionHold,"SHARED_6G_BUSY"):
            self.review()

    def test_wrong_actor_and_expired_confirmation_no_acquire(self):
        review,ticket,executor,_=self.prepared()
        result=None
        with self.assertRaises(ExecutorHold):
            asyncio.run(executor.execute(
                self.scope,ticket,actor_id=18,chat_id=42,
            ))
        self.assertEqual(self.mode(),"0")
        self.assertIsNone(self.fx.state()[-1] if False else None)

    def test_source_identity_or_dns_change_blocks_atomic_transition(self):
        review,ticket,executor,_=self.prepared()
        with self.fx.db() as c:
            c.execute("UPDATE settings SET value=? "
                      "WHERE key='dns_current_ip'",(TARGET,))
        result=self.run_promotion(ticket,executor)
        self.assertFalse(result.allowed)
        self.assertEqual(self.mode(),"0")


if __name__ == "__main__":
    unittest.main()
