"""M2 fail-closed read-only reconciliation after a partial stage."""
from __future__ import annotations
import unittest
from ops.k2_m2_guard_recovery import inspect_append_stage, StageRecoveryHold
from tests.test_edge_egress_k2_m2_guard_append import M2MultiUIDTests


class M2RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fx=M2MultiUIDTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.p=self.fx.plan
        self.full={
            "guard":self.p.manifest_bytes,
            "guard_unit":self.p.guard_unit.encode(),
            "dns_unit":self.p.dns_unit.encode(),
        }

    def review(self,**opts):
        arguments=dict(plan=self.p,roster_bytes=self.p.current_roster,
                       staged=self.full,pam_unchanged=True,
                       original_6g_running=True)
        arguments.update(opts)
        return inspect_append_stage(**arguments)

    def test_every_partial_stage_is_replayable_only_with_6g(self):
        for left in (0,1,2,3):
            staged={k:(v if i<left else None)
                    for i,(k,v) in enumerate(self.full.items())}
            r=self.review(staged=staged)
            self.assertFalse(r.customer_ready)
            self.assertTrue(r.may_request_replay)
            self.assertEqual(len(r.missing),3-left)
            self.assertTrue(r.needs_worker_review)
            off=self.review(staged=staged,original_6g_running=False)
            self.assertFalse(off.may_request_replay)
            self.assertEqual(off.reason,"ORIGINAL_6G_HOLD_REQUIRED")

    def test_committed_roster_is_never_replayed_or_customer_ready(self):
        r=self.review(roster_bytes=self.p.next_roster)
        self.assertEqual(r.state,"ROSTERED_DENY_ONLY")
        self.assertFalse(r.customer_ready)
        self.assertFalse(r.may_request_replay)

    def test_roster_referencing_missing_guard_is_hard_hold(self):
        incomplete=dict(self.full,guard=None)
        r=self.review(roster_bytes=self.p.next_roster,staged=incomplete)
        self.assertEqual(r.state,"HOLD")
        self.assertEqual(r.reason,"ROSTER_REFERENCES_MISSING_GUARD")

    def test_pam_or_roster_drift_is_hard_hold(self):
        self.assertEqual(self.review(pam_unchanged=False).reason,
                         "GLOBAL_PAM_DRIFT")
        self.assertEqual(self.review(roster_bytes=b"{}").reason,
                         "ROSTER_DRIFT")

    def test_mismatching_artifact_never_replaced(self):
        r=self.review(staged=dict(self.full,guard_unit=b"other"))
        self.assertEqual(r.reason,"STAGE_BYTES_MISMATCH")
        self.assertFalse(r.may_request_replay)

    def test_missing_or_nonbytes_stage_is_rejected(self):
        with self.assertRaises(StageRecoveryHold):
            self.review(staged={"guard":b"x"})
        with self.assertRaises(StageRecoveryHold):
            self.review(staged=dict(self.full,guard="not bytes"))


if __name__=="__main__":
    unittest.main()
