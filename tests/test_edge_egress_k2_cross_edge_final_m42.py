"""M42 FINAL signed root evidence: expected cross-edge M1 postcommit blockers.

This test injects M1 from real disposable SQLite and a synthetic signed
external observer. Real original-6G/F2 CAS verification has separate tests.
No production root observer, network or Telegram execution.
"""
import unittest
from unittest.mock import patch
from dataclasses import replace

from edge_egress_k2_m42_bindings import RootM42Bindings, HostReviewedPorts, RootAdminPolicy
from edge_egress_k2_m42_evidence import SignedExternalEvidence, WitnessAccount, REQUIRED_CHECKS
from edge_egress_k2_migration_inventory import LiveIngressWitness
from edge_egress_p3_executor import (
    ExecutionScope, FreshEvidence, issue_execution_ticket, BASE_GATES,
    ATTACH_GATES,
)
from tests.test_edge_egress_k2_migration_inventory import K2M1InventoryTests,NOW,SOURCE,TARGET


class M42CrossEdgeFinalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests(methodName="test_single_and_batch_use_same_account_evidence")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.scope=ExecutionScope(
            "UID_ATTACH","e9",SOURCE,TARGET,username="nvl0555",uid=1636
        )
        evidence=SignedExternalEvidence(
            "a"*64,NOW-1,NOW+15,"e9",TARGET,REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"s8",SOURCE,0),)
        )
        self.root=RootM42Bindings(
            ports=HostReviewedPorts(
                db_conn=self.fx.db,acquire_6g=lambda *a:None,
                journal_6g=lambda *a,**k:None,
                port_factory=lambda *a:None,
                live_admin_role=lambda *a:False,
                protected_mode=lambda:"0",
                external_evidence=lambda:evidence,
                ingress_provider=lambda **kwargs:None,
                os_uid=lambda n:self.fx.uids[n],
                now=lambda:NOW,geteuid=lambda:0,
            ),
            root_secret=b"t"*48,admin_policy=RootAdminPolicy(frozenset()),
            reviewed_release=True
        )
        self.ticket=issue_execution_ticket(
            self.scope,
            FreshEvidence("a"*64,NOW,BASE_GATES|ATTACH_GATES),
            actor_id=11,chat_id=11,now=NOW,
        )
        # Production review is M42.review, already separately checked against
        # root journal+current wg0. This replaces it ONLY inside hermetic tests.
        self.root.review=lambda selection:self.fx.preview(
            selection.usernames,selection.mode,
            ingress_witness=lambda n:LiveIngressWitness(
                n,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE"
            ),
        )

    def _protected(self):
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_runtime VALUES(?,?,?,?,?)",
            ("nvl0555",1636,"e9",TARGET,"PROTECTED")
        )
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_bindings VALUES(?,?,?,?,?)",
            ("nvl0555",1636,"e9",TARGET,"PROTECTED")
        )
        self.fx.c.execute(
            "INSERT INTO failover_operations VALUES(41,'RUNNING')"
        )

    def test_precommit_and_exact_postcommit_keep_same_signed_ticket_digest(self):
        with patch("edge_egress_k2_m42_bindings.M42_LIVE_BINDINGS_ENABLED",True),\
             patch("edge_egress_k2_m42_bindings.M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED",True):
            before=self.root.fresh_p3_evidence(self.scope)
            self._protected()
            issues=next(a.issues for a in self.root.review(
                self.fx.preview().selection
            ).accounts if a.selected)
            self.assertEqual(issues,(
                "TARGET_ALREADY_PROTECTED","PROTECTED_SOURCE_DRIFT"
            ))
            with patch.object(self.root,"_post_commit_under_current_6g",
                              return_value=True):
                after=self.root.fresh_p3_evidence(
                    self.scope,expected_ticket=self.ticket
                )
            self.assertEqual(before.digest,after.digest)
            with self.assertRaisesRegex(ValueError,"HOLD"):
                self.root.fresh_p3_evidence(self.scope)

    def test_postcommit_wrong_egress_owner_still_holds(self):
        with patch("edge_egress_k2_m42_bindings.M42_LIVE_BINDINGS_ENABLED",True),\
             patch("edge_egress_k2_m42_bindings.M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED",True):
            self._protected()
            self.fx.c.execute(
                "UPDATE edge_egress_uid_runtime SET edge_ipv4=?",
                (SOURCE,)
            )
            with patch.object(self.root,"_post_commit_under_current_6g",
                              return_value=True):
                with self.assertRaisesRegex(ValueError,"HOLD"):
                    self.root.fresh_p3_evidence(
                        self.scope,expected_ticket=self.ticket
                    )


if __name__=="__main__":
    unittest.main()
