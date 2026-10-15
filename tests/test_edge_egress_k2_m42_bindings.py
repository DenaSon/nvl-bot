"""K2 M4.2 trusted M1/M2/P3 binding source tests, not a live Core test."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import edge_egress_k2_m42_bindings as b
from edge_egress_k2_m42_evidence import (
    REQUIRED_CHECKS,SignedExternalEvidence,WitnessAccount,
)
from edge_egress_k2_migration_inventory import LiveIngressWitness,select_migration
from edge_egress_k2_m3_waves import build_wave_plan
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,TARGET,NOW,
)


class TrustedRootFactoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture=K2M1InventoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fx=fixture
        self.clock=lambda:NOW
        self.evidence=SignedExternalEvidence(
            "a"*64,NOW-1,NOW+15,"e9",TARGET,
            REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"e9",TARGET,0),),
        )
        self.called=[]
        self.ports=b.HostReviewedPorts(
            db_conn=fixture.db,
            acquire_6g=lambda *args:self.called.append("acquire"),
            journal_6g=lambda *args,**kwargs:self.called.append("journal"),
            port_factory=lambda scope,ticket,review:self.called.append("port"),
            live_admin_role=lambda actor,chat:actor==11 and chat==-222,
            protected_mode=lambda:"0",
            external_evidence=lambda:self.evidence,
            ingress_provider=lambda **kwargs:(
                lambda name:LiveIngressWitness(name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE")
            ),
            os_uid=lambda name:fixture.uids[name],
            now=self.clock,geteuid=lambda:0,
        )
        self.bind=b.RootM42Bindings(
            ports=self.ports,root_secret=b"k"*48,
            admin_policy=b.RootAdminPolicy(frozenset({(11,-222)})),
            reviewed_release=True,
        )
        self.patch=patch.object(b,"M42_LIVE_BINDINGS_ENABLED",True)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.selection=select_migration("SINGLE",("nvl0555",),"e9")

    def test_strict_original_m1_review_with_two_independent_sources(self):
        inventory=self.bind.review(self.selection)
        user=next(u for u in inventory.accounts if u.selected)
        self.assertEqual(user.uid,1636)
        self.assertEqual(user.active_sessions,0)
        self.assertEqual(user.source_edge_id,"e9")
        self.assertTrue(inventory.target_f4_accepted)
        self.assertFalse(inventory.global_issues)

    def test_original_current_admin_db_without_historical_fallback(self):
        self.fx.c.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)"
        )
        admin=b.LegacyCurrentAdminRole(self.fx.db)
        self.assertFalse(admin(11,11))
        self.fx.c.execute(
            "INSERT INTO settings VALUES ('historical_admin_ids','11')"
        )
        self.assertFalse(admin(11,11))
        self.fx.c.execute(
            "INSERT INTO settings VALUES ('admin_chat_ids','11,42')"
        )
        self.assertTrue(admin(11,11))
        self.assertTrue(admin(42,42))
        self.assertFalse(admin(11,-222))
        self.assertFalse(admin(42,11))
        self.assertFalse(admin(True,True))
        self.fx.c.execute(
            "DELETE FROM settings WHERE key='admin_chat_ids'"
        )
        self.assertFalse(admin(11,11))

    def test_corrupt_current_admin_login_list_denied(self):
        self.fx.c.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)"
        )
        self.fx.c.execute(
            "INSERT INTO settings VALUES ('admin_chat_ids','11')"
        )
        admin=b.LegacyCurrentAdminRole(self.fx.db)
        self.assertTrue(admin(11,11))
        for invalid in ("11,11","11,"," 11","011","-1",
                        "11,foo","0","11,"+"1"*24):
            with self.subTest(invalid=invalid):
                self.fx.c.execute(
                    "UPDATE settings SET value=? WHERE key='admin_chat_ids'",
                    (invalid,),
                )
                self.assertFalse(admin(11,11))
        self.fx.c.execute("DROP TABLE settings")
        self.assertFalse(admin(11,11))

    def test_operator_requires_root_policy_and_current_role(self):
        self.assertTrue(self.bind.admin(11,-222))
        self.assertFalse(self.bind.admin(11,-333))
        self.assertFalse(self.bind.admin(14,-222))
        bad=b.HostReviewedPorts(**{**self.ports.__dict__,"live_admin_role":lambda *_:False})
        another=b.RootM42Bindings(
            ports=bad,root_secret=b"k"*48,admin_policy=self.bind.policy,
            reviewed_release=True,
        )
        self.assertFalse(another.admin(11,-222))

    def test_signed_session_count_one_never_ready(self):
        self.evidence=SignedExternalEvidence(
            "a"*64,NOW-1,NOW+15,"e9",TARGET,REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"e9",TARGET,1),),
        )
        inv=self.bind.review(self.selection)
        self.assertIn("SESSION_STATE_NOT_ATTESTED",
                      next(a for a in inv.accounts if a.selected).issues)

    def test_wrong_source_signed_record_is_not_repaired_from_db(self):
        self.evidence=SignedExternalEvidence(
            "a"*64,NOW-1,NOW+15,"e9",TARGET,REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"s8","172.86.111.69",0),),
        )
        inv=self.bind.review(self.selection)
        self.assertIn("SOURCE_INGRESS_NOT_ATTESTED",
                      next(a for a in inv.accounts if a.selected).issues)

    def test_physical_f4_requires_correct_scope_and_current_readiness(self):
        plan=build_wave_plan(self.bind.review(self.selection))
        self.assertTrue(self.bind.physical_f4(plan))
        self.fx.c.execute("UPDATE edge_egress_readiness SET state='STAGED'")
        self.assertFalse(self.bind.physical_f4(plan))
        self.assertEqual(self.called,[])

    async def test_real_original_p3_ticket_but_no_fake_port(self):
        scope=b.ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,
            username="nvl0555",uid=1636,
        )
        ticket=self.bind.issue_ticket(scope,11,-222)
        self.assertEqual(ticket.actor_id,11)
        self.assertEqual(ticket.chat_id,-222)
        # Only exact, concrete DeferredOriginal6GHostPort accepted;
        # our synthetic mock port is denied BEFORE acquiring original 6G.
        with self.assertRaisesRegex(b.M42BindingHold,"HOST_PORT"):
            await self.bind.execute_single(scope,ticket,11,-222)
        self.assertEqual(self.called,["port"])
        with self.assertRaisesRegex(b.M42BindingHold,"ONE_SHOT"):
            await self.bind.execute_single(scope,ticket,11,-222)

    def test_original_p3_evidence_digest_pins_entire_signed_report(self):
        scope=b.ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,
            username="nvl0555",uid=1636,
        )
        before=self.bind.fresh_p3_evidence(scope)
        self.evidence=SignedExternalEvidence(
            "a"*64,NOW-1,NOW+16,"e9",TARGET,REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"e9",TARGET,0),),
        )
        after=self.bind.fresh_p3_evidence(scope)
        self.assertNotEqual(before.digest,after.digest)

    def test_wrong_actor_never_reaches_port_or_original_6g(self):
        scope=b.ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,
            username="nvl0555",uid=1636,
        )
        with self.assertRaisesRegex(b.M42BindingHold,"UNAUTHORIZED"):
            self.bind.issue_ticket(scope,12,-222)
        self.assertEqual(self.called,[])

    def test_cross_edge_legacy_cannot_issue_ticket(self):
        cross=b.ExecutionScope(
            "UID_ATTACH","e9","172.86.111.69",TARGET,
            username="nvl0555",uid=1636,
        )
        with self.assertRaisesRegex(b.M42BindingHold,"ONLY_SAME_EDGE"):
            self.bind.issue_ticket(cross,11,-222)
        self.assertEqual(self.called,[])

    def test_unknown_or_expired_evidence_denied(self):
        self.evidence=SignedExternalEvidence(
            "a"*64,NOW-50,NOW-1,"e9",TARGET,REQUIRED_CHECKS,
            (WitnessAccount("nvl0555",1636,"e9",TARGET,0),),
        )
        with self.assertRaisesRegex(b.M42BindingHold,"EXPIRED"):
            self.bind.review(self.selection)

    def test_release_flag_and_root_required(self):
        with patch.object(b,"M42_LIVE_BINDINGS_ENABLED",False):
            with self.assertRaisesRegex(b.M42BindingHold,"NOT_RELEASED"):
                self.bind.review(self.selection)
        self.bind.ports=b.HostReviewedPorts(**{
            **self.ports.__dict__,"geteuid":lambda:1000,
        })
        with self.assertRaisesRegex(b.M42BindingHold,"NOT_RELEASED"):
            self.bind.review(self.selection)

    def test_absent_checkpoint_denied_not_installed_implicitly(self):
        with self.assertRaisesRegex(b.M42BindingHold,"CHECKPOINT"):
            self.bind.portal(checkpoint=None)
        self.assertEqual(self.called,[])


if __name__=="__main__":
    unittest.main()
