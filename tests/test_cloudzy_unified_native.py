"""Atomic P3–P6 Unified receipt bridge regressions; no Cloudzy or DNS effects."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

from cloudzy_quick_edge import ReceiptStore, QuickEdgeHold
from cloudzy_cz06_orchestrator import QuickRelayJournal
from cloudzy_unified_native import (
    UnifiedLinkHold, mark_paid_intent, observe_native_status,
)
from cloudzy_cz04b_guarded import GuardedCloudzy04B


class UnifiedNativeBridgeTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "unified.db"

        @contextmanager
        def factory():
            db = sqlite3.connect(str(path))
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

        self.db = factory
        self.store = ReceiptStore(factory, now=lambda: 100)
        self.store.initialize()

    def reserve(self, *, quick=True, actor=17, chat=17):
        return self.store.reserve(
            actor=actor, chat=chat, region="us-east", plan="cpu-1",
            cycle="hourly", price=30, port=2244,
            pubkey="ssh-ed25519 AAAAX", quick_relay=quick,
        )

    def read(self, job):
        with self.db() as db:
            return dict(zip(
                ["id","kind","source_ref","actor","chat","step",
                 "state","version","external_intent","code"],
                db.execute(
                    "SELECT id,kind,source_ref,actor,chat,step,"
                    "state,version,external_intent,code "
                    "FROM cloudzy_uo_operations WHERE id=?", (job,)
                ).fetchone()
            ))

    def test_native_and_unified_are_atomically_reserved(self):
        job = self.reserve()
        record = self.read(job)
        self.assertEqual(record["source_ref"], "CZ03:"+job)
        self.assertEqual((record["actor"], record["chat"]), (17,17))
        self.assertEqual((record["state"],record["step"]),("PLANNED","PREFLIGHT"))
        self.assertFalse(record["external_intent"])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_uo_events WHERE operation_id=?",
                (job,)).fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT stage FROM cloudzy_cz06_runs WHERE operation_id=?",
                (job,)).fetchone()[0], "PURCHASING")

    def test_precharge_intent_required_once_before_paid_external_post(self):
        job = self.reserve()
        self.assertTrue(self.store.mark_paid_intent(job))
        record = self.read(job)
        self.assertEqual((record["step"],record["state"],record["external_intent"]),
                         ("PURCHASE","WAITING_EXTERNAL",1))
        with self.assertRaisesRegex(UnifiedLinkHold, "PAID_INTENT_ALREADY_PENDING"):
            self.store.mark_paid_intent(job)
        self.assertEqual(self.store.get(job)["status"], "CREATING")

    def test_provider_receipt_and_native_state_are_one_commit(self):
        job = self.reserve()
        self.store.mark_paid_intent(job)
        self.store.change(job, "CREATING", "CREATED", provider_server_id="srv-1")
        self.assertEqual((self.read(job)["step"],self.read(job)["state"]),
                         ("PROVIDER_WAIT","WAITING_EXTERNAL"))
        self.store.change(job, "CREATED", "WAITING")
        self.store.change(job, "WAITING", "HOLD_SSH",
                          public_ipv4="192.0.2.15")
        self.assertEqual(self.read(job)["state"], "NEEDS_ATTESTATION")
        self.store.change(job, "HOLD_SSH", "HOSTKEY_PENDING")
        self.store.change(job, "HOSTKEY_PENDING", "PROVISIONING")
        self.assertEqual(self.read(job)["step"], "EDGE_INSTALL")
        self.store.change(job, "PROVISIONING", "EDGE_READY")
        self.assertEqual((self.read(job)["step"],self.read(job)["state"]),
                         ("STANDBY","NEEDS_ATTESTATION"))
        self.assertNotEqual(self.read(job)["state"], "COMPLETED")
        with self.db() as db:
            n = db.execute(
                "SELECT COUNT(*) FROM cloudzy_uo_events WHERE operation_id=?",
                (job,)).fetchone()[0]
            self.assertGreater(n, 4)

    def test_cz06_ready_remains_client_attestation_pending(self):
        job = self.reserve(quick=True)
        self.store.mark_paid_intent(job)
        self.store.change(job,"CREATING","CREATED",provider_server_id="srv-1")
        self.store.change(job,"CREATED","WAITING")
        self.store.change(job,"WAITING","HOLD_SSH",public_ipv4="192.0.2.15")
        self.store.change(job,"HOLD_SSH","HOSTKEY_PENDING")
        self.store.change(job,"HOSTKEY_PENDING","PROVISIONING")
        self.store.change(job,"PROVISIONING","EDGE_READY")
        q = QuickRelayJournal(self.db, now=lambda: 102)
        for old,new in (
            ("PURCHASING","WAITING_PROVIDER"),
            ("WAITING_PROVIDER","HOSTKEY_PENDING"),
            ("HOSTKEY_PENDING","INSTALLING"),
            ("INSTALLING","EDGE_READY"),
            ("EDGE_READY","STANDBY_VERIFYING"),
            ("STANDBY_VERIFYING","READY"),
        ):
            q.advance(job, new, expected=old)
        record = self.read(job)
        self.assertEqual((record["step"],record["state"],record["code"]),
                         ("CLIENT_E2E","NEEDS_ATTESTATION",
                          "CZ06_STANDBY_READY_AWAITING_CLIENT_E2E"))
        self.assertNotEqual(record["state"],"COMPLETED")

    def test_native_cas_rolls_back_if_unified_checkpoint_cannot_commit(self):
        job = self.reserve()
        self.store.mark_paid_intent(job)
        with patch("cloudzy_unified_native.DurableCoordinator._transition",
                   side_effect=RuntimeError("SIMULATED_JOURNAL_FAILURE")):
            with self.assertRaisesRegex(RuntimeError,"SIMULATED_JOURNAL_FAILURE"):
                self.store.change(job, "CREATING", "CREATED",
                                  provider_server_id="srv-1")
        self.assertEqual(self.store.get(job)["status"], "CREATING")
        self.assertEqual(self.read(job)["code"], "CLOUDZY_PAID_POST_INTENT")
        self.assertEqual(self.read(job)["state"], "WAITING_EXTERNAL")

    def test_missing_link_never_enters_external_purchase(self):
        job = self.reserve()
        with self.db() as db:
            db.execute("DELETE FROM cloudzy_uo_events WHERE operation_id=?", (job,))
            db.execute("DELETE FROM cloudzy_uo_operations WHERE id=?", (job,))
        with self.assertRaisesRegex(UnifiedLinkHold, "UNIFIED_PURCHASE_LINK_MISSING"):
            self.store.mark_paid_intent(job)

    def test_legacy_receipt_unlinked_still_recoverable(self):
        job = self.reserve()
        with self.db() as db:
            db.execute("DELETE FROM cloudzy_uo_events WHERE operation_id=?", (job,))
            db.execute("DELETE FROM cloudzy_uo_operations WHERE id=?", (job,))
        self.store.change(job,"CREATING","CREATED",provider_server_id="legacy-1")
        self.assertEqual(self.store.get(job)["status"],"CREATED")
        with self.db() as db:
            self.assertFalse(observe_native_status(
                db, operation_id=job, status="CREATED"))
        self.assertIsNone(self.read_nullable(job))

    def read_nullable(self, job):
        with self.db() as db:
            return db.execute(
                "SELECT id FROM cloudzy_uo_operations WHERE id=?",
                (job,)).fetchone()

    def test_precharge_failure_prevents_new_cloudzy_post(self):
        job = self.reserve()
        with self.db() as db:
            db.execute("DELETE FROM cloudzy_uo_events WHERE operation_id=?", (job,))
            db.execute("DELETE FROM cloudzy_uo_operations WHERE id=?", (job,))
        # The effectful handler calls mark_paid_intent immediately before POST.
        # A missing link must HOLD and cannot be interpreted as an approval.
        with self.db() as db:
            with self.assertRaisesRegex(UnifiedLinkHold,
                                        "UNIFIED_PURCHASE_LINK_MISSING"):
                mark_paid_intent(db, operation_id=job)
        self.assertEqual(self.store.get(job)["status"], "CREATING")

    def test_cz07_mirror_requires_verified_provider_and_business_receipts(self):
        from cloudzy_cz07_queue import DurableCutoverQueue
        job = "f"*32
        source = "192.0.2.3"
        target = "192.0.2.15"
        purchase = self.reserve()
        self.store.mark_paid_intent(purchase)
        self.store.change(purchase, "CREATING", "CREATED",
                          provider_server_id="srv-1")
        self.store.change(purchase, "CREATED", "WAITING")
        self.store.change(purchase, "WAITING", "HOLD_SSH",
                          public_ipv4=target)
        self.store.change(purchase, "HOLD_SSH", "HOSTKEY_PENDING")
        self.store.change(purchase, "HOSTKEY_PENDING", "PROVISIONING")
        self.store.change(purchase, "PROVISIONING", "EDGE_READY")
        with self.db() as db:
            DurableCutoverQueue._init(db)
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs "
                "(id,cz06_operation,actor,chat,source,target,provider_id,"
                "source_fingerprint,status,total,moved,evidence,started_at,"
                "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job,purchase,17,17,source,target,"srv-1",
                 "digest","QUEUED",473,0,"VERIFIED",100,100)
            )
            q = DurableCutoverQueue(db_conn=self.db, cz04b=None,
                                    now=lambda:100)
            q._log(db,job,"QUEUED","APPROVED",0,473)
        self.assertEqual(self.read(purchase)["step"], "DNS_CUTOVER")
        with self.db() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET status='ROUTING' WHERE id=?",
                       (job,))
            q._log(db,job,"ROUTING","ROUTE_START",0,473)
        self.assertEqual(self.read(purchase)["external_intent"], 1)
        with self.db() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET status='MIGRATING', moved=200 "
                       "WHERE id=?", (job,))
            q._log(db,job,"MIGRATING","BATCH_CAS_COMMITTED",200,273)
        self.assertEqual((self.read(purchase)["step"],self.read(purchase)["code"]),
                         ("CUSTOMER_MIGRATION","CZ07_BATCH_200_OF_473"))
        with self.db() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET status='VERIFYING',moved=473 "
                       "WHERE id=?", (job,))
            q._log(db,job,"VERIFYING","AWAITING_BUSINESS_E2E",473,0)
        self.assertEqual(self.read(purchase)["state"], "NEEDS_ATTESTATION")
        with self.assertRaisesRegex(UnifiedLinkHold,
                                    "CZ07_INDEPENDENT_ACCEPTANCE_REQUIRED"):
            with self.db() as db:
                db.execute("UPDATE cloudzy_cz07_jobs SET status='DONE' WHERE id=?",
                           (job,))
                q._log(db,job,"DONE","BUSINESS_E2E_ACCEPTED",473,0)
        self.assertEqual(self.read(purchase)["state"], "NEEDS_ATTESTATION")
        with self.db() as db:
            db.execute(
                "INSERT INTO cloudzy_cz07_acceptance "
                "(job_id,actor,at,create_ref,renew_ref,client_ref) "
                "VALUES (?,?,?,?,?,?)",
                (job,17,100,"create-test","renew-test","isp-test"))
            db.execute("UPDATE cloudzy_cz07_jobs SET status='DONE' WHERE id=?",
                       (job,))
            q._log(db,job,"DONE","BUSINESS_E2E_ACCEPTED",473,0)
        self.assertEqual((self.read(purchase)["state"],self.read(purchase)["step"]),
                         ("COMPLETED","FINAL_VERIFY"))

    def test_guarded_phase5_is_the_route_executor_type(self):
        source=(Path(__file__).parent.parent/"bot_final_v49-2.py").read_text()
        self.assertIn("from cloudzy_cz04b_guarded import GuardedCloudzy04B",
                      source)
        self.assertIn("_cloudzy_04b = GuardedCloudzy04B(", source)
        self.assertIn("cz04b=_cloudzy_04b", source)
        self.assertTrue(issubclass(GuardedCloudzy04B,
                                   __import__("cloudzy_cz04b").Cloudzy04B))


if __name__=="__main__":
    unittest.main()
