"""P2 journal tests: deterministic SQLite, no external API or live users."""
from contextlib import contextmanager
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cloudzy_operation_coordinator import (
    DurableCoordinator, OperationHold, read_legacy_receipts,
    legacy_action,
)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite3"
        self.clock = 1000
        self.api_calls = []
        self.c = DurableCoordinator(self.db, now=lambda: self.clock)
        self.actor, self.chat = 900, -400

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.path)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def new(self):
        return self.c.register(kind="CLOUDZY_NEW", source_ref="CZ03:test-case",
                               actor=self.actor, chat=self.chat)

    def claim(self, op, *, worker="worker_123456"):
        return self.c.claim(op, actor=self.actor, chat=self.chat, worker=worker,
                            expected_version=self.c.get(op)["version"], seconds=60)

    def test_no_schema_created_by_import_or_read_only_preview(self):
        self.assertEqual(self.c.recovery_preview(), ())
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0], 0)

    def test_registration_additive_and_event_history(self):
        op = self.new()
        rec = self.c.get(op)
        self.assertEqual((rec["state"], rec["step"], rec["version"]),
                         ("PLANNED", "PREFLIGHT", 0))
        self.assertEqual([e["event"] for e in self.c.events(op)], ["REGISTER"])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM cloudzy_uo_operations"
            ).fetchone()[0], 1)
        with self.assertRaisesRegex(OperationHold, "OPERATION_ALREADY_REGISTERED"):
            self.new()

    def test_owner_mismatch_and_double_claim_are_blocked(self):
        op = self.new()
        with self.assertRaisesRegex(OperationHold, "OPERATOR_MISMATCH"):
            self.c.claim(op, actor=111, chat=self.chat, worker="worker_123456",
                         expected_version=0)
        generation = self.claim(op)
        self.assertEqual(generation, 1)
        with self.assertRaisesRegex(OperationHold, "STATE_NOT_CLAIMABLE"):
            self.c.claim(op, actor=self.actor, chat=self.chat,
                         worker="worker_second", expected_version=1)

    def test_stale_version_cannot_advance(self):
        op = self.new()
        self.claim(op)
        with self.assertRaisesRegex(OperationHold, "STALE_OPERATION_VERSION"):
            self.c.heartbeat(op, worker="worker_123456",
                             fencing=1, expected_version=0)

    def test_bounded_lease_and_heartbeat(self):
        op = self.new()
        self.claim(op)
        self.clock = 1020
        next_version = self.c.heartbeat(
            op, worker="worker_123456", fencing=1, expected_version=1)
        self.assertEqual(next_version, 2)
        self.assertEqual(self.c.get(op)["deadline"], 1080)
        self.clock = 1080
        with self.assertRaisesRegex(OperationHold, "LEASE_EXPIRED"):
            self.c.heartbeat(op, worker="worker_123456",
                             fencing=1, expected_version=2)

    def test_crash_between_registration_and_worker_claim_is_visible(self):
        op = self.new()
        # No async task has been launched; reload a new coordinator instance.
        after_restart = DurableCoordinator(self.db, now=lambda: self.clock)
        item, = after_restart.recovery_preview()
        self.assertEqual(item.operation_id, op)
        self.assertEqual(item.next_action, "CLAIM_PREFLIGHT_ONLY")
        self.assertFalse(item.lease_stale)

    def test_lost_worker_with_no_intent_is_never_auto_unlocked(self):
        op = self.new()
        self.claim(op)
        self.clock = 1061
        item, = self.c.recovery_preview()
        self.assertTrue(item.lease_stale)
        self.assertEqual(item.next_action, "VERIFY_QUIESCENCE_BEFORE_RECLAIM")
        with self.assertRaisesRegex(OperationHold, "STATE_NOT_CLAIMABLE"):
            self.claim(op, worker="worker_second")
        with self.assertRaisesRegex(OperationHold, "TRUSTED_WORKER_QUIESCENCE_REQUIRED"):
            self.c.reclaim_stale_no_effect(
                op, actor=self.actor, chat=self.chat, expected_version=1)
        self.c = DurableCoordinator(
            self.db, now=lambda: self.clock, worker_quiescent=lambda job: job == op)
        state = self.c.reclaim_stale_no_effect(
            op, actor=self.actor, chat=self.chat, expected_version=1)
        self.assertEqual(state, "PAUSED_SAFE")
        self.assertEqual(self.c.get(op)["worker"], None)
        generation = self.claim(op, worker="worker_second")
        self.assertEqual(generation, 2)
        with self.assertRaisesRegex(OperationHold, "WORKER_FENCED"):
            self.c.checkpoint(op, worker="worker_123456", fencing=1,
                              expected_version=3, step="PREFLIGHT")

    def test_expired_lease_with_external_intent_must_reconcile(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=1,
            step="PURCHASE", state="WAITING_EXTERNAL", external_intent=True
        )
        self.clock = 1061
        item, = self.c.recovery_preview()
        self.assertEqual(item.next_action, "RECONCILE_EXTERNAL_NO_REPLAY")
        self.c = DurableCoordinator(
            self.db, now=lambda: self.clock, worker_quiescent=lambda _: True)
        with self.assertRaisesRegex(OperationHold, "EXTERNAL_RECONCILIATION_REQUIRED"):
            self.c.reclaim_stale_no_effect(op, actor=self.actor, chat=self.chat,
                                           expected_version=2)
        with self.assertRaisesRegex(OperationHold, "TRUSTED_EXTERNAL_EVIDENCE_REQUIRED"):
            self.c.reconcile_external(op, actor=self.actor, chat=self.chat,
                                      expected_version=2)

    def test_cancel_before_start_closes_only_new_journal(self):
        op = self.new()
        self.assertEqual(
            self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                                  expected_version=0), "CANCELLED_SAFE"
        )
        self.assertEqual(self.c.request_cancel(
            op, actor=self.actor, chat=self.chat, expected_version=1), "CANCELLED_SAFE")
        self.assertEqual(len(self.c.events(op)), 2)
        with self.assertRaisesRegex(OperationHold, "STATE_NOT_CLAIMABLE"):
            self.claim(op)

    def test_cancel_during_running_requires_worker_ack(self):
        op = self.new()
        self.claim(op)
        self.assertEqual(self.c.request_cancel(
            op, actor=self.actor, chat=self.chat, expected_version=1),
            "CANCELLATION_REQUESTED")
        with self.assertRaisesRegex(OperationHold, "CANCEL_OR_STAGE_CHANGED"):
            self.c.checkpoint(op, worker="worker_123456", fencing=1,
                              expected_version=2, step="PURCHASE")
        self.assertEqual(self.c.stop_at_checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=2),
            "CANCELLED_SAFE")
        self.assertEqual(self.c.get(op)["worker"], None)

    def test_cancel_after_external_intent_never_declares_safe(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=1,
            step="DNS_CUTOVER", state="RUNNING", external_intent=True
        )
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=2)
        self.assertEqual(self.c.stop_at_checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=3),
            "RECONCILE_REQUIRED")
        self.assertEqual(self.c.get(op)["external_intent"], 1)

    def test_external_reconciliation_requires_verified_witness(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(op, worker="worker_123456", fencing=1,
                          expected_version=1, step="PURCHASE",
                          state="WAITING_EXTERNAL", external_intent=True)
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=2)
        self.clock = 1061
        with self.assertRaisesRegex(OperationHold, "TRUSTED_EXTERNAL_EVIDENCE_REQUIRED"):
            self.c.reconcile_external(op, actor=self.actor, chat=self.chat,
                                      expected_version=3)
        c = DurableCoordinator(self.db, now=lambda: self.clock,
                               external_verified=lambda _: False)
        with self.assertRaisesRegex(OperationHold, "TRUSTED_EXTERNAL_EVIDENCE_REQUIRED"):
            c.reconcile_external(op, actor=self.actor, chat=self.chat,
                                 expected_version=3)
        c = DurableCoordinator(self.db, now=lambda: self.clock,
                               external_verified=lambda job: job == op,
                               worker_quiescent=lambda job: job == op)
        self.assertEqual(c.reconcile_external(
            op, actor=self.actor, chat=self.chat, expected_version=3),
            "CANCELLED_SAFE")
        self.assertEqual(c.get(op)["external_intent"], 0)
        self.assertEqual(len(c.events(op)), 5)

    def test_cannot_reconcile_while_worker_lease_alive(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(op, worker="worker_123456", fencing=1,
                          expected_version=1, step="PURCHASE",
                          state="WAITING_EXTERNAL", external_intent=True)
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=2)
        c = DurableCoordinator(self.db, now=lambda: self.clock,
                               external_verified=lambda _: True)
        with self.assertRaisesRegex(OperationHold, "LIVE_WORKER_NOT_FENCED"):
            c.reconcile_external(op, actor=self.actor, chat=self.chat,
                                 expected_version=3)

    def test_safe_preflight_pause_and_no_effect_cancel(self):
        op = self.new()
        self.claim(op)
        self.assertEqual(self.c.pause_no_effect(
            op, worker="worker_123456", fencing=1, expected_version=1
        ), "PAUSED_SAFE")
        self.assertEqual(self.c.request_cancel(
            op, actor=self.actor, chat=self.chat, expected_version=2
        ), "CANCELLED_SAFE")

    def test_generic_claim_refuses_post_purchase_even_after_reconciliation(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=1,
            step="PURCHASE", state="WAITING_EXTERNAL", external_intent=True
        )
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=2)
        self.clock = 1061
        # Cancelling an ambiguous purchase may be closed, but never resumed.
        c = DurableCoordinator(
            self.db, now=lambda: self.clock,
            external_verified=lambda _: True,
            worker_quiescent=lambda _: True
        )
        self.assertEqual(c.reconcile_external(
            op, actor=self.actor, chat=self.chat, expected_version=3
        ), "CANCELLED_SAFE")
        with self.assertRaisesRegex(OperationHold, "STATE_NOT_CLAIMABLE"):
            c.claim(op, actor=self.actor, chat=self.chat,
                    worker="worker_second", expected_version=4)

    def test_expired_external_lease_cannot_reconcile_without_quiescence(self):
        op = self.new()
        self.claim(op)
        self.c.checkpoint(
            op, worker="worker_123456", fencing=1, expected_version=1,
            step="PURCHASE", state="WAITING_EXTERNAL", external_intent=True
        )
        self.clock = 1061
        c = DurableCoordinator(
            self.db, now=lambda: self.clock,
            external_verified=lambda _: True
        )
        with self.assertRaisesRegex(OperationHold, "TRUSTED_WORKER_QUIESCENCE_REQUIRED"):
            c.reconcile_external(
                op, actor=self.actor, chat=self.chat, expected_version=2
            )

    def test_adversarial_codes_never_enter_journal(self):
        op = self.new()
        self.claim(op)
        with self.assertRaisesRegex(OperationHold, "INVALID_EVENT_CODE"):
            self.c.checkpoint(op, worker="worker_123456", fencing=1,
                              expected_version=1, step="PREFLIGHT",
                              code="password=x")
        self.assertEqual(self.c.get(op)["version"], 1)

    def test_historical_projection_does_not_create_tables_or_leak_notes(self):
        with self.db() as db:
            db.executescript("""
                CREATE TABLE cloudzy_edge_operations(id TEXT, status TEXT,hold_reason TEXT);
                CREATE TABLE cloudzy_cz06_runs(operation_id TEXT,stage TEXT,detail_code TEXT);
                CREATE TABLE cloudzy_cz04a_actions(id TEXT,status TEXT,note TEXT);
                CREATE TABLE cloudzy_cz04b_operations(id TEXT,status TEXT,note TEXT);
                CREATE TABLE cloudzy_cz07_jobs(id TEXT,status TEXT,code TEXT);
                CREATE TABLE cloudzy_cz08_deletions(id TEXT,status TEXT,detail_code TEXT);
                INSERT INTO cloudzy_edge_operations VALUES('a','CREATE_UNCERTAIN','TOKEN=secret');
                INSERT INTO cloudzy_cz06_runs VALUES('b','HOLD','PREPURCHASE_STOCK_UNVERIFIED');
                INSERT INTO cloudzy_cz04a_actions VALUES('c','DONE','ssh private');
                INSERT INTO cloudzy_cz04b_operations VALUES('d','DNS_WRITE_INTENT','provider body');
                INSERT INTO cloudzy_cz07_jobs VALUES('e','QUEUED','');
                INSERT INTO cloudzy_cz08_deletions VALUES('f','HOLD','PROVIDER_RESULT_UNCERTAIN');
            """)
        with self.db() as db:
            db.execute("PRAGMA query_only=ON")
            all_rows = read_legacy_receipts(db)
        self.assertEqual(len(all_rows), 6)
        self.assertEqual(all_rows[0].next_action, "RECONCILE_CLOUDZY_CREATE_NO_POST")
        self.assertEqual(all_rows[0].code, "UNSPECIFIED")
        self.assertEqual(all_rows[3].next_action, "RECONCILE_DNS_CORE_6G_NO_REPLAY")
        self.assertEqual(all_rows[4].next_action, "INSPECT_WORKER_NO_AUTO_LAUNCH")
        self.assertEqual(all_rows[5].next_action, "RECONCILE_CLOUDZY_DELETE_NO_POST")
        self.assertNotIn("secret", str(all_rows))
        self.assertNotIn("private", str(all_rows))
        self.assertNotIn("body", str(all_rows))

    def test_old_tables_not_updated_by_new_journal(self):
        with self.db() as db:
            db.executescript("""
                CREATE TABLE cloudzy_cz07_jobs(id TEXT,status TEXT,code TEXT);
                INSERT INTO cloudzy_cz07_jobs VALUES('a','ROUTING','');
                CREATE TABLE failover_operations(id INTEGER,status TEXT);
                INSERT INTO failover_operations VALUES(1,'RUNNING');
            """)
        op = self.new()
        self.claim(op)
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=1)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz07_jobs WHERE id='a'"
            ).fetchone()[0], "ROUTING")
            self.assertEqual(db.execute(
                "SELECT status FROM failover_operations WHERE id=1"
            ).fetchone()[0], "RUNNING")

    def test_replayed_owner_cancel_invalid_version_fails(self):
        op = self.new()
        self.claim(op)
        self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                              expected_version=1)
        with self.assertRaisesRegex(OperationHold, "STALE_OPERATION_VERSION"):
            self.c.request_cancel(op, actor=self.actor, chat=self.chat,
                                  expected_version=1)

    def test_legacy_action_matrices_are_explanations_not_execution(self):
        self.assertEqual(legacy_action("CZ03", "CREATE_UNCERTAIN"),
                         "RECONCILE_CLOUDZY_CREATE_NO_POST")
        self.assertEqual(legacy_action("CZ03", "HOLD_PROVISION"),
                         "VERIFY_EXISTING_INSTALL_NO_RERUN")
        self.assertEqual(legacy_action("CZ07", "MIGRATING"),
                         "VERIFY_ROUTE_AND_BATCHES_NO_AUTO_RESUME")
        self.assertEqual(legacy_action("CZ08", "HOLD"),
                         "RECONCILE_CLOUDZY_DELETE_NO_POST")


if __name__ == "__main__":
    unittest.main()
