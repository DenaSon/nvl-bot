"""CZ-06 hermetic workflow/journal/standby safety tests; no provider writes."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_cz06_orchestrator import (
    QuickRelayHold, QuickRelayJournal, progress_html, promote_standby_once,
)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "runs.db"

        @contextmanager
        def connection():
            db = sqlite3.connect(self.path)
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        self.connection = connection
        self.journal = QuickRelayJournal(connection, now=lambda: 1000)

    def create(self, key):
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS cloudzy_edge_operations(id TEXT PRIMARY KEY)")
            db.execute("INSERT INTO cloudzy_edge_operations VALUES(?)", (key,))
            self.journal.create_in_receipt_transaction(
                db, opid=key, actor=12, chat=34, message_id=56)

    def test_stage_cas_journal_and_progress(self):
        self.create("a")
        self.assertEqual(self.journal.get("a")["stage"], "PURCHASING")
        self.journal.advance("a", "WAITING_PROVIDER", expected="PURCHASING")
        self.journal.advance("a", "HOSTKEY_PENDING", expected="WAITING_PROVIDER")
        self.journal.advance("a", "INSTALLING", expected="HOSTKEY_PENDING")
        self.journal.advance("a", "EDGE_READY", expected="INSTALLING")
        self.journal.advance("a", "STANDBY_VERIFYING", expected="EDGE_READY")
        self.journal.advance("a", "READY", expected="STANDBY_VERIFYING")
        with self.assertRaises(QuickRelayHold):
            self.journal.advance("a", "INSTALLING", expected="HOSTKEY_PENDING")
        self.assertIn("READY", progress_html(self.journal.get("a"), {"public_ipv4": "8.8.8.8"}))
        self.assertNotIn("password", progress_html(self.journal.get("a"), {"public_ipv4": "8.8.8.8"}))

    def test_holds_are_fail_closed_and_error_codes_sanitized(self):
        self.create("a")
        with self.assertRaises(QuickRelayHold):
            self.journal.advance("a", "READY", expected="PURCHASING", code="bad\nsecret")
        self.journal.advance("a", "HOLD", expected="PURCHASING", code="PROVIDER_UNCERTAIN")
        self.assertEqual(self.journal.get("a")["detail_code"], "PROVIDER_UNCERTAIN")
        self.create("b")  # HOLD does not leave a global wizard lease.
        with self.assertRaises(sqlite3.IntegrityError):
            self.create("c")  # One in-flight quick workflow at a time.


    def test_cancelled_stage_is_terminal_and_new_quick_run_can_begin(self):
        self.create("a")
        self.journal.advance("a", "HOLD", expected="PURCHASING",
                             code="INSTALL_REQUIRES_RECONCILIATION")
        self.journal.advance("a", "CANCELLED", expected="HOLD",
                             code="OPERATOR_CANCELLED")
        self.create("b")
        self.assertEqual(self.journal.get("a")["stage"], "CANCELLED")
        self.assertEqual(self.journal.get("b")["stage"], "PURCHASING")
        self.assertIn("لغو شده", progress_html(
            self.journal.get("a"), {"public_ipv4": "8.8.8.8"}))


class ProgressTimerTests(unittest.TestCase):
    def test_elapsed_stage_timer_is_not_countdown(self):
        run = {
            "operation_id": "abc123", "stage": "INSTALLING",
            "updated_at": 100, "detail_code": "",
        }
        text = progress_html(run, {"public_ipv4": "8.8.8.8"}, now=225)
        self.assertIn("02:05", text)
        self.assertIn("در حال اجراست", text)
        self.assertNotIn("باقی‌مانده", text)

    def test_hold_does_not_appear_active(self):
        run = {
            "operation_id": "abc123", "stage": "HOLD",
            "updated_at": 100, "detail_code": "APT_LOCK_BUSY",
        }
        text = progress_html(run, {"public_ipv4": "8.8.8.8"}, now=999)
        self.assertIn("توقف امن", text)
        self.assertNotIn("سپری‌شده از شروع این مرحله", text)


class Stub04A:
    def __init__(self):
        self.state = dict(active=False, standby=False, default=False,
                          listed=False, users=0, auto=False, k2_onboard=False,
                          port=2252, admin_port=22)
        self.reserved = []
        self.promoted = []
        self.provider_status = "active"
        self.probe_ok = True

    def _state(self, host, provider_id, *, mutation):
        assert host == "8.8.8.8" and provider_id == "vps-1"
        return dict(self.state)

    def _isolated(self, state):
        if any(state[k] for k in ("active", "standby", "default", "listed", "users")):
            raise QuickRelayHold("HOST_NOT_ISOLATED")

    async def _provider(self, provider_id, host):
        return self.provider_status

    async def probe(self, host, port, admin_port):
        return self.probe_ok

    def _reserve(self, actor, chat, host, provider_id, action):
        self.reserved.append((actor, chat, host, provider_id, action))
        return "04a-journal-id"

    def _promote(self, opid, host, provider_id):
        self.promoted.append((opid, host, provider_id))
        self.state.update(active=True, standby=True)

    def _finish(self, opid, status, note):
        self.promoted.append((opid, status, note))


class StandbyTests(unittest.IsolatedAsyncioTestCase):
    async def test_guarded_promote_only_once(self):
        svc = Stub04A()
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        self.assertEqual(await promote_standby_once(svc, **args), "READY")
        self.assertEqual(len(svc.reserved), 1)
        self.assertEqual(await promote_standby_once(svc, **args), "READY")
        self.assertEqual(len(svc.reserved), 1)
        self.assertEqual(len(svc.promoted), 1)

    async def test_no_promotion_when_autofailover_or_probe_or_provider_unverified(self):
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        for bad in ("auto", "k2_onboard"):
            svc = Stub04A()
            svc.state[bad] = True
            with self.subTest(bad=bad), self.assertRaises(QuickRelayHold):
                await promote_standby_once(svc, **args)
            self.assertEqual(svc.reserved, [])
        svc = Stub04A()
        svc.probe_ok = False
        with self.assertRaises(QuickRelayHold):
            await promote_standby_once(svc, **args)
        self.assertEqual(svc.reserved, [])
        svc = Stub04A()
        svc.provider_status = "stopped"
        with self.assertRaises(QuickRelayHold):
            await promote_standby_once(svc, **args)
        self.assertEqual(svc.reserved, [])


    async def test_existing_committed_standby_must_pass_fresh_probe(self):
        svc = Stub04A()
        svc.state.update(active=True, standby=True)
        svc.probe_ok = False
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        with self.assertRaisesRegex(QuickRelayHold, "FRESH_SSH_WG_PREFLIGHT_FAILED"):
            await promote_standby_once(svc, **args)
        self.assertEqual(svc.reserved, [])
        svc.probe_ok = True
        self.assertEqual(await promote_standby_once(svc, **args), "READY")
        self.assertEqual(svc.reserved, [])

    async def test_committed_standby_rejects_stale_route_and_provider(self):
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        for change in ("listed", "default", "users", "auto", "k2_onboard"):
            svc = Stub04A()
            svc.state.update(active=True, standby=True)
            svc.state[change] = 1 if change == "users" else True
            with self.subTest(change=change):
                with self.assertRaisesRegex(QuickRelayHold, "STANDBY_ROUTE_OR_AUTOMATION_CHANGED"):
                    await promote_standby_once(svc, **args)
                self.assertEqual(svc.reserved, [])
        svc = Stub04A()
        svc.state.update(active=True, standby=True)
        svc.provider_status = "stopped"
        with self.assertRaisesRegex(QuickRelayHold, "PROVIDER_NOT_ACTIVE"):
            await promote_standby_once(svc, **args)

    async def test_postcommit_probe_failure_holds_then_adopts_without_repromote(self):
        class ProbeFallsAfterCommit(Stub04A):
            async def probe(self, host, port, admin_port):
                return self.probe_ok if not self.promoted else False
        svc = ProbeFallsAfterCommit()
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        with self.assertRaisesRegex(QuickRelayHold, "FRESH_SSH_WG_PREFLIGHT_FAILED"):
            await promote_standby_once(svc, **args)
        self.assertTrue(svc.state["standby"])
        self.assertEqual(len(svc.reserved), 1)
        svc.probe = Stub04A.probe.__get__(svc)
        self.assertEqual(await promote_standby_once(svc, **args), "READY")
        self.assertEqual(len(svc.reserved), 1)

    async def test_postcommit_host_state_drift_is_never_ready(self):
        class PartialCommit(Stub04A):
            def _promote(self, opid, host, provider_id):
                self.promoted.append((opid, host, provider_id))
                self.state.update(active=True, standby=False)
        svc = PartialCommit()
        args = dict(actor=12, chat=34, host="8.8.8.8", provider_id="vps-1")
        with self.assertRaisesRegex(QuickRelayHold, "STANDBY_POSTCOMMIT_STATE_UNVERIFIED"):
            await promote_standby_once(svc, **args)
        self.assertEqual(len(svc.reserved), 1)


if __name__ == "__main__":
    unittest.main()
