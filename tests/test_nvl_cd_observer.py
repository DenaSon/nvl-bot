"""Offline observer tests: never send a real Telegram request."""
import sqlite3
import unittest
from unittest.mock import Mock
from ops import nvl_cd_observer as obs

SHA = "a" * 40
ENV = {"BOT_TOKEN": "123456:" + "A" * 35, "MARZBAN_ALERT_CHAT_ID": "-1001234567890"}


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.addCleanup(self.con.close)
        self.con.execute("""CREATE TABLE events(event_key TEXT PRIMARY KEY,
            message TEXT, observed INTEGER, sent INTEGER, attempts INTEGER DEFAULT 0,
            next_try INTEGER DEFAULT 0)""")

    def test_existing_group_only(self):
        self.assertEqual(obs.target(ENV), (ENV["BOT_TOKEN"], ENV["MARZBAN_ALERT_CHAT_ID"]))
        for env in ({}, {"BOT_TOKEN": ENV["BOT_TOKEN"], "MARZBAN_ALERT_CHAT_ID": "123456"},
                    {"BOT_TOKEN": ENV["BOT_TOKEN"], "NVL_DAILY_FINANCE_REPORT_CHAT_ID": "-1001234567890"}):
            self.assertIsNone(obs.target(env))

    def test_ci_pending_and_backoff_are_silent(self):
        for status in ("API_BACKOFF", "NO_NEW_COMMIT", "PLAN_READY"):
            self.assertIsNone(obs.event({"status": status, "candidate": SHA}))
        self.assertIsNone(obs.event({"status": "HOLD", "reason": "CI_NOT_SUCCESSFUL"}))

    def test_terminal_event_deduplication(self):
        event = {"phase": "COMMITTED", "candidate": SHA, "deployed": SHA}
        obs.record(self.con, event, 100)
        obs.record(self.con, event, 101)
        send = Mock(return_value=True)
        self.assertEqual(obs.drain(self.con, 102, send), "SENT")
        self.assertEqual(obs.drain(self.con, 103, send), "IDLE")
        send.assert_called_once()

    def test_retry_backoff_then_delivery(self):
        obs.record(self.con, {"phase": "ROLLED_BACK", "candidate": SHA}, 100)
        send = Mock(side_effect=[False, True])
        self.assertEqual(obs.drain(self.con, 100, send), "RETRY")
        self.assertEqual(obs.drain(self.con, 159, send), "IDLE")
        self.assertEqual(obs.drain(self.con, 160, send), "SENT")

    def test_no_raw_reason_or_path_in_notice(self):
        event = obs.event({"status": "HOLD", "candidate": SHA, "drift": ["private/path"],
                           "manual": [], "reason": "secret"})
        self.assertNotIn("private", event[1])
        self.assertNotIn("secret", event[1])

    def test_prune_preserves_pending_notifications(self):
        obs.record(self.con, {"phase": "HOLD", "candidate": SHA}, 1)
        obs.prune_history(self.con, 10**9)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_stale_plan_after_success_is_suppressed(self):
        checkpoint = {"phase": "COMMITTED", "deployed": SHA}
        old = {"baseline": "b" * 40, "candidate": SHA, "status": "HOLD"}
        self.assertFalse(obs.current_plan(old, checkpoint, 10, 20))
        self.assertFalse(obs.current_plan(old, checkpoint, 30, 20))

    def test_new_post_release_drift_is_preserved(self):
        checkpoint = {"phase": "COMMITTED", "deployed": SHA}
        plan = {"baseline": SHA, "candidate": SHA, "status": "HOLD", "drift": ["bot.py"]}
        self.assertFalse(obs.current_plan(plan, checkpoint, 10, 20))
        self.assertTrue(obs.current_plan(plan, checkpoint, 30, 20))
        self.assertTrue(obs.current_plan(plan, None, 10, 0))

    def test_incomplete_release_suppresses_plan_alerts(self):
        for phase in ("PUBLISHING", "STARTING", "HOLD"):
            self.assertFalse(obs.current_plan({"baseline": SHA},
                                             {"phase": phase, "deployed": SHA}, 30, 20))

    def test_live_env_uses_current_bot_only(self):
        ident = (753, "1" * 32)
        read = Mock(return_value=ENV | {"MASTER_PASS": "not-returned"})
        self.assertEqual(obs.live_env(lambda: ident, read), ENV)
        read.assert_called_once_with(753)

    def test_live_env_rejects_restarted_bot_and_missing_group(self):
        first, second = (753, "1" * 32), (754, "2" * 32)
        self.assertEqual(obs.live_env(Mock(side_effect=[first, second]),
                                      lambda pid: ENV), {})
        self.assertEqual(obs.live_env(lambda: first,
                                      lambda pid: {"BOT_TOKEN": ENV["BOT_TOKEN"]}), {})
        self.assertEqual(obs.live_env(lambda: None, lambda pid: ENV), {})

    def test_live_env_defers_on_read_error(self):
        self.assertEqual(obs.live_env(lambda: (753, "1" * 32),
                                      Mock(side_effect=PermissionError)), {})
