"""Offline auto-apply tick tests. No real systemd, network or bot mutations."""
import tempfile
from contextlib import nullcontext
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops import nvl_cd_apply as app

A, B = "a" * 40, "b" * 40


class ApplyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.config = {"baseline": A, "inventory": ["bot.py"]}
        self.plan = {"status": "PLAN_READY", "baseline": A, "candidate": B,
                     "updates": ["bot.py"]}
        host = Mock()
        host.active.return_value = True
        host.idle.return_value = True
        self.host = host
        for obj, attr, val in ((app.p, "trusted", None), (app.p, "poll", self.plan),
                               (app.pub, "accepted_config", self.config),
                               (app.pub, "Host", host),
                               (app.pub, "release", {"phase": "COMMITTED", "deployed": B, "candidate": B})):
            patcher = (patch.object(obj, attr, side_effect=lambda path, **kw: path)
                       if attr == "trusted" else patch.object(obj, attr, return_value=val))
            mock = patcher.start()
            self.addCleanup(patcher.stop)
            setattr(self, attr, mock)

    def tick(self):
        return app.tick(self.state, self.config, now=lambda: 100)

    def test_ready_is_only_a_hint_to_release_revalidation(self):
        self.assertEqual(self.tick()["phase"], "COMMITTED")
        self.release.assert_called_once_with(self.state, self.config, B)

    def test_busy_and_pending_do_not_release(self):
        self.host.idle.return_value = False
        self.assertEqual(self.tick()["status"], "BOT_OR_OPERATION_BUSY")
        self.poll.return_value = {"status": "API_BACKOFF"}
        self.assertEqual(self.tick()["status"], "API_BACKOFF")
        self.release.assert_not_called()

    def test_never_auto_recovers_incomplete_release(self):
        app.pub.durable_json(self.state / "release-state.json",
                             {"phase": "PUBLISHING", "candidate": B, "deployed": A})
        self.assertEqual(self.tick()["status"], "RECOVERY_REQUIRED")
        self.poll.assert_not_called()
        self.release.assert_not_called()

    def test_rolled_back_sha_never_retried(self):
        app.pub.durable_json(self.state / "release-state.json",
                             {"phase": "ROLLED_BACK", "candidate": B, "deployed": A})
        self.assertEqual(self.tick()["status"], "FAILED_CANDIDATE_REQUIRES_REVIEW")
        self.release.assert_not_called()

    def test_docs_only_does_not_require_stopping_bot(self):
        self.plan["updates"] = []
        self.host.active.return_value = False
        self.assertEqual(self.tick()["phase"], "COMMITTED")
        self.Host.assert_not_called()

    def test_changed_config_aborts(self):
        self.accepted_config.return_value = self.config | {"inventory": ["other.py"]}
        with self.assertRaisesRegex(app.p.Hold, "ACCEPTANCE_CONFIG_CHANGED"):
            self.tick()
        self.release.assert_not_called()

    def test_systemd_no_argument_invocation_runs_auto_tick(self):
        with patch.object(app.sys, "argv", ["nvl_cd_apply.py"]), \
                patch.object(app.os, "geteuid", return_value=0), \
                patch.object(app.p, "trusted", return_value=self.state), \
                patch.object(app.pub, "exclusive", return_value=nullcontext()), \
                patch.object(app, "planner_disabled", return_value=True), \
                patch.object(app, "tick", return_value={"phase": "COMMITTED"} ) as tick:
            self.assertEqual(app.main(), 0)
            tick.assert_called_once_with(self.state, self.config)

    def test_dry_run_timer_must_be_inactive_and_disabled(self):
        for active, unit, expected in (("active", "enabled", False),
                                       ("inactive", "enabled", False),
                                       ("inactive", "disabled", True),
                                       ("inactive", "masked", True),
                                       ("unknown", "disabled", False)):
            with patch.object(app.subprocess, "check_output",
                              return_value=f"ActiveState={active}\nUnitFileState={unit}\n"):
                self.assertEqual(app.planner_disabled(), expected)
