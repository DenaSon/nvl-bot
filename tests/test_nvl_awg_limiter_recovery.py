"""Regression tests for narrowly scoped operator Limiter recovery."""
from __future__ import annotations

import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import nvl_awg_limiter_recovery as recovery


class LimiterRecoveryTests(unittest.TestCase):
    def test_trusted_stale_image_is_reported(self):
        binding = SimpleNamespace(backend="amneziawg",
                                  edge_tunnel_ip="10.203.77.34")
        with (patch.object(recovery.sqlite3, "connect") as connect,
              patch.object(recovery, "lookup_binding", return_value=binding),
              patch.object(recovery, "_approved_source", return_value=object()),
              patch.object(recovery, "_live_service_matches_script",
                           side_effect=recovery.LimiterWitnessHold(
                               recovery.RESTARTABLE))):
            connect.return_value.__enter__.return_value = object()
            self.assertEqual(recovery.limiter_status("57.131.168.207"),
                             recovery.RESTARTABLE)

    def test_ready_requires_independent_marker(self):
        binding = SimpleNamespace(backend="amneziawg",
                                  edge_tunnel_ip="10.203.77.34")
        with (patch.object(recovery.sqlite3, "connect") as connect,
              patch.object(recovery, "lookup_binding", return_value=binding),
              patch.object(recovery, "_approved_source", return_value=object()),
              patch.object(recovery, "_live_service_matches_script"),
              patch.object(recovery, "core_limiter_canary_ready", return_value=False)):
            connect.return_value.__enter__.return_value = object()
            self.assertEqual(recovery.limiter_status("57.131.168.207"),
                             "WITNESS_PENDING")

    def test_only_stale_verified_process_is_restartable(self):
        runner = unittest.mock.Mock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0))
        with patch.object(recovery, "limiter_status",
                          side_effect=[recovery.RESTARTABLE, "WITNESS_PENDING"]):
            self.assertEqual(recovery.repair_stale_limiter(
                "57.131.168.207", runner=runner, root_check=lambda: 0),
                "WITNESS_PENDING")
        runner.assert_called_once_with(
            ["systemctl", "restart", "ssh-limiter.service"],
            capture_output=True, text=True, timeout=30)

    def test_unexpected_state_never_restarts(self):
        runner = unittest.mock.Mock()
        for code in ("READY", "RUNNING_LIMITER_SOURCE_MISMATCH",
                     "WITNESS_PENDING", "LIMITER_SERVICE_NOT_ACTIVE"):
            with self.subTest(code=code), patch.object(
                    recovery, "limiter_status", return_value=code):
                with self.assertRaisesRegex(
                        recovery.LimiterRecoveryHold, "RECOVERY_STATE_CHANGED"):
                    recovery.repair_stale_limiter(
                        "57.131.168.207", runner=runner, root_check=lambda: 0)
        runner.assert_not_called()

    def test_non_root_never_restarts(self):
        runner = unittest.mock.Mock()
        with self.assertRaisesRegex(recovery.LimiterRecoveryHold,
                                    "RECOVERY_ROOT_REQUIRED"):
            recovery.repair_stale_limiter(
                "57.131.168.207", runner=runner, root_check=lambda: 1000)
        runner.assert_not_called()

    def test_restart_failure_fails_closed(self):
        runner = unittest.mock.Mock(return_value=subprocess.CompletedProcess(
            args=[], returncode=1))
        with patch.object(recovery, "limiter_status", return_value=recovery.RESTARTABLE):
            with self.assertRaisesRegex(recovery.LimiterRecoveryHold,
                                        "LIMITER_RESTART_FAILED"):
                recovery.repair_stale_limiter(
                    "57.131.168.207", runner=runner, root_check=lambda: 0)
        runner.assert_called_once()

    def test_post_restart_identity_must_verify(self):
        runner = unittest.mock.Mock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0))
        with patch.object(recovery, "limiter_status",
                          side_effect=[recovery.RESTARTABLE,
                                       "LIMITER_PROCESS_UNVERIFIED"]):
            with self.assertRaisesRegex(recovery.LimiterRecoveryHold,
                                        "LIMITER_RESTART_NOT_VERIFIED"):
                recovery.repair_stale_limiter(
                    "57.131.168.207", runner=runner, root_check=lambda: 0)


if __name__ == "__main__":
    unittest.main()
