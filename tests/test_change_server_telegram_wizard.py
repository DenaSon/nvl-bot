import unittest
from types import SimpleNamespace
from unittest.mock import patch

from server_migration.telegram_wizard import (
    TelegramWizardBusy,
    TelegramWizardError,
    begin_session,
    cancel_session,
    normalize_dns_name,
    normalize_host,
    normalize_port,
    run_backup_step,
    run_cutover_plan_step,
    run_cutover_precheck_step,
    run_cutover_step,
    run_final_plan_step,
    run_final_sync_step,
    run_preflight_step,
    run_restore_step,
)


class TelegramWizardSessionTests(unittest.TestCase):
    def tearDown(self):
        cancel_session(1001)
        cancel_session(1002)

    def test_secret_values_never_enter_safe_summary_or_repr(self):
        session = begin_session(1001)
        session.source_host = "192.0.2.10"
        session.destination_host = "192.0.2.20"
        session.source_password = "source-secret"
        session.destination_password = "destination-secret"

        safe = repr(session.safe_summary())
        obj_repr = repr(session)
        self.assertNotIn("source-secret", safe)
        self.assertNotIn("destination-secret", safe)
        self.assertNotIn("source-secret", obj_repr)
        self.assertNotIn("destination-secret", obj_repr)

    def test_only_one_admin_can_hold_active_wizard(self):
        begin_session(1001)
        with self.assertRaises(TelegramWizardBusy):
            begin_session(1002)

    def test_normalizers_accept_expected_values_and_reject_bad_inputs(self):
        self.assertEqual(normalize_host("Example.COM."), "example.com")
        self.assertEqual(normalize_host("192.0.2.15"), "192.0.2.15")
        self.assertEqual(normalize_port("2222"), 2222)
        self.assertEqual(normalize_dns_name("gate.example.com"), "gate.example.com")
        with self.assertRaises(ValueError):
            normalize_port("70000")
        with self.assertRaises(ValueError):
            normalize_dns_name("192.0.2.15")


class TelegramWizardFlowTests(unittest.TestCase):
    def setUp(self):
        self.session = begin_session(1001)
        self.session.source_host = "192.0.2.10"
        self.session.destination_host = "192.0.2.20"
        self.session.source_password = "a"
        self.session.destination_password = "b"
        self.session.hostname = "gate.example.com"
        self.session.zone_name = "example.com"
        self.session.stage = "READY_FOR_PREFLIGHT"

    def tearDown(self):
        cancel_session(1001)

    @patch("server_migration.telegram_wizard.run_preflight")
    def test_happy_path_advances_through_all_five_phases(self, preflight):
        report = SimpleNamespace(ready=True)
        preflight.return_value = report

        phase2_result = SimpleNamespace(job_id="chg-test-job")
        phase3_result = SimpleNamespace(runtime_restored=True)
        phase4_plan = SimpleNamespace(finalization_ready=True, blockers=())
        phase4_result = SimpleNamespace(api_healthy=True)
        phase5_precheck = SimpleNamespace(
            cutover_ready=False,
            blockers=("Phase 4 FINAL_SYNC_COMPLETE marker is missing",),
        )
        phase5_plan = SimpleNamespace(cutover_ready=True, blockers=())
        phase5_result = SimpleNamespace(dns_updated=True)

        with patch(
            "server_migration.telegram_wizard.run_phase2",
            return_value=phase2_result,
        ), patch(
            "server_migration.telegram_wizard.run_phase3",
            return_value=phase3_result,
        ), patch(
            "server_migration.telegram_wizard.run_phase4",
            side_effect=[phase4_plan, phase4_result],
        ) as phase4, patch(
            "server_migration.telegram_wizard.run_phase5",
            side_effect=[phase5_plan, phase5_result],
        ) as phase5:
            self.assertTrue(run_preflight_step(self.session).ready)
            self.assertEqual(self.session.stage, "PREFLIGHT_READY")

            run_backup_step(self.session)
            self.assertEqual(self.session.job_id, "chg-test-job")
            self.assertEqual(self.session.stage, "BACKUP_COMPLETE")

            run_restore_step(self.session)
            self.assertEqual(self.session.stage, "RESTORE_COMPLETE")

            run_final_plan_step(self.session)
            self.assertEqual(self.session.stage, "FINAL_PLAN_READY")

            run_cutover_precheck_step(self.session)
            self.assertEqual(self.session.stage, "PRE_CUTOVER_READY")

            run_final_sync_step(self.session)
            self.assertEqual(self.session.stage, "FINAL_SYNC_COMPLETE")

            run_cutover_plan_step(self.session)
            self.assertEqual(self.session.stage, "CUTOVER_PLAN_READY")

            run_cutover_step(self.session)
            self.assertEqual(self.session.stage, "CUTOVER_COMPLETE")

        self.assertEqual(phase4.call_count, 2)
        self.assertEqual(phase5.call_count, 3)

    def test_stage_guards_fail_closed(self):
        self.session.stage = "SOURCE_HOST"
        with self.assertRaises(TelegramWizardError):
            run_backup_step(self.session)


if __name__ == "__main__":
    unittest.main()
