"""Phase 8 repeatable injected-boundary E2E acceptance matrix.

Runs the *actual* CZ03/04B/06/07/Rich implementations with their established
fake Cloudzy/DNS/SSH providers and ephemeral SQLite, never production APIs.
This is a staged fault-injection gate, NOT an actual live ISP field acceptance.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import unittest


@dataclass(frozen=True)
class Scenario:
    stage: str
    boundary: str
    test_id: str


SCENARIOS = (
    Scenario("PURCHASE", "CHANGED_STOCK_BEFORE_PAID_POST",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_stock_disappears_after_reservation_before_provider_post"),
    Scenario("PURCHASE", "PROVIDER_UNCERTAIN_PAID_RESULT",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_unknown_create_is_held_and_reconciled_only_by_read"),
    Scenario("PURCHASE", "CRASH_AFTER_CHARGE_BEFORE_RECEIPT",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_crash_during_create_recovers_from_exact_provider_name_without_post"),
    Scenario("PURCHASE", "ATOMIC_UNIFIED_RECEIPT",
             "tests.test_cloudzy_unified_native.UnifiedNativeBridgeTests."
             "test_native_and_unified_are_atomically_reserved"),
    Scenario("PURCHASE", "PRECHARGE_JOURNAL_CRASH",
             "tests.test_cloudzy_unified_native.UnifiedNativeBridgeTests."
             "test_missing_link_never_enters_external_purchase"),
    Scenario("PURCHASE", "NATIVE_AND_UNIFIED_COMMIT_FAIL",
             "tests.test_cloudzy_unified_native.UnifiedNativeBridgeTests."
             "test_native_cas_rolls_back_if_unified_checkpoint_cannot_commit"),
    Scenario("INSTALL", "PROVIDER_IP_RECYCLING",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_p4_provider_ipv4_reuse_prevents_legacy_install"),
    Scenario("INSTALL", "CHANGED_HOST_KEY_AFTER_INSTALL",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_p4_host_key_changes_after_install_must_hold_receipt"),
    Scenario("INSTALL", "APT_LOCK_NO_BLIND_REINSTALL",
             "tests.test_cloudzy_quick_edge.CZ03Tests."
             "test_p4_apt_lock_does_not_retry_or_accept"),
    Scenario("STANDBY", "CZ06_ATTESTATION_GATE",
             "tests.test_cloudzy_unified_native.UnifiedNativeBridgeTests."
             "test_cz06_ready_remains_client_attestation_pending"),
    Scenario("DNS", "PARTIAL_FIRST_CLOUDFLARE_WRITE",
             "tests.test_cloudzy_cz04b_guarded.GuardedRouteTests."
             "test_partial_first_dns_write_holds_without_any_rollback"),
    Scenario("DNS", "DNS_PROVIDER_CHANGED_AFTER_EFFECT_INTENT",
             "tests.test_cloudzy_cz04b_guarded.GuardedRouteTests."
             "test_dns_provider_changed_after_intent_remains_held"),
    Scenario("DNS", "EXTERNAL_RECORD_IDENTITY_CHANGED",
             "tests.test_cloudzy_cz04b_guarded.GuardedRouteTests."
             "test_preintent_dns_identity_drift_releases_unused_lease"),
    Scenario("DNS", "ORIGINAL_SHARED_6G_COLLISION",
             "tests.test_cloudzy_cz04b_guarded.GuardedRouteTests."
             "test_original_6g_running_stops_another_route"),
    Scenario("MIGRATION", "BATCH_200_AND_INDEPENDENT_ACCEPTANCE",
             "tests.test_cloudzy_cz07_queue.QueueTests."
             "test_200_batch_boundary_and_independent_business_acceptance"),
    Scenario("MIGRATION", "CRASH_AFTER_BATCH_ACCOUNT_CAS_BEFORE_JOURNAL",
             "tests.test_cloudzy_cz07_queue.QueueTests."
             "test_crash_after_committed_batch_reconstructs_remaining_from_sqlite"),
    Scenario("MIGRATION", "SAFE_CANCEL_AND_EXPLICIT_RESUME",
             "tests.test_cloudzy_cz07_queue.QueueTests."
             "test_safe_cancel_after_batch_and_guarded_resume"),
    Scenario("MIGRATION", "0_1_50_51_200_201_493_495_COHORTS",
             "tests.test_cloudzy_cz07_queue.QueueTests."
             "test_batch_boundaries_do_not_limit_total_job_size"),
    Scenario("MIGRATION", "UNRESOLVED_OLD_WORKER",
             "tests.test_cloudzy_cz07_queue.QueueTests."
             "test_recovery_rejects_worker_and_unverified_dns_and_changed_default"),
    Scenario("BUSINESS", "CREATE_RENEW_CLIENT_PROOF_REQUIRED",
             "tests.test_cloudzy_unified_native.UnifiedNativeBridgeTests."
             "test_cz07_mirror_requires_verified_provider_and_business_receipts"),
    Scenario("TELEGRAM", "LOST_RICH_ACK_REPLAY_DENIED",
             "tests.test_cloudzy_rich_admin_phase7.RichPhase7Tests."
             "test_crash_after_intent_does_not_duplicate_send"),
    Scenario("TELEGRAM", "UNCERTAIN_EDIT_DOES_NOT_REPLAY_PURCHASE",
             "tests.test_cloudzy_rich_admin_phase7.RichPhase7Tests."
             "test_uncertain_delivery_is_not_replayed_or_business_failure"),
    Scenario("FIELD_GATE", "COHORT_LIMIT_AND_INDEPENDENT_ISP_WITNESS",
             "tests.test_cloudzy_phase8_pilot.PilotReadinessTests."
             "test_full_production_cohort_cannot_be_called_a_small_pilot"),
    Scenario("FIELD_GATE", "NO_SELF_ATTESTED_CLIENT_PROOF",
             "tests.test_cloudzy_phase8_pilot.PilotReadinessTests."
             "test_operator_text_and_false_witness_never_grant_cutover"),
    Scenario("FIELD_GATE", "FINAL_DNS_AND_THREE_RECEIPTS",
             "tests.test_cloudzy_phase8_pilot.PilotReadinessTests."
             "test_final_requires_done_and_three_business_receipts"),
)


def build_suite(*, names=None):
    requested = set(names or (s.boundary for s in SCENARIOS))
    known = {s.boundary for s in SCENARIOS}
    unknown = requested - known
    if unknown:
        raise ValueError("PHASE8_UNKNOWN_SCENARIO")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for scenario in SCENARIOS:
        if scenario.boundary in requested:
            test = loader.loadTestsFromName(scenario.test_id)
            if test.countTestCases() != 1:
                raise RuntimeError("PHASE8_SCENARIO_IMPORT_UNVERIFIED")
            suite.addTests(test)
    return suite


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Phase 8 fault injection, all ephemeral fake providers")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--scenario", action="append",
                        help="Run only the exact named boundary; repeatable")
    args = parser.parse_args(argv)
    if args.list:
        for s in SCENARIOS:
            print(f"{s.stage} | {s.boundary}")
        return 0
    try:
        suite = build_suite(names=args.scenario)
    except (ValueError, RuntimeError):
        print(json.dumps({"result": "BLOCKED", "code": "SCENARIO_INVALID"}))
        return 2
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(json.dumps({
        "mode": "HERMETIC_FAULT_INJECTION",
        "result": "PASS" if result.wasSuccessful() else "FAIL",
        "count": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors),
    }))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
