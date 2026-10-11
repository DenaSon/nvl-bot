"""D1-C2: fault-injection tests for shared-lock, protected relay handoff.

No actual network, database, Cloudflare or production operation is invoked.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from edge_egress_handoff import (
    AccountOwner, HandoffSnapshot, HandoffResult, HandoffUnsafe,
    TargetObservation, MANUAL_RECOVERY_PHASE, run_protected_handoff,
)
from edge_egress_policy import EgressReadiness


NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


def snapshot(**changes) -> HandoffSnapshot:
    args = dict(
        source_host="172.86.94.174",
        target_host="216.126.229.12",
        core_public_ipv4="209.200.246.198",
        current_dns_ipv4="172.86.94.174",
        active_accounts=(AccountOwner("nvl0557", 1644), AccountOwner("nvl0558", 1645)),
        other_explicit_active_accounts=0,
        source_is_default=True,
        target_is_active_standby=True,
        source_service_port=2252,
        target_service_port=2252,
        target_egress_identity_unique=True,
    )
    args.update(changes)
    return HandoffSnapshot(**args)


def observation(**changes) -> TargetObservation:
    args = dict(
        edge_host="216.126.229.12",
        public_ipv4="216.126.229.12",
        observed_egress_ipv4="216.126.229.12",
        ingress_service_ok=True, management_ssh_ok=True,
        ingress_wireguard_ok=True, egress_wireguard_ok=True,
        egress_nat_ok=True, fail_closed_policy_ok=True,
        ipv6_leak_protected=True, fresh=True,
    )
    args.update(changes)
    return TargetObservation(EgressReadiness(**args), NOW, "fra-standby-001")


class Fake6GPorts:
    """Single fake operation lock, fake journal, no real Linux side effects."""
    steps = (
        "snapshot_under_lock", "stage_target_shadow", "rekey_dedicated_peer",
        "observe_target", "revalidate_before_cutover", "arm_fail_closed",
        "select_target_egress", "prove_selected_egress",
        "commit_source_accounts_cas", "switch_dns_direct_to_target", "verify_final",
    )
    def __init__(self, *, fail_at=None, bad_snapshot=None, bad_observation=None,
                 busy=False, fail_freeze=False, fail_journal=False):
        self.fail_at = fail_at
        self.bad_snapshot = bad_snapshot
        self.bad_observation = bad_observation
        self.busy = busy
        self.fail_freeze = fail_freeze
        self.fail_journal = fail_journal
        self.actions = []
        self.journal = []
        self.current_db_host = "172.86.94.174"
        self.dns = "172.86.94.174"
        self.selected_egress = None
        self.frozen = False
        self.account_count = None
        self.locked = False

    def mark(self, name):
        self.actions.append(name)
        if self.fail_at == name:
            raise RuntimeError("simulated uncertainty")

    async def acquire_6g_lock(self, source, target):
        self.mark("acquire_6g_lock")
        if self.busy:
            return None, 41
        self.locked = True
        return 42, None

    async def update_6g_journal(self, operation_id, *, status, phase, details):
        if operation_id != 42:
            raise AssertionError("wrong shared 6G lock identity")
        if self.fail_journal and phase == "ARM_FAIL_CLOSED":
            raise RuntimeError("journal offline")
        self.journal.append((status, phase, details))
        self.actions.append("journal:" + phase)
        if status != "RUNNING":
            self.locked = False

    async def snapshot_under_lock(self, source, target):
        self.mark("snapshot_under_lock")
        self.account_count = len(snapshot().active_accounts)
        return self.bad_snapshot or snapshot()

    async def stage_target_shadow(self, record):
        self.mark("stage_target_shadow")

    async def rekey_dedicated_peer(self, record):
        self.mark("rekey_dedicated_peer")

    async def observe_target(self, record):
        self.mark("observe_target")
        return self.bad_observation or observation()

    async def revalidate_before_cutover(self, record):
        self.mark("revalidate_before_cutover")

    async def arm_fail_closed(self, record):
        self.mark("arm_fail_closed")

    async def select_target_egress(self, record):
        self.mark("select_target_egress")
        self.selected_egress = record.target_host

    async def prove_selected_egress(self, record):
        self.mark("prove_selected_egress")

    async def commit_source_accounts_cas(self, record):
        self.mark("commit_source_accounts_cas")
        self.current_db_host = record.target_host

    async def switch_dns_direct_to_target(self, record):
        self.mark("switch_dns_direct_to_target")
        self.dns = record.target_host

    async def verify_final(self, record):
        self.mark("verify_final")

    async def freeze_customer_egress(self, record):
        self.actions.append("freeze_customer_egress")
        if self.fail_freeze:
            raise RuntimeError("freeze failed")
        self.frozen = True


class HandoffSimulationTests(unittest.TestCase):
    def run_saga(self, ports):
        return asyncio.run(run_protected_handoff(
            ports, "172.86.94.174", "216.126.229.12", now=NOW
        ))

    def test_success_uses_one_6g_lock_and_no_core_dns_fallback(self):
        ports = Fake6GPorts()
        outcome = self.run_saga(ports)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.operation_id, 42)
        self.assertEqual(ports.dns, "216.126.229.12")
        self.assertEqual(ports.selected_egress, "216.126.229.12")
        self.assertEqual(ports.current_db_host, "216.126.229.12")
        self.assertFalse(ports.locked)
        self.assertFalse(ports.frozen)
        self.assertEqual(ports.journal[-1][1], "SUCCEEDED")
        self.assertEqual([x for x in ports.actions if x == "acquire_6g_lock"],
                         ["acquire_6g_lock"])
        self.assertNotIn("core_fallback", " ".join(ports.actions))
        self.assertLess(ports.actions.index("arm_fail_closed"),
                        ports.actions.index("select_target_egress"))
        self.assertLess(ports.actions.index("prove_selected_egress"),
                        ports.actions.index("commit_source_accounts_cas"))
        self.assertLess(ports.actions.index("commit_source_accounts_cas"),
                        ports.actions.index("switch_dns_direct_to_target"))

    def test_busy_existing_failover_returns_without_any_side_effect(self):
        ports = Fake6GPorts(busy=True)
        result = self.run_saga(ports)
        self.assertFalse(result.ok)
        self.assertEqual(result.operation_id, 41)
        self.assertEqual(result.reason, "SHARED_FAILOVER_BUSY")
        self.assertEqual(ports.journal, [])

    def test_all_pre_cutover_faults_fail_without_touching_customer_state(self):
        for phase in Fake6GPorts.steps[:5]:
            with self.subTest(phase=phase):
                ports = Fake6GPorts(fail_at=phase)
                result = self.run_saga(ports)
                self.assertFalse(result.ok)
                self.assertFalse(result.needs_manual_recovery)
                self.assertFalse(ports.locked)
                self.assertEqual(ports.dns, "172.86.94.174")
                self.assertEqual(ports.current_db_host, "172.86.94.174")
                self.assertFalse(ports.frozen)
                self.assertEqual(ports.journal[-1][0], "FAILED")
                self.assertNotIn("arm_fail_closed", ports.actions)

    def test_every_post_arm_failure_freezes_and_keeps_shared_lock(self):
        for phase in Fake6GPorts.steps[5:]:
            with self.subTest(phase=phase):
                ports = Fake6GPorts(fail_at=phase)
                result = self.run_saga(ports)
                self.assertFalse(result.ok)
                self.assertTrue(result.needs_manual_recovery)
                self.assertTrue(ports.frozen)
                self.assertTrue(ports.locked)
                self.assertEqual(ports.journal[-1][0], "RUNNING")
                self.assertEqual(ports.journal[-1][1], MANUAL_RECOVERY_PHASE)
                self.assertNotIn("209.200.246.198", [ports.dns, ports.selected_egress])

    def test_failed_freeze_still_holds_shared_lock_and_flags_critical(self):
        ports = Fake6GPorts(fail_at="switch_dns_direct_to_target", fail_freeze=True)
        result = self.run_saga(ports)
        self.assertTrue(result.needs_manual_recovery)
        self.assertTrue(ports.locked)
        self.assertEqual(ports.journal[-1][2]["frozen"], False)

    def test_journal_failure_at_arm_holds_lock_and_tries_to_freeze(self):
        ports = Fake6GPorts(fail_journal=True)
        result = self.run_saga(ports)
        self.assertTrue(result.needs_manual_recovery)
        self.assertTrue(ports.frozen)
        self.assertTrue(ports.locked)

    def test_stale_or_wrong_egress_observation_blocks_all_mutations(self):
        wrong = [
            observation(observed_egress_ipv4="209.200.246.198"),
            replace(observation(), observed_at=NOW - timedelta(minutes=1)),
            replace(observation(), observed_at=NOW + timedelta(minutes=1)),
            replace(observation(), edge_instance=""),
            replace(observation(), readiness=replace(
                observation().readiness, fail_closed_policy_ok=False
            )),
            replace(observation(), readiness=replace(
                observation().readiness, ipv6_leak_protected=False
            )),
            replace(observation(), readiness=replace(
                observation().readiness, egress_wireguard_ok=False
            )),
        ]
        for case in wrong:
            with self.subTest(case=str(case)[:80]):
                ports = Fake6GPorts(bad_observation=case)
                result = self.run_saga(ports)
                self.assertFalse(result.ok)
                self.assertFalse(result.needs_manual_recovery)
                self.assertFalse(ports.frozen)
                self.assertFalse(ports.locked)
                self.assertNotIn("arm_fail_closed", ports.actions)

    def test_invalid_snapshot_guards_global_domain_and_wrong_host(self):
        bads = [
            snapshot(other_explicit_active_accounts=3),
            snapshot(target_is_active_standby=False),
            snapshot(source_is_default=False),
            snapshot(current_dns_ipv4="209.200.246.198"),
            snapshot(target_service_port=22),
            snapshot(target_egress_identity_unique=False),
            snapshot(active_accounts=()),
            snapshot(active_accounts=(AccountOwner("same", 1644),
                                      AccountOwner("different", 1644))),
            snapshot(source_host="216.126.229.12"),
        ]
        for bad in bads:
            with self.subTest(bad=str(bad)[:80]):
                ports = Fake6GPorts(bad_snapshot=bad)
                result = self.run_saga(ports)
                self.assertFalse(result.ok)
                self.assertFalse(result.needs_manual_recovery)
                self.assertNotIn("stage_target_shadow", ports.actions)

    def test_uid_zero_and_root_process_never_accepted(self):
        with self.assertRaises(HandoffUnsafe):
            AccountOwner("root", 0)
        with self.assertRaises(HandoffUnsafe):
            AccountOwner("nvl", True)
        with self.assertRaises(HandoffUnsafe):
            AccountOwner("nvl", 65534)


if __name__ == "__main__":
    unittest.main()
