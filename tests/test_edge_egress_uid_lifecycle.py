"""D1-C3B: Phase 6G-locked disposable canary, cleanup and crash holds."""
import asyncio
import json
import unittest

from edge_egress_handoff import is_egress_recovery_hold
from edge_egress_uid_lifecycle import run_disposable_uid_canary
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def request():
    return UIDPolicyRequest(
        EgressSpec.from_json({
            "edge_id": "fra1",
            "edge_public_ipv4": "216.126.229.12",
            "core_public_ipv4": "209.200.246.198",
            "tunnel_network": "10.78.100.0/30",
            "veth_network": "10.78.101.0/30",
            "edge_uplink": "eth0",
            "edge_listen_port": 51832,
            "route_table": 1780,
            "mode": "relay",
        }), "nvl0557", 1644, priority=1780,
    )


class FakePorts:
    def __init__(self, *, fail=None, observation="216.126.229.12", busy=False):
        self.fail = fail
        self.observation = observation
        self.busy = busy
        self.events = []
        self.journal = []

    def event(self, name):
        self.events.append(name)
        if name == self.fail:
            raise RuntimeError("synthetic " + name)

    async def acquire_6g_lock(self, source, target):
        self.event("lock")
        return (None, 55) if self.busy else (42, None)

    async def journal_6g(self, operation_id, status, phase, details):
        self.journal.append((operation_id, status, phase, details))
        self.event("journal:" + phase)

    async def assert_ownership_and_uid(self, request, source):
        self.event("check-ownership")

    async def assert_disposable_lab_ready(self, request):
        self.event("check-disposable")

    async def arm_guard(self, request):
        self.event("arm")

    async def start_shadow(self, request):
        self.event("start")

    async def attach_edge(self, request):
        self.event("attach")

    async def prove_public_edge_ip(self, request):
        self.event("prove-v4")
        return self.observation

    async def prove_ipv6_dns_blocked(self, request):
        self.event("prove-dns-v6")

    async def freeze_uid(self, request):
        self.event("freeze")

    async def stop_shadow(self, request):
        self.event("stop")

    async def restore_disposable_canary(self, request):
        self.event("restore")


def run(p, authorized=True):
    return asyncio.run(run_disposable_uid_canary(
        p, request(), source_edge="172.86.94.174",
        explicitly_authorized=authorized,
    ))


class LifecycleTests(unittest.TestCase):
    def test_default_deny_no_lock_no_kernel_call(self):
        p = FakePorts()
        result = run(p, False)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "EXPLICIT_LAB_AUTHORIZATION_REQUIRED")
        self.assertEqual(p.events, [])

    def test_busy_existing_6g_lock_never_mutates(self):
        p = FakePorts(busy=True)
        result = run(p)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SHARED_6G_BUSY")
        self.assertEqual(p.events, ["lock"])

    def test_success_proves_and_restores_under_same_lock(self):
        p = FakePorts()
        result = run(p)
        self.assertTrue(result.ok)
        self.assertFalse(result.customer_ready)
        self.assertFalse(result.recovery_required)
        self.assertEqual(result.state, "RESTORED")
        self.assertEqual([x for x in p.events if x in
                          {"arm", "start", "attach", "prove-v4",
                           "prove-dns-v6", "freeze", "stop", "restore"}],
                         ["arm", "start", "attach", "prove-v4",
                          "prove-dns-v6", "freeze", "stop", "restore"])
        self.assertEqual(p.journal[-1][1:3],
                         ("SUCCEEDED", "EGRESS_UID_CANARY_RESTORED"))
        self.assertIn(("RUNNING", "EGRESS_UID_ARM_GUARD"),
                      [(s, h) for _, s, h, _ in p.journal])
        self.assertIn(("RUNNING", "EGRESS_UID_ATTACH_ROUTE"),
                      [(s, h) for _, s, h, _ in p.journal])

    def test_failed_preflight_unlocks_without_touching_guard(self):
        p = FakePorts(fail="check-disposable")
        result = run(p)
        self.assertFalse(result.ok)
        self.assertFalse(result.recovery_required)
        self.assertEqual(result.state, "NOT_MUTATED")
        self.assertEqual(p.journal[-1][1], "FAILED")
        self.assertNotIn("arm", p.events)

    def test_wrong_observed_ip_holds_lock_and_freezes(self):
        p = FakePorts(observation="209.200.246.198")
        result = run(p)
        self.assertFalse(result.ok)
        self.assertTrue(result.recovery_required)
        self.assertEqual(result.state, "GUARDED_HOLD")
        self.assertIn("freeze", p.events)
        self.assertIn("stop", p.events)
        self.assertNotIn("restore", p.events)
        self.assertEqual(p.journal[-1][1:3],
                         ("RUNNING", "EGRESS_UID_RECOVERY_REQUIRED"))
        self.assertTrue(is_egress_recovery_hold(json.dumps({
            "phase": p.journal[-1][2]})))

    def test_failure_during_guard_is_held_even_if_guard_partial(self):
        p = FakePorts(fail="arm")
        result = run(p)
        self.assertTrue(result.recovery_required)
        self.assertIn("freeze", p.events)
        self.assertEqual(p.journal[-1][3]["guard_maybe_partial"], True)

    def test_error_while_restoring_never_releases_lock(self):
        p = FakePorts(fail="restore")
        result = run(p)
        self.assertFalse(result.ok)
        self.assertTrue(result.recovery_required)
        self.assertEqual(p.journal[-1][1], "RUNNING")
        self.assertTrue(is_egress_recovery_hold(json.dumps({
            "phase": p.journal[-1][2]})))

    def test_each_mutating_phase_is_recovery_hold(self):
        phases = ("EGRESS_UID_ARM_GUARD", "EGRESS_UID_START_SHADOW",
                  "EGRESS_UID_ATTACH_ROUTE", "EGRESS_UID_PROVE_IPV4",
                  "EGRESS_UID_PROVE_IPV6_DNS", "EGRESS_UID_STOP_SHADOW",
                  "EGRESS_UID_RESTORE_CANARY", "EGRESS_UID_RECOVERY_REQUIRED")
        for phase in phases:
            with self.subTest(phase=phase):
                self.assertTrue(is_egress_recovery_hold(json.dumps(
                    {"phase": phase, "kind": "EGRESS_UID_CANARY"}
                )))

    def test_wrong_source_edge_rejected_before_6g(self):
        p = FakePorts()
        result = asyncio.run(run_disposable_uid_canary(
            p, request(), source_edge="209.200.246.198",
            explicitly_authorized=True,
        ))
        self.assertEqual(result.reason, "INVALID_SOURCE_EDGE")
        self.assertEqual(p.events, [])


if __name__ == "__main__":
    unittest.main()
