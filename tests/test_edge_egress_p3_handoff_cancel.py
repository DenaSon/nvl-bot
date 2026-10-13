"""P3-D cancellation/crash gates in original shared-6G saga."""
from __future__ import annotations

import asyncio
import unittest

from edge_egress_handoff import (
    MANUAL_RECOVERY_PHASE, run_protected_handoff, is_egress_recovery_hold,
)
from tests.test_edge_egress_handoff import Fake6GPorts, NOW


class CancelledCandidate(Fake6GPorts):
    async def stage_target_shadow(self, snapshot):
        self.mark("stage_target_shadow")
        raise asyncio.CancelledError()


class CancelledRouting(Fake6GPorts):
    async def arm_fail_closed(self, snapshot):
        self.mark("arm_fail_closed")
        raise asyncio.CancelledError()


class CancelTests(unittest.TestCase):
    def _go(self, ports):
        return asyncio.run(run_protected_handoff(
            ports,"172.86.94.174","216.126.229.12",now=NOW,
            guarded_failover=True,require_admission_drain=False,
        ))

    def test_cancellation_during_candidate_staging_keeps_6g_running(self):
        p=CancelledCandidate()
        with self.assertRaises(asyncio.CancelledError):
            self._go(p)
        self.assertTrue(p.locked)
        self.assertEqual(p.journal[-1][0:2],("RUNNING",MANUAL_RECOVERY_PHASE))
        self.assertTrue(is_egress_recovery_hold(
            __import__("json").dumps({"phase":p.journal[-1][1]})))
        self.assertNotIn("switch_dns_direct_to_target",p.actions)

    def test_cancellation_after_possible_customer_mutation_freezes_and_holds(self):
        p=CancelledRouting()
        with self.assertRaises(asyncio.CancelledError):
            self._go(p)
        self.assertTrue(p.locked)
        self.assertTrue(p.frozen)
        self.assertEqual(p.journal[-1][0:2],("RUNNING",MANUAL_RECOVERY_PHASE))
        self.assertEqual(p.dns,"172.86.94.174")

    def test_untrusted_legacy_dns_or_core_fallback_never_runs_on_cancel(self):
        p=CancelledCandidate()
        with self.assertRaises(asyncio.CancelledError):
            self._go(p)
        self.assertNotIn("commit_source_accounts_cas",p.actions)
        self.assertNotIn("switch_dns_direct_to_target",p.actions)


if __name__ == "__main__":
    unittest.main()
