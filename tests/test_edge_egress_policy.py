"""Regression tests for future NVL protected Edge-egress readiness gates."""
import unittest
from dataclasses import replace

from edge_egress_policy import (
    EgressReadiness,
    REASON_READY,
    evaluate_egress_readiness,
    evaluate_protected_handoff,
)


class EgressPolicyTests(unittest.TestCase):
    @staticmethod
    def good() -> EgressReadiness:
        return EgressReadiness(
            edge_host="172.86.94.174",
            public_ipv4="172.86.94.174",
            observed_egress_ipv4="172.86.94.174",
            ingress_service_ok=True,
            management_ssh_ok=True,
            ingress_wireguard_ok=True,
            egress_wireguard_ok=True,
            egress_nat_ok=True,
            fail_closed_policy_ok=True,
            ipv6_leak_protected=True,
            fresh=True,
        )

    def handoff(self, **kwargs):
        fields = dict(
            source_edge="216.126.229.12",
            target=self.good(),
            core_public_ipv4="209.200.246.198",
            legacy_dns_core_fallback_enabled=False,
            global_domain_multi_edge_conflict=False,
        )
        fields.update(kwargs)
        return evaluate_protected_handoff(**fields)

    def test_complete_candidate_is_ready(self):
        result = evaluate_egress_readiness(self.good())
        self.assertTrue(result.ready)
        self.assertEqual(result.reason, REASON_READY)

    def test_each_missing_network_proof_blocks(self):
        for field in (
            "ingress_service_ok", "management_ssh_ok", "ingress_wireguard_ok",
            "egress_wireguard_ok", "egress_nat_ok", "fail_closed_policy_ok",
            "ipv6_leak_protected", "fresh",
        ):
            with self.subTest(field=field):
                self.assertFalse(evaluate_egress_readiness(
                    replace(self.good(), **{field: False})
                ).ready)

    def test_handshake_is_not_enough_without_correct_external_ip(self):
        for value in (None, "209.200.246.198", "bad-ip", "::1"):
            with self.subTest(value=value):
                self.assertFalse(evaluate_egress_readiness(
                    replace(self.good(), observed_egress_ipv4=value)
                ).ready)

    def test_host_mismatch_and_datapath_are_rejected(self):
        for overrides in (
            dict(edge_host="216.126.229.12"),
            dict(public_ipv4="209.200.246.198"),
            dict(public_ipv4="10.0.0.2", edge_host="10.0.0.2"),
            dict(mode="datapath"),
        ):
            with self.subTest(overrides=overrides):
                self.assertFalse(evaluate_egress_readiness(
                    replace(self.good(), **overrides)
                ).ready)

    def test_core_fallback_must_not_be_active_in_protected_mode(self):
        result = self.handoff(legacy_dns_core_fallback_enabled=True)
        self.assertFalse(result.ready)
        self.assertEqual(result.reason, "LEGACY_DNS_CORE_FALLBACK_UNSAFE")

    def test_global_domain_multi_edge_guard_is_preserved(self):
        result = self.handoff(global_domain_multi_edge_conflict=True)
        self.assertFalse(result.ready)
        self.assertEqual(result.reason, "GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT")

    def test_cannot_switch_to_same_edge_or_core(self):
        self.assertEqual(
            self.handoff(source_edge="172.86.94.174").reason,
            "SOURCE_EQUALS_TARGET",
        )
        self.assertEqual(
            self.handoff(core_public_ipv4="172.86.94.174").reason,
            "TARGET_IS_CORE",
        )

    def test_target_must_prove_fail_closed_before_assignment(self):
        result = self.handoff(
            target=replace(self.good(), fail_closed_policy_ok=False)
        )
        self.assertFalse(result.ready)
        self.assertIn("FAIL_CLOSED_NOT_VERIFIED", result.reason)

    def test_all_checks_allow_handoff_policy_approval(self):
        result = self.handoff()
        self.assertTrue(result.ready)
        self.assertEqual(result.reason, REASON_READY)


if __name__ == "__main__":
    unittest.main()
