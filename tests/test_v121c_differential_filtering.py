import unittest
from types import SimpleNamespace

from differential_filtering import (
    DIFF_CONTROL_NOT_CLEAR,
    DIFF_INSUFFICIENT_EVIDENCE,
    DIFF_SHARED_FAILURE,
    DIFF_SOURCE_NOT_LIKELY,
    DIFF_TARGET_SPECIFIC,
    evaluate_differential_confirmation,
)


def ev(node, ok, asn, pending=False):
    return SimpleNamespace(
        node=node,
        ok=ok,
        pending=pending,
        asn=asn,
    )


class DifferentialFilteringPolicyTests(unittest.TestCase):
    def test_target_specific_failure_is_confirmed(self):
        source = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS2"),
            ev("ir3", False, "AS3"),
            ev("ir4", True, "AS4"),
        )
        control = (
            ev("ir1", True, "AS1"),
            ev("ir2", True, "AS2"),
            ev("ir3", True, "AS3"),
            ev("ir4", True, "AS4"),
        )
        d = evaluate_differential_confirmation(
            "LIKELY", "CLEAR", source, control
        )
        self.assertTrue(d.confirmed)
        self.assertEqual(d.verdict, DIFF_TARGET_SPECIFIC)
        self.assertEqual(d.target_specific_count, 3)
        self.assertEqual(
            d.target_specific_failed_asns,
            ("AS1", "AS2", "AS3"),
        )

    def test_shared_regional_failure_is_not_confirmed(self):
        source = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS2"),
            ev("ir3", False, "AS3"),
        )
        control = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS2"),
            ev("ir3", True, "AS3"),
        )
        d = evaluate_differential_confirmation(
            "LIKELY", "POSSIBLE", source, control
        )
        self.assertFalse(d.confirmed)
        self.assertEqual(d.verdict, DIFF_SHARED_FAILURE)
        self.assertEqual(d.shared_failure_count, 2)

    def test_control_unknown_is_not_confirmed(self):
        source = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS2"),
        )
        control = (
            ev("ir1", None, "AS1", pending=True),
            ev("ir2", None, "AS2", pending=True),
        )
        d = evaluate_differential_confirmation(
            "LIKELY", "UNKNOWN", source, control
        )
        self.assertFalse(d.confirmed)
        self.assertEqual(d.verdict, DIFF_CONTROL_NOT_CLEAR)

    def test_requires_diverse_target_specific_failures(self):
        source = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS1"),
            ev("ir3", True, "AS3"),
        )
        control = (
            ev("ir1", True, "AS1"),
            ev("ir2", True, "AS1"),
            ev("ir3", True, "AS3"),
        )
        d = evaluate_differential_confirmation(
            "LIKELY", "CLEAR", source, control
        )
        self.assertFalse(d.confirmed)
        self.assertEqual(d.verdict, DIFF_INSUFFICIENT_EVIDENCE)

    def test_source_must_remain_likely(self):
        source = (
            ev("ir1", False, "AS1"),
            ev("ir2", False, "AS2"),
        )
        control = (
            ev("ir1", True, "AS1"),
            ev("ir2", True, "AS2"),
        )
        d = evaluate_differential_confirmation(
            "POSSIBLE", "CLEAR", source, control
        )
        self.assertFalse(d.confirmed)
        self.assertEqual(d.verdict, DIFF_SOURCE_NOT_LIKELY)


if __name__ == "__main__":
    unittest.main()
