import unittest

from radar_notifications import (
    NOTIFY_DEGRADED,
    NOTIFY_NONE,
    NOTIFY_OUTAGE,
    NOTIFY_RECOVERED,
    evaluate_radar_notification,
)


class RadarNotificationPolicyTests(unittest.TestCase):
    def test_outage_notifies_immediately_once(self):
        first = evaluate_radar_notification(
            previous_effective_state="NORMAL",
            observed_state="OUTAGE",
        )
        self.assertTrue(first.notify)
        self.assertEqual(first.kind, NOTIFY_OUTAGE)
        self.assertEqual(first.effective_state, "OUTAGE")

        repeated = evaluate_radar_notification(
            previous_effective_state=first.effective_state,
            observed_state="OUTAGE",
        )
        self.assertFalse(repeated.notify)
        self.assertEqual(repeated.kind, NOTIFY_NONE)

    def test_degraded_requires_two_consecutive_rounds(self):
        first = evaluate_radar_notification(
            previous_effective_state="NORMAL",
            observed_state="DEGRADED",
            degraded_confirm_rounds=2,
        )
        self.assertFalse(first.notify)
        self.assertEqual(first.effective_state, "NORMAL")
        self.assertEqual(first.degraded_streak, 1)

        second = evaluate_radar_notification(
            previous_effective_state=first.effective_state,
            observed_state="DEGRADED",
            degraded_streak=first.degraded_streak,
            degraded_confirm_rounds=2,
        )
        self.assertTrue(second.notify)
        self.assertEqual(second.kind, NOTIFY_DEGRADED)
        self.assertEqual(second.effective_state, "DEGRADED")

        third = evaluate_radar_notification(
            previous_effective_state=second.effective_state,
            observed_state="DEGRADED",
            degraded_streak=second.degraded_streak,
            degraded_confirm_rounds=2,
        )
        self.assertFalse(third.notify)

    def test_outage_to_degraded_does_not_spam_or_fake_recovery(self):
        result = evaluate_radar_notification(
            previous_effective_state="OUTAGE",
            observed_state="DEGRADED",
        )
        self.assertFalse(result.notify)
        self.assertEqual(result.effective_state, "OUTAGE")

    def test_recovery_requires_two_normal_rounds(self):
        first = evaluate_radar_notification(
            previous_effective_state="OUTAGE",
            observed_state="NORMAL",
            recovery_confirm_rounds=2,
        )
        self.assertFalse(first.notify)
        self.assertEqual(first.effective_state, "OUTAGE")
        self.assertEqual(first.normal_streak, 1)

        second = evaluate_radar_notification(
            previous_effective_state=first.effective_state,
            observed_state="NORMAL",
            normal_streak=first.normal_streak,
            recovery_confirm_rounds=2,
        )
        self.assertTrue(second.notify)
        self.assertEqual(second.kind, NOTIFY_RECOVERED)
        self.assertEqual(second.effective_state, "NORMAL")

    def test_unknown_never_notifies_and_breaks_streaks(self):
        result = evaluate_radar_notification(
            previous_effective_state="DEGRADED",
            observed_state="UNKNOWN",
            degraded_streak=2,
            normal_streak=1,
        )
        self.assertFalse(result.notify)
        self.assertEqual(result.kind, NOTIFY_NONE)
        self.assertEqual(result.effective_state, "DEGRADED")
        self.assertEqual(result.degraded_streak, 0)
        self.assertEqual(result.normal_streak, 0)


if __name__ == "__main__":
    unittest.main()
