"""Static contract for the two independent NVL systemd timer cadences."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def effective_timer_values(path):
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value == "":
            values[key] = []
        else:
            values.setdefault(key, []).append(value)
    return values


class NetworkTimerCadenceTests(unittest.TestCase):
    def test_sampler_is_scheduled_every_15_seconds(self):
        path = (ROOT / "systemd/nvl-network-sampler.timer.d/"
                "90-nvl-cadence.conf.example")
        values = effective_timer_values(path)
        self.assertEqual(values.get("OnActiveSec"), ["1s"])
        self.assertEqual(values.get("OnUnitActiveSec"), ["15s"])
        self.assertEqual(values.get("OnUnitInactiveSec"), [])
        self.assertEqual(values.get("OnCalendar"), [])
        self.assertEqual(values.get("AccuracySec"), ["1s"])
        self.assertEqual(values.get("RandomizedDelaySec"), ["0"])

    def test_detector_runs_20_seconds_after_previous_oneshot_finishes(self):
        path = (ROOT / "systemd/nvl-network-alerts.timer.d/"
                "90-nvl-cadence.conf.example")
        values = effective_timer_values(path)
        self.assertEqual(values.get("OnActiveSec"), ["1s"])
        self.assertEqual(values.get("OnUnitInactiveSec"), ["20s"])
        self.assertEqual(values.get("OnUnitActiveSec"), [])
        self.assertEqual(values.get("OnCalendar"), [])
        self.assertEqual(values.get("AccuracySec"), ["1s"])
        self.assertEqual(values.get("RandomizedDelaySec"), ["0"])


if __name__ == "__main__":
    unittest.main()
