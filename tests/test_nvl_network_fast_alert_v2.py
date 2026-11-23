"""Fast Alert V2 regression: synthetic telemetry and fake Telegram only.

No external requests, live state, routes, users or systemd services are touched.
"""
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ops import nvl_network_live_alerts as live

T0 = datetime(2026, 11, 22, 20, 0, tzinfo=timezone.utc)


def sample(t, *, ssh=120, udp=112, cw=5, tx=30000, missing=False):
    return {
        "timestamp_utc": t.isoformat(),
        "ports": {
            "established": {"by_port": {
                "2252": {"local": ssh}, "7300": {"local": udp}}},
            "close-wait": {"by_port": {"7300": {"remote": cw}}},
        },
        "interface_rates_kbps": (
            {} if missing else {
                "awg0": {"received": 3000, "sent": tx},
                "eth0": {"received": tx, "sent": tx},
            }),
    }


class AdaptiveFastAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.source = root / "samples"
        self.source.mkdir()
        self.store = root / "store"
        self.config = root / "telegram.json"
        self.rows = []
        self.sent = []
        live.atomic_json(self.config, {
            "schema": "nvl-group-telegram-1",
            "chat_id": "-1001234567890",
            "bot_token": "123456789:" + "A" * 30,
            "message_thread_id": None,
        })
        live.atomic_json(self.store / "baseline.json", {
            "schema": "nvl-network-live-baseline-1",
            "status": "NORMAL_VERIFIED",
            "mode": "LIVE_PILOT_EVALUATION",
            "normal_verified": True,
            "values": {"ssh": 154, "udpgw": 140, "close_wait": 10,
                       "awg_rx_mbps": 4.337, "awg_tx_mbps": 33.274},
            "window_start": T0.isoformat(),
            "window_end": (T0 + timedelta(hours=1)).isoformat(),
        })

    def tick(self, i, **kwargs):
        t = T0 + timedelta(minutes=i)
        self.rows.append(sample(t, **kwargs))
        path = self.source / ("nvl-samples-" + t.strftime("%Y%m%d") + ".jsonl")
        path.write_text("".join(json.dumps(r) + "\n" for r in self.rows))
        def send(config, message):
            self.sent.append(message)
            return 1000 + len(self.sent)
        return live.tick(self.source, self.store, self.config,
                         now=t + timedelta(seconds=20), send=send)

    def stable(self, count=20):
        for i in range(count):
            self.tick(i)

    def decisions(self):
        with sqlite3.connect(
            f"file:{self.store}/state.sqlite3?mode=ro", uri=True
        ) as db:
            return db.execute(
                "SELECT candidate, phase, metrics_json FROM decisions "
                "ORDER BY sample_utc"
            ).fetchall()

    def test_night_cw_spike_without_legacy_ssh_surge_alerts_in_two_samples(self):
        self.stable()
        for i in (20, 21):
            self.tick(i, ssh=140, udp=88, cw=43, tx=15000)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("اختلال احتمالی", self.sent[0])
        self.assertIn("CW SPIKE", self.sent[0])
        self.assertNotIn("123456789:", self.sent[0])
        decisions = self.decisions()
        self.assertIn(decisions[-1][0], ("SUSPECTED", "DEGRADED"))
        self.assertIn("CW_SPIKE", json.loads(decisions[-1][2])["decision_reason"])

    def test_warmup_strong_corroborated_problem_still_alerts(self):
        self.tick(0, ssh=130, udp=85, cw=44, tx=13000)
        self.assertEqual(self.sent, [])
        self.tick(1, ssh=130, udp=85, cw=44, tx=13000)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("WARMUP", self.sent[0])

    def test_sudden_ssh_and_udpgw_collapse_alerts_with_no_cw_spike(self):
        self.stable()
        self.tick(20, ssh=80, udp=70, cw=5, tx=29000)
        self.assertEqual(self.sent, [])
        self.tick(21, ssh=80, udp=70, cw=5, tx=29000)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("CONNECTION COLLAPSE", self.sent[0])

    def test_traffic_collapse_with_udpgw_corroboration_alerts(self):
        self.stable()
        self.tick(20, ssh=108, udp=90, cw=5, tx=12000)
        self.tick(21, ssh=108, udp=90, cw=5, tx=12000)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("TRAFFIC COLLAPSE", self.sent[0])

    def test_slow_night_ramp_down_does_not_trigger_drop_path(self):
        for i in range(75):
            self.tick(i, ssh=125-i*.45, udp=115-i*.40,
                      cw=5, tx=35000-i*250)
        self.assertEqual(self.sent, [])
        self.assertFalse(any(
            candidate in ("SUSPECTED", "DEGRADED")
            for candidate, _, _ in self.decisions()))

    def test_one_minute_spike_not_enough(self):
        self.stable()
        self.tick(20, ssh=140, udp=85, cw=45, tx=13000)
        self.tick(21)
        self.assertEqual(self.sent, [])

    def test_invalid_sample_breaks_two_sample_gate(self):
        self.stable()
        self.tick(20, ssh=140, udp=85, cw=45, tx=13000)
        self.tick(21, missing=True)
        self.tick(22, ssh=140, udp=85, cw=45, tx=13000)
        self.assertEqual(self.sent, [])
        self.tick(23, ssh=140, udp=85, cw=45, tx=13000)
        self.assertEqual(len(self.sent), 1)

    def test_incident_escalates_recovers_and_never_spams(self):
        self.stable()
        for i in range(20, 27):
            self.tick(i, ssh=120, udp=75, cw=50, tx=12000)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("تشدید", self.sent[1])
        for i in range(27, 60):
            self.tick(i)
        self.assertEqual(len(self.sent), 3)
        self.assertIn("بازگشت", self.sent[2])
        with live.db_connect(self.store) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM outbox WHERE status='SENT'"
            ).fetchone()[0], 3)

    def test_new_reference_only_keeps_healthy_45min_window(self):
        self.stable()
        with live.db_connect(self.store) as db:
            state = live.state_read(db)
        self.assertGreaterEqual(len(state["recent_good"]), 12)
        original = len(state["recent_good"])
        self.tick(20, ssh=140, udp=85, cw=45, tx=13000)
        with live.db_connect(self.store) as db:
            state = live.state_read(db)
        self.assertEqual(len(state["recent_good"]), original)


if __name__ == "__main__":
    unittest.main()
