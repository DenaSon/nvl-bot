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
from ops import nvl_network_fast_alert_v2_replay as offline

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
                         now=t + timedelta(seconds=20), send=send,
                         max_gap_seconds=150)

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

    def test_night_cw_spike_with_independent_traffic_drop_confirms_after_three_samples(self):
        self.stable()
        for i in (20, 21, 22):
            self.tick(i, ssh=140, udp=88, cw=43, tx=15000)
            self.assertEqual(len(self.sent), 0 if i < 22 else 1)
        self.assertIn("تأیید اختلال", self.sent[0])
        self.assertIn("CW SPIKE", self.sent[0])
        self.assertNotIn("123456789:", self.sent[0])
        decisions = self.decisions()
        self.assertIn(decisions[-1][0], ("SUSPECTED", "DEGRADED"))
        self.assertIn("CW_SPIKE", json.loads(decisions[-1][2])["decision_reason"])

    def test_warmup_strong_corroborated_problem_requires_three_samples(self):
        for i in (0, 1, 2):
            self.tick(i, ssh=130, udp=85, cw=44, tx=13000)
            self.assertEqual(len(self.sent), 0 if i < 2 else 1)
        self.assertIn("WARMUP", self.sent[0])

    def test_sudden_ssh_and_udpgw_collapse_alerts_after_three_samples(self):
        self.stable()
        for i in (20, 21, 22):
            self.tick(i, ssh=80, udp=70, cw=5, tx=29000)
            self.assertEqual(len(self.sent), 0 if i < 22 else 1)
        self.assertIn("CONNECTION COLLAPSE", self.sent[0])

    def test_traffic_collapse_with_udpgw_corroboration_requires_three_samples(self):
        self.stable()
        for i in (20, 21, 22):
            self.tick(i, ssh=108, udp=90, cw=5, tx=12000)
            self.assertEqual(len(self.sent), 0 if i < 22 else 1)
        self.assertIn("TRAFFIC COLLAPSE", self.sent[0])

    def test_slow_night_ramp_down_does_not_trigger_drop_path(self):
        for i in range(75):
            self.tick(i, ssh=125-i*.45, udp=115-i*.40,
                      cw=5, tx=35000-i*250)
        self.assertEqual(self.sent, [])
        self.assertFalse(any(
            candidate in ("SUSPECTED", "DEGRADED")
            for candidate, _, _ in self.decisions()))

    def test_one_minute_cw_spike_is_internal_only(self):
        self.stable()
        self.tick(20, ssh=140, udp=85, cw=45, tx=13000)
        self.tick(21)
        self.assertEqual(self.sent, [])
        with live.db_connect(self.store) as db:
            state = live.state_read(db)
        self.assertEqual(state["phase"], "INFO")

    def test_invalid_sample_breaks_three_sample_gate(self):
        self.stable()
        strong = {"ssh": 80, "udp": 70, "cw": 45, "tx": 12000}
        self.tick(20, **strong)
        self.tick(21, missing=True)
        self.tick(22, **strong)
        self.tick(23, **strong)
        self.assertEqual(len(self.sent), 1)
        self.tick(24, **strong)
        self.assertEqual(len(self.sent), 2)

    def test_incident_escalates_after_three_samples_recovers_and_never_spams(self):
        self.stable()
        for i in range(20, 27):
            self.tick(i, ssh=120, udp=75, cw=50, tx=12000)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("تأیید اختلال", self.sent[0])
        self.assertNotIn("تشدید", "\n".join(self.sent))
        self.assertIn(live.ALERT_MENTIONS, self.sent[0])
        for i in range(27, 60):
            self.tick(i)
        self.assertEqual(len(self.sent), 2)
        self.assertIn("بازگشت", self.sent[1])
        self.assertNotIn(live.ALERT_MENTIONS, self.sent[1])
        with live.db_connect(self.store) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM outbox WHERE status='SENT'"
            ).fetchone()[0], 2)

    def test_offline_replay_queues_same_alert_without_live_side_effects(self):
        self.stable()
        self.tick(20, ssh=140, udp=88, cw=43, tx=15000)
        self.tick(21, ssh=140, udp=88, cw=43, tx=15000)
        self.tick(22, ssh=140, udp=88, cw=43, tx=15000)
        original_state = (self.store / "state.sqlite3").read_bytes()
        original_base = (self.store / "baseline.json").read_bytes()
        original_telegram = self.config.read_bytes()
        sent_before = len(self.sent)
        report = offline.replay(
            self.source, self.store, T0, T0 + timedelta(minutes=23))
        self.assertEqual(report["telegram_messages_sent"], 0)
        self.assertEqual(len(report["would_queue"]), 1)
        self.assertEqual(report["samples"], 23)
        self.assertEqual(sent_before, len(self.sent))
        self.assertEqual((self.store / "state.sqlite3").read_bytes(), original_state)
        self.assertEqual((self.store / "baseline.json").read_bytes(), original_base)
        self.assertEqual(self.config.read_bytes(), original_telegram)

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


    def test_fast_cadence_cw_spike_is_internal_then_three_strong_samples(self):
        base = live.baseline_load(self.store)
        state = live.default_state()
        with live.db_connect(self.store) as db:
            # A single CLOSE-WAIT sample is diagnostic only; it never queues INFO.
            obs = live.observation(sample(T0, cw=20, missing=True))
            live.process_sample(state, T0, obs, base, db)
            keys = lambda: [k for (k,) in db.execute(
                "SELECT event_key FROM outbox ORDER BY created_at")]
            self.assertEqual(len(keys()), 0)
            strong = {"ssh": 80, "udp": 70, "cw": 44, "tx": 12000}
            for i in (1, 2):
                t = T0 + timedelta(seconds=15*i)
                obs = live.observation(sample(t, **strong))
                live.process_sample(state, t, obs, base, db)
                self.assertEqual(len(keys()), 0)
            t = T0 + timedelta(seconds=45)
            live.process_sample(state, t, live.observation(sample(t, **strong)), base, db)
            self.assertEqual(len(keys()), 1)
            self.assertTrue(keys()[0].endswith(":SUSPECTED"))
            for i in range(4, 9):
                t = T0 + timedelta(seconds=15*i)
                live.process_sample(state, t, live.observation(sample(t)), base, db)
                self.assertEqual(len(keys()), 1 if i < 8 else 2)
            self.assertTrue(keys()[1].endswith(":RECOVERED"))
            self.assertEqual(state["phase"], "NORMAL")

    def test_fast_cadence_gap_resets_three_sample_confirmation_window(self):
        base = live.baseline_load(self.store)
        state = live.default_state()
        with live.db_connect(self.store) as db:
            for seconds in (0, 15, 30):
                t = T0 + timedelta(seconds=seconds)
                live.process_sample(state, t, live.observation(sample(t, cw=20)), base, db)
            self.assertEqual(state["phase"], "INFO")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
            strong = {"ssh": 80, "udp": 70, "cw": 44, "tx": 12000}
            for seconds in (45, 90, 105):
                t = T0 + timedelta(seconds=seconds)
                live.process_sample(state, t, live.observation(sample(t, **strong)), base, db)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
            t = T0 + timedelta(seconds=120)
            live.process_sample(state, t, live.observation(sample(t, **strong)), base, db)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1)

    def test_cw_udpgw_spike_and_legacy_ssh_surge_without_traffic_drop_stays_info_only(self):
        base = live.baseline_load(self.store)
        state = live.default_state()
        with live.db_connect(self.store) as db:
            # Build a valid 12+ minute adaptive reference window.
            for i in range(50):
                t = T0 + timedelta(seconds=15*i)
                live.process_sample(state, t, live.observation(sample(t)), base, db)
            incident_rows = [
                (150, 116, 32, 21200),
                (167, 84, 79, 32100),
                (177, 101, 76, 40800),
                (183, 103, 80, 39200),
                (185, 107, 78, 47400),
                (190, 106, 82, 42600),
                (196, 113, 81, 41600),
                (200, 116, 81, 39000),
                (199, 115, 81, 55500),
            ]
            for i, (ssh, udp, cw, tx) in enumerate(incident_rows, start=50):
                t = T0 + timedelta(seconds=15*i)
                live.process_sample(
                    state, t, live.observation(sample(
                        t, ssh=ssh, udp=udp, cw=cw, tx=tx)), base, db)
            keys = [key for (key,) in db.execute(
                "SELECT event_key FROM outbox ORDER BY created_at")]
            self.assertEqual(len(keys), 0)
            self.assertEqual(state["phase"], "INFO")
            self.assertFalse(any(
                item in ("SUSPECTED", "DEGRADED") for item in state["window"]))

    def test_20261125_historical_false_positive_is_internal_only(self):
        baseline_path = self.store / "baseline.json"
        baseline_data = json.loads(baseline_path.read_text())
        baseline_data["values"].update({
            "ssh": 153.0,
            "udpgw": 135.0,
            "close_wait": 12.0,
            "awg_rx_mbps": 4.931035,
            "awg_tx_mbps": 35.39244,
        })
        live.atomic_json(baseline_path, baseline_data)
        base = live.baseline_load(self.store)
        state = live.default_state()
        historical = [
            (181, 139, 29, 39.23862),
            (206, 140, 54, 25.80593),
            (224, 126, 84, 20.42940),
            (239, 56, 167, 25.50691),
            (280, 71, 194, 27.54817),
            (261, 83, 167, 26.81031),
            (188, 94, 88, 21.56500),
            (138, 110, 23, 26.47243),
            (126, 114, 8, 30.10134),
            (138, 121, 10, 35.20544),
            (153, 134, 10, 46.26227),
            (153, 133, 12, 47.55169),
            (156, 135, 14, 51.04339),
        ]
        with live.db_connect(self.store) as db:
            for i, (ssh, udp, cw, tx) in enumerate(historical):
                stamp = T0 + timedelta(seconds=62*i)
                obs = live.observation(sample(
                    stamp, ssh=ssh, udp=udp, cw=cw, tx=round(tx*1000)))
                live.process_sample(
                    state, stamp, obs, base, db, max_gap_seconds=75)
            keys = [key for (key,) in db.execute(
                "SELECT event_key FROM outbox ORDER BY created_at")]
            self.assertEqual(keys, [])
            self.assertEqual(state["phase"], "NORMAL")
            self.assertFalse(any(
                item in ("SUSPECTED", "DEGRADED") for item in state["window"]))

    def test_fast_reference_retains_45_minutes_not_45_samples(self):
        base = live.baseline_load(self.store)
        state = live.default_state()
        with live.db_connect(self.store) as db:
            for i in range(200):
                t = T0 + timedelta(seconds=i*15)
                live.process_sample(state, t, live.observation(sample(t)), base, db)
            self.assertEqual(len(state["recent_good"]), 180)
            self.assertIsNotNone(live.adaptive_reference(state, t))


if __name__ == "__main__":
    unittest.main()
