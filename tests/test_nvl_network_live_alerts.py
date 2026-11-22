"""Live Telegram alert policy is tested with synthetic Core data and fake delivery.

No real Telegram API calls, systemd operations or socket mutations.
"""
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ops.nvl_network_intelligence import observation
from ops import nvl_network_live_alerts as live

T0 = datetime(2026, 11, 22, 11, 0, tzinfo=timezone.utc)


def row(t, *, ssh=154, udp=140, cw=10, rx=4337, tx=33274, missing=False):
    return {
        "timestamp_utc": t.isoformat(),
        "sample_type": "unlabeled",
        "ports": {
            "established": {"by_port": {
                "2252": {"local": ssh, "remote": 0},
                "7300": {"local": udp, "remote": udp}}},
            "close-wait": {"by_port": {"7300": {"remote": cw, "local": 0}}},
        },
        "interface_rates_kbps": (
            {} if missing else {
                "awg0": {"received": rx, "sent": tx},
                "eth0": {"received": tx, "sent": tx}}
        ),
        "netdata_1m_average": {},
    }


class LiveAlertsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.src = root / "samples"
        self.src.mkdir()
        self.store = root / "state"
        self.config = root / "telegram.json"
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
            "values": {"ssh":154, "udpgw":140, "close_wait":10,
                       "awg_rx_mbps":4.337, "awg_tx_mbps":33.274},
            "window_start": T0.isoformat(),
            "window_end": (T0 + timedelta(minutes=60)).isoformat(),
        })
        self.events = []
        self.calls = []
        def deliver(config, message):
            self.calls.append(message)
            return 1000 + len(self.calls)
        self.deliver = deliver

    def _write(self):
        with (self.src / "nvl-samples-20261122.jsonl").open("w") as f:
            for item in self.events:
                f.write(json.dumps(item) + "\n")

    def _tick(self, at):
        self._write()
        return live.tick(self.src, self.store, self.config, now=at, send=self.deliver)

    def test_incident_escalation_and_recovery_group_only(self):
        for i in range(85):
            t = T0 + timedelta(minutes=i)
            if 10 <= i < 16:
                r = row(t, ssh=205, cw=57, udp=132, tx=32000)
            elif 16 <= i < 29:
                r = row(t, ssh=290, cw=135, udp=107, tx=20500)
            else:
                r = row(t)
            self.events.append(r)
            self._tick(t + timedelta(seconds=20))
        alltext = "\n".join(self.calls)
        self.assertEqual(len(self.calls), 3)
        self.assertIn("اختلال احتمالی", alltext)
        self.assertIn("تشدید", alltext)
        self.assertIn("بازگشت", alltext)
        self.assertIn("AWG RX", alltext)
        self.assertIn("SSH :2252", alltext)
        self.assertNotIn("123456789:", alltext)
        outcome = self._tick(T0 + timedelta(minutes=84, seconds=40))
        self.assertEqual(outcome["delivery"], "IDLE")
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(outcome["state"], "NORMAL")

    def test_four_of_five_is_not_an_unbounded_stream_of_alerts(self):
        for i in range(25):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=200, cw=55))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("اختلال احتمالی", self.calls[0])

    def test_unknown_metric_never_becomes_zero_or_recovery(self):
        for i in range(18):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=280, cw=145, udp=105, tx=18000))
            self._tick(t + timedelta(seconds=20))
        sent = len(self.calls)
        for i in range(18, 28):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, missing=True))
            self._tick(t + timedelta(seconds=20))
        self.assertNotIn("بازگشت شاخص", "\n".join(self.calls[sent:]))
        self.assertEqual(self._tick(T0 + timedelta(minutes=27, seconds=40))["state"],
                         "UNKNOWN")

    def test_data_stale_sends_one_monitor_notice(self):
        self.events = [row(T0)]
        self._tick(T0 + timedelta(seconds=20))
        self._tick(T0 + timedelta(minutes=6))
        self._tick(T0 + timedelta(minutes=7))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("وقفه در پایش", self.calls[0])

    def test_fail_then_retry_outbox_not_double_queue(self):
        self.events = [row(T0 + timedelta(minutes=i), ssh=205, cw=55)
                       for i in range(7)]
        self._write()
        def failing(*args):
            raise live.EvidenceError("Telegram HTTP 503")
        first = live.tick(self.src, self.store, self.config,
                          now=T0 + timedelta(minutes=6, seconds=20),
                          send=failing)
        self.assertIn("SEND_ERROR:", first["delivery"])
        self.assertEqual(first["outbox_pending"], 1)
        second = self._tick(T0 + timedelta(minutes=6, seconds=30))
        self.assertEqual(second["outbox_pending"], 1)
        third = self._tick(T0 + timedelta(minutes=8, seconds=21))
        self.assertEqual(third["outbox_pending"], 0)
        self.assertEqual(len(self.calls), 1)

    def test_malformed_historical_log_does_not_block_live_alert(self):
        self.events = [row(T0 + timedelta(minutes=i), ssh=205, cw=55)
                       for i in range(7)]
        self._write()
        old = self.src / "nvl-samples-20261121.jsonl"
        old.write_text("{broken-json}\\n" * 120)
        report = self._tick(T0 + timedelta(minutes=6, seconds=20))
        self.assertEqual(report["bad_recent_lines"], 0)
        self.assertEqual(report["delivery"], "SENT")
        self.assertEqual(len(self.calls), 1)

    def test_repeated_incomplete_samples_warn_once_without_fake_recovery(self):
        for i in range(12):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, missing=True))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("وقفه در پایش", self.calls[0])
        self.assertNotIn("بازگشت شاخص", self.calls[0])

    def test_research_baseline_rejected(self):
        p = self.store / "baseline.json"
        data = json.loads(p.read_text())
        data["status"] = "RESEARCH_ONLY"
        live.atomic_json(p, data)
        with self.assertRaises(live.EvidenceError):
            live.baseline_load(self.store)

    def test_test_message_has_no_alarm_claim(self):
        body = live.render("TEST", None, T0.isoformat(), None, None)
        self.assertIn("آزمایش", body)
        self.assertNotIn("تشدید اختلال", body)

    def test_negative_group_only_and_no_token_output(self):
        env = self.src / "bot.env"
        env.write_text("BOT_TOKEN=123456789:" + ("A" * 30) + "\n")
        with self.assertRaises(live.EvidenceError):
            live.configure(env, "123456789", None, self.config)
        live.configure(env, "-1001234567890", None, self.config)
        cfg = json.loads(self.config.read_text())
        self.assertEqual(cfg["chat_id"], "-1001234567890")

    def test_anomaly_pilot_requires_operator_confirmed_60m(self):
        records = [row(T0 + timedelta(minutes=i)) for i in range(60)]
        self.events = records
        self._write()
        with self.assertRaises(live.EvidenceError):
            live.baseline_build(self.src, self.store, T0.isoformat(),
                                (T0 + timedelta(minutes=60)).isoformat(),
                                confirmed=False)
        live.baseline_build(self.src, self.store, T0.isoformat(),
                            (T0 + timedelta(minutes=60)).isoformat(),
                            confirmed=True)
        self.assertEqual(live.baseline_load(self.store)["status"],
                         "NORMAL_VERIFIED")

    def test_reject_degraded_auto_baseline(self):
        self.events = [row(T0 + timedelta(minutes=i),
                           ssh=270, cw=130, udp=45, tx=1000)
                       for i in range(60)]
        self._write()
        with self.assertRaises(live.EvidenceError):
            live.baseline_build(self.src, self.store, T0.isoformat(),
                                (T0 + timedelta(minutes=60)).isoformat(),
                                confirmed=True)


if __name__ == "__main__":
    unittest.main()
