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
        return live.tick(self.src, self.store, self.config, now=at, send=self.deliver,
                         max_gap_seconds=150)

    def test_incident_escalation_and_recovery_group_only(self):
        for i in range(85):
            t = T0 + timedelta(minutes=i)
            if 10 <= i < 16:
                r = row(t, ssh=205, cw=57, udp=132, tx=32000)
            elif 16 <= i < 29:
                r = row(t, ssh=90, cw=135, udp=75, tx=18000)
            else:
                r = row(t)
            self.events.append(r)
            self._tick(t + timedelta(seconds=20))
        alltext = "\n".join(self.calls)
        self.assertEqual(len(self.calls), 3)
        self.assertIn("اختلال احتمالی", alltext)
        self.assertIn("تأیید اختلال", alltext)
        self.assertNotIn("تشدید", alltext)
        self.assertEqual(sum(live.ALERT_MENTIONS in m for m in self.calls), 2)
        self.assertIn("بازگشت", alltext)
        self.assertRegex(alltext, r"AWG  RX <b>[0-9.]+</b>.*TX <b>[0-9.]+</b>")
        self.assertRegex(alltext, r"ETH  RX <b>[0-9.]+</b>.*TX <b>[0-9.]+</b>")
        self.assertIn("SSH <b>", alltext)
        self.assertIn("UDPGW <b>", alltext)
        self.assertIn("CLOSE-WAIT <b>", alltext)
        self.assertNotIn("123456789:", alltext)
        outcome = self._tick(T0 + timedelta(minutes=84, seconds=40))
        self.assertEqual(outcome["delivery"], "IDLE")
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(outcome["state"], "NORMAL")

    def test_three_consecutive_strong_samples_confirm_after_single_info(self):
        for i in range(9):
            t = T0 + timedelta(minutes=i)
            if i == 5:
                r = row(t, cw=44)
            elif i >= 6:
                r = row(t, ssh=90, udp=70, cw=50, tx=12000)
            else:
                r = row(t)
            self.events.append(r)
            self._tick(t + timedelta(seconds=20))
            expected = 0 if i < 5 else (1 if i < 8 else 2)
            self.assertEqual(len(self.calls), expected)
        self.assertIn("اختلال احتمالی", self.calls[0])
        self.assertIn("تأیید اختلال", self.calls[1])
        with live.db_connect(self.store) as db:
            keys = [k for (k,) in db.execute("SELECT event_key FROM outbox ORDER BY created_at")]
        self.assertTrue(keys[0].endswith(":INFO"))
        self.assertTrue(keys[1].endswith(":SUSPECTED"))
        self.assertEqual(keys[0].rsplit(":", 1)[0], keys[1].rsplit(":", 1)[0])
        for i in range(9, 16):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=250, cw=80))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 2)

    def test_fast_path_single_transient_info_only(self):
        for i in range(9):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=210, cw=56) if i == 3 else row(t))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("اختلال احتمالی", self.calls[0])
        self.assertEqual(self._tick(T0 + timedelta(minutes=8, seconds=40))["state"],
                         "NORMAL")

    def test_fast_path_requires_three_contiguous_valid_samples(self):
        strong = {"ssh": 90, "udp": 70, "cw": 55, "tx": 12000}
        self.events = [row(T0, **strong),
                       row(T0 + timedelta(minutes=4), **strong)]
        self._tick(T0 + timedelta(minutes=4, seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("اختلال احتمالی", self.calls[0])
        self.events.append(row(T0 + timedelta(minutes=5), **strong))
        self._tick(T0 + timedelta(minutes=5, seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.events.append(row(T0 + timedelta(minutes=6), **strong))
        self._tick(T0 + timedelta(minutes=6, seconds=20))
        self.assertEqual(len(self.calls), 2)
        self.assertIn("تأیید اختلال", self.calls[1])

    def test_fast_path_invalid_sample_breaks_three_sample_confirmation(self):
        strong = {"ssh": 90, "udp": 70, "cw": 55, "tx": 12000}
        data = [row(T0, **strong),
                row(T0 + timedelta(minutes=1), missing=True),
                row(T0 + timedelta(minutes=2), **strong),
                row(T0 + timedelta(minutes=3), **strong),
                row(T0 + timedelta(minutes=4), **strong)]
        for i, entry in enumerate(data):
            self.events.append(entry)
            self._tick(T0 + timedelta(minutes=i, seconds=20))
            self.assertEqual(len(self.calls), 1 if i < 4 else 2)
        self.assertIn("تأیید اختلال", self.calls[1])

    def test_nonconsecutive_anomalies_do_not_confirm(self):
        for i in range(5):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=200, cw=55) if i in (0, 2, 4) else row(t))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("اختلال احتمالی", self.calls[0])
        with live.db_connect(self.store) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1)

    def test_persistent_confirmed_outage_is_announced_only_twice(self):
        for i in range(25):
            t = T0 + timedelta(minutes=i)
            self.events.append(row(t, ssh=90, udp=70, cw=55, tx=12000))
            self._tick(t + timedelta(seconds=20))
        self.assertEqual(len(self.calls), 2)
        self.assertIn("اختلال احتمالی", self.calls[0])
        self.assertIn("تأیید اختلال", self.calls[1])

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
        self.events = [row(T0 + timedelta(minutes=i), ssh=90, udp=70,
                            cw=55, tx=12000) for i in range(7)]
        self._write()
        def failing(*args):
            raise live.EvidenceError("Telegram HTTP 503")
        first = live.tick(self.src, self.store, self.config,
                          now=T0 + timedelta(minutes=6, seconds=20),
                          send=failing, max_gap_seconds=150)
        self.assertIn("SEND_ERROR:", first["delivery"])
        self.assertEqual(first["outbox_pending"], 2)
        second = self._tick(T0 + timedelta(minutes=6, seconds=30))
        self.assertEqual(second["outbox_pending"], 2)
        third = self._tick(T0 + timedelta(minutes=8, seconds=21))
        self.assertEqual(third["outbox_pending"], 1)
        fourth = self._tick(T0 + timedelta(minutes=8, seconds=40))
        self.assertEqual(fourth["outbox_pending"], 0)
        self.assertEqual(len(self.calls), 2)
        self.assertIn("اختلال احتمالی", self.calls[0])
        self.assertIn("تأیید اختلال", self.calls[1])

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

    def test_private_credential_file_required_and_shared_parent_unchanged(self):
        parent = self.src / "shared"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        live.atomic_json(parent / "private.json", {"ok": True})
        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual((parent / "private.json").stat().st_mode & 0o777, 0o600)
        self.config.chmod(0o644)
        with self.assertRaises(live.EvidenceError):
            live.config_load(self.config)

    def test_detection_policy_upgrade_discards_old_confirmation_window_only(self):
        with live.db_connect(self.store) as db:
            old = live.default_state()
            old.pop("policy_version", None)
            old.update({
                "phase": "INFO",
                "incident": "NVL-20261122T110000Z-001",
                "incident_open": True,
                "alerted_phases": ["INFO"],
                "window": ["SUSPECTED", "SUSPECTED"],
                "recent_good": [{"utc": T0.isoformat(), "ssh": 154,
                                 "udpgw": 140, "close_wait": 10,
                                 "awg_tx_mbps": 33.274}],
            })
            live.state_write(db, old)
            migrated = live.state_read(db)
            self.assertEqual(migrated["window"], [])
            self.assertEqual(migrated["policy_version"],
                             live.DETECTION_POLICY_VERSION)
            self.assertEqual(migrated["phase"], "INFO")
            self.assertEqual(migrated["incident"], old["incident"])
            self.assertTrue(migrated["incident_open"])
            self.assertEqual(migrated["alerted_phases"], ["INFO"])
            self.assertEqual(migrated["recent_good"], old["recent_good"])

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
        self.assertIn("eth_rx_mbps", live.baseline_load(self.store)["values"])
        self.assertIn("eth_tx_mbps", live.baseline_load(self.store)["values"])

    def test_existing_live_baseline_eth_enrichment_does_not_touch_state(self):
        # Existing Core already has a running pilot and verified immutable baseline.
        self.events = [row(T0 + timedelta(minutes=i),
                           tx=30000 + i * 10)
                       for i in range(60)]
        self._write()
        baseline_file = self.store / "baseline.json"
        original = baseline_file.read_bytes()
        with live.db_connect(self.store) as db:
            db.execute("INSERT INTO kv(k,v) VALUES('marker','existing')")
            db.commit()
        prior_db = (self.store / "state.sqlite3").read_bytes()
        result = live.enrich_eth_baseline(self.src, self.store)
        self.assertEqual(result["schema"], live.ETH_REFERENCE_SCHEMA)
        self.assertEqual(baseline_file.read_bytes(), original)
        self.assertEqual((self.store / "state.sqlite3").read_bytes(), prior_db)
        self.assertEqual(result["coverage"]["eth_rx_mbps"], 1.0)
        self.assertAlmostEqual(result["values"]["eth_rx_mbps"], 30.295)
        self.assertAlmostEqual(result["values"]["eth_tx_mbps"], 30.295)
        live_base = live.baseline_load(self.store)
        self.assertAlmostEqual(live_base["values"]["eth_rx_mbps"], 30.295)
        self.assertEqual(live_base["values"]["ssh"], 154)
        self.assertEqual(result["window_start"], T0.isoformat())
        with self.assertRaisesRegex(live.EvidenceError, "already exists"):
            live.enrich_eth_baseline(self.src, self.store)

    def test_eth_reference_low_coverage_fails_without_changes(self):
        self.events = [row(T0 + timedelta(minutes=i)) for i in range(60)]
        for sample in self.events[40:]:
            sample["interface_rates_kbps"].pop("eth0")
        self._write()
        original = (self.store / "baseline.json").read_bytes()
        with self.assertRaisesRegex(live.EvidenceError, "ETH0 coverage"):
            live.enrich_eth_baseline(self.src, self.store)
        self.assertFalse((self.store / "eth-reference.json").exists())
        self.assertEqual((self.store / "baseline.json").read_bytes(), original)
        self.assertEqual(live.baseline_load(self.store)["values"]["ssh"], 154)

    def test_eth_reference_cannot_bind_to_another_baseline(self):
        self.events = [row(T0 + timedelta(minutes=i)) for i in range(60)]
        self._write()
        live.enrich_eth_baseline(self.src, self.store)
        base = json.loads((self.store / "baseline.json").read_text())
        base["values"]["ssh"] += 1
        live.atomic_json(self.store / "baseline.json", base)
        with self.assertRaisesRegex(live.EvidenceError, "does not match"):
            live.baseline_load(self.store)

    def test_compact_alerts_have_persian_title_english_body(self):
        self.events = [row(T0 + timedelta(minutes=i)) for i in range(60)]
        self._write()
        live.enrich_eth_baseline(self.src, self.store)
        base = live.baseline_load(self.store)
        m = live.observation(row(T0, ssh=230, udp=100, cw=90,
                                 rx=3200, tx=22000))
        m["eth_rx_mbps"] = 42.0
        m["eth_tx_mbps"] = 25.0
        incident = "NVL-20261122T110000Z-001"
        moment = (T0 + timedelta(minutes=9)).isoformat()
        for phase in ("SUSPECTED", "RECOVERED"):
            msg = live.render(phase, incident, moment, m, base)
            title, *body = msg.splitlines()
            self.assertIn("NVL |", title)
            self.assertRegex(title, r"[\u0600-\u06FF]")
            self.assertNotRegex("\n".join(body), r"[\u0600-\u06FF]")
            self.assertEqual(body[0], "Core · 2026-11-22 14:39:00 Tehran")
            self.assertIn("Age 9m", body[1])
            self.assertIn("<b>Connections</b> <i>· vs baseline</i>", msg)
            self.assertIn("<b>Traffic</b> <i>· Mbps · vs baseline</i>", msg)
            self.assertIn("SSH <b>230</b>", msg)
            self.assertIn("CLOSE-WAIT <b>90</b>", msg)
            self.assertIn("AWG  RX <b>3.20</b>", msg)
            self.assertIn("ETH  RX <b>42.00</b>", msg)
            self.assertIn("TX <b>25.00</b>", msg)
            self.assertIn("+26%", msg)
            self.assertIn("vs baseline", msg)
            self.assertNotIn("Shadow", msg)
            self.assertNotIn("بدون", msg)
            self.assertNotIn("📊", msg)
            self.assertNotIn("📶", msg)
            self.assertLessEqual(len(msg.splitlines()), 16)
            self.assertEqual(live.ALERT_MENTIONS in msg, phase == "SUSPECTED")
            self.assertLess(len(msg), 1300)
            self.assertEqual(msg.count("<b>"), msg.count("</b>"))
            self.assertEqual(msg.count("<i>"), msg.count("</i>"))
        self.assertIn("Signal: Sustained connection / traffic degradation.",
                      live.render("SUSPECTED", incident, moment, m, base))
        info = live.render("INFO", incident, moment, m, base)
        self.assertIn(live.ALERT_MENTIONS, info)
        self.assertIn("CLOSE-WAIT", info)
        self.assertNotIn("Traffic", info)
        self.assertIn("Client access not verified.",
                      live.render("RECOVERED", incident, moment, m, base))

    def test_monitor_notices_short_and_english_after_title(self):
        for phase, marker in (
            ("UNKNOWN", "Telemetry unavailable"),
            ("RESUMED", "Telemetry resumed"),
            ("TEST", "Delivery test OK")
        ):
            msg = live.render(phase, None, T0.isoformat(), None, None)
            title, *body = msg.splitlines()
            self.assertRegex(title, r"[\u0600-\u06FF]")
            self.assertNotRegex("\n".join(body), r"[\u0600-\u06FF]")
            self.assertIn(marker, msg)
            self.assertEqual(len(msg.splitlines()), 3)
            self.assertNotIn("Connections", msg)
            self.assertNotIn("Traffic", msg)
            self.assertNotIn("Shadow", msg)

    def test_missing_eth_reference_explicit_NA_no_persian_body(self):
        base = live.baseline_load(self.store)
        m = live.observation(row(T0))
        m["eth_rx_mbps"] = 20
        m["eth_tx_mbps"] = None
        text = live.render("SUSPECTED", None, T0.isoformat(), m, base)
        self.assertIn("RX <b>20.00</b> <i>N/A</i>", text)
        self.assertIn("TX <b>N/A</b> <i>N/A</i>", text)
        self.assertNotRegex("\n".join(text.splitlines()[1:]), r"[\u0600-\u06FF]")

    def test_format_no_negative_zero_and_safe_incident_id(self):
        self.assertEqual(live.pct(100, 100.2), "0%")
        self.assertEqual(live.pct(None, 100), "N/A")
        self.assertEqual(live.pct(20, 0), "N/A")
        msg = live.render("UNKNOWN", "id-<script>&", T0.isoformat(), None, None)
        self.assertNotIn("<script>", msg)
        self.assertIn("id-&lt;script&gt;&amp;", msg)
        first = live.render("SUSPECTED", "NVL-20261122T110000Z-001",
                            T0.isoformat(), None, None)
        self.assertNotIn("Age 0m", first)


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
