"""R2-D1 regression tests: real Collector SQLite schema, read-only metrics and UI auth."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from denaprobe_ingest import collector
from denaprobe_ingest.metrics import build_report
from denaprobe_admin_dashboard import authorized, render, handle_dashboard

ID = "dp-mci-01"
BOOT = "57fce203c6e94baf8d32749c11f0a65d"
BOOT2 = "8af37b68cf1d4662acd8d9512b70f305"


def probe(q, u, boot_id=BOOT, **kw):
    record = {"v": 1, "id": ID, "b": boot_id, "q": q, "u": u,
              "k": 1, "t": 1, "w": 1, "r": -42, "s": 1,
              "p": 52, "o": 255, "d": 5, "x": 3300, "a": 184}
    record.update(kw)
    return record


class MetricsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "telemetry.sqlite3"
        collector.initialize(self.db)
        collector.register_target(self.db, 1, "n1.nvlsup.com", 2252)
        self.now = int(time.time() * 1000)

    def put(self, obj, *, when, sent=None):
        payload = json.dumps(obj, separators=(",", ":")).encode()
        if sent is None:
            sent = obj["u"] + 40
        return collector.store(self.db, obj, payload, sent, [1], now_ms=when)

    def started(self):
        self.assertEqual(self.put(
            {"v": 1, "id": ID, "b": BOOT, "q": 1, "u": 1000,
             "k": 3, "w": 1}, when=self.now - 60000), 0)

    def test_fresh_metrics_and_no_ssh_inference_from_wifi_event(self):
        self.started()
        self.assertEqual(self.put(
            {"v": 1, "id": ID, "b": BOOT, "q": 2, "u": 2000,
             "k": 2, "s": 96, "w": 1}, when=self.now - 59000), 0)
        self.assertEqual(self.put(
            probe(3, 10000, h={"c": 1, "u": 15000, "n": 65536, "bt": 2600,
                               "ms": 5115, "hc": 200}),
            when=self.now - 45000, sent=15100), 0)
        self.assertEqual(self.put(
            probe(4, 40000, d=1, x=3500, a=1461),
            when=self.now - 10000), 0)
        result = build_report(self.db, ID, 24, self.now)
        self.assertEqual(result["events"]["stored"], 4)
        self.assertEqual(result["events"]["observed_missing_sequences"], 0)
        self.assertEqual(result["events"]["history_only"], 0)
        self.assertEqual(result["ssh"]["pass"], 2)
        self.assertEqual(result["ssh"]["local"], 0)  # local Wi-Fi was k=2
        self.assertEqual(result["ssh"]["service_accept"],
                         {"count": 2, "p50_ms": 184, "p95_ms": 1461})
        self.assertEqual(result["https"]["pass"], 1)
        self.assertEqual(result["https"]["body_transfer"]["p95_ms"], 2600)
        self.assertEqual(result["live"]["ssh_sequence"], 4)
        self.assertEqual(result["live"]["https_sequence"], 3)
        self.assertEqual(result["live"]["monitoring_gap"], 0)
        self.assertEqual(result["live"]["delivery_freshness"], "FRESH")
        self.assertEqual(result["live"]["https_freshness"], "FRESH")
        self.assertIn("DenaProbe", render(result))
        self.assertIn("24 ساعت", render(result))
        self.assertNotIn("n1.nvlsup.com", render(result))

    def test_sequence_gap_is_observable_not_cross_boot_loss(self):
        self.started()
        self.assertEqual(self.put(probe(4, 5000), when=self.now - 30000), 2)
        result = build_report(self.db, ID, 24, self.now)
        self.assertEqual(result["events"]["observed_missing_sequences"], 2)
        self.assertEqual(result["events"]["history_only"], 1)
        self.assertEqual(result["ssh"]["pass"], 0)
        self.assertEqual(result["live"]["monitoring_gap"], 1)
        self.assertEqual(self.put(
            {"v": 1, "id": ID, "b": BOOT2, "q": 1, "u": 1000,
             "k": 3, "w": 1}, when=self.now - 20000), 0)
        result = build_report(self.db, ID, 24, self.now)
        self.assertEqual(result["events"]["observed_missing_sequences"], 2)
        self.assertEqual(result["live"]["ssh_freshness"], "NOT_TESTED")

    def test_staleness_and_read_only(self):
        self.started()
        self.assertEqual(self.put(probe(2, 5000), when=self.now-300000), 0)
        self.assertEqual(self.put(probe(3, 25000), when=self.now-290000), 0)
        with sqlite3.connect(self.db) as db:
            original = db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0]
        result = build_report(self.db, ID, 24, self.now)
        self.assertEqual(result["live"]["ssh_freshness"], "STALE")
        self.assertEqual(result["live"]["delivery_freshness"], "STALE")
        with sqlite3.connect(self.db) as db:
            current = db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0]
        self.assertEqual(original, current)

    def test_unknown_status_does_not_count_as_network_failure(self):
        self.started()
        self.assertEqual(self.put(probe(2, 5000, s=199, p=199),
                                  when=self.now-30000), 2)
        result = build_report(self.db, ID, 24, self.now)
        self.assertEqual(result["events"]["unknown_codes"], 1)
        self.assertEqual(result["ssh"]["path_nonpass"], 0)
        self.assertEqual(result["ssh"]["pass"], 0)

    def test_validation_and_no_missing_db_creation(self):
        for device in ("bad id", "../core", "", "a"*100):
            with self.subTest(device=device), self.assertRaises(ValueError):
                build_report(self.db, device, 24, self.now)
        with self.assertRaises(ValueError):
            build_report(self.db, ID, 25, self.now)
        missing = Path(self.tmp.name) / "missing.sqlite3"
        with self.assertRaises(sqlite3.OperationalError):
            build_report(missing, ID, 24, self.now)
        self.assertFalse(missing.exists())

    def test_admin_access_is_private_actor_exact_and_current(self):
        self.assertTrue(authorized(role="admin", actor=12, chat=12,
                                   is_private=True, active_admin_ids={12}))
        for change in (
            {"role": "agent"}, {"actor": 13}, {"chat": 13},
            {"is_private": False}, {"active_admin_ids": set()},
        ):
            args = {"role": "admin", "actor": 12, "chat": 12,
                    "is_private": True, "active_admin_ids": {12}}
            args.update(change)
            self.assertFalse(authorized(**args))
        self.assertFalse(authorized(role="admin", actor=True, chat=True,
                                    is_private=True, active_admin_ids={True}))

    def test_denied_callback_never_reads_db(self):
        class Message:
            def __init__(self):
                self.messages = []
            async def reply_text(self, message):
                self.messages.append(message)
        class Query:
            def __init__(self):
                self.message = Message()
        q = Query()
        self.assertTrue(asyncio.run(handle_dashboard(
            q, data="apps_dpt_24", role="agent", actor=55, chat=55,
            is_private=True, active_admin_ids={55})))
        self.assertEqual(len(q.message.messages), 1)
        self.assertIn("خصوصی", q.message.messages[0])
        self.assertFalse(asyncio.run(handle_dashboard(
            q, data="apps_edge_quick_home", role="admin", actor=55, chat=55,
            is_private=True, active_admin_ids={55})))


if __name__ == "__main__":
    unittest.main()
