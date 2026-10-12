"""Small K2 Telegram Egress UI contracts; no Production/network writes."""
import sqlite3
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_status import EgressStatus, EgressRow
from edge_egress_v1_console import (
    edge_id_checked, read_edge_detail, overview_html, detail_html,
    instructions_html, live_ip_probe, probe_html, EgressConsoleHold,
)

IP = "144.172.84.82"


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.db = lambda: self.conn
        self.conn.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE edge_egress_allocations(
                edge_id TEXT PRIMARY KEY,edge_public_ipv4 TEXT,status TEXT
            );
            INSERT INTO edge_egress_allocations VALUES('e9','144.172.84.82','STAGED');
            CREATE TABLE edge_egress_readiness(
                edge_id TEXT PRIMARY KEY,edge_ipv4 TEXT,state TEXT,
                observed_ipv4 TEXT,witness TEXT,probed_at INTEGER,
                expires_at INTEGER,generation INTEGER,last_operation_id INTEGER
            );
        """)

    def test_clean_overview_has_navigation_but_no_ready_claim(self):
        state = EgressStatus("0", True, (EgressRow("e9", IP, "STAGED"),), 1)
        html = overview_html(state)
        self.assertIn("e9", html)
        self.assertIn("K2", html)
        self.assertNotIn("READY ✅", html)
        self.assertIn("Ingress", instructions_html())

    def test_missing_evidence_is_held_not_ready(self):
        detail = read_edge_detail(self.db, "e9")
        self.assertFalse(detail.ready_for_protected)
        self.assertFalse(detail.stage_pin_present)
        self.assertEqual(detail.readiness, "NO_EVIDENCE")
        self.assertIn("تأیید نشده", detail_html(detail))
        with self.assertRaisesRegex(EgressConsoleHold, "STAGE_PIN_NOT_ATTESTED"):
            live_ip_probe(self.db, "e9", geteuid=lambda: 0)

    def test_readiness_is_not_implied_by_stage_or_expired_f4(self):
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO edge_egress_readiness VALUES"
            "('e9',?,'READY',?,'F4_PRODUCTION_ACCEPTANCE',?,?,1,42)",
            (IP, IP, now-180, now-1),
        )
        self.assertFalse(read_edge_detail(self.db, "e9").ready_for_protected)
        self.conn.execute("UPDATE edge_egress_readiness SET expires_at=?",
                          (now+200,))
        self.assertTrue(read_edge_detail(self.db, "e9").ready_for_protected)
        self.conn.execute("UPDATE edge_egress_readiness SET witness='PINNED_SHADOW_NAMESPACE'")
        self.assertFalse(read_edge_detail(self.db, "e9").ready_for_protected)

    def test_probe_uses_only_pinned_existing_netns_and_compares_ipv4(self):
        self.conn.execute("INSERT INTO settings VALUES(?,?)",
                          ("edge_egress_v1_stage_sha256_e9", "a"*64))
        spec = SimpleNamespace(edge_id="e9", edge_public_ipv4=IP,
                               namespace="nvl-egress-e9")
        called = []
        def command(argv, **kwargs):
            called.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout="fl=7a9\nip="+IP+"\n")
        with patch("ops.edge_egress_v1_transport.pinned",
                   return_value=(spec, "peer")), patch(
                       "ops.edge_egress_v1_transport.observe", return_value="UP"
                   ):
            result = live_ip_probe(self.db, "e9", run=command,
                                   geteuid=lambda: 0)
        self.assertTrue(result.matches)
        self.assertIn("برابر", probe_html(result))
        argv = called[0][0]
        self.assertEqual(argv[:4],
                         ("ip", "netns", "exec", "nvl-egress-e9"))
        self.assertIn("--resolve", argv)
        self.assertNotIn("ensure", argv)
        self.assertNotIn("iptables", argv)

    def test_mismatch_is_denied_and_partial_transport_never_probed(self):
        self.conn.execute("INSERT INTO settings VALUES(?,?)",
                          ("edge_egress_v1_stage_sha256_e9", "a"*64))
        spec = SimpleNamespace(edge_id="e9", edge_public_ipv4=IP,
                               namespace="nvl-egress-e9")
        def run(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout="ip=144.172.84.76\n")
        with patch("ops.edge_egress_v1_transport.pinned",
                   return_value=(spec, "peer")), patch(
                       "ops.edge_egress_v1_transport.observe", return_value="UP"
                   ):
            self.assertFalse(live_ip_probe(
                self.db, "e9", run=run, geteuid=lambda: 0
            ).matches)
        with patch("ops.edge_egress_v1_transport.pinned",
                   return_value=(spec, "peer")), patch(
                       "ops.edge_egress_v1_transport.observe", return_value="ABSENT"
                   ):
            with self.assertRaisesRegex(EgressConsoleHold, "DEDICATED_TRANSPORT_NOT_RUNNING"):
                live_ip_probe(
                    self.db, "e9",
                    run=lambda *a, **kw: self.fail("Probe must not be invoked"),
                    geteuid=lambda: 0,
                )

    def test_forged_edge_id_or_unregistered_edge_cannot_probe(self):
        for identity in ("../../etc/passwd", "", "e9;rm", "x"*80):
            with self.subTest(identity=identity), self.assertRaises(EgressConsoleHold):
                edge_id_checked(identity)
        self.assertIsNone(read_edge_detail(self.db, "e10"))
        with self.assertRaisesRegex(EgressConsoleHold, "EDGE_NOT_REGISTERED"):
            live_ip_probe(self.db, "e10", geteuid=lambda: 0)


if __name__ == "__main__":
    unittest.main()
