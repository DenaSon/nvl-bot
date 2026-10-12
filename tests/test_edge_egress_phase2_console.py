"""K2 Phase 2 Telegram UX: no database, route, SSH, DNS or PAM writes."""
import sqlite3
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_phase2_console import (
    read_dashboard, get_card, dashboard_html, detail_html, health_html,
    actions_html, transport_check, TransportCheck,
)
from edge_egress_v1_console import EgressConsoleHold
from edge_egress_v1_ingress import IngressHold

EDGE = "172.86.105.67"
CORE = "209.200.246.198"


class Phase2TelegramTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(":memory:")
        self.addCleanup(self.c.close)
        self.db = lambda: self.c
        self.c.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.76');
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
                                   is_default INTEGER);
            INSERT INTO host_pool VALUES('144.172.84.76',1,1);
            INSERT INTO host_pool VALUES('172.86.105.67',1,0);
            CREATE TABLE edge_egress_allocations(
                edge_id TEXT PRIMARY KEY,edge_public_ipv4 TEXT,status TEXT);
            CREATE TABLE edge_egress_readiness(
                edge_id TEXT PRIMARY KEY,edge_ipv4 TEXT,state TEXT,
                observed_ipv4 TEXT,witness TEXT,probed_at INTEGER,
                expires_at INTEGER,generation INTEGER,last_operation_id INTEGER);
        """)
        self.peer = SimpleNamespace(edge_id="e7", edge_ipv4=EDGE,
                                    ingress_ipv4="10.77.0.7",
                                    wg_public_key="test")
        self.clock = int(time.time())
        self.read = lambda **kw: read_dashboard(
            self.db, ingress_loader=lambda: (self.peer,),
            now=self.clock, **kw,
        )

    def test_ingress_only_e7_visible_without_egress_allocation(self):
        board = self.read()
        self.assertTrue(board.registry_trusted)
        self.assertEqual(board.total, 1)
        card = get_card(board, "e7")
        self.assertTrue(card.ingress_verified)
        self.assertTrue(card.pool_active)
        self.assertFalse(card.pool_default)
        self.assertFalse(card.dns_target)
        self.assertEqual(card.allocation, "NOT_STAGED")
        self.assertFalse(card.f4_valid)
        self.assertFalse(card.can_probe)
        self.assertIn(EDGE, dashboard_html(board))
        self.assertIn("پیش‌فرض", dashboard_html(board))
        self.assertIn("مقصد DNS", detail_html(card))
        self.assertIn("⏳", detail_html(card))
        with patch("ops.edge_egress_v1_transport.pinned",
                   side_effect=AssertionError("should not inspect unpinned")):
            self.assertEqual(transport_check(
                card, geteuid=lambda: 0, now=lambda: self.clock
            ).state, "ALLOCATION_NOT_READY")
        self.assertIn("HOLD", actions_html(
            card, TransportCheck("ALLOCATION_NOT_READY", self.clock)))

    def test_stage_and_valid_f4_do_not_allow_unpinned_action(self):
        self.c.execute(
            "INSERT INTO edge_egress_allocations VALUES(?,?,?)",
            ("e7", EDGE, "STAGED"),
        )
        self.c.execute(
            "INSERT INTO edge_egress_readiness VALUES"
            "(?,?,?,?,?,?,?,?,?)",
            ("e7", EDGE, "READY", EDGE,
             "F4_PRODUCTION_ACCEPTANCE", self.clock - 4,
             self.clock + 180, 1, 42),
        )
        card = get_card(self.read(), "e7")
        self.assertTrue(card.f4_valid)
        self.assertFalse(card.can_probe)
        self.assertEqual(
            transport_check(card, geteuid=lambda: 0).state,
            "STAGE_PIN_REQUIRED",
        )
        self.assertIn("HOLD", actions_html(
            card, TransportCheck("STAGE_PIN_REQUIRED", self.clock)))
        self.c.execute("INSERT INTO settings VALUES(?,?)",
                       ("edge_egress_v1_stage_sha256_e7", "a"*64))
        updated = get_card(self.read(), "e7")
        self.assertTrue(updated.can_probe)
        self.assertTrue(updated.f4_valid)
        with patch("ops.edge_egress_v1_transport.pinned",
                   return_value=(
                       SimpleNamespace(edge_id="e7",
                                       edge_public_ipv4=EDGE), "peer"
                   )) as pin, patch(
                       "ops.edge_egress_v1_transport.observe",
                       return_value="UP"
                   ) as observed:
            health = transport_check(
                updated, geteuid=lambda: 0,
                now=lambda: self.clock)
        self.assertEqual(health.state, "UP")
        self.assertTrue(pin.called)
        self.assertTrue(observed.called)
        self.assertIn("HOLD", actions_html(updated, health))
        self.assertIn("فقط تونل", health_html(updated, health))

    def test_expired_ready_or_wrong_edge_ip_is_not_f4(self):
        self.c.execute(
            "INSERT INTO edge_egress_allocations VALUES(?,?,?)",
            ("e7", EDGE, "STAGED"))
        self.c.execute(
            "INSERT INTO edge_egress_readiness VALUES(?,?,?,?,?,?,?,?,?)",
            ("e7", EDGE, "READY", EDGE, "F4_PRODUCTION_ACCEPTANCE",
             self.clock - 100, self.clock - 1, 1, 10))
        self.assertFalse(get_card(self.read(), "e7").f4_valid)
        self.c.execute("UPDATE edge_egress_readiness SET expires_at=?",
                       (self.clock+60,))
        self.assertTrue(get_card(self.read(), "e7").f4_valid)
        self.c.execute("UPDATE edge_egress_readiness SET edge_ipv4=?",
                       ("144.172.84.76",))
        self.assertFalse(get_card(self.read(), "e7").f4_valid)

    def test_foreign_allocation_conflict_never_shows_approved_ingress(self):
        self.c.execute(
            "INSERT INTO edge_egress_allocations VALUES(?,?,?)",
            ("e7", "144.172.84.72", "STAGED"))
        card = get_card(self.read(), "e7")
        self.assertFalse(card.ingress_verified)
        self.assertEqual(card.allocation, "STAGED")
        self.assertFalse(card.can_probe)
        self.assertIn("تأیید نشده", detail_html(card))

    def test_missing_untrusted_registry_does_not_invent_edge_identity(self):
        def fail():
            raise IngressHold("REGISTRY_UNAVAILABLE_OR_UNTRUSTED")
        out = read_dashboard(self.db, ingress_loader=fail,
                             now=self.clock)
        self.assertFalse(out.registry_trusted)
        self.assertFalse(out.cards)
        self.assertIn("قابل اعتماد نیست", dashboard_html(out))
        with self.assertRaisesRegex(EgressConsoleHold, "EDGE_NOT_IN_CURRENT_PAGE"):
            get_card(out, "e7")

    def test_host_pool_default_and_dns_divergence_never_sets_ready(self):
        board = self.read()
        self.assertEqual(board.default_ip, "144.172.84.76")
        self.assertEqual(board.dns_ip, "144.172.84.76")
        self.assertNotIn("یکسان نیستند", dashboard_html(board))
        self.c.execute("UPDATE settings SET value=?", (EDGE,))
        board = self.read()
        self.assertIn("یکسان نیستند", dashboard_html(board))
        self.assertTrue(get_card(board, "e7").dns_target)
        self.assertFalse(get_card(board, "e7").pool_default)

    def test_unpinned_health_does_not_open_external_process(self):
        board = self.read()
        card = get_card(board, "e7")
        with patch("subprocess.run", side_effect=AssertionError("network mutation")):
            result = transport_check(card, geteuid=lambda: 0)
        self.assertEqual(result.state, "ALLOCATION_NOT_READY")

    def test_untrusted_identity_and_readiness_block_while_preserving_html(self):
        # A registry peer is canonical, so the UI must not HTML-inject DB status.
        self.c.execute("INSERT INTO edge_egress_allocations VALUES(?,?,?)",
                       ("e7", EDGE, "<danger>"))
        card = get_card(self.read(), "e7")
        self.assertIn("&lt;danger&gt;", detail_html(card))
        self.assertNotIn("<danger>", detail_html(card))
        self.assertIn("فعال‌سازی", actions_html(
            card, TransportCheck("HOLD", self.clock)))


if __name__ == "__main__":
    unittest.main()
