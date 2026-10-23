"""K2 Phase 1: isolated Telegram Edge wizard must not select customer traffic."""
import sqlite3
import unittest
from pathlib import Path

from edge_egress_k2_phase1_wizard import (
    assert_isolated_new_edge_candidate, K2WizardHold,
    normalize_k2_customer_port,
)
from edge_egress_phase2_console import inspect_local_stage, EdgeCard


class IsolatedWizardGateTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','1');
            INSERT INTO settings VALUES('hosts','144.172.84.82');
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.82');
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER);
            INSERT INTO host_pool VALUES('144.172.84.82',1);
            CREATE TABLE failover_operations(id INTEGER,status TEXT);
            CREATE TABLE edge_egress_uid_bindings(username TEXT, status TEXT);
            INSERT INTO edge_egress_uid_bindings VALUES('protected_user','PROTECTED');
            CREATE TABLE edge_egress_allocations(
                edge_id TEXT, edge_public_ipv4 TEXT);
            CREATE TABLE edge_egress_f3_ingress_candidates(
                edge_ipv4 TEXT);
        """)
        self.database = lambda: self.conn

    def test_new_stage_allowed_in_mixed_protected_mode_without_writes(self):
        sql = []
        self.conn.set_trace_callback(sql.append)
        assert_isolated_new_edge_candidate(
            self.database, "172.86.105.68", 2222,
        )
        self.assertEqual(
            self.conn.execute("SELECT value FROM settings WHERE key='hosts'").fetchone(),
            ("144.172.84.82",),
        )
        self.assertEqual(self.conn.execute(
            "SELECT username,status FROM edge_egress_uid_bindings"
        ).fetchone(), ("protected_user", "PROTECTED"))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM host_pool").fetchone()[0], 1)
        self.assertFalse(any(line.lstrip().upper().startswith((
            "UPDATE ", "INSERT ", "DELETE ", "CREATE ", "ALTER ", "REPLACE ",
        )) for line in sql))

    def test_k2_telegram_port_normalized_before_both_admission_checks(self):
        # Telegram supplies a string, but the K2 gate and StagePin need an int.
        for raw, expected in (("2252", 2252), (2252, 2252),
                              ("1", 1), ("65535", 65535)):
            with self.subTest(raw=raw):
                normalized = normalize_k2_customer_port(raw)
                self.assertEqual(normalized, expected)
                self.assertIs(type(normalized), int)
                assert_isolated_new_edge_candidate(
                    self.database, "172.86.105.68", normalized,
                )

    def test_k2_port_normalization_fails_closed(self):
        for raw in ("", "0", 0, "65536", 65536, "22x", " 2252",
                    "2252 ", "+2252", "٢٢٥٢", True, False, 2252.0,
                    None, [], "999999999999999"):
            with self.subTest(raw=raw), self.assertRaisesRegex(
                    K2WizardHold, "INVALID_CUSTOMER_PORT"):
                normalize_k2_customer_port(raw)

    def test_running_6g_and_reused_host_hold(self):
        self.conn.execute(
            "INSERT INTO failover_operations VALUES(3,'RUNNING')")
        with self.assertRaisesRegex(K2WizardHold, "BUSY"):
            assert_isolated_new_edge_candidate(
                self.database, "172.86.105.68", 2222)
        self.conn.execute("DELETE FROM failover_operations")
        with self.assertRaisesRegex(K2WizardHold, "ALREADY_IN_HOST_POOL"):
            assert_isolated_new_edge_candidate(
                self.database, "144.172.84.82", 2222)

    def test_existing_allocation_or_candidate_holds(self):
        self.conn.execute(
            "INSERT INTO edge_egress_allocations VALUES('e8','172.86.105.68')")
        with self.assertRaisesRegex(K2WizardHold, "ALLOCATION_EXISTS"):
            assert_isolated_new_edge_candidate(
                self.database, "172.86.105.68", 2222)
        self.conn.execute("DELETE FROM edge_egress_allocations")
        self.conn.execute(
            "INSERT INTO edge_egress_f3_ingress_candidates VALUES('172.86.105.68')")
        with self.assertRaisesRegex(K2WizardHold, "INGRESS_ALREADY_REGISTERED"):
            assert_isolated_new_edge_candidate(
                self.database, "172.86.105.68", 2222)

    def test_invalid_ip_port_and_missing_control_schema_hold(self):
        for ip in ("127.0.0.1", "10.0.0.1", "172.86.105.068", "not-ip"):
            with self.subTest(ip=ip), self.assertRaises(K2WizardHold):
                assert_isolated_new_edge_candidate(self.database, ip, 2222)
        for port in (0, 65536, "22", True):
            with self.subTest(port=port), self.assertRaises(K2WizardHold):
                assert_isolated_new_edge_candidate(
                    self.database, "172.86.105.68", port)
        self.conn.execute("DROP TABLE failover_operations")
        with self.assertRaisesRegex(K2WizardHold, "SCHEMA_UNAVAILABLE"):
            assert_isolated_new_edge_candidate(
                self.database, "172.86.105.68", 2222)

    def test_stage_inspection_allows_ingress_registry_without_customer_activation(self):
        # Integrated Wizard writes no active Legacy host row. Only the
        # trustworthy Stage view should be available, not customer transfers.
        card = EdgeCard(
            edge_id="e8", ip="172.86.105.68", ingress_verified=True,
            pool_active=False, pool_default=False, dns_target=False,
            allocation="NOT_STAGED", f4_state="NO_EVIDENCE", f4_valid=False,
            witness="", observed_ip="", evidence_at=None, expires_at=None,
            stage_pin=None,
        )
        from unittest.mock import patch
        spec = type("Spec", (), {"edge_id":"e8", "edge_public_ipv4":"172.86.105.68"})()
        with patch("ops.edge_egress_v1_transport.stage_hash", return_value="a"*64), \
             patch("ops.edge_egress_v1_transport.pinned", return_value=(spec, "peer")), \
             patch("ops.edge_egress_v1_transport.observe", return_value="ABSENT"):
            status = inspect_local_stage(card, geteuid=lambda:0)
        self.assertEqual(status.stage_state, "LOCAL_UNATTESTED")
        self.assertEqual(status.tunnel_state, "ABSENT")

    def test_bot_new_wizard_isolated_and_legacy_unchanged(self):
        src = Path("bot_final_v49-2.py").read_text(encoding="utf-8")
        block = src.split("async def _provision_new_edge(", 1)[1].split(
            "# ============================================================================",1)[0]
        self.assertIn("if egress_stage_requested:", block)
        self.assertIn("assert_isolated_new_edge_candidate,", block)
        self.assertIn("protected_wizard=egress_stage_requested", block)
        # Legacy callers continue using the original no-kwargs signature; CZ-03
        # uses a separate inactive registration branch that cannot serve users.
        self.assertIn("if pool_active:\n            await asyncio.to_thread(_db_add_host_pool, edge_ip)", block)
        self.assertIn("await asyncio.to_thread(_db_add_host_pool, edge_ip, active=False)", block)
        self.assertIn("_db_add_host_pool, edge_ip", block)
        self.assertIn("legacy_new_edge_gate(", block)
        self.assertIn("if not protected_wizard:", src)
        self.assertIn("onboard_after_ingress,", block)
        # Regression: the real Telegram path supplies str("2252"). The K2
        # boundary must use one canonical int for pre/post gates and StagePin.
        self.assertIn(
            "k2_customer_port = normalize_k2_customer_port(customer_port)",
            block,
        )
        self.assertEqual(
            block.count("assert_isolated_new_edge_candidate, db_conn, edge_ip, k2_customer_port"),
            2,
        )
        self.assertIn(
            "customer_port=k2_customer_port if egress_stage_requested else 0,",
            block,
        )
        # Legacy's existing installer still receives the original input.
        self.assertIn(
            "_provision_new_edge_sync, edge_ip, root_password, customer_port, edge_name",
            block,
        )


if __name__ == "__main__":
    unittest.main()
