"""Focused regressions for the legacy Core/Edge dashboard and safe metadata delete."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

import server_role_panel as panel

CORE = "91.107.170.239"
RELAY = "45.59.114.76"
OTHER = "153.75.95.142"
OLD = "104.194.143.83"


class ServerRolePanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "panel.sqlite"
        with self.db_conn() as c:
            c.executescript("""
                CREATE TABLE host_pool(host TEXT PRIMARY KEY, active INTEGER,
                                      is_default INTEGER);
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY, host TEXT);
                CREATE TABLE domains(domain TEXT, host TEXT);
                CREATE TABLE failover_operations(source_host TEXT, target_host TEXT,
                                                 finished_at TEXT);
                CREATE TABLE filter_incidents(source_host TEXT, target_host TEXT,
                                              closed_at TEXT);
                CREATE TABLE edge_egress_allocations(edge_id TEXT, edge_public_ipv4 TEXT);
            """)
            c.executemany(
                "INSERT INTO host_pool VALUES(?,?,?)",
                [(CORE, 1, 0), (RELAY, 1, 1), (OTHER, 1, 0), (OLD, 0, 0)],
            )
            c.executemany(
                "INSERT INTO settings VALUES(?,?)",
                [("dns_current_ip", RELAY), ("hosts", f"{RELAY},{OTHER}")],
            )
        self.reg = patch.object(panel, "_registry_blocker", return_value=None)
        self.reg.start()
        self.addCleanup(self.reg.stop)

    @contextmanager
    def db_conn(self):
        con = sqlite3.connect(self.db)
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def pool(self):
        with self.db_conn() as conn:
            return conn.execute(
                "SELECT host,active,0,0,0,0,0,is_default FROM host_pool"
            ).fetchall()

    def test_dns_and_default_mismatch_never_show_two_selected_relays(self):
        selected, warning = panel.relay_selection(self.pool(), CORE, OTHER)
        self.assertEqual(selected, RELAY)
        self.assertIn("متفاوت", warning)
        text, kb = panel.overview(CORE, self.pool(), OTHER)
        self.assertEqual(text.count("رله منتخب:"), 1)
        relay_button = next(b[0][0] for b in kb if b[0][1] == "srv_view_" + RELAY)
        other_button = next(b[0][0] for b in kb if b[0][1] == "srv_view_" + OTHER)
        self.assertIn("🎯", relay_button)
        self.assertNotIn("🎯", other_button)

    def test_conflicting_default_flags_are_explicitly_ambiguous(self):
        with self.db_conn() as conn:
            conn.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (OTHER,))
        selected, warning = panel.relay_selection(self.pool(), CORE, RELAY)
        self.assertIsNone(selected)
        self.assertIn("چند سرور", warning)

    def test_detail_keeps_legacy_callbacks_and_offers_delete_only_when_inactive(self):
        _, buttons = panel.detail(CORE, OLD, self.pool(), RELAY, 2252, 22)
        callbacks = [cb for row in buttons for _, cb in row]
        self.assertIn("srv_del_" + OLD, callbacks)
        self.assertIn("srv_promote_" + OLD, callbacks)
        self.assertIn("srv_update_ep_" + OLD, callbacks)
        self.assertIn("srv_optimize_" + OLD, callbacks)
        self.assertIn("srv_installkey_" + OLD, callbacks)
        _, active_buttons = panel.detail(CORE, RELAY, self.pool(), RELAY, 2252, 22)
        self.assertNotIn("srv_del_" + RELAY, [cb for row in active_buttons for _, cb in row])
        _, core_buttons = panel.detail(CORE, CORE, self.pool(), RELAY, 2252, 22)
        self.assertIn("srv_demote_" + CORE, [cb for row in core_buttons for _, cb in row])
        self.assertNotIn("srv_del_" + CORE, [cb for row in core_buttons for _, cb in row])

    def test_overview_pagination_is_bounded(self):
        for n in range(10, 21):
            with self.db_conn() as conn:
                conn.execute(
                    "INSERT INTO host_pool VALUES(?,0,0)", (f"104.194.143.{n}",)
                )
        _, buttons = panel.overview(CORE, self.pool(), RELAY, 999)
        self.assertTrue(any(cb == "srv_page_0" or cb.startswith("srv_page_")
                            for row in buttons for _, cb in row))
        self.assertLessEqual(
            sum(any(cb.startswith("srv_view_") for _, cb in row) for row in buttons),
            panel.PAGE_SIZE + 1,
        )

    def test_inactive_record_can_be_removed_without_mutating_settings_or_users(self):
        ok, _ = panel.deletion_preview(self.db_conn, OLD, CORE)
        self.assertTrue(ok)
        ok, message = panel.delete_inactive(self.db_conn, OLD, CORE)
        self.assertTrue(ok, message)
        with self.db_conn() as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM host_pool WHERE host=?", (OLD,)
            ).fetchone())
            self.assertEqual(conn.execute(
                "SELECT value FROM settings WHERE key='hosts'"
            ).fetchone()[0], f"{RELAY},{OTHER}")
            self.assertEqual(conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()[0], RELAY)
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])

    def test_default_core_active_and_serving_hosts_are_protected(self):
        for host in (CORE, RELAY, OTHER):
            self.assertFalse(panel.delete_inactive(self.db_conn, host, CORE)[0])
        with self.db_conn() as conn:
            conn.execute("UPDATE host_pool SET active=0 WHERE host=?", (OTHER,))
        ok, reason = panel.deletion_preview(self.db_conn, OTHER, CORE)
        self.assertFalse(ok)
        self.assertIn("hosts", reason)
        with self.db_conn() as conn:
            conn.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (OLD,))
        ok, reason = panel.delete_inactive(self.db_conn, OLD, CORE)
        self.assertFalse(ok)
        self.assertIn("پیش‌فرض", reason)

    def test_bound_ssh_user_and_protected_allocation_block_delete(self):
        with self.db_conn() as conn:
            conn.execute("INSERT INTO ssh_accounts VALUES('alice',?)", (OLD,))
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as conn:
            conn.execute("DELETE FROM ssh_accounts")
            conn.execute("INSERT INTO edge_egress_allocations VALUES('e9',?)", (OLD,))
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])

    def test_open_failover_and_incident_block_delete(self):
        with self.db_conn() as conn:
            conn.execute("INSERT INTO failover_operations VALUES(?,NULL,NULL)", (OLD,))
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as conn:
            conn.execute("DELETE FROM failover_operations")
            conn.execute("INSERT INTO filter_incidents VALUES(NULL,?,NULL)", (OLD,))
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])

    def test_cannot_delete_when_registry_blocks(self):
        with patch.object(panel, "_registry_blocker", return_value="registered"):
            ok, message = panel.delete_inactive(self.db_conn, OLD, CORE)
            self.assertFalse(ok)
            self.assertEqual(message, "registered")

    def test_rechecks_conditions_after_preview_and_legacy_protection(self):
        self.assertTrue(panel.deletion_preview(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as conn:
            conn.execute("UPDATE host_pool SET active=1 WHERE host=?", (OLD,))
        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as conn:
            conn.execute("UPDATE host_pool SET active=0 WHERE host=?", (OLD,))

        def deny(_conn):
            raise RuntimeError("PROTECTED_MODE")

        self.assertFalse(panel.delete_inactive(self.db_conn, OLD, CORE, deny)[0])
        with self.db_conn() as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM host_pool WHERE host=?", (OLD,)
            ).fetchone())


    def prepare_real_retirement_schema(self):
        with self.db_conn() as db:
            db.execute("ALTER TABLE host_pool ADD COLUMN is_standby INTEGER DEFAULT 0")
            db.execute("ALTER TABLE ssh_accounts ADD COLUMN status TEXT")
            db.execute("ALTER TABLE ssh_accounts ADD COLUMN service_type TEXT")
            db.execute("DROP TABLE filter_incidents")
            db.execute("""CREATE TABLE filter_incidents (
                id INTEGER PRIMARY KEY,incident_id TEXT,source_host TEXT,
                target_host TEXT,state TEXT,last_reason TEXT,
                opened_at TEXT,updated_at TEXT,closed_at TEXT
            )""")
            db.execute("""CREATE TABLE filter_incident_events (
                id INTEGER PRIMARY KEY,incident_id TEXT,event_type TEXT,state TEXT,
                reason_code TEXT,source_host TEXT,target_host TEXT,
                detail_json TEXT,created_at TEXT
            )""")

    def test_probe_history_is_archived_before_cascading_host_delete(self):
        with self.db_conn() as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("""CREATE TABLE host_probe_results(
                id INTEGER PRIMARY KEY,host TEXT NOT NULL,probe_type TEXT NOT NULL,
                source TEXT NOT NULL,ok INTEGER,latency_ms REAL,reason TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY(host) REFERENCES host_pool(host) ON DELETE CASCADE
            )""")
            db.execute(
                "INSERT INTO host_probe_results VALUES(1,?,'service','core',0,"
                "NULL,'TIMEOUT','2026-01-01')", (OLD,)
            )
        self.assertTrue(panel.delete_inactive(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as db:
            self.assertEqual(
                db.execute("SELECT host,probe_type,reason "
                           "FROM host_probe_archive WHERE original_id=1").fetchone(),
                (OLD, "service", "TIMEOUT")
            )

    def test_stale_open_incident_is_closed_with_audit_before_metadata_delete(self):
        self.prepare_real_retirement_schema()
        with self.db_conn() as db:
            db.execute(
                "INSERT INTO filter_incidents VALUES "
                "(1,'INC-OLD',?,NULL,'CONFIRMING','REGIONAL_SUSPECTED',"
                "'2026-01-01','2026-01-01',NULL)", (OLD,)
            )
        ok, why = panel.deletion_preview(self.db_conn, OLD, CORE)
        self.assertFalse(ok)
        self.assertIn("رخداد باز", why)
        ready, report = panel.dependency_report(self.db_conn, OLD, CORE)
        self.assertTrue(ready, report)
        self.assertIn("INC-OLD", report)
        ok, message = panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101
        )
        self.assertTrue(ok, message)
        with self.db_conn() as db:
            state = db.execute(
                "SELECT state,last_reason,closed_at FROM filter_incidents"
            ).fetchone()
            self.assertEqual(state[:2], ("RETIRED", "HOST_RETIRED_BY_OPERATOR"))
            self.assertIsNotNone(state[2])
            evt = db.execute(
                "SELECT incident_id,event_type,state,reason_code FROM filter_incident_events"
            ).fetchone()
            self.assertEqual(evt, ("INC-OLD", "HOST_RETIRED", "RETIRED",
                                   "HOST_RETIRED_BY_OPERATOR"))
            audit = db.execute(
                "SELECT host,actor_id,account_count,incident_count "
                "FROM host_retirement_audit"
            ).fetchone()
            self.assertEqual(audit, (OLD, 101, 0, 1))
        self.assertTrue(panel.delete_inactive(self.db_conn, OLD, CORE)[0])

    def test_detach_inactive_ssh_and_independent_marzban_without_deleting_accounts(self):
        self.prepare_real_retirement_schema()
        with self.db_conn() as db:
            db.executemany(
                "INSERT INTO ssh_accounts(username,host,status,service_type) VALUES (?,?,?,?)",
                [
                    ("inactive-ssh", OLD, "🔴 غیرفعال", "ssh"),
                    ("remote-v2", OLD, "🟢 فعال", "v2ray"),
                    ("remote-v2-vol", OLD, "🟢 فعال", "v2ray_vol"),
                ]
            )
        self.assertFalse(panel.deletion_preview(self.db_conn, OLD, CORE)[0])
        ready, report = panel.dependency_report(self.db_conn, OLD, CORE)
        self.assertTrue(ready, report)
        self.assertIn("حساب SSH غیرفعال", report)
        self.assertIn("حساب مستقل Marzban", report)
        ok, message = panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101
        )
        self.assertTrue(ok, message)
        with self.db_conn() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE host IS NULL"
            ).fetchone()[0], 3)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM host_retirement_account_audit"
            ).fetchone()[0], 3)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM ssh_accounts"
            ).fetchone()[0], 3)
        self.assertTrue(panel.delete_inactive(self.db_conn, OLD, CORE)[0])

    def test_retirement_blocks_active_ssh_and_unknown_types(self):
        self.prepare_real_retirement_schema()
        with self.db_conn() as db:
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?,?)",
                       ("active-ssh", OLD, "🟢 فعال", "ssh"))
        self.assertFalse(panel.dependency_report(self.db_conn, OLD, CORE)[0])
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])
        with self.db_conn() as db:
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='active-ssh'"
            ).fetchone()[0], OLD)
            db.execute(
                "UPDATE ssh_accounts SET status='🔴 غیرفعال',service_type=NULL"
            )
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])

    def test_retirement_rejects_operational_incident_and_active_failover(self):
        self.prepare_real_retirement_schema()
        with self.db_conn() as db:
            db.execute(
                "INSERT INTO filter_incidents VALUES "
                "(1,'INC-BLOCK',?,NULL,'FAILOVER_STARTED','STARTED',"
                "'2026-01-01','2026-01-01',NULL)", (OLD,)
            )
        self.assertFalse(panel.dependency_report(self.db_conn, OLD, CORE)[0])
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])
        with self.db_conn() as db:
            db.execute(
                "UPDATE filter_incidents SET state='SUSPECTED' WHERE id=1"
            )
            db.execute(
                "INSERT INTO failover_operations VALUES(?,NULL,NULL)", (OLD,)
            )
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])
        with self.db_conn() as db:
            self.assertIsNone(db.execute(
                "SELECT closed_at FROM filter_incidents"
            ).fetchone()[0])

    def test_retirement_rechecks_route_role_and_egress_at_commit(self):
        self.prepare_real_retirement_schema()
        with self.db_conn() as db:
            db.execute(
                "INSERT INTO filter_incidents VALUES "
                "(1,'INC-OLD',?,NULL,'SUSPECTED','REGIONAL_SUSPECTED',"
                "'2026-01-01','2026-01-01',NULL)", (OLD,)
            )
        self.assertTrue(panel.dependency_report(self.db_conn, OLD, CORE)[0])
        with self.db_conn() as db:
            db.execute(
                "UPDATE host_pool SET is_standby=1 WHERE host=?", (OLD,)
            )
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])
        with self.db_conn() as db:
            db.execute(
                "UPDATE host_pool SET is_standby=0 WHERE host=?", (OLD,)
            )
            db.execute(
                "INSERT INTO edge_egress_allocations VALUES('edge-staged',?)",
                (OLD,)
            )
        self.assertFalse(panel.retire_inactive_dependencies(
            self.db_conn, OLD, CORE, actor=101)[0])

    def test_malformed_ip_never_approves_delete(self):
        for bad in ("127.0.0.1", "0.0.0.0", "1.2.3.4;DROP", "8.8.8.08", ""):
            self.assertFalse(panel.deletion_preview(self.db_conn, bad, CORE)[0])
            self.assertFalse(panel.delete_inactive(self.db_conn, bad, CORE)[0])


if __name__ == "__main__":
    unittest.main()
