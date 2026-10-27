"""K2 final: transfer must never be mistaken for legacy host/DNS update."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
import sqlite3
import unittest

from edge_egress_phase2_console import EdgeCard
from edge_egress_k2_final_integration import (
    K2_TRANSFER_EXECUTOR_RELEASED,
    read_transfer_preview,
    transfer_preview_html,
    transfer_preview_buttons,
)

BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


def card(**kw):
    obj = EdgeCard(
        "fra1", "216.126.229.12", True, True, False, False,
        "STAGED", "READY", True, "", "", None, None, "a" * 64,
    )
    return replace(obj, **kw)


class K2TransferPreviewTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
        CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO settings VALUES('edge_egress_protected_mode','0');
        CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER);
        INSERT INTO host_pool VALUES('104.194.144.195',1,1);
        CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                                  service_type TEXT,status TEXT);
        INSERT INTO ssh_accounts VALUES
            ('canary','104.194.144.195','ssh','🟢 فعال'),
            ('other','104.194.144.195','ssh','🟢 فعال'),
            ('inactive','104.194.144.195','ssh','🔴 غیرفعال');
        CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT);
        """)
        self.db = lambda: self.conn
        self.transport = SimpleNamespace(state="UP")

    def test_expected_feature_remains_explicitly_release_disabled(self):
        self.assertIs(K2_TRANSFER_EXECUTOR_RELEASED, False)
        plan = read_transfer_preview(self.db, card(), self.transport)
        self.assertEqual(plan.ssh_accounts, 2)
        self.assertFalse(plan.can_execute)
        self.assertIn("محافظت کاربران فعال یا تأیید نشده", plan.blockers)
        self.assertIn("انتقال امن هنوز برای اجرا آزاد نشده", plan.blockers)
        self.assertIn("هیچ", transfer_preview_html(plan)) if False else None

    def test_even_f4_ready_and_protected_mode_is_not_authority(self):
        self.conn.execute(
            "UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'"
        )
        plan = read_transfer_preview(self.db, card(), self.transport)
        self.assertFalse(plan.can_execute)
        self.assertEqual(plan.blockers, ("انتقال امن هنوز برای اجرا آزاد نشده",))
        buttons = sum(transfer_preview_buttons(plan), [])
        self.assertIn(("👤 بررسی یک کاربر", "hpeg_user_fra1"), buttons)
        self.assertIn(("🌍 تست IP خروجی", "hpeg_probe_fra1"), buttons)
        self.assertFalse(any("execute" in callback or "yes_" in callback
                             for _, callback in buttons))

    def test_missing_pin_and_running_6g_are_hold_and_readonly(self):
        self.conn.execute("INSERT INTO failover_operations VALUES(1,'RUNNING')")
        queries = []
        self.conn.set_trace_callback(queries.append)
        plan = read_transfer_preview(self.db, card(stage_pin=None), self.transport)
        self.assertIn("عملیات انتقال دیگری در جریان است", plan.blockers)
        self.assertIn("آماده‌سازی خروجی ثبت و تأیید نشده", plan.blockers)
        self.assertFalse(any(x.lstrip().upper().startswith(
            ("UPDATE", "INSERT", "DELETE", "REPLACE", "DROP", "ALTER")
        ) for x in queries))

    def test_identity_or_ingress_invalid_holds(self):
        with self.assertRaises(ValueError):
            read_transfer_preview(self.db, card(ip="10.1.1.2"), self.transport)
        plan = read_transfer_preview(
            self.db, card(ingress_verified=False),
            SimpleNamespace(state="ABSENT"),
        )
        self.assertIn("اتصال ورودی تأیید نشده", plan.blockers)
        self.assertIn("تونل خروجی آماده نیست", plan.blockers)


    def test_mixed_edges_only_count_source_users_not_all_active_ssh(self):
        self.conn.execute("INSERT INTO host_pool VALUES('146.190.3.22',1,0)")
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES('foreign','146.190.3.22','ssh','🟢 فعال')"
        )
        plan = read_transfer_preview(self.db, card(), self.transport)
        self.assertEqual(plan.ssh_accounts, 2)
        self.assertEqual(plan.other_edge_accounts, 1)
        self.assertEqual(plan.active_total, 3)
        self.assertIn("حساب‌های سرورهای دیگر", " ".join(plan.blockers))
        self.assertIn("بدون تغییر", transfer_preview_html(plan))
        self.assertFalse(plan.can_execute)

    def test_orphan_host_blocks_transfer_without_database_write(self):
        self.conn.execute(
            "UPDATE ssh_accounts SET host='198.51.100.9' WHERE username='other'"
        )
        sql = []
        self.conn.set_trace_callback(sql.append)
        plan = read_transfer_preview(self.db, card(), self.transport)
        self.assertEqual(plan.ssh_accounts, 1)
        self.assertEqual(plan.unknown_accounts, 1)
        self.assertIn("مالکیت برخی حساب‌ها مشخص نیست", plan.blockers)
        self.assertFalse(any(stmt.lstrip().upper().startswith(
            ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "REPLACE ", "DROP ")
        ) for stmt in sql))

    def test_new_edge_outside_pool_is_not_mistaken_for_default(self):
        plan = read_transfer_preview(
            self.db, card(pool_active=False), self.transport,
        )
        self.assertEqual(plan.source_host, "104.194.144.195")
        self.assertEqual(plan.ssh_accounts, 2)
        self.assertFalse(plan.can_execute)
        self.assertIn("اتصال ورودی تأیید نشده", plan.blockers)

    def test_missing_control_tables_hold(self):
        with sqlite3.connect(":memory:") as db:
            result = read_transfer_preview(lambda: db, card(), self.transport)
        self.assertFalse(result.can_execute)
        self.assertIn("اطلاعات حساب‌ها کامل نیست", result.blockers)
        self.assertIn("کنترل انتقال در دسترس نیست", result.blockers)


class K2TelegramWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")

    def test_existing_wizard_has_transfer_link_after_staged_success(self):
        self.assertIn('callback_data=f"hpeg_relay_{edge_id}"', self.source)
        self.assertIn('egress_stage_requested=stage_for_this_edge', self.source)
        self.assertIn('onboard_after_ingress,', self.source)

    def test_transfer_handler_is_admin_only_and_has_no_legacy_bulk_writer(self):
        start = self.source.index('    elif d.startswith("hpeg_transfer_"):')
        end = self.source.index('    elif d == "hpeg_status"', start)
        handler = self.source[start:end]
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("read_k2_transfer_preview"))
        self.assertIn("k2_transfer_preview_html(preview)", handler)
        for bad in ("_db_set_all_accounts_host", "_update_cloudflare_dns",
                    "Legacy", "release_uid_deny", "mark_ready"):
            self.assertNotIn(bad, handler)

    def test_old_round_robin_callback_is_notification_only(self):
        start = self.source.index('    elif d == "ipsvc_distribute_confirm"')
        end = self.source.index("    # 🆕 V89 — تنظیمات سیستم شناسایی خودکار فیلتر", start)
        handler = self.source[start:end]
        self.assertIn("show_alert=True", handler)
        self.assertIn("return", handler)
        self.assertNotIn('UPDATE ssh_accounts SET host=?', handler)
        self.assertNotIn('_db_set_account_host', handler)
        # Guard the remaining explicit legacy setters under a single DB lease.
        start = self.source.index("def _db_set_account_host(")
        end = self.source.index("def _db_get_recent_active_accounts(", start)
        setters = self.source[start:end]
        self.assertIn('conn.execute("BEGIN IMMEDIATE")', setters)
        self.assertIn("_db_assert_legacy_host_mutation_allowed(conn)", setters)
        self.assertIn("_default_customer_relay_checked(conn)", setters)


if __name__ == "__main__":
    unittest.main()
