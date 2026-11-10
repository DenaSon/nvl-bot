"""Regression tests for opt-in NVL reseller expiry view (R1)."""
import sqlite3
import unittest
from datetime import date

from nvl_agent_lifecycle import (PAGE_SIZE, list_expiring_accounts, list_expired_accounts,
                                 select_low_volume_accounts, renewal_reminder)


class ExpiringAgentTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            "CREATE TABLE ssh_accounts (username TEXT PRIMARY KEY, agent_id INTEGER, "
            "service_type TEXT, status TEXT, hold_active INTEGER, "
            "customer_name TEXT, expire_date TEXT)"
        )
        self.today = date(2026, 11, 10)

    def tearDown(self):
        self.db.close()

    def add(self, username, owner=8, stype="ssh", status="🟢 فعال",
            hold=0, expires="2026-11-12"):
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, owner, stype, status, hold, "Customer " + username, expires),
        )

    def test_only_owned_active_timed_non_hold(self):
        self.add("today", expires="2026-11-10")
        self.add("three", stype="v2ray", expires="2026-11-13")
        self.add("too_far", expires="2026-11-14")
        self.add("already_expired", expires="2026-11-09")
        self.add("volume_only", stype="v2ray_vol")
        self.add("hold", hold=1)
        self.add("disabled", status="🔴 غیرفعال")
        self.add("foreign", owner=9)
        self.add("admin", owner=0)
        self.add("unlimited", expires="نامحدود")
        self.add("bad_date", expires="2026-11-12 INVALID")
        total, rows = list_expiring_accounts(self.db, 8, today=self.today)
        self.assertEqual(total, 2)
        self.assertEqual([r[0] for r in rows], ["today", "three"])

    def test_window_and_stable_paging(self):
        for i in range(PAGE_SIZE + 3):
            self.add(f"u{i:02d}", expires="2026-11-11")
        total, first = list_expiring_accounts(self.db, 8, days=1, today=self.today)
        count, second = list_expiring_accounts(self.db, 8, days=1, page=1, today=self.today)
        self.assertEqual((total, count), (13, 13))
        self.assertEqual((len(first), len(second)), (10, 3))
        self.assertTrue(set(first).isdisjoint(second))

    def test_invalid_ownership_and_range_are_denied(self):
        for args in ((0, 3, 0), (-1, 3, 0), (8, 100, 0), (8, 3, -1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                list_expiring_accounts(self.db, args[0], days=args[1],
                                       page=args[2], today=self.today)


    def test_expired_includes_disabled_but_excludes_unstarted_and_foreign(self):
        self.add("old", status="🔴 غیرفعال", expires="2026-11-08")
        self.add("older", expires="2026-10-08")
        self.add("today", expires="2026-11-10")
        self.add("held", hold=1, expires="2026-11-09")
        self.add("volume", stype="v2ray_vol", expires="2026-11-09")
        self.add("foreign", owner=11, expires="2026-11-09")
        self.add("invalid_calendar", expires="2026-02-30")
        total, rows = list_expired_accounts(self.db, 8, today=self.today)
        self.assertEqual(total, 2)
        self.assertEqual([r[0] for r in rows], ["old", "older"])


class LowVolumeTests(unittest.TestCase):
    def test_owner_intersection_and_active_usage(self):
        local = [("mine", "Customer", "🟢 فعال"),
                 ("locked", "Other", "🔴 غیرفعال")]
        remote = [
            {"username": "mine", "status": "active", "data_limit": 1000, "used_traffic": 950},
            {"username": "foreign", "status": "active", "data_limit": 1000, "used_traffic": 1000},
            {"username": "locked", "status": "active", "data_limit": 1000, "used_traffic": 1000},
            {"username": "unlimited", "status": "active", "data_limit": 0, "used_traffic": 1000},
        ]
        self.assertEqual(select_low_volume_accounts(local, remote),
                         [("mine", "Customer", 50, 1000)])

    def test_exhausted_traffic_is_visible_but_manual_disable_is_not(self):
        local = [("exhausted", "A", "🔴 غیرفعال"),
                 ("manual_off", "B", "🔴 غیرفعال")]
        remote = [
            {"username": "exhausted", "status": "limited", "data_limit": 1000,
             "used_traffic": 1000},
            {"username": "manual_off", "status": "active", "data_limit": 1000,
             "used_traffic": 950},
        ]
        self.assertEqual(select_low_volume_accounts(local, remote),
                         [("exhausted", "A", 0, 1000)])

    def test_missing_api_usage_cannot_invent_low_volume(self):
        self.assertEqual(select_low_volume_accounts(
            [("u", "", "🟢 فعال")],
            [{"username": "u", "status": "active", "data_limit": 1000}],
        ), [])
        with self.assertRaises(ValueError):
            select_low_volume_accounts([("u", "", "🟢 فعال")], None)

    def test_manual_reminder_never_sends_or_exposes_credentials(self):
        message = renewal_reminder("account01", "2026-11-12",
                                   today=date(2026, 11, 10))
        self.assertIn("۲", message.replace("2", "۲"))  # remaining days
        self.assertIn("account01", message)
        self.assertNotIn("password", message)
        self.assertIn("به پایان رسیده", renewal_reminder(
            "account01", "2026-11-09", today=date(2026, 11, 10)))


if __name__ == "__main__":
    unittest.main()
