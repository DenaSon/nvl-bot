"""Regression tests for opt-in NVL reseller expiry view (R1)."""
import sqlite3
import unittest
from datetime import date

from nvl_agent_lifecycle import PAGE_SIZE, list_expiring_accounts


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


if __name__ == "__main__":
    unittest.main()
