"""No new emergency borrowing, even from concurrent/stale wallet charge paths."""
import sqlite3
import unittest

import nvl_daily_business as business


class EmergencyWalletGuardTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE agents(id INTEGER PRIMARY KEY, balance REAL)")
        self.db.execute("INSERT INTO agents(id,balance) VALUES (1,100)")
        business.install_schema(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_overdraw_rejected_without_balance_or_ledger_mutation(self):
        with self.assertRaisesRegex(ValueError, "insufficient wallet"):
            with self.db:
                business.charge_purchase(self.db, 1, 101)
        self.assertEqual(self.db.execute("SELECT balance FROM agents WHERE id=1").fetchone()[0], 100)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM nvl_business_events").fetchone()[0], 0)

    def test_purchase_at_exact_balance_is_allowed(self):
        with self.db:
            business.charge_purchase(self.db, 1, 100)
        self.assertEqual(self.db.execute("SELECT balance FROM agents WHERE id=1").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT kind FROM nvl_business_events").fetchone()[0], "PURCHASE")

    def test_second_purchase_cannot_overdraw_already_spent_balance(self):
        with self.db:
            business.charge_purchase(self.db, 1, 75)
        with self.assertRaises(ValueError):
            with self.db:
                business.charge_purchase(self.db, 1, 50)
        self.assertEqual(self.db.execute("SELECT balance FROM agents WHERE id=1").fetchone()[0], 25)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM nvl_business_events").fetchone()[0], 1)

    def test_negative_purchase_amount_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid purchase amount"):
            with self.db:
                business.charge_purchase(self.db, 1, -50)
        self.assertEqual(self.db.execute("SELECT balance FROM agents WHERE id=1").fetchone()[0], 100)


if __name__ == "__main__":
    unittest.main()
