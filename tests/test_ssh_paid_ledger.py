"""Verified SSH wallet journal: synthetic SQLite, no OS or production access."""
import sqlite3
from datetime import date
from decimal import Decimal
import unittest

import nvl_daily_business
from ssh_paid_ledger import (
    SSHFinanceHold, apply_paid_change, create_paid_purchase,
    preview_delete, quote_time_reduction, record_hold_activation, install_schema,
)

TODAY = date(2026, 11, 18)


class PaidSSHJournalTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("""
          CREATE TABLE agents (
             id INTEGER PRIMARY KEY, balance REAL, base_price TEXT, emergency_used REAL
          );
          CREATE TABLE ssh_accounts (
             username TEXT PRIMARY KEY, agent_id INTEGER, creation_date TEXT,
             expire_date TEXT, users_limit INTEGER, status TEXT,
             hold_active INTEGER DEFAULT 0, hold_duration_days INTEGER,
             service_type TEXT
          );
          INSERT INTO agents VALUES (7, 100000, '30000', 0);
          INSERT INTO ssh_accounts VALUES (
             'sample',7,'2026-11-01','2026-12-01',2,'🟢 فعال',0,NULL,'ssh'
          );
        """)
        nvl_daily_business.install_schema(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def buy(self, amount=30000):
        with self.db:
            create_paid_purchase(
                self.db, username="sample", agent=7, amount=amount,
                created="2026-11-01", expiry="2026-12-01", users=2,
            )

    def change(self, *, kind, expiry="2026-12-01", new_expiry="2026-12-31",
               users=2, new_users=2, amount=30000, repay=None):
        with self.db:
            return apply_paid_change(
                self.db, username="sample", agent=7,
                expected_created="2026-11-01", expected_expiry=expiry,
                expected_users=users, expected_status="🟢 فعال",
                new_expiry=new_expiry, new_users=new_users, kind=kind,
                amount=amount, today=TODAY, repay_emergency=repay,
            )

    def quote(self):
        row = self.db.execute(
            "SELECT agent_id,creation_date,expire_date,users_limit,hold_active "
            "FROM ssh_accounts WHERE username='sample'",
        ).fetchone()
        return preview_delete(
            self.db, "sample", agent=row[0], created=row[1],
            expiry=row[2], users=row[3], hold=bool(row[4]), today=TODAY,
        )

    def test_legacy_ongoing_purchase_is_not_assumed_paid(self):
        with self.assertRaisesRegex(SSHFinanceHold, "HISTORICAL_PAYMENT_UNVERIFIED"):
            self.quote()
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],100000)
        self.assertFalse(self.db.execute("SELECT 1 FROM sqlite_master WHERE name='ssh_paid_accounts'").fetchone())

    def test_legacy_expired_account_has_zero_credit(self):
        self.db.execute("UPDATE ssh_accounts SET expire_date='2026-10-31'")
        self.db.commit()
        result = self.quote()
        self.assertEqual((result.amount, result.reason),(0,"EXPIRED_ZERO"))

    def test_first_purchase_is_linked_atomically_and_current_price_does_not_change_refund(self):
        self.buy()
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],70000)
        self.assertEqual(self.quote().amount,13000)
        self.db.execute("UPDATE agents SET base_price='900000' WHERE id=7")
        self.db.commit()
        self.assertEqual(self.quote().amount,13000)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ssh_paid_events").fetchone()[0],1)
        self.assertEqual(self.db.execute(
            "SELECT kind,amount_toman FROM ssh_paid_events"
        ).fetchone(),("PURCHASE","30000"))

    def test_duplicate_purchase_and_negative_funds_do_not_create_credit(self):
        self.buy()
        with self.assertRaisesRegex(SSHFinanceHold,"PAID_ACCOUNT_ALREADY_EXISTS"):
            self.buy()
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],70000)

    def test_insufficient_wallet_has_no_fake_paid_receipt(self):
        with self.assertRaisesRegex(SSHFinanceHold,"INSUFFICIENT_WALLET"):
            self.buy(amount=200000)
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],100000)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM nvl_business_events").fetchone()[0],0)
        self.assertFalse(self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='ssh_paid_accounts'"
        ).fetchone())

    def test_hidden_hold_activation_shifts_original_paid_period(self):
        self.buy()
        with self.db:
            self.db.execute(
                "UPDATE ssh_accounts SET hold_active=1 WHERE username='sample'"
            )
        self.assertEqual(self.quote().amount,30000)
        with self.db:
            self.db.execute(
                "UPDATE ssh_accounts SET expire_date='2026-12-04',hold_active=0 "
                "WHERE username='sample'"
            )
            record_hold_activation(
                self.db, username="sample",
                old_expiry="2026-12-01", new_expiry="2026-12-04",
                started_on=date(2026,11,4),
            )
        # 30 paid days shift forward 3; today's quote is 16/30.
        self.assertEqual(self.quote().amount,16000)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM ssh_paid_events WHERE kind='HOLD_ACTIVATE'"
        ).fetchone()[0],1)

    def test_extension_has_its_own_paid_interval_and_real_rate(self):
        self.buy()
        self.change(kind="EXTEND")
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],40000)
        self.assertEqual(self.quote().amount,43000)
        self.assertEqual(self.db.execute(
            "SELECT kind,amount_toman FROM ssh_paid_events ORDER BY id DESC LIMIT 1"
        ).fetchone(),("EXTEND","30000"))

    def test_time_reduction_quote_is_read_only_and_not_current_tariff(self):
        self.buy()
        self.change(kind="EXTEND")
        before = list(self.db.iterdump())
        result = quote_time_reduction(
            self.db, username="sample", agent=7, created="2026-11-01",
            expiry="2026-12-31", users=2,
            new_expiry="2026-12-21", today=TODAY,
        )
        self.assertEqual(result,10000)
        self.assertEqual(before,list(self.db.iterdump()))
        self.db.execute("UPDATE agents SET base_price='1000000'")
        self.db.commit()
        self.assertEqual(quote_time_reduction(
            self.db, username="sample", agent=7, created="2026-11-01",
            expiry="2026-12-31", users=2,
            new_expiry="2026-12-21", today=TODAY,
        ),10000)

    def test_time_reduction_refunds_only_removed_paid_entitlement(self):
        self.buy()
        self.change(kind="EXTEND")
        amount = self.change(
            kind="TIME_REDUCE",expiry="2026-12-31",
            new_expiry="2026-12-21",amount=0,
        )
        self.assertEqual(amount,10000)
        self.assertEqual(self.quote().amount,33000)
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],50000)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM nvl_business_events "
                                         "WHERE kind='PURCHASE_REFUND'").fetchone()[0],1)

    def test_seat_increase_records_extra_paid_interval(self):
        self.buy()
        self.change(kind="SEAT_INCREASE",new_expiry="2026-12-01",
                    new_users=3,amount=13000)
        self.assertEqual(self.quote().amount,26000)
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],57000)

    def test_seat_decrease_fails_closed_without_guessing_old_rates(self):
        self.buy()
        with self.assertRaisesRegex(SSHFinanceHold,"MANUAL_SEAT_REDUCTION_REQUIRED"):
            self.change(kind="SEAT_DECREASE",new_expiry="2026-12-01",
                        new_users=1,amount=15000)
        self.assertEqual(self.db.execute("SELECT users_limit FROM ssh_accounts").fetchone()[0],2)
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],70000)

    def test_admin_edit_invalidates_automatic_refunds(self):
        self.buy()
        self.change(kind="ADMIN_ADJUST",new_expiry="2026-12-11",amount=0)
        with self.assertRaisesRegex(SSHFinanceHold, "HISTORICAL_PAYMENT_UNVERIFIED"):
            self.quote()

    def test_legacy_extension_is_recorded_but_not_fake_certified(self):
        self.change(kind="EXTEND",amount=30000)
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],70000)
        with self.assertRaisesRegex(SSHFinanceHold, "HISTORICAL_PAYMENT_UNVERIFIED"):
            self.quote()

    def test_repeated_reduction_cannot_recredit_same_days(self):
        self.buy()
        self.change(kind="EXTEND")
        self.change(kind="TIME_REDUCE",expiry="2026-12-31",new_expiry="2026-12-21")
        self.change(kind="TIME_REDUCE",expiry="2026-12-21",new_expiry="2026-12-11")
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],60000)
        with self.assertRaisesRegex(SSHFinanceHold,"PAID_CHANGE_SNAPSHOT_CHANGED"):
            self.change(kind="TIME_REDUCE",expiry="2026-12-31",new_expiry="2026-12-21")
        self.assertEqual(self.db.execute("SELECT balance FROM agents").fetchone()[0],60000)


if __name__ == "__main__":
    unittest.main()
