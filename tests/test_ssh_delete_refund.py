"""Regression tests for the NVL SSH refund math and atomic deletion settlement."""
from datetime import date
import sqlite3
import unittest

import nvl_daily_business as business
from ssh_paid_ledger import create_paid_purchase, SSHFinanceHold
from ssh_refund_policy import calculate_ssh_refund
from ssh_delete_settlement import (
    finalize_ssh_delete, preflight_ssh_delete, SSHDeleteSettlementHold,
)


TODAY = date(2026, 11, 18)


def quote(users, remaining, *, price=100000, plan_days=60, hold=False, hold_days=None):
    return calculate_ssh_refund(
        monthly_price=price,
        users_limit=users,
        creation_date="2026-11-03",
        expire_date=date.fromordinal(TODAY.toordinal() + remaining),
        hold_active=hold,
        hold_duration_days=hold_days,
        today=TODAY,
    )


class SSHRefundMathTests(unittest.TestCase):
    def test_one_user_15_days_monthly_price(self):
        self.assertEqual(quote(1, 15).amount, 50000)

    def test_two_users_15_days_on_long_plan(self):
        self.assertEqual(quote(2, 15, plan_days=60).amount, 100000)

    def test_two_users_unused_60_day_hidden_hold(self):
        result = quote(2, 1, hold=True, hold_days=60)
        self.assertEqual((result.amount, result.days, result.reason),
                         (400000, 60, "HOLD_UNUSED"))

    def test_hidden_hold_missing_days_preserves_legacy_month(self):
        result = quote(2, 10, hold=True)
        self.assertEqual(result.amount, 200000)
        self.assertEqual(result.reason, "HOLD_LEGACY_30_DAY_FALLBACK")

    def test_expired_and_bad_values_never_refund(self):
        self.assertEqual(quote(2, -1).amount, 0)
        self.assertEqual(quote(0, 15).amount, 0)
        self.assertEqual(quote(2, 15, price="not a price").amount, 0)
        self.assertEqual(quote(2, 15, hold=True, hold_days=-3).amount, 0)


class SSHRefundSettlementTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript("""
            CREATE TABLE agents (
                id INTEGER PRIMARY KEY, balance REAL, base_price TEXT,
                emergency_used REAL
            );
            CREATE TABLE ssh_accounts (
                username TEXT PRIMARY KEY, agent_id INTEGER,
                expire_date TEXT, creation_date TEXT, users_limit INTEGER,
                status TEXT, hold_active INTEGER, hold_duration_days INTEGER,
                service_type TEXT
            );
            INSERT INTO agents VALUES (7, 250000, '100000', 15000);
            INSERT INTO ssh_accounts VALUES (
                'sample', 7, '2026-12-03', '2026-11-03', 2,
                '🟢 فعال', 0, NULL, 'ssh'
            );
        """)
        business.install_schema(self.conn)
        self.conn.commit()
        with self.conn:
            create_paid_purchase(
                self.conn, username="sample", agent=7, amount=200000,
                created="2026-11-03", expiry="2026-12-03", users=2,
            )

    def tearDown(self):
        self.conn.close()

    @staticmethod
    def repay(conn, agent_id, amount):
        conn.execute(
            "UPDATE agents SET emergency_used = MAX(0, emergency_used-?) WHERE id=?",
            (amount, agent_id),
        )

    def settle(self, *, expiry="2026-12-03", repay=None):
        return finalize_ssh_delete(
            self.conn, username="sample", expected_agent_id=7,
            expected_expiry=expiry, expected_created="2026-11-03",
            expected_users=2, expected_status="🟢 فعال",
            repay_emergency=repay or self.repay, today=TODAY,
        )

    def preflight(self):
        return preflight_ssh_delete(
            self.conn, username="sample", expected_agent_id=7,
            expected_expiry="2026-12-03", expected_created="2026-11-03",
            expected_users=2, expected_status="🟢 فعال", today=TODAY,
        )

    def test_preflight_is_read_only_and_quotes_expected_refund(self):
        before = list(self.conn.iterdump())
        agent, refund = self.preflight()
        self.assertEqual((agent, refund.amount, refund.days), (7, 100000, 15))
        self.assertEqual(before, list(self.conn.iterdump()))

    def test_preflight_ignores_current_tariff_changes(self):
        with self.conn:
            self.conn.execute("UPDATE agents SET base_price='invalid' WHERE id=7")
        agent, refund = self.preflight()
        self.assertEqual((agent, refund.amount), (7, 100000))

    def test_preflight_blocks_non_ssh_account_before_userdel(self):
        with self.conn:
            self.conn.execute("UPDATE ssh_accounts SET service_type='v2ray' WHERE username='sample'")
        with self.assertRaisesRegex(SSHDeleteSettlementHold, "ACCOUNT_SNAPSHOT_CHANGED"):
            self.preflight()

    def test_missing_agent_preflight_blocks_before_userdel(self):
        with self.conn:
            self.conn.execute("DELETE FROM agents WHERE id=7")
        with self.assertRaisesRegex(SSHDeleteSettlementHold, "OWNER_AGENT_MISSING"):
            self.preflight()
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM ssh_accounts").fetchone()[0], 1)

    def test_delete_credit_ledger_and_historical_debt_are_atomic(self):
        with self.conn:
            amount, repaid, reason, days = self.settle()
        self.assertEqual((amount, repaid, reason, days),
                         (100000, 15000, "PAID_UNUSED", 15))
        self.assertEqual(
            self.conn.execute("SELECT balance,emergency_used FROM agents WHERE id=7").fetchone(),
            (150000, 0),
        )
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ssh_accounts").fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT kind,amount_toman FROM nvl_business_events"
        ).fetchall(), [("PURCHASE", 200000), ("PURCHASE_REFUND", 100000)])

    def test_stale_double_callback_cannot_refund_twice(self):
        with self.conn:
            self.settle()
        with self.assertRaisesRegex(SSHDeleteSettlementHold, "ACCOUNT_ALREADY_DELETED"):
            with self.conn:
                self.settle()
        self.assertEqual(self.conn.execute("SELECT balance FROM agents").fetchone()[0], 150000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM nvl_business_events").fetchone()[0], 2)

    def test_stale_account_snapshot_blocks_settlement(self):
        with self.assertRaisesRegex(SSHDeleteSettlementHold, "ACCOUNT_SNAPSHOT_CHANGED"):
            with self.conn:
                self.settle(expiry="2027-01-01")
        self.assertEqual(self.conn.execute("SELECT balance FROM agents").fetchone()[0], 50000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ssh_accounts").fetchone()[0], 1)

    def test_credit_failure_rolls_back_account_delete(self):
        def fail_repay(*args):
            raise RuntimeError("repayment failed")
        with self.assertRaisesRegex(RuntimeError, "repayment failed"):
            with self.conn:
                self.settle(repay=fail_repay)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ssh_accounts").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT balance FROM agents").fetchone()[0], 50000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM nvl_business_events").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
