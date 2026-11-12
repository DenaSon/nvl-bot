"""NVL Daily Business Report accounting and delivery regressions."""
from datetime import datetime, timezone, timedelta
import sqlite3
import unittest

import nvl_daily_business as business

UTC = timezone.utc

def instant(y, m, d, h=0, minute=0):
    return datetime(y, m, d, h, minute, tzinfo=UTC)


class DailyBusinessTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE agents(id INTEGER PRIMARY KEY, balance REAL)")
        self.conn.execute("INSERT INTO agents VALUES(1, 2000)")
        self.conn.execute("INSERT INTO agents VALUES(2, 1000)")
        business.install_schema(self.conn, now=instant(2026, 11, 10))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_purchase_and_wallet_update_atomic(self):
        with self.assertRaises(RuntimeError):
            with self.conn:
                business.charge_purchase(self.conn, 1, 400)
                raise RuntimeError("rollback")
        self.assertEqual(self.conn.execute(
            "SELECT balance FROM agents WHERE id=1"
        ).fetchone()[0], 2000)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nvl_business_events"
        ).fetchone()[0], 0)
        with self.conn:
            business.charge_purchase(self.conn, 1, 400)
            business.refund_purchase(self.conn, 1, 100)
        self.assertEqual(self.conn.execute(
            "SELECT balance FROM agents WHERE id=1"
        ).fetchone()[0], 1700)
        r = business.summarize(self.conn, "2026-11-12",
                               now=instant(2026,11,13))
        # Real event timestamps in this test use system clock, so check ledger itself.
        self.assertEqual(self.conn.execute(
            "SELECT kind FROM nvl_business_events ORDER BY id"
        ).fetchall(), [("PURCHASE",), ("PURCHASE_REFUND",)])

    def test_bank_inflow_not_double_counted_and_partner_card_separated(self):
        at = instant(2026, 11, 12, 12)
        business.record_event(self.conn, kind="AGENT_CREATED", agent_id=2,
                              source_key="agent:2", now=at)
        business.record_event(self.conn, kind="BANK_TOPUP", agent_id=1,
                              amount=1200, source_key="receipt:91", now=at)
        business.record_event(self.conn, kind="BANK_TOPUP", agent_id=2,
                              amount=700, source_key="receipt:92",
                              card_owner_agent_id=1, now=at)
        business.record_event(self.conn, kind="MANUAL_TOPUP",
                              agent_id=1, amount=300, now=at)
        business.record_event(self.conn, kind="PURCHASE",
                              agent_id=1, amount=850, now=at)
        business.record_event(self.conn, kind="PURCHASE_REFUND",
                              agent_id=1, amount=50, now=at)
        data = business.summarize(self.conn, "2026-11-12")
        self.assertEqual(data["counts"]["AGENT_CREATED"], 1)
        self.assertEqual(data["buyers"], 1)
        self.assertEqual(data["topuppers"], 2)
        self.assertEqual(data["counts"]["PURCHASE"], 1)
        self.assertEqual(data["net_purchases"], 800)
        self.assertEqual(data["central_bank"], 1200)
        self.assertEqual(data["partner_bank"], 700)
        self.assertEqual(data["wallet_topups"], 2200)
        rendered = business.render_report(data, label="۲۱ آبان")
        self.assertIn("۱,۲۰۰", rendered.replace("1,200", "۱,۲۰۰"))
        self.assertIn("حساب مرکزی NVL", rendered)
        self.assertIn("۲۱ آبان", rendered)
        self.assertIn("خرید از کیف پول، دوباره", rendered)

    def test_receipt_idempotent(self):
        at = instant(2026, 11, 12, 12)
        opts = dict(kind="BANK_TOPUP", agent_id=1, amount=1000,
                    source_key="receipt:9", now=at)
        self.assertEqual(business.record_event(self.conn, **opts), 1)
        self.assertEqual(business.record_event(self.conn, **opts), 0)
        self.assertEqual(business.summarize(
            self.conn, "2026-11-12"
        )["central_bank"], 1000)

    def test_tehran_calendar_boundary(self):
        # 21:00 UTC on the 12th is 00:30 Tehran on the 13th.
        at = instant(2026, 11, 12, 21)
        business.record_event(self.conn, kind="BANK_TOPUP", agent_id=1,
                              amount=250, now=at)
        self.assertEqual(business.summarize(
            self.conn, "2026-11-12"
        )["central_bank"], 0)
        self.assertEqual(business.summarize(
            self.conn, "2026-11-13"
        )["central_bank"], 250)

    def test_no_cash_inflow_for_manual_credit_or_wallet_purchase(self):
        at = instant(2026, 11, 12, 10)
        business.record_event(self.conn, kind="MANUAL_TOPUP", agent_id=1,
                              amount=2000, now=at)
        business.record_event(self.conn, kind="PURCHASE", agent_id=1,
                              amount=1200, now=at)
        info = business.summarize(self.conn, "2026-11-12")
        self.assertEqual(info["central_bank"], 0)
        self.assertEqual(info["wallet_topups"], 2000)
        self.assertEqual(info["net_purchases"], 1200)

    def test_startup_partial_day_and_comparison(self):
        other = sqlite3.connect(":memory:")
        try:
            business.install_schema(other, now=instant(2026,11,12,17))
            info = business.summarize(other, "2026-11-12")
            self.assertTrue(info["partial"])
            self.assertIn("داده‌های ناقص", business.render_report(info))
            previous = business.summarize(other, "2026-11-11")
            self.assertNotIn("تغییر خالص خرید نسبت به دیروز",
                             business.render_report(info, previous=previous))
        finally:
            other.close()

    def test_claim_at_0005_tehran_once_and_no_auto_retry(self):
        # Started 10 Nov; report 10 Nov is first eligible after 11 Nov 00:05 Tehran.
        before = instant(2026,11,10,20,34) # 00:04 Tehran on 11th
        at = instant(2026,11,10,20,35)     # 00:05 Tehran on 11th
        self.assertIsNone(business.claim_due_day(self.conn, now=before))
        self.assertEqual(business.claim_due_day(self.conn, now=at), "2026-11-10")
        self.assertIsNone(business.claim_due_day(self.conn, now=at))
        business.finish_delivery(self.conn, "2026-11-10",
                                 error_kind="TimeoutError", now=at)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM nvl_business_report_deliveries"
        ).fetchone()[0], "UNCERTAIN")
        self.assertIsNone(business.claim_due_day(self.conn, now=at))

    def test_catch_up_previous_closed_days(self):
        clock = instant(2026, 11, 14, 1)
        days = [business.claim_due_day(self.conn, now=clock) for _ in range(4)]
        self.assertEqual(days[:3], ["2026-11-10", "2026-11-11", "2026-11-12"])
        self.assertEqual(days[3], "2026-11-13")
        self.assertIsNone(business.claim_due_day(self.conn, now=clock))

    def test_bad_values_rejected(self):
        with self.assertRaises(ValueError):
            business.record_event(self.conn, kind="BANK_TOPUP",
                                  amount=-2)
        with self.assertRaises(ValueError):
            business.record_event(self.conn, kind="WHATEVER",
                                  amount=2)
        with self.assertRaises(ValueError):
            business.claim_due_day(self.conn, send_time="99:99")


if __name__ == "__main__":
    unittest.main()
