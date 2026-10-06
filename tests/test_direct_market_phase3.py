import sqlite3
import unittest
from pathlib import Path

import market_commerce
import market_wallet


class DirectMarketWalletPhase3Tests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(
            """
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE ssh_accounts (
                username TEXT PRIMARY KEY,
                agent_id INTEGER DEFAULT 0
            );
            """
        )
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id, username, first_name) "
            "VALUES (101, 101, 'buyer', 'Buyer')"
        )
        self.customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=101"
        ).fetchone()[0]
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_phase3_schema_is_additive_and_versioned(self):
        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertIn("customer_topup_receipts", tables)
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_schema_version'"
            ).fetchone()[0],
            str(market_commerce.DIRECT_MARKET_SCHEMA_VERSION),
        )

    def test_wallet_is_created_lazily_with_zero_balance(self):
        snapshot = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(snapshot["balance_toman"], 0)
        self.assertEqual(snapshot["reserved_toman"], 0)
        self.assertEqual(snapshot["available_toman"], 0)

    def test_topup_receipt_creation_is_idempotent(self):
        first = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=250000,
            photo_id="photo-1",
            idempotency_key="telegram-update-1",
        )
        second = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=250000,
            photo_id="photo-1",
            idempotency_key="telegram-update-1",
        )
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM customer_topup_receipts"
            ).fetchone()[0],
            1,
        )

    def test_topup_idempotency_collision_fails_closed(self):
        market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=250000,
            photo_id="photo-1",
            idempotency_key="same-key",
        )
        with self.assertRaises(ValueError):
            market_wallet.create_topup_receipt(
                self.conn,
                customer_id=self.customer_id,
                amount_toman=350000,
                photo_id="photo-2",
                idempotency_key="same-key",
            )

    def test_approval_atomically_credits_wallet_and_ledger(self):
        receipt = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=300000,
            photo_id="photo-2",
            idempotency_key="telegram-update-2",
        )
        self.conn.commit()

        result = market_wallet.approve_topup_receipt(
            self.conn,
            receipt_id=receipt["id"],
            reviewer_chat_id=999,
        )

        self.assertEqual(result["outcome"], "approved")
        self.assertEqual(result["wallet"]["balance_toman"], 300000)
        row = self.conn.execute(
            "SELECT kind, amount_toman, balance_after_toman, reference_type, reference_id "
            "FROM wallet_transactions"
        ).fetchone()
        self.assertEqual(
            row,
            ("topup", 300000, 300000, "customer_topup_receipt", str(receipt["id"])),
        )
        receipt_row = self.conn.execute(
            "SELECT status, wallet_transaction_id, reviewed_by_chat_id "
            "FROM customer_topup_receipts WHERE id=?",
            (receipt["id"],),
        ).fetchone()
        self.assertEqual(receipt_row[0], "approved")
        self.assertIsNotNone(receipt_row[1])
        self.assertEqual(receipt_row[2], 999)

    def test_duplicate_approval_never_double_credits(self):
        receipt = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=400000,
            photo_id="photo-3",
            idempotency_key="telegram-update-3",
        )
        self.conn.commit()

        first = market_wallet.approve_topup_receipt(
            self.conn, receipt_id=receipt["id"], reviewer_chat_id=1
        )
        second = market_wallet.approve_topup_receipt(
            self.conn, receipt_id=receipt["id"], reviewer_chat_id=2
        )

        self.assertEqual(first["outcome"], "approved")
        self.assertEqual(second["outcome"], "already_approved")
        self.assertEqual(
            market_wallet.get_wallet_snapshot(self.conn, self.customer_id)["balance_toman"],
            400000,
        )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM wallet_transactions").fetchone()[0],
            1,
        )

    def test_rejected_receipt_cannot_later_be_approved(self):
        receipt = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=150000,
            photo_id="photo-4",
            idempotency_key="telegram-update-4",
        )
        self.conn.commit()
        rejected = market_wallet.reject_topup_receipt(
            self.conn, receipt_id=receipt["id"], reviewer_chat_id=7
        )
        approved = market_wallet.approve_topup_receipt(
            self.conn, receipt_id=receipt["id"], reviewer_chat_id=8
        )
        self.assertEqual(rejected["outcome"], "rejected")
        self.assertEqual(approved["outcome"], "rejected")
        self.assertEqual(
            market_wallet.get_wallet_snapshot(self.conn, self.customer_id)["balance_toman"],
            0,
        )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM wallet_transactions").fetchone()[0],
            0,
        )

    def test_blocked_customer_cannot_submit_new_topup(self):
        self.conn.execute(
            "UPDATE customers SET status='blocked' WHERE id=?",
            (self.customer_id,),
        )
        with self.assertRaises(PermissionError):
            market_wallet.create_topup_receipt(
                self.conn,
                customer_id=self.customer_id,
                amount_toman=100000,
                photo_id="photo-blocked",
                idempotency_key="blocked-topup",
            )

    def test_topup_amount_requires_integer_positive_toman(self):
        self.assertEqual(market_wallet.normalize_topup_amount("250000"), 250000)
        for invalid in (0, -1, 1.5, "abc", market_wallet.MAX_TOPUP_TOMAN + 1):
            with self.assertRaises(ValueError):
                market_wallet.normalize_topup_amount(invalid)

    def test_transaction_history_is_customer_scoped(self):
        receipt = market_wallet.create_topup_receipt(
            self.conn,
            customer_id=self.customer_id,
            amount_toman=120000,
            photo_id="photo-history",
            idempotency_key="history-1",
        )
        self.conn.commit()
        market_wallet.approve_topup_receipt(
            self.conn, receipt_id=receipt["id"], reviewer_chat_id=1
        )
        rows = market_wallet.list_wallet_transactions(self.conn, self.customer_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "topup")
        self.assertEqual(rows[0]["amount_toman"], 120000)


class DirectMarketPhase3SourceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("bot_final_v49-2.py").read_text(encoding="utf-8")

    def test_customer_receipt_callback_contains_only_receipt_id(self):
        self.assertIn('callback_data=f"mkt_topup_acc_{receipt_id}"', self.source)
        self.assertNotIn('mkt_topup_acc_{receipt_id}_{customer_id}', self.source)
        self.assertNotIn('mkt_topup_acc_{receipt_id}_{customer_id}_{amount}', self.source)

    def test_admin_approval_loads_receipt_from_domain_function(self):
        self.assertIn(
            "_db_approve_market_topup,\n                receipt_id,\n                update.effective_chat.id",
            self.source,
        )

    def test_customer_callbacks_remain_allowlisted(self):
        self.assertIn("if d == 'mkt_wallet_home':", self.source)
        self.assertIn("if d == 'mkt_wallet_topup':", self.source)
        self.assertIn(
            'await query.message.reply_text("⛔️ این عملیات برای حساب مشتری در دسترس نیست.")',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
