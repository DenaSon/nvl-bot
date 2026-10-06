import sqlite3
import unittest
from pathlib import Path

import market_commerce
import market_orders
import market_wallet


class DirectMarketSSHOrderPhase4Tests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(
            """
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE ssh_accounts (
                username TEXT PRIMARY KEY,
                password TEXT,
                expire_date TEXT,
                creation_date TEXT,
                users_limit INTEGER,
                status TEXT DEFAULT '🟢 فعال',
                agent_id INTEGER DEFAULT 0,
                conn_mode TEXT DEFAULT 'direct',
                service_type TEXT DEFAULT 'ssh',
                host TEXT
            );
            """
        )
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id, username, first_name) "
            "VALUES (4001, 4001, 'buyer4', 'Buyer Four')"
        )
        self.customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=4001"
        ).fetchone()[0]
        self.wallet_id = market_wallet.ensure_wallet(self.conn, self.customer_id)
        self.conn.execute(
            "UPDATE wallets SET balance_toman=500000 WHERE id=?",
            (self.wallet_id,),
        )
        self.conn.execute(
            """
            INSERT INTO market_plans(
                code, service_type, title, duration_days, users_limit,
                price_toman, active, sort_order
            ) VALUES ('ssh-30-1', 'ssh', 'SSH 30 روزه', 30, 1, 150000, 1, 10)
            """
        )
        self.plan_id = self.conn.execute(
            "SELECT id FROM market_plans WHERE code='ssh-30-1'"
        ).fetchone()[0]
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _create(self, key="order-key-1"):
        return market_orders.create_ssh_order_and_reserve(
            self.conn,
            customer_id=self.customer_id,
            plan_id=self.plan_id,
            idempotency_key=key,
        )

    def _claim(self, order_id):
        return market_orders.claim_order_for_provisioning(
            self.conn,
            order_id=order_id,
            customer_id=self.customer_id,
        )

    def _attach_active_service(self, order, username="dmssh0001"):
        market_orders.set_provisioning_target(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            service_username=username,
            service_host="203.0.113.10",
        )
        self.conn.execute(
            """
            INSERT INTO ssh_accounts(
                username, password, expire_date, creation_date, users_limit,
                status, agent_id, conn_mode, service_type, host,
                customer_id, market_order_id
            ) VALUES (?, '12345', '2026-12-01', '2026-10-07', 1,
                      '🟢 فعال', 0, 'direct', 'ssh', '203.0.113.10', ?, ?)
            """,
            (username, self.customer_id, order["id"]),
        )
        self.conn.commit()

    def test_schema_v3_adds_order_and_service_link_columns(self):
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_schema_version'"
            ).fetchone()[0],
            str(market_commerce.DIRECT_MARKET_SCHEMA_VERSION),
        )
        order_cols = {
            row[1] for row in self.conn.execute("PRAGMA table_info(orders)")
        }
        self.assertTrue(
            {
                "duration_days",
                "users_limit",
                "connection_mode",
                "service_host",
                "purchase_transaction_id",
                "provisioning_started_at",
                "failed_at",
            } <= order_cols
        )
        account_cols = {
            row[1] for row in self.conn.execute("PRAGMA table_info(ssh_accounts)")
        }
        self.assertIn("market_order_id", account_cols)

    def test_active_ssh_plan_listing_excludes_invalid_or_other_services(self):
        self.conn.execute(
            "INSERT INTO market_plans(code, service_type, title, duration_days, users_limit, price_toman, active) "
            "VALUES ('v2', 'v2ray', 'V2', 30, 1, 100000, 1)"
        )
        self.conn.execute(
            "INSERT INTO market_plans(code, service_type, title, duration_days, users_limit, price_toman, active) "
            "VALUES ('ssh-off', 'ssh', 'Off', 30, 1, 100000, 0)"
        )
        rows = market_orders.list_active_ssh_plans(self.conn)
        self.assertEqual([row["code"] for row in rows], ["ssh-30-1"])

    def test_order_reserves_funds_without_debiting_balance(self):
        result = self._create()
        order = result["order"]
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(order["status"], market_orders.ORDER_FUNDS_RESERVED)
        self.assertEqual(order["price_toman"], 150000)
        self.assertEqual(order["duration_days"], 30)
        self.assertEqual(order["users_limit"], 1)
        self.assertEqual(wallet["balance_toman"], 500000)
        self.assertEqual(wallet["reserved_toman"], 150000)
        self.assertEqual(wallet["available_toman"], 350000)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM wallet_transactions").fetchone()[0],
            0,
        )

    def test_plan_snapshot_is_immutable_for_existing_order(self):
        order = self._create()["order"]
        self.conn.execute(
            "UPDATE market_plans SET price_toman=999999, duration_days=365 WHERE id=?",
            (self.plan_id,),
        )
        stored = market_orders.get_order(self.conn, order["id"])
        self.assertEqual(stored["price_toman"], 150000)
        self.assertEqual(stored["duration_days"], 30)

    def test_order_creation_is_idempotent_and_does_not_double_reserve(self):
        first = self._create("same-purchase")
        second = self._create("same-purchase")
        self.assertEqual(first["order"]["id"], second["order"]["id"])
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["reserved_toman"], 150000)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
            1,
        )

    def test_insufficient_funds_creates_no_order_or_reservation(self):
        self.conn.execute(
            "UPDATE wallets SET balance_toman=100000, reserved_toman=0 WHERE id=?",
            (self.wallet_id,),
        )
        self.conn.commit()
        with self.assertRaises(market_orders.InsufficientFundsError):
            self._create("poor-wallet")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
            0,
        )
        self.assertEqual(
            market_wallet.get_wallet_snapshot(self.conn, self.customer_id)["reserved_toman"],
            0,
        )

    def test_order_atomic_boundary_does_not_commit_caller_transaction(self):
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES ('outer-transaction-marker', '1')"
        )
        self.assertTrue(self.conn.in_transaction)

        created = market_orders.create_ssh_order_and_reserve(
            self.conn,
            customer_id=self.customer_id,
            plan_id=self.plan_id,
            idempotency_key="nested-order",
        )
        self.assertEqual(created["order"]["status"], market_orders.ORDER_FUNDS_RESERVED)
        self.assertTrue(self.conn.in_transaction)

        self.conn.rollback()
        self.assertIsNone(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='outer-transaction-marker'"
            ).fetchone()
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM orders WHERE idempotency_key='nested-order'"
            ).fetchone()[0],
            0,
        )
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["balance_toman"], 500000)
        self.assertEqual(wallet["reserved_toman"], 0)

    def test_provisioning_claim_is_single_writer(self):
        order = self._create()["order"]
        first = self._claim(order["id"])
        second = self._claim(order["id"])
        self.assertEqual(first["outcome"], "claimed")
        self.assertEqual(second["outcome"], "in_progress")

    def test_completion_requires_exact_active_customer_service(self):
        order = self._create()["order"]
        self._claim(order["id"])
        market_orders.set_provisioning_target(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            service_username="missing-user",
            service_host="203.0.113.10",
        )
        with self.assertRaises(market_orders.OrderStateError):
            market_orders.complete_ssh_order(
                self.conn,
                order_id=order["id"],
                customer_id=self.customer_id,
            )
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["balance_toman"], 500000)
        self.assertEqual(wallet["reserved_toman"], 150000)

    def test_successful_completion_captures_once_and_appends_purchase_ledger(self):
        order = self._create()["order"]
        claimed = self._claim(order["id"])["order"]
        self._attach_active_service(claimed)

        completed = market_orders.complete_ssh_order(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
        )
        again = market_orders.complete_ssh_order(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
        )

        self.assertEqual(completed["outcome"], "completed")
        self.assertEqual(again["outcome"], "already_completed")
        wallet = completed["wallet"]
        self.assertEqual(wallet["balance_toman"], 350000)
        self.assertEqual(wallet["reserved_toman"], 0)
        tx = self.conn.execute(
            "SELECT kind, amount_toman, balance_after_toman, order_id "
            "FROM wallet_transactions WHERE order_id=?",
            (order["id"],),
        ).fetchone()
        self.assertEqual(tx, ("purchase", -150000, 350000, order["id"]))
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM wallet_transactions WHERE order_id=?",
                (order["id"],),
            ).fetchone()[0],
            1,
        )

    def test_failed_provisioning_releases_reservation_without_debit(self):
        order = self._create()["order"]
        self._claim(order["id"])
        failed = market_orders.fail_ssh_order_and_release(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            failure_reason="useradd failed",
        )
        self.assertEqual(failed["order"]["status"], market_orders.ORDER_FAILED)
        self.assertEqual(failed["wallet"]["balance_toman"], 500000)
        self.assertEqual(failed["wallet"]["reserved_toman"], 0)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM wallet_transactions").fetchone()[0],
            0,
        )

    def test_funds_cannot_be_released_while_service_row_exists(self):
        order = self._create()["order"]
        claimed = self._claim(order["id"])["order"]
        self._attach_active_service(claimed)
        with self.assertRaises(market_orders.OrderStateError):
            market_orders.fail_ssh_order_and_release(
                self.conn,
                order_id=order["id"],
                customer_id=self.customer_id,
                failure_reason="should not release",
            )
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["reserved_toman"], 150000)

    def test_wrong_customer_cannot_claim_order(self):
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id) VALUES (9999, 9999)"
        )
        other_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=9999"
        ).fetchone()[0]
        order = self._create()["order"]
        with self.assertRaises(market_orders.OrderStateError):
            market_orders.claim_order_for_provisioning(
                self.conn,
                order_id=order["id"],
                customer_id=other_id,
            )

    def test_recovery_marker_keeps_reserved_money_held(self):
        order = self._create()["order"]
        self._claim(order["id"])
        recovery = market_orders.mark_order_recovery_required(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            reason="cleanup uncertain",
        )
        self.assertEqual(recovery["status"], market_orders.ORDER_PROVISIONING)
        self.assertIn("RECOVERY_REQUIRED", recovery["failure_reason"])
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["balance_toman"], 500000)
        self.assertEqual(wallet["reserved_toman"], 150000)


class DirectMarketPhase4SourceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("bot_final_v49-2.py").read_text(encoding="utf-8")
        cls.orders_source = Path("market_orders.py").read_text(encoding="utf-8")

    def test_customer_buy_path_uses_market_order_engine(self):
        self.assertIn("_db_market_create_ssh_order", self.source)
        self.assertIn("_db_market_claim_ssh_order", self.source)
        self.assertIn("_db_market_complete_ssh_order", self.source)

    def test_direct_market_finalizer_binds_customer_and_order(self):
        self.assertIn("customer_id=None, market_order_id=None", self.source)
        self.assertIn("customer_id=?, market_order_id=?", self.source)

    def test_direct_market_never_uses_agent_balance(self):
        self.assertNotIn("agents SET balance", self.orders_source)
        self.assertNotIn("commission", self.orders_source.lower())

    def test_customer_actions_recheck_master_feature_flag(self):
        self.assertGreaterEqual(
            self.source.count("await asyncio.to_thread(_db_direct_market_enabled)"),
            4,
        )

    def test_purchase_callback_nonce_is_idempotency_source(self):
        self.assertIn(
            'idempotency_key = f"market-ssh:{customer_id}:{nonce}"',
            self.source,
        )

    def test_uncertain_cleanup_keeps_money_reserved(self):
        self.assertIn(
            "مبلغ آزاد نشده است تا سرویس و تسویه دستی بررسی شوند.",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
