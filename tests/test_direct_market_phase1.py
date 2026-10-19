import sqlite3
import unittest

import market_commerce


class DirectMarketPhase1SchemaTests(unittest.TestCase):
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
                agent_id INTEGER DEFAULT 0
            );
            CREATE TABLE agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                balance REAL DEFAULT 0.0
            );
            CREATE TABLE receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER,
                amount REAL,
                status TEXT
            );
            CREATE TABLE activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER,
                username TEXT,
                cost REAL
            );
            """
        )
        self.conn.execute("INSERT INTO settings VALUES ('brand', 'NeVeL')")
        self.conn.executemany(
            "INSERT INTO ssh_accounts(username, password, expire_date, creation_date, users_limit, status, agent_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("legacy_agent", "p1", "2026-12-01", "2026-10-01", 1, "🟢 فعال", 7),
                ("legacy_direct", "p2", "2026-12-02", "2026-10-02", 2, "🟢 فعال", 0),
            ],
        )
        self.conn.executemany(
            "INSERT INTO agents(username, balance) VALUES (?, ?)",
            [("a1", 125000.0), ("a2", 80000.0)],
        )
        self.conn.execute(
            "INSERT INTO receipts(agent_id, amount, status) VALUES (1, 50000.0, 'pending')"
        )
        self.conn.execute(
            "INSERT INTO activity_log(agent_id, username, cost) VALUES (1, 'legacy_agent', 125000.0)"
        )

    def tearDown(self):
        self.conn.close()

    def _legacy_snapshot(self):
        return {
            "settings": self.conn.execute(
                "SELECT key, value FROM settings WHERE key='brand'"
            ).fetchall(),
            "accounts": self.conn.execute(
                "SELECT username, password, expire_date, creation_date, users_limit, status, agent_id "
                "FROM ssh_accounts ORDER BY username"
            ).fetchall(),
            "agents": self.conn.execute(
                "SELECT id, username, balance FROM agents ORDER BY id"
            ).fetchall(),
            "agent_balance_total": self.conn.execute(
                "SELECT SUM(balance) FROM agents"
            ).fetchone()[0],
            "receipts": self.conn.execute(
                "SELECT id, agent_id, amount, status FROM receipts ORDER BY id"
            ).fetchall(),
            "activity": self.conn.execute(
                "SELECT id, agent_id, username, cost FROM activity_log ORDER BY id"
            ).fetchall(),
        }

    def test_install_is_additive_and_preserves_legacy_data(self):
        before = self._legacy_snapshot()

        market_commerce.install_schema(self.conn)

        self.assertEqual(before, self._legacy_snapshot())
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE customer_id IS NOT NULL"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_enabled'"
            ).fetchone()[0],
            "0",
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_schema_version'"
            ).fetchone()[0],
            str(market_commerce.DIRECT_MARKET_SCHEMA_VERSION),
        )

        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertTrue(
            {"customers", "wallets", "wallet_transactions", "market_plans", "orders"}
            <= tables
        )

    def test_installer_is_idempotent_and_does_not_reset_feature_flag(self):
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "UPDATE settings SET value='1' WHERE key='direct_market_enabled'"
        )

        market_commerce.install_schema(self.conn)

        columns = [
            row[1] for row in self.conn.execute("PRAGMA table_info(ssh_accounts)")
        ]
        self.assertEqual(columns.count("customer_id"), 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_enabled'"
            ).fetchone()[0],
            "1",
        )

    def test_new_money_columns_reject_non_integer_values(self):
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id) VALUES (1001, 2001)"
        )
        customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=1001"
        ).fetchone()[0]
        self.conn.execute(
            "INSERT INTO wallets(customer_id, balance_toman, reserved_toman) VALUES (?, 100000, 0)",
            (customer_id,),
        )

        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id) VALUES (1002, 2002)"
        )
        customer2_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=1002"
        ).fetchone()[0]

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO wallets(customer_id, balance_toman) VALUES (?, ?)",
                (customer2_id, 12.5),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO market_plans(code, service_type, title, price_toman) "
                "VALUES ('bad-float', 'ssh', 'Bad', 99.5)"
            )

    def test_wallet_ledger_is_append_only(self):
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id) VALUES (3001, 4001)"
        )
        customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=3001"
        ).fetchone()[0]
        self.conn.execute(
            "INSERT INTO wallets(customer_id, balance_toman) VALUES (?, 500000)",
            (customer_id,),
        )
        wallet_id = self.conn.execute(
            "SELECT id FROM wallets WHERE customer_id=?", (customer_id,)
        ).fetchone()[0]
        self.conn.execute(
            """
            INSERT INTO wallet_transactions(
                wallet_id, customer_id, kind, amount_toman,
                balance_after_toman, idempotency_key
            ) VALUES (?, ?, 'topup', 500000, 500000, 'tx-topup-1')
            """,
            (wallet_id, customer_id),
        )
        tx_id = self.conn.execute(
            "SELECT id FROM wallet_transactions WHERE idempotency_key='tx-topup-1'"
        ).fetchone()[0]

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE wallet_transactions SET amount_toman=1 WHERE id=?", (tx_id,)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM wallet_transactions WHERE id=?", (tx_id,))

    def test_orders_have_idempotency_boundary(self):
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id) VALUES (5001, 6001)"
        )
        customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=5001"
        ).fetchone()[0]
        self.conn.execute(
            """
            INSERT INTO market_plans(
                code, service_type, title, duration_days,
                users_limit, price_toman
            ) VALUES ('ssh-30-1', 'ssh', 'SSH 30 days', 30, 1, 150000)
            """
        )
        plan_id = self.conn.execute(
            "SELECT id FROM market_plans WHERE code='ssh-30-1'"
        ).fetchone()[0]

        self.conn.execute(
            """
            INSERT INTO orders(
                order_no, customer_id, plan_id, service_type,
                status, price_toman, idempotency_key
            ) VALUES ('ORD-1', ?, ?, 'ssh', 'pending', 150000, 'purchase-5001-1')
            """,
            (customer_id, plan_id),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """
                INSERT INTO orders(
                    order_no, customer_id, plan_id, service_type,
                    status, price_toman, idempotency_key
                ) VALUES ('ORD-2', ?, ?, 'ssh', 'pending', 150000, 'purchase-5001-1')
                """,
                (customer_id, plan_id),
            )


if __name__ == "__main__":
    unittest.main()
