import sqlite3
import unittest
from datetime import datetime
from pathlib import Path

import market_commerce
import market_orders
import market_v2ray
import market_wallet


class DirectMarketV2RayOrderPhase5Tests(unittest.TestCase):
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
                data_limit INTEGER DEFAULT 0,
                sub_url TEXT,
                host TEXT
            );
            """
        )
        market_commerce.install_schema(self.conn)
        self.conn.execute(
            "INSERT INTO customers(telegram_user_id, telegram_chat_id, username, first_name) "
            "VALUES (5001, 5001, 'buyer5', 'Buyer Five')"
        )
        self.customer_id = self.conn.execute(
            "SELECT id FROM customers WHERE telegram_user_id=5001"
        ).fetchone()[0]
        self.wallet_id = market_wallet.ensure_wallet(self.conn, self.customer_id)
        self.conn.execute(
            "UPDATE wallets SET balance_toman=1000000 WHERE id=?",
            (self.wallet_id,),
        )
        self.conn.executemany(
            """
            INSERT INTO market_plans(
                code, service_type, title, duration_days, data_limit_gb,
                users_limit, price_toman, active, sort_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("v2-unlimited", "v2ray", "V2 نامحدود", 30, None, 2, 220000, 1, 10),
                ("v2-daily", "v2ray", "V2 روزانه", 30, 10, 1, 180000, 1, 20),
                ("v2-volume", "v2ray_vol", "V2 حجمی 50", None, 50, 1, 160000, 1, 30),
                ("v2-volume-exp", "v2ray_vol", "V2 حجمی 30 روز", 30, 100, 1, 260000, 1, 40),
            ],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _plan_id(self, code):
        return self.conn.execute(
            "SELECT id FROM market_plans WHERE code=?",
            (code,),
        ).fetchone()[0]

    def _create(self, code, service_type, key):
        return market_orders.create_v2ray_order_and_reserve(
            self.conn,
            customer_id=self.customer_id,
            plan_id=self._plan_id(code),
            service_type=service_type,
            idempotency_key=key,
        )

    def _claim(self, order_id):
        return market_orders.claim_order_for_provisioning(
            self.conn,
            order_id=order_id,
            customer_id=self.customer_id,
        )

    def _attach(self, order, username):
        market_orders.set_provisioning_target(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            service_username=username,
            service_host="https://marzban.example.test",
        )
        self.conn.execute(
            """
            INSERT INTO ssh_accounts(
                username, password, expire_date, creation_date, users_limit,
                status, agent_id, conn_mode, service_type, data_limit, sub_url,
                customer_id, market_order_id
            ) VALUES (?, '-', '2026-11-06', '2026-10-07', ?,
                      '🟢 فعال', 0, 'v2ray', ?, ?, 'https://sub.example/u', ?, ?)
            """,
            (
                username,
                0 if order["service_type"] == "v2ray_vol" else order["users_limit"],
                order["service_type"],
                int(order["data_limit_gb"] or 0) * 1024**3,
                self.customer_id,
                order["id"],
            ),
        )
        self.conn.commit()

    def test_schema_v4_snapshots_data_limit(self):
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM settings WHERE key='direct_market_schema_version'"
            ).fetchone()[0],
            "4",
        )
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(orders)")}
        self.assertIn("data_limit_gb", cols)

    def test_lists_only_sellable_timed_and_volume_plans(self):
        self.conn.execute(
            "INSERT INTO market_plans(code, service_type, title, duration_days, data_limit_gb, users_limit, price_toman, active) "
            "VALUES ('bad-timed', 'v2ray', 'bad', NULL, 10, 1, 1000, 1)"
        )
        self.conn.execute(
            "INSERT INTO market_plans(code, service_type, title, duration_days, data_limit_gb, users_limit, price_toman, active) "
            "VALUES ('bad-volume', 'v2ray_vol', 'bad', 30, NULL, 1, 1000, 1)"
        )
        timed = market_orders.list_active_v2ray_plans(
            self.conn, service_type="v2ray"
        )
        volume = market_orders.list_active_v2ray_plans(
            self.conn, service_type="v2ray_vol"
        )
        self.assertEqual([p["code"] for p in timed], ["v2-unlimited", "v2-daily"])
        self.assertEqual(
            [p["code"] for p in volume],
            ["v2-volume", "v2-volume-exp"],
        )

    def test_v2_order_reserves_without_debit_and_snapshots_plan(self):
        result = self._create("v2-daily", "v2ray", "v2-order-1")
        order = result["order"]
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(order["status"], market_orders.ORDER_FUNDS_RESERVED)
        self.assertEqual(order["price_toman"], 180000)
        self.assertEqual(order["duration_days"], 30)
        self.assertEqual(order["data_limit_gb"], 10)
        self.assertEqual(order["users_limit"], 1)
        self.assertEqual(order["connection_mode"], "v2ray")
        self.assertEqual(wallet["balance_toman"], 1000000)
        self.assertEqual(wallet["reserved_toman"], 180000)

        self.conn.execute(
            "UPDATE market_plans SET price_toman=999999, data_limit_gb=99 WHERE id=?",
            (order["plan_id"],),
        )
        stored = market_orders.get_order(self.conn, order["id"])
        self.assertEqual(stored["price_toman"], 180000)
        self.assertEqual(stored["data_limit_gb"], 10)

    def test_v2_order_idempotency_does_not_double_reserve(self):
        first = self._create("v2-unlimited", "v2ray", "same-v2")
        second = self._create("v2-unlimited", "v2ray", "same-v2")
        self.assertEqual(first["order"]["id"], second["order"]["id"])
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["reserved_toman"], 220000)

    def test_timed_v2_completion_captures_once(self):
        order = self._create("v2-unlimited", "v2ray", "timed-complete")["order"]
        claimed = self._claim(order["id"])["order"]
        self._attach(claimed, "marketv2001")
        result = market_orders.complete_v2ray_order(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
        )
        again = market_orders.complete_v2ray_order(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
        )
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(again["outcome"], "already_completed")
        self.assertEqual(result["wallet"]["balance_toman"], 780000)
        self.assertEqual(result["wallet"]["reserved_toman"], 0)
        tx = self.conn.execute(
            "SELECT kind, amount_toman FROM wallet_transactions WHERE order_id=?",
            (order["id"],),
        ).fetchone()
        self.assertEqual(tx, ("purchase", -220000))

    def test_volume_v2_completion_uses_exact_service_type(self):
        order = self._create("v2-volume", "v2ray_vol", "vol-complete")["order"]
        claimed = self._claim(order["id"])["order"]
        self._attach(claimed, "marketvv001")
        result = market_orders.complete_v2ray_order(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
        )
        self.assertEqual(result["order"]["service_type"], "v2ray_vol")
        self.assertEqual(result["wallet"]["balance_toman"], 840000)

    def test_completion_rejects_mismatched_local_service_type(self):
        order = self._create("v2-volume", "v2ray_vol", "wrong-local-type")["order"]
        self._claim(order["id"])
        market_orders.set_provisioning_target(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            service_username="wrongtype001",
            service_host="https://marzban.example.test",
        )
        self.conn.execute(
            """
            INSERT INTO ssh_accounts(
                username, status, agent_id, conn_mode, service_type,
                customer_id, market_order_id
            ) VALUES ('wrongtype001', '🟢 فعال', 0, 'v2ray', 'v2ray', ?, ?)
            """,
            (self.customer_id, order["id"]),
        )
        self.conn.commit()
        with self.assertRaises(market_orders.OrderStateError):
            market_orders.complete_v2ray_order(
                self.conn,
                order_id=order["id"],
                customer_id=self.customer_id,
            )
        wallet = market_wallet.get_wallet_snapshot(self.conn, self.customer_id)
        self.assertEqual(wallet["reserved_toman"], 160000)
        self.assertEqual(wallet["balance_toman"], 1000000)

    def test_failure_release_is_blocked_while_v2_service_row_exists(self):
        order = self._create("v2-daily", "v2ray", "blocked-release")["order"]
        claimed = self._claim(order["id"])["order"]
        self._attach(claimed, "blockv2001")
        with self.assertRaises(market_orders.OrderStateError):
            market_orders.fail_v2ray_order_and_release(
                self.conn,
                order_id=order["id"],
                customer_id=self.customer_id,
                failure_reason="must stay held",
            )

    def test_failure_without_service_releases_reservation(self):
        order = self._create("v2-daily", "v2ray", "safe-release")["order"]
        self._claim(order["id"])
        result = market_orders.fail_v2ray_order_and_release(
            self.conn,
            order_id=order["id"],
            customer_id=self.customer_id,
            failure_reason="preflight failed",
        )
        self.assertEqual(result["order"]["status"], market_orders.ORDER_FAILED)
        self.assertEqual(result["wallet"]["balance_toman"], 1000000)
        self.assertEqual(result["wallet"]["reserved_toman"], 0)


class DirectMarketV2RaySpecTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 7, 12, 0, 0)

    def test_timed_unlimited_spec(self):
        spec = market_v2ray.build_provisioning_spec(
            {
                "id": 11,
                "customer_id": 7,
                "service_type": "v2ray",
                "duration_days": 30,
                "data_limit_gb": None,
                "users_limit": 2,
            },
            now=self.now,
        )
        self.assertEqual(spec.data_limit_bytes, 0)
        self.assertEqual(spec.reset_strategy, "no_reset")
        self.assertEqual(spec.local_users_limit, 2)
        self.assertIn("NVL_MARKET_ORDER:11;CUSTOMER:7", spec.note_marker)
        self.assertIn("IP_LIMIT:2", spec.note_marker)

    def test_timed_daily_limit_spec(self):
        spec = market_v2ray.build_provisioning_spec(
            {
                "id": 12,
                "customer_id": 7,
                "service_type": "v2ray",
                "duration_days": 30,
                "data_limit_gb": 10,
                "users_limit": 1,
            },
            now=self.now,
        )
        self.assertEqual(spec.data_limit_bytes, 10 * 1024**3)
        self.assertEqual(spec.reset_strategy, "day")

    def test_volume_unlimited_time_spec(self):
        spec = market_v2ray.build_provisioning_spec(
            {
                "id": 13,
                "customer_id": 7,
                "service_type": "v2ray_vol",
                "duration_days": None,
                "data_limit_gb": 50,
                "users_limit": 1,
            },
            now=self.now,
        )
        self.assertEqual(spec.data_limit_bytes, 50 * 1024**3)
        self.assertEqual(spec.expire_timestamp, 0)
        self.assertEqual(spec.local_expire_date, "نامحدود")
        self.assertEqual(spec.local_users_limit, 0)
        self.assertEqual(spec.reset_strategy, "no_reset")

    def test_remote_verification_requires_order_marker_and_exact_runtime_values(self):
        spec = market_v2ray.build_provisioning_spec(
            {
                "id": 14,
                "customer_id": 8,
                "service_type": "v2ray_vol",
                "duration_days": None,
                "data_limit_gb": 25,
                "users_limit": 1,
            },
            now=self.now,
        )
        payload = {
            "username": "verify001",
            "status": "active",
            "data_limit": 25 * 1024**3,
            "expire": 0,
            "data_limit_reset_strategy": "no_reset",
            "note": spec.note_marker,
        }
        self.assertEqual(
            market_v2ray.verify_remote_user(
                payload,
                username="verify001",
                spec=spec,
            ),
            (True, "ok"),
        )
        payload["note"] = "someone-else"
        ok, reason = market_v2ray.verify_remote_user(
            payload,
            username="verify001",
            spec=spec,
        )
        self.assertFalse(ok)
        self.assertIn("ownership", reason.lower())

    def test_create_failure_classification_is_fail_closed(self):
        self.assertEqual(
            market_v2ray.classify_create_failure("user already exists"),
            "collision",
        )
        self.assertEqual(
            market_v2ray.classify_create_failure("Network Error: connection reset"),
            "uncertain",
        )
        self.assertEqual(
            market_v2ray.classify_create_failure(
                {"created": True, "stage": "verify"}
            ),
            "uncertain",
        )
        self.assertEqual(
            market_v2ray.classify_create_failure("validation failed"),
            "definite",
        )


class DirectMarketPhase5SourceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("bot_final_v49-2.py").read_text(encoding="utf-8")
        cls.orders = Path("market_orders.py").read_text(encoding="utf-8")
        cls.v2 = Path("market_v2ray.py").read_text(encoding="utf-8")

    def test_customer_buy_hub_has_ssh_and_both_v2ray_families(self):
        self.assertIn('callback_data="mkt_buy_ssh"', self.source)
        self.assertIn('callback_data="mkt_buy_v2"', self.source)
        self.assertIn('callback_data="mkt_buy_v2vol"', self.source)

    def test_direct_market_v2ray_uses_verified_marzban_service(self):
        self.assertIn("await service.create_user(", self.source)
        self.assertIn("market_v2ray.verify_remote_user(", self.source)
        self.assertIn("NVL_MARKET_ORDER:", self.v2)

    def test_v2ray_finalizer_binds_customer_and_order(self):
        self.assertIn("customer_id=None, market_order_id=None", self.source)
        self.assertIn("service_type='v2ray'", self.source)
        self.assertIn("customer_id=?, market_order_id=?", self.source)

    def test_direct_market_v2ray_has_no_agent_finance_dependency(self):
        self.assertNotIn("agents SET balance", self.orders)
        self.assertNotIn("commission", self.orders.lower())
        self.assertNotIn("agents", self.v2.lower())

    def test_uncertain_marzban_create_keeps_recovery_path(self):
        self.assertIn("MARZBAN_CREATE_UNCERTAIN", self.source)
        self.assertIn("_db_market_mark_order_recovery", self.source)
        self.assertIn("مبلغ <b>کسر نشده</b>", self.source)

    def test_v2ray_purchase_callbacks_use_nonce_idempotency(self):
        self.assertIn('idem_prefix = "market-v2"', self.source)
        self.assertIn('else "market-v2vol"', self.source)
        self.assertIn("secrets.token_hex(6)", self.source)


if __name__ == "__main__":
    unittest.main()
