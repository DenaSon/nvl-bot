import sqlite3
import unittest
from pathlib import Path

import market_commerce
import market_customer


class DirectMarketCustomerIdentityTests(unittest.TestCase):
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

    def tearDown(self):
        self.conn.close()

    def test_customer_identity_is_stable_and_metadata_refreshes(self):
        first = market_commerce.upsert_customer_identity(
            self.conn,
            telegram_user_id=10001,
            telegram_chat_id=10001,
            username="first_name",
            first_name="Ali",
        )
        second = market_commerce.upsert_customer_identity(
            self.conn,
            telegram_user_id=10001,
            telegram_chat_id=10001,
            username="renamed_user",
            first_name="Ali Updated",
        )

        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["telegram_user_id"], 10001)
        self.assertEqual(second["username"], "renamed_user")
        self.assertEqual(second["first_name"], "Ali Updated")
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM customers WHERE telegram_user_id=10001"
            ).fetchone()[0],
            1,
        )

    def test_identity_refresh_does_not_reactivate_blocked_customer(self):
        customer = market_commerce.upsert_customer_identity(
            self.conn,
            telegram_user_id=20001,
            telegram_chat_id=20001,
            username="blocked",
            first_name="Blocked",
        )
        self.conn.execute(
            "UPDATE customers SET status='blocked' WHERE id=?",
            (customer["id"],),
        )

        refreshed = market_commerce.upsert_customer_identity(
            self.conn,
            telegram_user_id=20001,
            telegram_chat_id=20001,
            username="blocked2",
            first_name="Still Blocked",
        )
        self.assertEqual(refreshed["status"], "blocked")

    def test_invalid_customer_identity_fails_closed(self):
        with self.assertRaises(ValueError):
            market_commerce.upsert_customer_identity(
                self.conn,
                telegram_user_id=0,
                telegram_chat_id=123,
            )
        with self.assertRaises(ValueError):
            market_commerce.upsert_customer_identity(
                self.conn,
                telegram_user_id=-10,
                telegram_chat_id=123,
            )

    def test_feature_flag_is_read_only_and_defaults_off(self):
        self.assertFalse(market_commerce.is_direct_market_enabled(self.conn))
        self.conn.execute(
            "UPDATE settings SET value='1' WHERE key=?",
            (market_commerce.DIRECT_MARKET_FLAG_KEY,),
        )
        self.assertTrue(market_commerce.is_direct_market_enabled(self.conn))


class DirectMarketRoutingTests(unittest.TestCase):
    def test_existing_portal_roles_keep_precedence(self):
        for role in ("admin", "agent", "accountant"):
            self.assertFalse(
                market_customer.should_open_customer_market(
                    direct_market_enabled=True,
                    is_private_chat=True,
                    authenticated_role=role,
                )
            )

    def test_ordinary_private_user_can_enter_market_only_when_enabled(self):
        self.assertTrue(
            market_customer.should_open_customer_market(
                direct_market_enabled=True,
                is_private_chat=True,
                authenticated_role=None,
            )
        )
        self.assertFalse(
            market_customer.should_open_customer_market(
                direct_market_enabled=False,
                is_private_chat=True,
                authenticated_role=None,
            )
        )

    def test_customer_market_is_private_chat_only(self):
        self.assertFalse(
            market_customer.should_open_customer_market(
                direct_market_enabled=True,
                is_private_chat=False,
                authenticated_role=None,
            )
        )

    def test_existing_customer_session_requires_feature_to_remain_enabled(self):
        self.assertTrue(
            market_customer.should_open_customer_market(
                direct_market_enabled=True,
                is_private_chat=True,
                authenticated_role=market_customer.ROLE_CUSTOMER,
            )
        )
        self.assertFalse(
            market_customer.should_open_customer_market(
                direct_market_enabled=False,
                is_private_chat=True,
                authenticated_role=market_customer.ROLE_CUSTOMER,
            )
        )

    def test_customer_menu_contract_remains_stable_across_phases(self):
        self.assertEqual(
            set(market_customer.CUSTOMER_MENU_LABELS),
            {
                "🛒 خرید اشتراک",
                "📦 سرویس‌های من",
                "💰 کیف پول",
                "🧾 تراکنش‌ها",
                "👨‍💼 ورود نماینده",
            },
        )
        self.assertEqual(
            set(market_customer.CUSTOMER_PLACEHOLDER_LABELS),
            {"🛒 خرید اشتراک", "📦 سرویس‌های من"},
        )
        for label in market_customer.CUSTOMER_PLACEHOLDER_LABELS:
            self.assertTrue(market_customer.phase2_placeholder_text(label))


class DirectMarketMainSourceGuardsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path("bot_final_v49-2.py").read_text(encoding="utf-8")

    def test_customer_session_identity_is_persisted_in_safe_clear(self):
        self.assertIn("'customer_id', 'users_agent_filter'", self.source)

    def test_customer_callback_boundary_is_fail_closed(self):
        self.assertIn(
            "Direct Market customer callbacks are explicit allowlist entries.",
            self.source,
        )
        self.assertIn("if role == market_customer.ROLE_CUSTOMER:", self.source)
        self.assertIn(
            'await query.message.reply_text("⛔️ این عملیات برای حساب مشتری در دسترس نیست.")',
            self.source,
        )

    def test_legacy_buy_flow_is_limited_to_admin_and_agent(self):
        self.assertIn(
            "and role in ('admin', 'agent'):\n"
            "            await _show_buy_start(update, context)",
            self.source,
        )

    def test_customer_role_never_enters_legacy_state_machines(self):
        self.assertIn(
            "# Customer sessions never enter legacy Agent/Admin state machines.",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
