"""Regression tests for existing agent wallet mutations and their financial journal.

Only isolated in-memory SQLite databases are used; no bot startup or production DB access.
"""
import ast
import asyncio
import logging
import sqlite3
import unittest
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import nvl_daily_business as business


SOURCE = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text(
    encoding="utf-8"
)
TREE = ast.parse(SOURCE)


def isolated_function(name, globals_dict):
    node = next(
        item for item in TREE.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name
    )
    scope = dict(globals_dict)
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(module, "<nvl-wallet-isolated>", "exec"), scope)
    return scope[name]


class AgentWalletAccountingTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript("""
            CREATE TABLE agents (
                id INTEGER PRIMARY KEY,
                balance REAL NOT NULL DEFAULT 0,
                parent_id INTEGER,
                l2_pct REAL NOT NULL DEFAULT 0,
                l3_pct REAL NOT NULL DEFAULT 0,
                withdrawable_balance REAL NOT NULL DEFAULT 0,
                referral_income REAL NOT NULL DEFAULT 0,
                cashback_income REAL NOT NULL DEFAULT 0,
                lifetime_accounts_sold INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO agents VALUES
                (1, 1000, 2, 0, 0, 0, 0, 0, 50),
                (2, 0, 3, 10, 0, 500, 0, 0, 0),
                (3, 0, NULL, 0, 5, 0, 0, 0, 0);
            CREATE TABLE withdrawal_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                card_number TEXT NOT NULL,
                full_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                done_at TEXT
            );
        """)
        business.install_schema(self.conn)
        self.conn.commit()

        globals_dict = {
            "db_conn": lambda: self.conn,
            "nvl_daily_business": business,
            "sqlite3": sqlite3,
            "datetime": datetime,
            "Decimal": Decimal,
            "asyncio": asyncio,
            "log": logging.getLogger("nvl-wallet-tests"),
            "AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS": 50,
            "AGENT_CASHBACK_PCT": Decimal("7"),
            "_db_get_agent_lifetime_sold": lambda aid: 50 if aid == 1 else 0,
        }
        self.deduct = isolated_function("_db_admin_deduct_agent", globals_dict)
        self.distribute = isolated_function("_db_distribute_commission", globals_dict)
        self.cashback = isolated_function(
            "_apply_agent_cashback_if_eligible", globals_dict
        )
        self.move_to_wallet = isolated_function(
            "_db_move_withdrawable_to_wallet", globals_dict
        )
        self.create_withdrawal = isolated_function(
            "_db_create_withdrawal_request", globals_dict
        )
        self.mark_withdrawal_done = isolated_function(
            "_db_mark_withdrawal_done", globals_dict
        )
        self.cancel_withdrawal = isolated_function(
            "_db_cancel_withdrawal_request", globals_dict
        )

    def tearDown(self):
        self.conn.close()

    def scalar(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()[0]

    def test_manual_deduction_is_journaled_and_duplicate_callback_is_ignored(self):
        key = "manual-deduct:1001:501"
        self.assertTrue(self.deduct(1, 125, key))
        self.assertFalse(self.deduct(1, 125, key))
        self.assertEqual(self.scalar("SELECT balance FROM agents WHERE id=1"), 875)
        self.assertEqual(
            self.conn.execute(
                "SELECT kind, agent_id, amount_toman, event_key "
                "FROM nvl_business_events"
            ).fetchone(),
            ("MANUAL_DEDUCT", 1, 125.0, key),
        )

    def test_manual_deduction_rolls_back_when_journal_write_fails(self):
        with patch.object(business, "record_event", side_effect=RuntimeError("ledger down")):
            with self.assertRaisesRegex(RuntimeError, "ledger down"):
                self.deduct(1, 125, "manual-deduct:1001:502")
        self.assertEqual(self.scalar("SELECT balance FROM agents WHERE id=1"), 1000)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM nvl_business_events"), 0)

    def test_referral_commissions_are_recorded_for_each_existing_parent(self):
        self.distribute(1, Decimal("1000"))
        self.assertEqual(
            self.conn.execute(
                "SELECT id, withdrawable_balance, referral_income "
                "FROM agents WHERE id IN (2,3) ORDER BY id"
            ).fetchall(),
            [(2, 600.0, 100.0), (3, 50.0, 50.0)],
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT kind, agent_id, amount_toman FROM nvl_business_events "
                "ORDER BY agent_id"
            ).fetchall(),
            [
                ("REFERRAL_COMMISSION", 2, 100.0),
                ("REFERRAL_COMMISSION", 3, 50.0),
            ],
        )

    def test_cashback_credit_and_event_are_atomic(self):
        self.assertEqual(asyncio.run(self.cashback(1, Decimal("1000"))), 70.0)
        self.assertEqual(
            self.scalar("SELECT withdrawable_balance FROM agents WHERE id=1"), 70
        )
        self.assertEqual(
            self.scalar("SELECT cashback_income FROM agents WHERE id=1"), 70
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT kind, agent_id, amount_toman FROM nvl_business_events"
            ).fetchone(),
            ("AGENT_CASHBACK", 1, 70.0),
        )

    def test_withdrawable_transfer_is_atomic_and_idempotent(self):
        key = "withdrawable-transfer:2:message-77"
        self.assertTrue(self.move_to_wallet(2, 200, key))
        self.assertFalse(self.move_to_wallet(2, 200, key))
        self.assertEqual(
            self.conn.execute(
                "SELECT balance, withdrawable_balance FROM agents WHERE id=2"
            ).fetchone(),
            (200.0, 300.0),
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT kind, agent_id, amount_toman, event_key "
                "FROM nvl_business_events"
            ).fetchone(),
            ("WITHDRAWABLE_TRANSFER", 2, 200.0, key),
        )

    def test_withdrawable_transfer_never_overdraws_pool(self):
        self.assertFalse(self.move_to_wallet(2, 600, "transfer:too-large"))
        self.assertEqual(
            self.scalar("SELECT withdrawable_balance FROM agents WHERE id=2"), 500
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM nvl_business_events"), 0)

    def test_withdrawal_request_reservation_is_atomic_and_idempotent(self):
        key = "withdrawal-request:2001:801"
        self.conn.execute(
            "UPDATE agents SET withdrawable_balance=1000 WHERE id=2"
        )
        self.conn.commit()
        req_id = self.create_withdrawal(2, 300, "4111111111111111", "Agent Two", key)
        self.assertIsNotNone(req_id)
        self.assertIsNone(
            self.create_withdrawal(2, 300, "4111111111111111", "Agent Two", key)
        )
        self.assertEqual(
            self.scalar("SELECT withdrawable_balance FROM agents WHERE id=2"), 700
        )
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM withdrawal_requests"), 1
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT kind, agent_id, amount_toman, event_key "
                "FROM nvl_business_events"
            ).fetchone(),
            ("WITHDRAWAL_REQUEST", 2, 300.0, key),
        )

    def test_withdrawal_request_rolls_back_if_journal_write_fails(self):
        with patch.object(business, "record_event", side_effect=RuntimeError("ledger down")):
            with self.assertRaisesRegex(RuntimeError, "ledger down"):
                self.create_withdrawal(
                    2, 300, "4111111111111111", "Agent Two", "withdrawal-request:fail"
                )
        self.assertEqual(
            self.scalar("SELECT withdrawable_balance FROM agents WHERE id=2"), 500
        )
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM withdrawal_requests"), 0)

    def test_withdrawal_completion_is_a_single_pending_to_done_transition(self):
        req_id = self.create_withdrawal(
            2, 100, "4111111111111111", "Agent Two", "withdrawal-request:done"
        )
        self.assertTrue(self.mark_withdrawal_done(req_id))
        self.assertFalse(self.mark_withdrawal_done(req_id))
        self.assertEqual(
            self.scalar("SELECT status FROM withdrawal_requests WHERE id=?", (req_id,)),
            "done",
        )
        self.assertEqual(
            self.scalar(
                "SELECT COUNT(*) FROM nvl_business_events WHERE kind='WITHDRAWAL_PAID'"
            ),
            1,
        )

    def test_withdrawal_cancellation_restores_reserve_only_once(self):
        req_id = self.create_withdrawal(
            2, 150, "4111111111111111", "Agent Two", "withdrawal-request:cancel"
        )
        self.assertTrue(self.cancel_withdrawal(req_id))
        self.assertFalse(self.cancel_withdrawal(req_id))
        self.assertEqual(
            self.scalar("SELECT withdrawable_balance FROM agents WHERE id=2"), 500
        )
        self.assertEqual(
            self.scalar("SELECT status FROM withdrawal_requests WHERE id=?", (req_id,)),
            "cancelled",
        )
        self.assertEqual(
            self.scalar(
                "SELECT COUNT(*) FROM nvl_business_events "
                "WHERE kind='WITHDRAWAL_CANCELLED'"
            ),
            1,
        )

    def test_new_internal_events_do_not_change_cash_in_or_purchase_totals(self):
        business.record_event(
            self.conn, kind="MANUAL_DEDUCT", agent_id=1, amount=50,
            source_key="manual-deduct:report",
        )
        business.record_event(
            self.conn, kind="REFERRAL_COMMISSION", agent_id=2, amount=20,
            source_key="commission:report",
        )
        business.record_event(
            self.conn, kind="AGENT_CASHBACK", agent_id=1, amount=10,
            source_key="cashback:report",
        )
        data = business.summarize(
            self.conn, datetime.now(business.UTC).astimezone(business.TEHRAN).date()
        )
        self.assertEqual(data["central_bank"], 0)
        self.assertEqual(data["wallet_topups"], 0)
        self.assertEqual(data["net_purchases"], 0)


if __name__ == "__main__":
    unittest.main()
