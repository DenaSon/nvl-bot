"""NVL Direct Market commerce schema foundation.

Phase 1 is intentionally additive and inert:
- no customer UI or /start routing changes
- no direct-sale provisioning
- no mutation of legacy agent/account rows
- money in the new commerce domain is stored as INTEGER toman

The installer is idempotent so normal bot restarts can safely call it.
"""

from __future__ import annotations

import sqlite3
from typing import Set

DIRECT_MARKET_SCHEMA_VERSION = 2
DIRECT_MARKET_FLAG_KEY = "direct_market_enabled"


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        is not None
    )


def _table_columns(conn: sqlite3.Connection, table: str) -> Set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _require_legacy_prerequisites(conn: sqlite3.Connection) -> None:
    missing = [name for name in ("settings", "ssh_accounts") if not _table_exists(conn, name)]
    if missing:
        raise RuntimeError(
            "Direct Market schema installer must run after legacy schema creation; "
            f"missing: {', '.join(missing)}"
        )


def install_schema(conn: sqlite3.Connection) -> None:
    """Install Direct Market Phase-1 schema without rewriting legacy data."""
    _require_legacy_prerequisites(conn)

    # Feature remains OFF for Phase 1. INSERT OR IGNORE is deliberate: later
    # phases may enable it and normal restarts must never reset that decision.
    conn.execute(
        "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
        (DIRECT_MARKET_FLAG_KEY, "0"),
    )
    # Legacy service ownership remains untouched. Existing rows receive NULL,
    # which means "not owned by a direct-market customer".
    if "customer_id" not in _table_columns(conn, "ssh_accounts"):
        conn.execute(
            "ALTER TABLE ssh_accounts "
            "ADD COLUMN customer_id INTEGER DEFAULT NULL"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ssh_accounts_customer_id "
        "ON ssh_accounts(customer_id)"
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_user_id INTEGER NOT NULL UNIQUE,
            telegram_chat_id INTEGER NOT NULL,
            username TEXT DEFAULT NULL,
            first_name TEXT DEFAULT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL UNIQUE,
            balance_toman INTEGER NOT NULL DEFAULT 0
                CHECK(typeof(balance_toman) = 'integer' AND balance_toman >= 0),
            reserved_toman INTEGER NOT NULL DEFAULT 0
                CHECK(
                    typeof(reserved_toman) = 'integer'
                    AND reserved_toman >= 0
                    AND reserved_toman <= balance_toman
                ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE RESTRICT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS market_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            service_type TEXT NOT NULL,
            title TEXT NOT NULL,
            duration_days INTEGER DEFAULT NULL
                CHECK(duration_days IS NULL OR duration_days > 0),
            data_limit_gb INTEGER DEFAULT NULL
                CHECK(data_limit_gb IS NULL OR data_limit_gb > 0),
            users_limit INTEGER NOT NULL DEFAULT 1
                CHECK(users_limit > 0),
            price_toman INTEGER NOT NULL
                CHECK(typeof(price_toman) = 'integer' AND price_toman >= 0),
            active INTEGER NOT NULL DEFAULT 1
                CHECK(active IN (0, 1)),
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_no TEXT NOT NULL UNIQUE,
            customer_id INTEGER NOT NULL,
            plan_id INTEGER NOT NULL,
            service_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            price_toman INTEGER NOT NULL
                CHECK(typeof(price_toman) = 'integer' AND price_toman >= 0),
            idempotency_key TEXT NOT NULL UNIQUE,
            service_username TEXT DEFAULT NULL,
            failure_reason TEXT DEFAULT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT DEFAULT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE RESTRICT,
            FOREIGN KEY(plan_id) REFERENCES market_plans(id) ON DELETE RESTRICT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            order_id INTEGER DEFAULT NULL,
            kind TEXT NOT NULL,
            amount_toman INTEGER NOT NULL
                CHECK(typeof(amount_toman) = 'integer' AND amount_toman <> 0),
            balance_after_toman INTEGER NOT NULL
                CHECK(typeof(balance_after_toman) = 'integer' AND balance_after_toman >= 0),
            idempotency_key TEXT NOT NULL UNIQUE,
            reference_type TEXT DEFAULT NULL,
            reference_id TEXT DEFAULT NULL,
            metadata_json TEXT DEFAULT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE RESTRICT,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE RESTRICT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS customer_topup_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            amount_toman INTEGER NOT NULL
                CHECK(typeof(amount_toman) = 'integer' AND amount_toman > 0),
            photo_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'approved', 'rejected')),
            idempotency_key TEXT NOT NULL UNIQUE,
            wallet_transaction_id INTEGER DEFAULT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT DEFAULT NULL,
            reviewed_by_chat_id INTEGER DEFAULT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE RESTRICT,
            FOREIGN KEY(wallet_transaction_id) REFERENCES wallet_transactions(id) ON DELETE RESTRICT
        )
        """
    )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_customer_created "
        "ON orders(customer_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_orders_status_created "
        "ON orders(status, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_customer_created "
        "ON wallet_transactions(customer_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wallet_transactions_order "
        "ON wallet_transactions(order_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_market_plans_active_sort "
        "ON market_plans(active, sort_order, id)"
    )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_topup_receipts_status_created "
        "ON customer_topup_receipts(status, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_topup_receipts_customer_created "
        "ON customer_topup_receipts(customer_id, created_at DESC)"
    )

    # Ledger rows are append-only. Corrections must be compensating entries,
    # which keeps audit history intact.
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS wallet_transactions_no_update
        BEFORE UPDATE ON wallet_transactions
        BEGIN
            SELECT RAISE(ABORT, 'wallet_transactions is append-only');
        END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS wallet_transactions_no_delete
        BEFORE DELETE ON wallet_transactions
        BEGIN
            SELECT RAISE(ABORT, 'wallet_transactions is append-only');
        END
        """
    )

    # Mark the Direct Market schema version only after all additive DDL succeeds.
    conn.execute(
        """
        INSERT INTO settings(key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
        ("direct_market_schema_version", str(DIRECT_MARKET_SCHEMA_VERSION)),
    )


def is_direct_market_enabled(conn: sqlite3.Connection) -> bool:
    """Read the master Direct Market feature flag without mutating it."""
    row = conn.execute(
        "SELECT value FROM settings WHERE key=?",
        (DIRECT_MARKET_FLAG_KEY,),
    ).fetchone()
    return bool(row and str(row[0]).strip() == "1")


def _normalize_telegram_id(value: int, field: str, *, allow_negative: bool = False) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer Telegram id")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer Telegram id") from exc
    if normalized == 0 or (normalized < 0 and not allow_negative):
        raise ValueError(f"{field} is invalid")
    return normalized


def _normalize_optional_identity_text(value: object, max_length: int) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    return normalized[:max_length]


def upsert_customer_identity(
    conn: sqlite3.Connection,
    *,
    telegram_user_id: int,
    telegram_chat_id: int,
    username: str | None = None,
    first_name: str | None = None,
) -> dict:
    """Create/refresh one Telegram customer identity and return its DB record.

    Status is deliberately never overwritten here: a future blocked/disabled
    customer cannot reactivate itself just by sending /start again.
    """
    user_id = _normalize_telegram_id(telegram_user_id, "telegram_user_id")
    chat_id = _normalize_telegram_id(
        telegram_chat_id,
        "telegram_chat_id",
        allow_negative=True,
    )
    username_n = _normalize_optional_identity_text(username, 64)
    first_name_n = _normalize_optional_identity_text(first_name, 255)

    conn.execute(
        """
        INSERT INTO customers(
            telegram_user_id, telegram_chat_id, username, first_name
        ) VALUES (?, ?, ?, ?)
        ON CONFLICT(telegram_user_id) DO UPDATE SET
            telegram_chat_id=excluded.telegram_chat_id,
            username=excluded.username,
            first_name=excluded.first_name,
            updated_at=CURRENT_TIMESTAMP
        """,
        (user_id, chat_id, username_n, first_name_n),
    )
    row = conn.execute(
        """
        SELECT id, telegram_user_id, telegram_chat_id, username, first_name, status
        FROM customers
        WHERE telegram_user_id=?
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("customer identity upsert did not return a record")
    return {
        "id": int(row[0]),
        "telegram_user_id": int(row[1]),
        "telegram_chat_id": int(row[2]),
        "username": row[3],
        "first_name": row[4],
        "status": str(row[5] or ""),
    }
