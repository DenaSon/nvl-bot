"""Direct Market customer wallet and top-up domain.

Phase 3 owns customer wallet reads, immutable ledger entries and card-to-card
receipt approval.  Agent finance is intentionally out of scope.
"""

from __future__ import annotations

import sqlite3
from typing import Any

MAX_TOPUP_TOMAN = 1_000_000_000
TX_KIND_TOPUP = "topup"
RECEIPT_PENDING = "pending"
RECEIPT_APPROVED = "approved"
RECEIPT_REJECTED = "rejected"


def normalize_topup_amount(value: Any) -> int:
    if isinstance(value, (bool, float)):
        raise ValueError("amount must be an integer toman value")
    try:
        amount = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("amount must be an integer toman value") from exc
    if amount <= 0:
        raise ValueError("amount must be positive")
    if amount > MAX_TOPUP_TOMAN:
        raise ValueError("amount exceeds Direct Market top-up limit")
    return amount


def _customer_exists(conn: sqlite3.Connection, customer_id: int) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM customers WHERE id=?",
            (int(customer_id),),
        ).fetchone()
        is not None
    )


def ensure_wallet(conn: sqlite3.Connection, customer_id: int) -> int:
    customer_id = int(customer_id)
    if customer_id <= 0 or not _customer_exists(conn, customer_id):
        raise ValueError("customer does not exist")
    conn.execute(
        "INSERT OR IGNORE INTO wallets(customer_id, balance_toman, reserved_toman) "
        "VALUES (?, 0, 0)",
        (customer_id,),
    )
    row = conn.execute(
        "SELECT id FROM wallets WHERE customer_id=?",
        (customer_id,),
    ).fetchone()
    if not row:
        raise RuntimeError("wallet could not be created")
    return int(row[0])


def get_wallet_snapshot(conn: sqlite3.Connection, customer_id: int) -> dict:
    wallet_id = ensure_wallet(conn, customer_id)
    row = conn.execute(
        "SELECT balance_toman, reserved_toman FROM wallets WHERE id=?",
        (wallet_id,),
    ).fetchone()
    balance = int(row[0] or 0)
    reserved = int(row[1] or 0)
    pending = conn.execute(
        """
        SELECT COUNT(*), COALESCE(SUM(amount_toman), 0)
        FROM customer_topup_receipts
        WHERE customer_id=? AND status=?
        """,
        (int(customer_id), RECEIPT_PENDING),
    ).fetchone()
    return {
        "wallet_id": wallet_id,
        "customer_id": int(customer_id),
        "balance_toman": balance,
        "reserved_toman": reserved,
        "available_toman": balance - reserved,
        "pending_topup_count": int(pending[0] or 0),
        "pending_topup_toman": int(pending[1] or 0),
    }


def create_topup_receipt(
    conn: sqlite3.Connection,
    *,
    customer_id: int,
    amount_toman: int,
    photo_id: str,
    idempotency_key: str,
) -> dict:
    customer_id = int(customer_id)
    amount = normalize_topup_amount(amount_toman)
    photo = str(photo_id or "").strip()
    idem = str(idempotency_key or "").strip()
    if not photo:
        raise ValueError("photo_id is required")
    if not idem:
        raise ValueError("idempotency_key is required")

    customer = conn.execute(
        "SELECT status FROM customers WHERE id=?",
        (customer_id,),
    ).fetchone()
    if not customer:
        raise ValueError("customer does not exist")
    if str(customer[0] or "") != "active":
        raise PermissionError("customer is not active")

    ensure_wallet(conn, customer_id)

    existing = conn.execute(
        """
        SELECT id, customer_id, amount_toman, photo_id, status
        FROM customer_topup_receipts
        WHERE idempotency_key=?
        """,
        (idem,),
    ).fetchone()
    if existing:
        if (
            int(existing[1]) != customer_id
            or int(existing[2]) != amount
            or str(existing[3]) != photo
        ):
            raise ValueError("idempotency key collision")
        return get_topup_receipt(conn, int(existing[0]))

    cur = conn.execute(
        """
        INSERT INTO customer_topup_receipts(
            customer_id, amount_toman, photo_id, idempotency_key
        ) VALUES (?, ?, ?, ?)
        """,
        (customer_id, amount, photo, idem),
    )
    return get_topup_receipt(conn, int(cur.lastrowid))


def get_topup_receipt(conn: sqlite3.Connection, receipt_id: int) -> dict | None:
    row = conn.execute(
        """
        SELECT
            r.id, r.customer_id, r.amount_toman, r.photo_id, r.status,
            r.idempotency_key, r.wallet_transaction_id, r.created_at,
            r.reviewed_at, r.reviewed_by_chat_id,
            c.telegram_user_id, c.telegram_chat_id, c.username, c.first_name
        FROM customer_topup_receipts r
        JOIN customers c ON c.id=r.customer_id
        WHERE r.id=?
        """,
        (int(receipt_id),),
    ).fetchone()
    if not row:
        return None
    return {
        "id": int(row[0]),
        "customer_id": int(row[1]),
        "amount_toman": int(row[2]),
        "photo_id": row[3],
        "status": str(row[4]),
        "idempotency_key": row[5],
        "wallet_transaction_id": int(row[6]) if row[6] is not None else None,
        "created_at": row[7],
        "reviewed_at": row[8],
        "reviewed_by_chat_id": row[9],
        "telegram_user_id": int(row[10]),
        "telegram_chat_id": int(row[11]),
        "username": row[12],
        "first_name": row[13],
    }


def _atomic_begin(conn: sqlite3.Connection, savepoint: str) -> bool:
    if conn.in_transaction:
        conn.execute(f"SAVEPOINT {savepoint}")
        return False
    conn.execute("BEGIN IMMEDIATE")
    return True


def _atomic_commit(conn: sqlite3.Connection, started_transaction: bool, savepoint: str) -> None:
    if started_transaction:
        conn.commit()
    else:
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")


def _atomic_rollback(conn: sqlite3.Connection, started_transaction: bool, savepoint: str) -> None:
    if started_transaction:
        conn.rollback()
    else:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")


def approve_topup_receipt(
    conn: sqlite3.Connection,
    *,
    receipt_id: int,
    reviewer_chat_id: int,
) -> dict:
    """Approve exactly once and atomically credit wallet + append ledger."""
    savepoint = "market_topup_approve"
    started = _atomic_begin(conn, savepoint)
    try:
        receipt = get_topup_receipt(conn, receipt_id)
        if not receipt:
            result = {"outcome": "missing", "receipt": None}
            _atomic_commit(conn, started, savepoint)
            return result

        if receipt["status"] == RECEIPT_APPROVED:
            snapshot = get_wallet_snapshot(conn, receipt["customer_id"])
            result = {
                "outcome": "already_approved",
                "receipt": receipt,
                "wallet": snapshot,
            }
            _atomic_commit(conn, started, savepoint)
            return result

        if receipt["status"] == RECEIPT_REJECTED:
            result = {"outcome": "rejected", "receipt": receipt}
            _atomic_commit(conn, started, savepoint)
            return result

        wallet_id = ensure_wallet(conn, receipt["customer_id"])
        tx_idem = f"customer-topup-receipt:{receipt['id']}"
        existing_tx = conn.execute(
            """
            SELECT id, balance_after_toman
            FROM wallet_transactions
            WHERE idempotency_key=?
            """,
            (tx_idem,),
        ).fetchone()

        if existing_tx:
            tx_id = int(existing_tx[0])
        else:
            wallet_row = conn.execute(
                "SELECT balance_toman FROM wallets WHERE id=?",
                (wallet_id,),
            ).fetchone()
            current_balance = int(wallet_row[0] or 0)
            new_balance = current_balance + int(receipt["amount_toman"])
            conn.execute(
                "UPDATE wallets SET balance_toman=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (new_balance, wallet_id),
            )
            cur = conn.execute(
                """
                INSERT INTO wallet_transactions(
                    wallet_id, customer_id, kind, amount_toman,
                    balance_after_toman, idempotency_key,
                    reference_type, reference_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    wallet_id,
                    receipt["customer_id"],
                    TX_KIND_TOPUP,
                    int(receipt["amount_toman"]),
                    new_balance,
                    tx_idem,
                    "customer_topup_receipt",
                    str(receipt["id"]),
                ),
            )
            tx_id = int(cur.lastrowid)

        conn.execute(
            """
            UPDATE customer_topup_receipts
            SET status=?, wallet_transaction_id=?,
                reviewed_at=CURRENT_TIMESTAMP, reviewed_by_chat_id=?
            WHERE id=? AND status=?
            """,
            (
                RECEIPT_APPROVED,
                tx_id,
                int(reviewer_chat_id),
                int(receipt["id"]),
                RECEIPT_PENDING,
            ),
        )

        final_receipt = get_topup_receipt(conn, receipt["id"])
        snapshot = get_wallet_snapshot(conn, receipt["customer_id"])
        result = {
            "outcome": "approved",
            "receipt": final_receipt,
            "wallet": snapshot,
        }
        _atomic_commit(conn, started, savepoint)
        return result
    except Exception:
        _atomic_rollback(conn, started, savepoint)
        raise


def reject_topup_receipt(
    conn: sqlite3.Connection,
    *,
    receipt_id: int,
    reviewer_chat_id: int,
) -> dict:
    savepoint = "market_topup_reject"
    started = _atomic_begin(conn, savepoint)
    try:
        receipt = get_topup_receipt(conn, receipt_id)
        if not receipt:
            result = {"outcome": "missing", "receipt": None}
            _atomic_commit(conn, started, savepoint)
            return result
        if receipt["status"] == RECEIPT_APPROVED:
            result = {"outcome": "approved", "receipt": receipt}
            _atomic_commit(conn, started, savepoint)
            return result
        if receipt["status"] == RECEIPT_REJECTED:
            result = {"outcome": "already_rejected", "receipt": receipt}
            _atomic_commit(conn, started, savepoint)
            return result

        conn.execute(
            """
            UPDATE customer_topup_receipts
            SET status=?, reviewed_at=CURRENT_TIMESTAMP, reviewed_by_chat_id=?
            WHERE id=? AND status=?
            """,
            (
                RECEIPT_REJECTED,
                int(reviewer_chat_id),
                int(receipt_id),
                RECEIPT_PENDING,
            ),
        )
        result = {
            "outcome": "rejected",
            "receipt": get_topup_receipt(conn, receipt_id),
        }
        _atomic_commit(conn, started, savepoint)
        return result
    except Exception:
        _atomic_rollback(conn, started, savepoint)
        raise


def list_wallet_transactions(
    conn: sqlite3.Connection,
    customer_id: int,
    *,
    limit: int = 10,
) -> list[dict]:
    ensure_wallet(conn, customer_id)
    safe_limit = max(1, min(int(limit), 50))
    rows = conn.execute(
        """
        SELECT id, kind, amount_toman, balance_after_toman,
               reference_type, reference_id, created_at
        FROM wallet_transactions
        WHERE customer_id=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(customer_id), safe_limit),
    ).fetchall()
    return [
        {
            "id": int(row[0]),
            "kind": str(row[1]),
            "amount_toman": int(row[2]),
            "balance_after_toman": int(row[3]),
            "reference_type": row[4],
            "reference_id": row[5],
            "created_at": row[6],
        }
        for row in rows
    ]
