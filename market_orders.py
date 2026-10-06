"""Direct Market order state machine for paid SSH purchases.

Phase 4 deliberately separates customer money/order state from provisioning.
Money is reserved before any Linux side effect. A purchase is captured only
after an active SSH service is proven to belong to the same customer/order.
"""

from __future__ import annotations

import hashlib
import sqlite3

import market_wallet

SERVICE_SSH = "ssh"

ORDER_PENDING = "pending"
ORDER_FUNDS_RESERVED = "funds_reserved"
ORDER_PROVISIONING = "provisioning"
ORDER_COMPLETED = "completed"
ORDER_FAILED = "failed"

TX_KIND_PURCHASE = "purchase"


class MarketOrderError(RuntimeError):
    pass


class PlanUnavailableError(MarketOrderError):
    pass


class InsufficientFundsError(MarketOrderError):
    def __init__(self, required_toman: int, available_toman: int):
        self.required_toman = int(required_toman)
        self.available_toman = int(available_toman)
        super().__init__(
            f"insufficient funds: required={self.required_toman} "
            f"available={self.available_toman}"
        )


class OrderStateError(MarketOrderError):
    pass


def _begin_immediate(conn: sqlite3.Connection) -> bool:
    """Start our atomic boundary without committing a caller-owned transaction."""
    if conn.in_transaction:
        conn.execute("SAVEPOINT market_order_atomic")
        return False
    conn.execute("BEGIN IMMEDIATE")
    return True


def _commit(conn: sqlite3.Connection, started_transaction: bool) -> None:
    if started_transaction:
        conn.commit()
    else:
        conn.execute("RELEASE SAVEPOINT market_order_atomic")


def _rollback(conn: sqlite3.Connection, started_transaction: bool) -> None:
    if started_transaction:
        conn.rollback()
    else:
        conn.execute("ROLLBACK TO SAVEPOINT market_order_atomic")
        conn.execute("RELEASE SAVEPOINT market_order_atomic")


def _plan_dict(row) -> dict | None:
    if not row:
        return None
    return {
        "id": int(row[0]),
        "code": str(row[1]),
        "service_type": str(row[2]),
        "title": str(row[3]),
        "duration_days": int(row[4]) if row[4] is not None else None,
        "data_limit_gb": int(row[5]) if row[5] is not None else None,
        "users_limit": int(row[6]),
        "price_toman": int(row[7]),
        "active": bool(row[8]),
        "sort_order": int(row[9]),
    }


def get_ssh_plan(
    conn: sqlite3.Connection,
    plan_id: int,
    *,
    require_active: bool = True,
) -> dict | None:
    row = conn.execute(
        """
        SELECT id, code, service_type, title, duration_days, data_limit_gb,
               users_limit, price_toman, active, sort_order
        FROM market_plans
        WHERE id=?
        """,
        (int(plan_id),),
    ).fetchone()
    plan = _plan_dict(row)
    if not plan or plan["service_type"] != SERVICE_SSH:
        return None
    if require_active and not plan["active"]:
        return None
    if (
        plan["duration_days"] is None
        or plan["duration_days"] <= 0
        or plan["users_limit"] <= 0
        or plan["price_toman"] <= 0
    ):
        return None
    return plan


def list_active_ssh_plans(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, code, service_type, title, duration_days, data_limit_gb,
               users_limit, price_toman, active, sort_order
        FROM market_plans
        WHERE service_type=? AND active=1
          AND duration_days IS NOT NULL AND duration_days > 0
          AND users_limit > 0 AND price_toman > 0
        ORDER BY sort_order ASC, id ASC
        """,
        (SERVICE_SSH,),
    ).fetchall()
    return [_plan_dict(row) for row in rows]


def _order_dict(row) -> dict | None:
    if not row:
        return None
    return {
        "id": int(row[0]),
        "order_no": str(row[1]),
        "customer_id": int(row[2]),
        "plan_id": int(row[3]),
        "service_type": str(row[4]),
        "status": str(row[5]),
        "price_toman": int(row[6]),
        "idempotency_key": str(row[7]),
        "service_username": row[8],
        "failure_reason": row[9],
        "created_at": row[10],
        "updated_at": row[11],
        "completed_at": row[12],
        "duration_days": int(row[13]) if row[13] is not None else None,
        "users_limit": int(row[14]) if row[14] is not None else None,
        "connection_mode": str(row[15] or "direct"),
        "service_host": row[16],
        "purchase_transaction_id": (
            int(row[17]) if row[17] is not None else None
        ),
        "provisioning_started_at": row[18],
        "failed_at": row[19],
    }


_ORDER_SELECT = """
    SELECT id, order_no, customer_id, plan_id, service_type, status,
           price_toman, idempotency_key, service_username, failure_reason,
           created_at, updated_at, completed_at, duration_days, users_limit,
           connection_mode, service_host, purchase_transaction_id,
           provisioning_started_at, failed_at
    FROM orders
"""


def get_order(conn: sqlite3.Connection, order_id: int) -> dict | None:
    return _order_dict(
        conn.execute(_ORDER_SELECT + " WHERE id=?", (int(order_id),)).fetchone()
    )


def _get_order_by_idempotency(
    conn: sqlite3.Connection,
    idempotency_key: str,
) -> dict | None:
    return _order_dict(
        conn.execute(
            _ORDER_SELECT + " WHERE idempotency_key=?",
            (str(idempotency_key),),
        ).fetchone()
    )


def create_ssh_order_and_reserve(
    conn: sqlite3.Connection,
    *,
    customer_id: int,
    plan_id: int,
    idempotency_key: str,
) -> dict:
    """Create exactly one order and reserve its price before provisioning."""
    customer_id = int(customer_id)
    plan_id = int(plan_id)
    idem = str(idempotency_key or "").strip()
    if not idem:
        raise ValueError("idempotency_key is required")

    started_transaction = _begin_immediate(conn)
    try:
        existing = _get_order_by_idempotency(conn, idem)
        if existing:
            if (
                existing["customer_id"] != customer_id
                or existing["plan_id"] != plan_id
                or existing["service_type"] != SERVICE_SSH
            ):
                raise OrderStateError("order idempotency key collision")
            _commit(conn, started_transaction)
            return {"outcome": "existing", "order": existing}

        customer = conn.execute(
            "SELECT status FROM customers WHERE id=?",
            (customer_id,),
        ).fetchone()
        if not customer or str(customer[0] or "") != "active":
            raise PermissionError("customer is not active")

        plan = get_ssh_plan(conn, plan_id, require_active=True)
        if not plan:
            raise PlanUnavailableError("SSH plan is unavailable")

        wallet_id = market_wallet.ensure_wallet(conn, customer_id)
        wallet_row = conn.execute(
            "SELECT balance_toman, reserved_toman FROM wallets WHERE id=?",
            (wallet_id,),
        ).fetchone()
        balance = int(wallet_row[0] or 0)
        reserved = int(wallet_row[1] or 0)
        available = balance - reserved
        price = int(plan["price_toman"])
        if available < price:
            raise InsufficientFundsError(price, available)

        order_no = "DMSSH-" + hashlib.sha256(idem.encode("utf-8")).hexdigest()[:16].upper()
        cur = conn.execute(
            """
            INSERT INTO orders(
                order_no, customer_id, plan_id, service_type, status,
                price_toman, idempotency_key, duration_days, users_limit,
                connection_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'direct')
            """,
            (
                order_no,
                customer_id,
                plan_id,
                SERVICE_SSH,
                ORDER_PENDING,
                price,
                idem,
                int(plan["duration_days"]),
                int(plan["users_limit"]),
            ),
        )
        order_id = int(cur.lastrowid)

        updated = conn.execute(
            """
            UPDATE wallets
            SET reserved_toman=reserved_toman+?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND (balance_toman-reserved_toman)>=?
            """,
            (price, wallet_id, price),
        )
        if updated.rowcount != 1:
            raise InsufficientFundsError(price, available)

        conn.execute(
            """
            UPDATE orders
            SET status=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND status=?
            """,
            (ORDER_FUNDS_RESERVED, order_id, ORDER_PENDING),
        )
        order = get_order(conn, order_id)
        _commit(conn, started_transaction)
        return {"outcome": "created", "order": order}
    except Exception:
        _rollback(conn, started_transaction)
        raise


def claim_order_for_provisioning(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
) -> dict:
    """Single-writer claim: only funds_reserved may transition to provisioning."""
    started_transaction = _begin_immediate(conn)
    try:
        order = get_order(conn, order_id)
        if not order or order["customer_id"] != int(customer_id):
            raise OrderStateError("order not found for customer")

        if order["status"] == ORDER_COMPLETED:
            _commit(conn, started_transaction)
            return {"outcome": "completed", "order": order}
        if order["status"] == ORDER_FAILED:
            _commit(conn, started_transaction)
            return {"outcome": "failed", "order": order}
        if order["status"] == ORDER_PROVISIONING:
            _commit(conn, started_transaction)
            return {"outcome": "in_progress", "order": order}
        if order["status"] != ORDER_FUNDS_RESERVED:
            raise OrderStateError(f"cannot provision order in state {order['status']}")

        cur = conn.execute(
            """
            UPDATE orders
            SET status=?, provisioning_started_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND customer_id=? AND status=?
            """,
            (
                ORDER_PROVISIONING,
                int(order_id),
                int(customer_id),
                ORDER_FUNDS_RESERVED,
            ),
        )
        if cur.rowcount != 1:
            raise OrderStateError("order provisioning claim lost")
        order = get_order(conn, order_id)
        _commit(conn, started_transaction)
        return {"outcome": "claimed", "order": order}
    except Exception:
        _rollback(conn, started_transaction)
        raise


def set_provisioning_target(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
    service_username: str,
    service_host: str,
) -> dict:
    username = str(service_username or "").strip()
    host = str(service_host or "").strip()
    if not username or not host:
        raise ValueError("service username and host are required")
    cur = conn.execute(
        """
        UPDATE orders
        SET service_username=?, service_host=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND customer_id=? AND status=?
        """,
        (
            username,
            host,
            int(order_id),
            int(customer_id),
            ORDER_PROVISIONING,
        ),
    )
    if cur.rowcount != 1:
        raise OrderStateError("cannot attach provisioning target")
    return get_order(conn, order_id)


def complete_ssh_order(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
) -> dict:
    """Capture reserved funds only after exact service ownership is proven."""
    started_transaction = _begin_immediate(conn)
    try:
        order = get_order(conn, order_id)
        if not order or order["customer_id"] != int(customer_id):
            raise OrderStateError("order not found for customer")
        if order["status"] == ORDER_COMPLETED:
            wallet = market_wallet.get_wallet_snapshot(conn, customer_id)
            _commit(conn, started_transaction)
            return {"outcome": "already_completed", "order": order, "wallet": wallet}
        if order["status"] != ORDER_PROVISIONING:
            raise OrderStateError(f"cannot complete order in state {order['status']}")
        if not order["service_username"]:
            raise OrderStateError("order has no provisioned service username")

        service = conn.execute(
            """
            SELECT username
            FROM ssh_accounts
            WHERE username=? AND customer_id=? AND market_order_id=?
              AND agent_id=0 AND service_type='ssh' AND status='🟢 فعال'
            """,
            (
                order["service_username"],
                int(customer_id),
                int(order_id),
            ),
        ).fetchone()
        if not service:
            raise OrderStateError("active SSH service ownership is not proven")

        wallet_id = market_wallet.ensure_wallet(conn, customer_id)
        wallet_row = conn.execute(
            "SELECT balance_toman, reserved_toman FROM wallets WHERE id=?",
            (wallet_id,),
        ).fetchone()
        balance = int(wallet_row[0] or 0)
        reserved = int(wallet_row[1] or 0)
        price = int(order["price_toman"])
        if balance < price or reserved < price:
            raise OrderStateError("wallet reservation invariant failed")

        new_balance = balance - price
        cur = conn.execute(
            """
            UPDATE wallets
            SET balance_toman=?, reserved_toman=reserved_toman-?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND balance_toman>=? AND reserved_toman>=?
            """,
            (new_balance, price, wallet_id, price, price),
        )
        if cur.rowcount != 1:
            raise OrderStateError("wallet capture compare-and-swap failed")

        tx_idem = f"customer-purchase-order:{order_id}"
        existing_tx = conn.execute(
            "SELECT id FROM wallet_transactions WHERE idempotency_key=?",
            (tx_idem,),
        ).fetchone()
        if existing_tx:
            raise OrderStateError("purchase ledger already exists for non-completed order")

        tx_cur = conn.execute(
            """
            INSERT INTO wallet_transactions(
                wallet_id, customer_id, order_id, kind, amount_toman,
                balance_after_toman, idempotency_key,
                reference_type, reference_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'order', ?)
            """,
            (
                wallet_id,
                int(customer_id),
                int(order_id),
                TX_KIND_PURCHASE,
                -price,
                new_balance,
                tx_idem,
                str(order_id),
            ),
        )
        tx_id = int(tx_cur.lastrowid)

        updated = conn.execute(
            """
            UPDATE orders
            SET status=?, purchase_transaction_id=?, completed_at=CURRENT_TIMESTAMP,
                failure_reason=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND customer_id=? AND status=?
            """,
            (
                ORDER_COMPLETED,
                tx_id,
                int(order_id),
                int(customer_id),
                ORDER_PROVISIONING,
            ),
        )
        if updated.rowcount != 1:
            raise OrderStateError("order completion compare-and-swap failed")

        result = {
            "outcome": "completed",
            "order": get_order(conn, order_id),
            "wallet": market_wallet.get_wallet_snapshot(conn, customer_id),
        }
        _commit(conn, started_transaction)
        return result
    except Exception:
        _rollback(conn, started_transaction)
        raise


def fail_ssh_order_and_release(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
    failure_reason: str,
) -> dict:
    """Release held money only when no service row remains for this order."""
    started_transaction = _begin_immediate(conn)
    try:
        order = get_order(conn, order_id)
        if not order or order["customer_id"] != int(customer_id):
            raise OrderStateError("order not found for customer")
        if order["status"] == ORDER_FAILED:
            wallet = market_wallet.get_wallet_snapshot(conn, customer_id)
            _commit(conn, started_transaction)
            return {"outcome": "already_failed", "order": order, "wallet": wallet}
        if order["status"] == ORDER_COMPLETED:
            raise OrderStateError("completed order cannot release reserved funds")
        if order["status"] not in (ORDER_FUNDS_RESERVED, ORDER_PROVISIONING):
            raise OrderStateError(f"cannot fail order in state {order['status']}")

        service_row = conn.execute(
            "SELECT username FROM ssh_accounts WHERE market_order_id=? LIMIT 1",
            (int(order_id),),
        ).fetchone()
        if service_row:
            raise OrderStateError(
                "service row still exists; funds must remain reserved until cleanup"
            )

        wallet_id = market_wallet.ensure_wallet(conn, customer_id)
        price = int(order["price_toman"])
        cur = conn.execute(
            """
            UPDATE wallets
            SET reserved_toman=reserved_toman-?, updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND reserved_toman>=?
            """,
            (price, wallet_id, price),
        )
        if cur.rowcount != 1:
            raise OrderStateError("wallet release invariant failed")

        reason = str(failure_reason or "provisioning failed")[:1000]
        conn.execute(
            """
            UPDATE orders
            SET status=?, failure_reason=?, failed_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND customer_id=?
            """,
            (ORDER_FAILED, reason, int(order_id), int(customer_id)),
        )
        result = {
            "outcome": "failed",
            "order": get_order(conn, order_id),
            "wallet": market_wallet.get_wallet_snapshot(conn, customer_id),
        }
        _commit(conn, started_transaction)
        return result
    except Exception:
        _rollback(conn, started_transaction)
        raise


def mark_order_recovery_required(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
    reason: str,
) -> dict:
    """Keep money reserved and record an operator-visible recovery reason."""
    message = ("RECOVERY_REQUIRED: " + str(reason or "unknown failure"))[:1000]
    cur = conn.execute(
        """
        UPDATE orders
        SET failure_reason=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND customer_id=? AND status=?
        """,
        (
            message,
            int(order_id),
            int(customer_id),
            ORDER_PROVISIONING,
        ),
    )
    if cur.rowcount != 1:
        raise OrderStateError("cannot mark recovery-required order")
    return get_order(conn, order_id)
