"""Direct Market order state machine for paid service purchases.

Commerce reserves money before provisioning and captures it only after the
local service registry proves exact customer/order ownership. Provisioning
implementations remain service-specific; financial state stays shared.
"""

from __future__ import annotations

import hashlib
import sqlite3

import market_wallet

SERVICE_SSH = "ssh"
SERVICE_V2RAY = "v2ray"
SERVICE_V2RAY_VOL = "v2ray_vol"
V2RAY_SERVICE_TYPES = frozenset({SERVICE_V2RAY, SERVICE_V2RAY_VOL})

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


def _valid_v2ray_plan(plan: dict | None, service_type: str) -> bool:
    if not plan or service_type not in V2RAY_SERVICE_TYPES:
        return False
    if plan["service_type"] != service_type or plan["price_toman"] <= 0:
        return False
    if plan["users_limit"] <= 0:
        return False
    if service_type == SERVICE_V2RAY:
        return plan["duration_days"] is not None and plan["duration_days"] > 0
    return plan["data_limit_gb"] is not None and plan["data_limit_gb"] > 0


def get_v2ray_plan(
    conn: sqlite3.Connection,
    plan_id: int,
    *,
    service_type: str,
    require_active: bool = True,
) -> dict | None:
    if service_type not in V2RAY_SERVICE_TYPES:
        return None
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
    if require_active and plan and not plan["active"]:
        return None
    return plan if _valid_v2ray_plan(plan, service_type) else None


def list_active_v2ray_plans(
    conn: sqlite3.Connection,
    *,
    service_type: str,
) -> list[dict]:
    if service_type not in V2RAY_SERVICE_TYPES:
        raise ValueError("invalid V2Ray market service type")
    rows = conn.execute(
        """
        SELECT id, code, service_type, title, duration_days, data_limit_gb,
               users_limit, price_toman, active, sort_order
        FROM market_plans
        WHERE service_type=? AND active=1
        ORDER BY sort_order ASC, id ASC
        """,
        (service_type,),
    ).fetchall()
    plans = [_plan_dict(row) for row in rows]
    return [plan for plan in plans if _valid_v2ray_plan(plan, service_type)]


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
        "data_limit_gb": int(row[14]) if row[14] is not None else None,
        "users_limit": int(row[15]) if row[15] is not None else None,
        "connection_mode": str(row[16] or "direct"),
        "service_host": row[17],
        "purchase_transaction_id": (
            int(row[18]) if row[18] is not None else None
        ),
        "provisioning_started_at": row[19],
        "failed_at": row[20],
    }


_ORDER_SELECT = """
    SELECT id, order_no, customer_id, plan_id, service_type, status,
           price_toman, idempotency_key, service_username, failure_reason,
           created_at, updated_at, completed_at, duration_days, data_limit_gb,
           users_limit, connection_mode, service_host, purchase_transaction_id,
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


def create_v2ray_order_and_reserve(
    conn: sqlite3.Connection,
    *,
    customer_id: int,
    plan_id: int,
    service_type: str,
    idempotency_key: str,
) -> dict:
    """Create one V2Ray order and reserve its immutable retail price."""
    if service_type not in V2RAY_SERVICE_TYPES:
        raise ValueError("invalid V2Ray market service type")

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
                or existing["service_type"] != service_type
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

        plan = get_v2ray_plan(
            conn,
            plan_id,
            service_type=service_type,
            require_active=True,
        )
        if not plan:
            raise PlanUnavailableError("V2Ray plan is unavailable")

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

        prefix = "DMV2-" if service_type == SERVICE_V2RAY else "DMV2V-"
        order_no = prefix + hashlib.sha256(idem.encode("utf-8")).hexdigest()[:16].upper()
        cur = conn.execute(
            """
            INSERT INTO orders(
                order_no, customer_id, plan_id, service_type, status,
                price_toman, idempotency_key, duration_days, data_limit_gb,
                users_limit, connection_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'v2ray')
            """,
            (
                order_no,
                customer_id,
                plan_id,
                service_type,
                ORDER_PENDING,
                price,
                idem,
                plan["duration_days"],
                plan["data_limit_gb"],
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


def _complete_order(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
    allowed_service_types: frozenset[str],
) -> dict:
    """Capture a reserved purchase after exact local ownership is proven."""
    started_transaction = _begin_immediate(conn)
    try:
        order = get_order(conn, order_id)
        if not order or order["customer_id"] != int(customer_id):
            raise OrderStateError("order not found for customer")
        if order["service_type"] not in allowed_service_types:
            raise OrderStateError("order service type does not match completion boundary")
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
              AND agent_id=0 AND service_type=? AND status='🟢 فعال'
            """,
            (
                order["service_username"],
                int(customer_id),
                int(order_id),
                order["service_type"],
            ),
        ).fetchone()
        if not service:
            raise OrderStateError("active service ownership is not proven")

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


def complete_ssh_order(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
) -> dict:
    return _complete_order(
        conn,
        order_id=order_id,
        customer_id=customer_id,
        allowed_service_types=frozenset({SERVICE_SSH}),
    )


def complete_v2ray_order(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
) -> dict:
    return _complete_order(
        conn,
        order_id=order_id,
        customer_id=customer_id,
        allowed_service_types=V2RAY_SERVICE_TYPES,
    )

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


def fail_v2ray_order_and_release(
    conn: sqlite3.Connection,
    *,
    order_id: int,
    customer_id: int,
    failure_reason: str,
) -> dict:
    # The release invariant is service-neutral: no row may still reference the order.
    return fail_ssh_order_and_release(
        conn,
        order_id=order_id,
        customer_id=customer_id,
        failure_reason=failure_reason,
    )


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
