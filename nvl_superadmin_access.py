"""Authoritative, fail-closed NVL Super Admin access from existing bot_access.

The legacy bot has shared-admin-password logins and persisted sessions. Those are
NOT Super Admin authorization. All privileged menus/callbacks and private
notifications must check role=super_admin, active=1 in the current SQLite DB.

This module never changes the schema or writes to any database.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

# Explicitly revoked legacy principal: permanently deny even if a stale
# login session, a shared MASTER_PASS, or admin_chat_ids still includes it.
REVOKED_LEGACY_ADMIN_ID = 1947045855


def is_revoked_principal(user_id: object) -> bool:
    return type(user_id) is int and user_id == REVOKED_LEGACY_ADMIN_ID


def _read_access(db_path: str, user_id: int | None = None) -> set[int]:
    try:
        path = Path(db_path).expanduser().resolve(strict=True)
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=3) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=3000")
            if user_id is None:
                rows = db.execute("""
                    SELECT telegram_id FROM bot_access
                    WHERE role='super_admin' AND active=1
                """)
            else:
                rows = db.execute("""
                    SELECT telegram_id FROM bot_access
                    WHERE role='super_admin' AND active=1 AND telegram_id=?
                """, (user_id,))
            allowed = set()
            for (raw_id,) in rows:
                try:
                    value = int(raw_id)
                    if value > 0 and value != REVOKED_LEGACY_ADMIN_ID:
                        allowed.add(value)
                except (TypeError, ValueError, OverflowError):
                    continue
            return allowed
    except (sqlite3.Error, OSError, ValueError):
        # Never fall back to a hardcoded admin ID on DB failure.
        return set()


def active_superadmin_ids(db_path: str) -> frozenset[int]:
    return frozenset(_read_access(db_path))


def is_active_superadmin(db_path: str, user_id: object) -> bool:
    if type(user_id) is not int or user_id <= 0 or is_revoked_principal(user_id):
        return False
    return user_id in _read_access(db_path, user_id=user_id)


def is_private_superadmin(
    db_path: str, user_id: object, chat_id: object, chat_type: object
) -> bool:
    return (
        type(user_id) is int
        and type(chat_id) is int
        and user_id == chat_id
        and str(chat_type) == "private"
        and is_active_superadmin(db_path, user_id)
    )


def permitted_notification_ids(db_path: str, legacy_admin_ids=()) -> frozenset[int]:
    """Preserve authorized legacy admin recipients, but ban revoked principal.

    Active bot_access super_admin records override old agent-role collisions:
    a legitimate Super Admin can also have historical agents.telegram_id.
    """
    result = set(active_superadmin_ids(db_path))
    for raw in legacy_admin_ids:
        try:
            value = int(raw)
            if value > 0 and not is_revoked_principal(value):
                result.add(value)
        except (TypeError, ValueError, OverflowError):
            continue
    result.discard(REVOKED_LEGACY_ADMIN_ID)
    return frozenset(result)
