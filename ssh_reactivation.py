"""Fail-closed SSH reactivation host reconciliation (SQLite transaction caller-owned).

Only a configured active, non-standby customer Relay can be assigned to a
reactivated SSH account. A completed CZ-07 source is retired for a cutover with
the current single-host target, even if its host_pool row remains active.
This module does not perform Linux operations, DNS changes or migrations.
"""


class SSHReactivationHold(RuntimeError):
    """An unsafe SSH activation must not set status=active."""


def _table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def resolve_ssh_reactivation_host(db, previous_host):
    """Return (approved_host, reason) using a caller-held BEGIN IMMEDIATE lease.

    A valid explicit customer Relay stays pinned unless an authoritative CZ-07
    DONE cutover retired it. Unknown, inactive, standby, Core and unlisted hosts
    must be replaced only by a verifiably eligible current default.
    """
    if _table_exists(db, "cloudzy_cz07_jobs"):
        unresolved = db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE status NOT IN ('DONE','ABORTED') LIMIT 1"
        ).fetchone()
        if unresolved:
            raise SSHReactivationHold("SSH_REACTIVATION_CZ07_UNRESOLVED")

    settings = dict(db.execute(
        "SELECT key,value FROM settings "
        "WHERE key IN ('hosts','core_wg_public_ip','dns_current_ip')"
    ).fetchall())
    configured = list(dict.fromkeys(
        x.strip() for x in (settings.get("hosts") or "").split(",") if x.strip()
    ))
    core = (settings.get("core_wg_public_ip") or "").strip()
    pool = {
        host: (int(active or 0), int(standby or 0))
        for host, active, standby in db.execute(
            "SELECT host,active,is_standby FROM host_pool"
        ).fetchall()
    }

    def eligible(host):
        return bool(host and core and host != core
                    and host in configured and pool.get(host) == (1, 0))

    old = (previous_host or "").strip()
    defaults = [
        r[0] for r in db.execute(
            "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
        ).fetchall()
    ]
    default = defaults[0] if len(defaults) == 1 else None

    # A completed all-users CZ-07 cutover is authoritative; the previous
    # source may still be powered on and even active in host_pool.
    retired = False
    if old and old != default and _table_exists(db, "cloudzy_cz07_jobs"):
        retired = db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE source=? AND status='DONE' LIMIT 1", (old,)
        ).fetchone() is not None

    if eligible(old) and not retired:
        return old, "PRESERVED_VALID_EXPLICIT_HOST"

    if not default or not eligible(default):
        raise SSHReactivationHold("SSH_REACTIVATION_NO_VALID_DEFAULT_RELAY")

    if retired:
        # Only trust a retired-source redirection while the completed CZ-07
        # single-destination routing contract still holds.
        if configured != [default] or settings.get("dns_current_ip") != default:
            raise SSHReactivationHold("SSH_REACTIVATION_CZ07_ROUTE_CHANGED")
        return default, "CZ07_RETIRED_SOURCE"

    return default, "INVALID_OR_UNASSIGNED_HOST"


def audit_ssh_reactivation(db, username, previous_host, target_host, reason, actor):
    """Durable audit in the exact same transaction as status/host mutation."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS ssh_reactivation_audit ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, previous_host TEXT, target_host TEXT NOT NULL, "
        "reason TEXT NOT NULL, actor TEXT NOT NULL, "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    db.execute(
        "INSERT INTO ssh_reactivation_audit "
        "(username,previous_host,target_host,reason,actor) VALUES (?,?,?,?,?)",
        (username, previous_host, target_host, reason, str(actor or "unknown")),
    )
