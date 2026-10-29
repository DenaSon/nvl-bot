"""Fail-closed SSH reactivation host reconciliation (SQLite transaction caller-owned).

Only a configured active, non-standby customer Relay can be assigned to a
reactivated SSH account. A transport-complete CZ-07 source (MOVED or DONE)
is retired when the live single-host route points at a verified default Relay,
even if its host_pool row remains active. Customer CREATE/RENEW/ISP postchecks
are not required to release the transfer lock.
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
    MOVED/DONE cutover retired it. Unknown, inactive, standby, Core and unlisted hosts
    must be replaced only by a verifiably eligible current default.
    """
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

    # An unrelated historical CZ-07 HOLD must not freeze SSH renewals.
    # Only a nonfinal job involving the current customer route (or an
    # explicitly configured previous customer host) owns this reactivation.
    # Keep the check inside the caller's BEGIN IMMEDIATE transaction.
    if _table_exists(db, "cloudzy_cz07_jobs"):
        open_jobs = db.execute(
            "SELECT source,target FROM cloudzy_cz07_jobs "
            "WHERE status NOT IN ('DONE','ABORTED','MOVED')"
        ).fetchall()
        if open_jobs:
            # Do not ignore stale migration metadata if the live single-host
            # route cannot be established from the authoritative local DB.
            if (not default or not eligible(default) or not configured
                    or configured[0] != default
                    or settings.get("dns_current_ip") != default):
                raise SSHReactivationHold(
                    "SSH_REACTIVATION_CZ07_ROUTE_UNVERIFIED")
            affected = {default}
            if eligible(old):
                affected.add(old)
            if any(source in affected or target in affected
                   for source, target in open_jobs):
                raise SSHReactivationHold(
                    "SSH_REACTIVATION_CZ07_UNRESOLVED")

    # A verified transport-complete CZ-07 cutover is authoritative; the previous
    # source may still be powered on and even active in host_pool.
    retired = False
    if old and old != default and _table_exists(db, "cloudzy_cz07_jobs"):
        retired = db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE source=? AND status IN ('DONE','MOVED') LIMIT 1", (old,)
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
