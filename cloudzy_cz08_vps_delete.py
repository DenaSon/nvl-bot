"""CZ-08: guarded Cloudzy VPS deletion, independent of Relay IP constants.

Provider inventory is authoritative for what exists; NVL SQLite is authoritative
for routing roles. A missing or inconsistent database disables delete, not list.
A durable deletion intent prevents blind replay of uncertain provider writes.
"""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import os
import re
import secrets
import sqlite3
import time

VALID_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,98}\Z")
ACTIVE = "status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"


class DeletionHold(RuntimeError):
    pass


def ipv4_from_service(value):
    """Extract a public IPv4 without mistaking a private/WG IP for a VPS address."""
    if not isinstance(value, dict):
        return None
    root = value.get("data", value)
    if isinstance(root, dict):
        root = root.get("service", root.get("server", root))
    if not isinstance(root, dict):
        return None
    candidates = [root.get(k) for k in (
        "primaryIpv4", "primaryIPv4", "ipv4", "publicIp", "ipAddress", "ip")]
    for field in ("ips", "ipAddresses", "addresses"):
        records = root.get(field)
        if isinstance(records, list):
            for record in records:
                if isinstance(record, str):
                    candidates.append(record)
                elif isinstance(record, dict):
                    candidates.extend(record.get(k) for k in ("address", "ip", "ipAddress", "ipv4"))
    for value in candidates:
        try:
            ip = ipaddress.IPv4Address(value)
            if ip.is_global:
                return str(ip)
        except (ipaddress.AddressValueError, ValueError, TypeError):
            continue
    return None


def default_connection():
    path = os.environ.get("NVL_DB_PATH", "/root/master_bot.db")
    # A missing DB must NOT silently create an empty SQLite file.
    return sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=15)


class CloudzyDeleteGuard:
    def __init__(self, db_factory=default_connection, *, now=time.time):
        self.db_factory = db_factory
        self.now = now

    @contextmanager
    def _db(self):
        db = self.db_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _table(db, name):
        return db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    @staticmethod
    def _initialize(db):
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz08_deletions (
            id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            ipv4 TEXT NOT NULL,
            actor INTEGER NOT NULL,
            chat INTEGER NOT NULL,
            status TEXT NOT NULL,
            detail_code TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz08_one_open_per_server
            ON cloudzy_cz08_deletions (provider_id)
            WHERE status IN ('DELETING','HOLD')""")

    @staticmethod
    def _status(db, provider_id, ipv4):
        defaults = db.execute(
            "SELECT host,provider_instance_id FROM host_pool "
            "WHERE active=1 AND is_default=1"
        ).fetchall()
        if len(defaults) != 1:
            return ("UNKNOWN", "DEFAULT_AMBIGUOUS")
        default_host, default_id = defaults[0]
        settings = dict(db.execute(
            "SELECT key,value FROM settings "
            "WHERE key IN ('dns_current_ip','hosts','core_wg_public_ip'," 
            "'phase6h_auto_failover_enabled','auto_failover_mode')"
        ).fetchall())
        if (settings.get("dns_current_ip") != default_host
                or (settings.get("hosts") or "").split(",")[0] != default_host):
            return ("UNKNOWN", "DEFAULT_ROUTE_MISMATCH")
        if ipv4 == default_host or (default_id and provider_id == default_id):
            return ("PRIMARY", "PRIMARY_RELAY")
        if not ipv4:
            return ("UNKNOWN", "PROVIDER_IPV4_NOT_VERIFIED")
        if ipv4 == settings.get("core_wg_public_ip"):
            return ("PROTECTED", "CORE_SERVER")
        related = db.execute(
            "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
            "FROM host_pool WHERE host=? OR "
            "(provider='cloudzy' AND provider_instance_id=?)",
            (ipv4, provider_id),
        ).fetchall()
        # A legacy Edge can predate provider metadata. Accept only completely
        # blank legacy identity OR an exact Cloudzy ID/IP pair, never a
        # conflicting provider association.
        if any((host != ipv4 or
                not ((not prov and not pid) or
                     (prov == "cloudzy" and pid == provider_id)))
               for host, _active, _default, _standby, prov, pid in related):
            return ("PROTECTED", "PROVIDER_OWNERSHIP_CONFLICT")
        if any(is_default for _host, _active, is_default, _standby, _prov, _pid in related):
            return ("PROTECTED", "DEFAULT_HOST_REFERENCE")
        # Automatic failover protects live standby targets, not every retired
        # Edge with no customers and no route. A previously registered,
        # now-unrouted non-standby host can safely be retired after the normal
        # account/route/operation guards below. Unknown inventory remains
        # protected under global auto failover.
        if any(is_standby for _host, _active, _default, is_standby, _prov, _pid in related):
            return ("PROTECTED", "STANDBY_FAILOVER_TARGET")
        if ((settings.get("phase6h_auto_failover_enabled") == "1"
                or settings.get("auto_failover_mode") == "1")
                and not related):
            return ("PROTECTED", "AUTOMATIC_FAILOVER_ENABLED")
        if ipv4 in [h.strip() for h in (settings.get("hosts") or "").split(",")]:
            return ("PROTECTED", "CUSTOMER_HOSTS_REFERENCE")
        users = db.execute(
            "SELECT COUNT(*) FROM ssh_accounts "
            f"WHERE host=? AND {ACTIVE}", (ipv4,)
        ).fetchone()[0]
        if users:
            return ("PROTECTED", "ACTIVE_ACCOUNTS_ASSIGNED")
        if CloudzyDeleteGuard._table(db, "cloudzy_cz08_deletions"):
            pending = db.execute(
                "SELECT status FROM cloudzy_cz08_deletions "
                "WHERE provider_id=? AND status IN ('DELETING','HOLD') LIMIT 1",
                (provider_id,),
            ).fetchone()
            if pending:
                return ("PROTECTED", "DELETION_" + pending[0])
        if db.execute("SELECT 1 FROM failover_operations WHERE status='RUNNING'").fetchone():
            return ("PROTECTED", "FAILOVER_BUSY")
        if CloudzyDeleteGuard._table(db, "cloudzy_cz04b_operations") and db.execute(
            "SELECT 1 FROM cloudzy_cz04b_operations "
            "WHERE status NOT IN ('READY','DONE','ABORTED') LIMIT 1"
        ).fetchone():
            return ("PROTECTED", "CUTOVER_BUSY")
        if CloudzyDeleteGuard._table(db, "cloudzy_cz07_jobs") and db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE status NOT IN ('DONE','ABORTED') LIMIT 1"
        ).fetchone():
            return ("PROTECTED", "MIGRATION_BUSY")
        if CloudzyDeleteGuard._table(db, "cloudzy_cz04a_actions") and db.execute(
            "SELECT 1 FROM cloudzy_cz04a_actions "
            "WHERE status NOT IN ('DONE','REJECTED') LIMIT 1"
        ).fetchone():
            return ("PROTECTED", "STANDBY_ACTION_BUSY")
        if CloudzyDeleteGuard._table(db, "cloudzy_edge_operations") and db.execute(
            "SELECT 1 FROM cloudzy_edge_operations "
            "WHERE provider_server_id=? AND status NOT IN ('EDGE_READY','REJECTED','CANCELLED') LIMIT 1",
            (provider_id,),
        ).fetchone():
            return ("PROTECTED", "PROVISIONING_UNRESOLVED")
        return ("ELIGIBLE", "SAFE_NONDEFAULT")

    def status(self, provider_id, ipv4):
        if not isinstance(provider_id, str) or not VALID_ID.fullmatch(provider_id):
            return ("UNKNOWN", "PROVIDER_ID_NOT_VERIFIED")
        try:
            with self._db() as db:
                return self._status(db, provider_id, ipv4)
        except (sqlite3.Error, OSError):
            return ("UNKNOWN", "NVL_DATABASE_UNAVAILABLE")

    def reserve(self, provider_id, ipv4, *, actor, chat):
        if not isinstance(provider_id, str) or not VALID_ID.fullmatch(provider_id):
            raise DeletionHold("INVALID_PROVIDER_ID")
        if not isinstance(ipv4, str):
            raise DeletionHold("INVALID_PROVIDER_IPV4")
        try:
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                state, reason = self._status(db, provider_id, ipv4)
                if state != "ELIGIBLE":
                    raise DeletionHold(reason)
                self._initialize(db)
                opid = secrets.token_hex(16)
                now = int(self.now())
                db.execute(
                    "INSERT INTO cloudzy_cz08_deletions "
                    "(id,provider_id,ipv4,actor,chat,status,detail_code,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,'DELETING','DELETE_REQUESTED',?,?)",
                    (opid, provider_id, ipv4, actor, chat, now, now),
                )
                return opid
        except sqlite3.Error:
            raise DeletionHold("DELETION_JOURNAL_ERROR") from None

    def finish(self, opid, *, success, code):
        if not re.fullmatch(r"[A-Z0-9_]{1,64}", code):
            raise DeletionHold("INVALID_RESULT_CODE")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT provider_id,ipv4,status FROM cloudzy_cz08_deletions WHERE id=?",
                (opid,),
            ).fetchone()
            if row is None or row[2] != "DELETING":
                raise DeletionHold("DELETION_STATE_CHANGED")
            provider_id, ipv4, _ = row
            if success:
                # Remove standby/active eligibility but preserve historic host identity.
                # Never modify the default or user assignments.
                matching = db.execute(
                    "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
                    "FROM host_pool WHERE host=?",
                    (ipv4,),
                ).fetchall()
                if any(is_default or is_standby
                       for _host, _active, is_default, is_standby, _prov, _pid in matching):
                    raise DeletionHold("POST_DELETE_ROLE_CHANGED")
                if any(not ((not prov and not pid)
                            or (prov == "cloudzy" and pid == provider_id))
                       for _host, _active, _default, _standby, prov, pid in matching):
                    raise DeletionHold("POST_DELETE_OWNERSHIP_CHANGED")
                if matching:
                    # Retire even older NVL entries created before Cloudzy
                    # provider metadata was persisted. Preserve the history row.
                    db.execute(
                        "UPDATE host_pool SET active=0,is_standby=0 "
                        "WHERE host=? AND is_default=0 AND is_standby=0",
                        (ipv4,),
                    )
            db.execute(
                "UPDATE cloudzy_cz08_deletions "
                "SET status=?,detail_code=?,updated_at=? WHERE id=? AND status='DELETING'",
                ("DONE" if success else "REJECTED" if code.startswith("PROVIDER_REJECTED_") else "HOLD",
                 code, int(self.now()), opid),
            )
