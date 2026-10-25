"""CZ-04B: guarded Legacy Relay cutover + independently confirmed SSH owner moves.

The Core still terminates SSH; Edge tunnels/NAT relay to Core. No K2 UID
egress, no bulk helper/SSH password rebuild, no old srv_mkactive callbacks.
A pinned CZ03 Cloudzy Standby is eligible; old/default Edge stays online.
"""
from __future__ import annotations
import asyncio
import hashlib
from html import escape
import json
import secrets
import sqlite3
import time

from safe_failover import FAILOVER_STATUS_RUNNING
from edge_egress_k2_a_6g_shared import acquire_original_6g, update_original_6g

REF_TTL = 600
CONFIRM_TTL = 180
PAGE_SIZE = 8
MAX_BATCH = 200
CLOSED = ("READY", "DONE", "ABORTED")
RUNNING_6G = "RUNNING"
ACTIVE_STATUS = "status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
DEFAULT_LOCK = "CZ04B_DISABLED"


class CutoverHold(RuntimeError):
    pass


def _esc(s):
    return escape(str(s if s is not None else "—")[:100])


def _digest(rows):
    return hashlib.sha256(
        json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


class Cloudzy04B:
    def __init__(self, *, db_conn, guard, provider, probe, nat, dns,
                 enabled=lambda: False, now=time.time):
        self.db = db_conn
        self.guard = guard
        self.provider = provider
        self.probe = probe
        self.nat = nat
        self.dns = dns
        self.enabled = enabled
        self.now = now

    def _init(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz04b_operations (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL, status TEXT NOT NULL,
            actor INTEGER NOT NULL, chat INTEGER NOT NULL,
            source TEXT NOT NULL, target TEXT NOT NULL, provider_id TEXT NOT NULL,
            started_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            shared_6g_id INTEGER,
            old_hosts TEXT, old_dns TEXT, source_fingerprint TEXT,
            count INTEGER NOT NULL DEFAULT 0, payload_json TEXT,
            note TEXT
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz04b_one_unresolved
            ON cloudzy_cz04b_operations ((1))
            WHERE status NOT IN ('READY','DONE','ABORTED')""")

    @staticmethod
    def _settings(db):
        return dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN ("
            "'hosts','dns_current_ip','core_wg_public_ip','tls_port',"
            "'tls_passthrough','phase6h_auto_failover_enabled',"
            "'auto_failover_mode','edge_egress_v1_onboard_enabled')"
        ).fetchall())

    @staticmethod
    def _source_accounts(db, source):
        return db.execute(
            "SELECT username,host,status FROM ssh_accounts "
            "WHERE service_type='ssh' AND (host=? OR host IS NULL OR host='') "
            f"AND {ACTIVE_STATUS} ORDER BY username", (source,)
        ).fetchall()

    def _open(self, db):
        self._init(db)
        return db.execute(
            "SELECT id,status,kind FROM cloudzy_cz04b_operations "
            "WHERE status NOT IN ('READY','DONE','ABORTED') LIMIT 1"
        ).fetchone()

    @staticmethod
    def _guard_settings(st):
        if st.get("phase6h_auto_failover_enabled") == "1" or st.get("auto_failover_mode") == "1":
            raise CutoverHold("AUTOMATIC_FAILOVER_ENABLED")
        if st.get("edge_egress_v1_onboard_enabled") == "1":
            raise CutoverHold("K2_ONBOARDING_ENABLED")

    def _state(self, target, *, mode="route", locked=False):
        """Recheck authoritative roles/provider/account scope in one DB transaction."""
        with self.db() as db:
            self._init(db)
            self.guard(db)
            st = self._settings(db)
            self._guard_settings(st)
            # Do not route clients toward a Cloudzy VPS being deleted.
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                          "AND name='cloudzy_cz08_deletions'").fetchone():
                if db.execute(
                    "SELECT 1 FROM cloudzy_cz08_deletions "
                    "WHERE provider_id IN ("
                    "SELECT provider_instance_id FROM host_pool WHERE host=?) "
                    "AND status IN ('DELETING','HOLD') LIMIT 1", (target,)
                ).fetchone():
                    raise CutoverHold("TARGET_PROVIDER_DELETE_UNRESOLVED")
            if not locked and db.execute(
                "SELECT 1 FROM failover_operations WHERE status=? LIMIT 1",
                (FAILOVER_STATUS_RUNNING,),
            ).fetchone():
                raise CutoverHold("SHARED_6G_BUSY")
            if self._open(db):
                raise CutoverHold("CZ04B_UNRESOLVED_OPERATION")
            if db.execute(
                "SELECT 1 FROM cloudzy_cz04a_actions "
                "WHERE status NOT IN ('DONE','REJECTED') LIMIT 1"
            ).fetchone():
                raise CutoverHold("CZ04A_UNRESOLVED_OPERATION")
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
            ).fetchall()
            if len(defaults) != 1:
                raise CutoverHold("DEFAULT_HOST_AMBIGUOUS")
            current = str(defaults[0][0])
            if current == target:
                raise CutoverHold("TARGET_IS_ALREADY_DEFAULT")
            if current == str(st.get("core_wg_public_ip") or "") or target == str(st.get("core_wg_public_ip") or ""):
                raise CutoverHold("CORE_MUST_NOT_BE_RELAY")
            tr = db.execute(
                "SELECT active,is_default,is_standby,service_port,admin_ssh_port,"
                "provider,provider_instance_id FROM host_pool WHERE host=?", (target,)
            ).fetchone()
            sr = db.execute(
                "SELECT active,service_port FROM host_pool WHERE host=?", (current,)
            ).fetchone()
            if not tr or not sr or not tr[0] or tr[1] or not tr[2]:
                raise CutoverHold("TARGET_NOT_READY_STANDBY")
            if tr[5] != "cloudzy" or not tr[6]:
                raise CutoverHold("TARGET_NOT_MANAGED_CLOUDZY")
            receipt = db.execute(
                "SELECT host_key_type,host_key_base64 FROM cloudzy_edge_operations "
                "WHERE status='EDGE_READY' AND provider_server_id=? AND public_ipv4=?",
                (str(tr[6]), target)
            ).fetchall()
            if len(receipt) != 1 or not all(receipt[0]):
                raise CutoverHold("CZ03_VERIFIED_PIN_MISSING")
            if int(tr[3] or 0) != int(sr[1] or 0):
                raise CutoverHold("SOURCE_TARGET_SERVICE_PORT_MISMATCH")
            if not 1 <= int(tr[3] or 0) <= 65535:
                raise CutoverHold("INVALID_SERVICE_PORT")
            if st.get("dns_current_ip") != current:
                raise CutoverHold("CACHED_DNS_NOT_SOURCE")
            hosts = [h.strip() for h in st.get("hosts", "").split(",") if h.strip()]
            if not hosts or hosts[0] != current:
                raise CutoverHold("LEGACY_HOSTS_ORDER_MISMATCH")
            if target in hosts:
                raise CutoverHold("STANDBY_ALREADY_IN_CUSTOMER_HOSTS")
            other = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts "
                f"WHERE service_type='ssh' AND {ACTIVE_STATUS} "
                "AND host IS NOT NULL AND host<>'' AND host<>?",
                (current,),
            ).fetchone()[0]
            if other:
                raise CutoverHold("GLOBAL_DNS_OTHER_EXPLICIT_CUSTOMERS")
            users_target = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE host=?", (target,)
            ).fetchone()[0]
            if users_target:
                raise CutoverHold("TARGET_ALREADY_HAS_USERS")
            tls_port = int(st.get("tls_port") or "2088")
            if not 1 <= tls_port <= 65535:
                raise CutoverHold("TLS_PORT_INVALID")
            return {
                "source": current, "target": target, "provider_id": str(tr[6]),
                "customer_port": int(tr[3]), "admin_port": int(tr[4] or 22),
                "tls_port": tls_port, "hosts": st["hosts"],
                "dns": current, "users": self._source_accounts(db, current),
                "pinned_key": tuple(receipt[0]),
            }

    def _targets(self):
        with self.db() as db:
            self._init(db)
            try:
                rows = db.execute(
                    "SELECT h.host,h.provider_instance_id FROM host_pool h "
                    "JOIN cloudzy_edge_operations c "
                    "ON c.provider_server_id=h.provider_instance_id AND c.public_ipv4=h.host "
                    "WHERE h.provider='cloudzy' AND h.active=1 AND h.is_default=0 "
                    "AND h.is_standby=1 AND c.status='EDGE_READY' ORDER BY h.host"
                ).fetchall()
            except sqlite3.OperationalError:
                # No CZ03 order placed yet. Never create fake provider ownership.
                rows = []
            return [(str(ip), str(pid)) for ip, pid in rows]

    def _latest(self):
        with self.db() as db:
            self._init(db)
            return db.execute(
                "SELECT id,kind,status,source,target,provider_id,count,note "
                "FROM cloudzy_cz04b_operations ORDER BY started_at DESC,id DESC LIMIT 1"
            ).fetchone()

    def _route_ready(self):
        with self.db() as db:
            self._init(db)
            route = db.execute(
                "SELECT source,target,provider_id FROM cloudzy_cz04b_operations "
                "WHERE kind='route' AND status='READY' "
                "ORDER BY started_at DESC,id DESC LIMIT 1"
            ).fetchone()
            if not route:
                raise CutoverHold("NO_SUCCESSFUL_ROUTE_HANDOFF")
            source, target, pid = route
            default = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
            ).fetchall()
            settings = self._settings(db)
            if len(default) != 1 or default[0][0] != target:
                raise CutoverHold("DEFAULT_CHANGED_SINCE_ROUTE")
            if settings.get("dns_current_ip") != target:
                raise CutoverHold("DNS_CHANGED_SINCE_ROUTE")
            hosts = [h.strip() for h in (settings.get("hosts") or "").split(",") if h.strip()]
            if not hosts or hosts[0] != target:
                raise CutoverHold("HOST_ORDER_CHANGED")
            tr = db.execute(
                "SELECT provider,provider_instance_id,active,is_default,is_standby "
                "FROM host_pool WHERE host=?", (target,)
            ).fetchone()
            if not tr or tr != ("cloudzy", pid, 1, 1, 0):
                raise CutoverHold("TARGET_ROLE_CHANGED")
            return source, target, pid

    def _ready_probe_state(self, source, target, provider_id):
        with self.db() as db:
            self.guard(db)
            st = self._settings(db)
            self._guard_settings(st)
            row = db.execute(
                "SELECT active,is_default,is_standby,service_port,admin_ssh_port,"
                "provider,provider_instance_id FROM host_pool WHERE host=?",
                (target,)
            ).fetchone()
            if (not row or row[0:3] != (1, 1, 0)
                or row[5:] != ("cloudzy", provider_id)):
                raise CutoverHold("ROUTE_TARGET_CHANGED")
            pinned = db.execute(
                "SELECT host_key_type,host_key_base64 FROM cloudzy_edge_operations "
                "WHERE status='EDGE_READY' AND provider_server_id=? AND public_ipv4=?",
                (provider_id, target)
            ).fetchall()
            if len(pinned) != 1 or not all(pinned[0]):
                raise CutoverHold("CZ03_PIN_CHANGED")
            tls = int(st.get("tls_port") or "2088")
            if not (1 <= int(row[3] or 0) <= 65535 and
                    1 <= int(row[4] or 0) <= 65535 and 1 <= tls <= 65535):
                raise CutoverHold("INVALID_PORT")
            return {
                "source": source, "target": target, "provider_id": provider_id,
                "customer_port": int(row[3]), "admin_port": int(row[4]),
                "tls_port": tls, "pinned_key": tuple(pinned[0]),
            }

    def _migration_snapshot(self, source, target):
        with self.db() as db:
            self._init(db)
            self.guard(db)
            self._guard_settings(self._settings(db))
            if self._open(db) or db.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise CutoverHold("MIGRATION_LEASE_BUSY")
            rows = self._source_accounts(db, source)
            return rows, _digest(rows)

    def _migration_rows_locked(self, source):
        with self.db() as db:
            self.guard(db)
            rows = self._source_accounts(db, source)
            return rows, _digest(rows)

    def _reserve(self, kind, actor, chat, state, *, shared, fingerprint="", names=None):
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            self._guard_settings(self._settings(db))
            if self._open(db):
                raise CutoverHold("OPERATION_CONCURRENT")
            locked = db.execute(
                "SELECT 1 FROM failover_operations WHERE id=? AND status='RUNNING'",
                (shared,),
            ).fetchone()
            if not locked:
                raise CutoverHold("SHARED_6G_LEASE_LOST")
            # Repeat all critical route identity checks inside the same
            # BEGIN IMMEDIATE reservation that precedes the DNS write intent.
            if kind == "route":
                current = db.execute(
                    "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
                ).fetchall()
                tr = db.execute(
                    "SELECT active,is_default,is_standby,provider,provider_instance_id "
                    "FROM host_pool WHERE host=?", (state["target"],)
                ).fetchone()
                st = self._settings(db)
                receipt = db.execute(
                    "SELECT COUNT(*) FROM cloudzy_edge_operations "
                    "WHERE status='EDGE_READY' AND provider_server_id=? AND public_ipv4=?",
                    (state["provider_id"], state["target"])
                ).fetchone()[0]
                if (len(current) != 1 or current[0][0] != state["source"]
                    or tr != (1, 0, 1, "cloudzy", state["provider_id"])
                    or st.get("dns_current_ip") != state.get("dns")
                    or st.get("hosts") != state.get("hosts")
                    or receipt != 1
                    or _digest(self._source_accounts(db, state["source"]))
                    != state.get("fingerprint")):
                    raise CutoverHold("ROUTE_RESERVATION_SNAPSHOT_CHANGED")
            op_id = secrets.token_hex(16)
            ts = int(self.now())
            db.execute("""
                INSERT INTO cloudzy_cz04b_operations
                (id,kind,status,actor,chat,source,target,provider_id,
                 started_at,updated_at,shared_6g_id,old_hosts,old_dns,
                 source_fingerprint,count,payload_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                op_id, kind, "PREPARING", actor, chat, state["source"],
                state["target"], state["provider_id"], ts, ts,
                shared, state.get("hosts"), state.get("dns"), fingerprint,
                len(names or []), json.dumps(names or [], ensure_ascii=False),
            ))
            return op_id

    def _transition(self, op_id, status, note=""):
        with self.db() as db:
            n = db.execute(
                "UPDATE cloudzy_cz04b_operations SET status=?,updated_at=?,note=? "
                "WHERE id=? AND status NOT IN ('READY','DONE','ABORTED')",
                (status, int(self.now()), str(note)[:100], op_id)
            ).rowcount
            if n != 1:
                raise CutoverHold("OPERATION_JOURNAL_STALE")

    def _shared_finish(self, lock_id, *, completed, hold=False):
        update_original_6g(
            self.db, lock_id, status=("SUCCEEDED" if completed else
                                      "RUNNING" if hold else "FAILED"),
            detail={"phase": ("EGRESS_RECOVERY_REQUIRED" if hold else
                              "CZ04B_ROUTE_COMPLETED" if completed else "CZ04B_ABORTED")},
            finished=not hold, require_running=True,
        )

    async def _fresh(self, state, *, check_nat=True):
        if await self.provider(state["target"], state["provider_id"]) is not True:
            raise CutoverHold("CLOUDZY_PROVIDER_ID_STATUS_IP_UNVERIFIED")
        if await self.probe(state["target"], state["customer_port"],
                            state["admin_port"]) is not True:
            raise CutoverHold("CUSTOMER_ADMIN_WG_PREFLIGHT_FAILED")
        if check_nat and await self.nat(
                state["target"], state["admin_port"],
                state["customer_port"], state["tls_port"],
                state["pinned_key"]) is not True:
            raise CutoverHold("PINNED_SSH_NAT_RULES_NOT_VERIFIED")

    @staticmethod
    def _expect_dns(snapshot, host):
        if not snapshot or any(item["ip"] != host for item in snapshot):
            raise CutoverHold("LIVE_DNS_NOT_EXPECTED_IP")

    def _commit_route(self, op_id, state):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            self._guard_settings(self._settings(db))
            live = db.execute(
                "SELECT status,shared_6g_id FROM cloudzy_cz04b_operations "
                "WHERE id=? AND kind='route'", (op_id,)
            ).fetchone()
            if not live or live[0] != "DNS_TARGET_CONFIRMED":
                raise CutoverHold("ROUTE_JOURNAL_NOT_READY")
            if not db.execute(
                "SELECT 1 FROM failover_operations WHERE id=? AND status='RUNNING'",
                (live[1],),
            ).fetchone():
                raise CutoverHold("SHARED_LEASE_LOST")
            src, dst = state["source"], state["target"]
            current = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
            ).fetchall()
            if len(current) != 1 or current[0][0] != src:
                raise CutoverHold("SOURCE_DEFAULT_CHANGED")
            row = db.execute(
                "SELECT active,is_default,is_standby,provider,provider_instance_id "
                "FROM host_pool WHERE host=?", (dst,)
            ).fetchone()
            if row != (1, 0, 1, "cloudzy", state["provider_id"]):
                raise CutoverHold("TARGET_CHANGED")
            st = self._settings(db)
            if st.get("dns_current_ip") != src or st.get("hosts") != state["hosts"]:
                raise CutoverHold("ROUTING_METADATA_CHANGED")
            other = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts "
                f"WHERE service_type='ssh' AND {ACTIVE_STATUS} "
                "AND host IS NOT NULL AND host<>'' AND host<>?",
                (src,)
            ).fetchone()[0]
            if other or _digest(self._source_accounts(db, src)) != state["fingerprint"]:
                raise CutoverHold("ACCOUNTS_CHANGED_AFTER_PREVIEW")
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (src,))
            updated = db.execute(
                "UPDATE host_pool SET is_default=1,is_standby=0 "
                "WHERE host=? AND provider='cloudzy' AND provider_instance_id=? "
                "AND active=1 AND is_standby=1 AND is_default=0",
                (dst, state["provider_id"])
            ).rowcount
            if updated != 1:
                raise CutoverHold("TARGET_CAS_MISMATCH")
            hosts = [h.strip() for h in state["hosts"].split(",") if h.strip()]
            hosts = [dst] + [h for h in hosts if h != dst]
            for key, value in (
                ("hosts", ",".join(hosts)), ("dns_current_ip", dst),
                ("last_ip_switch_at", time.strftime("%Y-%m-%d %H:%M:%S")),
            ):
                db.execute(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
                    (key, value),
                )
            db.execute(
                "UPDATE cloudzy_cz04b_operations "
                "SET status='DB_TARGET_COMMITTED',updated_at=?,"
                "note='POST_COMMIT_DNS_VERIFICATION_REQUIRED' WHERE id=?",
                (int(self.now()), op_id)
            )

    def _route_db_postcheck(self, target):
        with self.db() as db:
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
            ).fetchall()
            st = self._settings(db)
            if (len(defaults) != 1 or defaults[0][0] != target
                or st.get("dns_current_ip") != target
                or st.get("hosts", "").split(",")[0] != target):
                raise CutoverHold("POST_COMMIT_DATABASE_ROUTE_MISMATCH")

    def _hold_after_commit(self, op_id):
        with self.db() as db:
            db.execute(
                "UPDATE cloudzy_cz04b_operations "
                "SET status='HOLD',updated_at=?,note=? WHERE id=?",
                (int(self.now()), "POST_COMMIT_RECONCILIATION_REQUIRED", op_id)
            )

    def _commit_users(self, op_id, state, fingerprint, names):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            self._guard_settings(self._settings(db))
            op = db.execute(
                "SELECT status,shared_6g_id,source_fingerprint "
                "FROM cloudzy_cz04b_operations WHERE id=? AND kind='users'",
                (op_id,)
            ).fetchone()
            if not op or op[0] != "USERS_COMMITTING" or op[2] != fingerprint:
                raise CutoverHold("MIGRATION_OP_CHANGED")
            if not db.execute(
                "SELECT 1 FROM failover_operations WHERE id=? AND status='RUNNING'",
                (op[1],)
            ).fetchone():
                raise CutoverHold("SHARED_LEASE_LOST")
            # Revalidate route without opening another SQLite connection.
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
            ).fetchall()
            st = self._settings(db)
            if (len(defaults) != 1 or defaults[0][0] != state["target"]
                    or st.get("dns_current_ip") != state["target"]
                    or st.get("hosts", "").split(",")[0] != state["target"]):
                raise CutoverHold("ROUTE_NOT_CURRENT")
            rows = self._source_accounts(db, state["source"])
            if _digest(rows) != fingerprint:
                raise CutoverHold("SOURCE_ACCOUNT_SNAPSHOT_CHANGED")
            available = {name: host for name, host, _status in rows}
            if not names or len(set(names)) != len(names) or not set(names).issubset(available):
                raise CutoverHold("MIGRATION_SELECTION_STALE")
            for name in names:
                original = available[name]
                if original is None:
                    cur = db.execute(
                        "UPDATE ssh_accounts SET host=? WHERE username=? AND host IS NULL "
                        f"AND service_type='ssh' AND {ACTIVE_STATUS}",
                        (state["target"], name)
                    )
                else:
                    cur = db.execute(
                        "UPDATE ssh_accounts SET host=? WHERE username=? AND host=? "
                        f"AND service_type='ssh' AND {ACTIVE_STATUS}",
                        (state["target"], name, original)
                    )
                if cur.rowcount != 1:
                    raise CutoverHold("ACCOUNT_CAS_MISMATCH")
            db.execute(
                "UPDATE cloudzy_cz04b_operations SET status='DONE',count=?,updated_at=?,"
                "note='SSH_HOST_CAS_COMMITTED' WHERE id=?",
                (len(names), int(self.now()), op_id)
            )

    async def _acquire(self, source, target):
        lock, busy = await asyncio.to_thread(
            acquire_original_6g, self.db, source, target,
            stale_seconds=0, parse_datetime=lambda s: None,
            allow_legacy_stale_recovery=False,
        )
        if lock:
            # Persist a recovery-protected 6G phase immediately after acquiring
            # the lease; legacy stale recovery must never steal this lease
            # after a crash between DNS write intent and journal update.
            await asyncio.to_thread(
                update_original_6g, self.db, lock,
                detail={"phase": "EGRESS_RECOVERY_REQUIRED",
                        "controller": "CLOUDZY_CZ04B_LEASE"},
                require_running=True,
            )
        return lock, busy

    async def _run_route(self, actor, chat, target):
        if not self.enabled():
            raise CutoverHold(DEFAULT_LOCK)
        state = await asyncio.to_thread(self._state, target)
        await self._fresh(state)
        initial = await asyncio.to_thread(self.dns.snapshot)
        self._expect_dns(initial, state["source"])
        fingerprint = _digest(state["users"])
        state["fingerprint"] = fingerprint
        lock, busy = await self._acquire(state["source"], target)
        if not lock:
            raise CutoverHold("SHARED_6G_BUSY")
        op_id = None
        committed = False
        try:
            # Snapshot and guards under the shared lease.
            fresh = await asyncio.to_thread(self._state, target, locked=True)
            if _digest(fresh["users"]) != fingerprint or fresh["hosts"] != state["hosts"]:
                raise CutoverHold("ROUTE_PREVIEW_STALE")
            op_id = await asyncio.to_thread(
                self._reserve, "route", actor, chat, state, shared=lock
            )
            self._transition(op_id, "DNS_WRITE_INTENT")
            await asyncio.to_thread(self.dns.set_all, initial, target)
            self._transition(op_id, "DNS_TARGET_CONFIRMED")
            actual = await asyncio.to_thread(self.dns.snapshot)
            self._expect_dns(actual, target)
            await asyncio.to_thread(self._commit_route, op_id, state)
            committed = True
            final_dns = await asyncio.to_thread(self.dns.snapshot)
            self._expect_dns(final_dns, target)
            await asyncio.to_thread(self._route_db_postcheck, target)
            await asyncio.to_thread(self._transition, op_id, "READY",
                                    "DNS_DEFAULT_READY_NO_USER_MOVE")
            await asyncio.to_thread(self._shared_finish, lock, completed=True)
            return "READY"
        except Exception:
            # Never revert a committed DB/default while DNS points to target.
            if committed:
                if op_id:
                    try:
                        await asyncio.to_thread(self._hold_after_commit, op_id)
                    except Exception:
                        pass
                try:
                    await asyncio.to_thread(
                        update_original_6g, self.db, lock,
                        detail={"phase": "EGRESS_RECOVERY_REQUIRED"},
                        require_running=True,
                    )
                except Exception:
                    pass
                raise CutoverHold("ROUTE_POSTCOMMIT_RECONCILE") from None
            try:
                observed = await asyncio.to_thread(self.dns.snapshot)
                if [r["name"] for r in observed] != [r["name"] for r in initial]:
                    raise CutoverHold("DNS_RECORD_SET_CHANGED")
                if any(r["ip"] != state["source"] for r in observed):
                    await asyncio.to_thread(self.dns.set_all, observed, state["source"])
                observed = await asyncio.to_thread(self.dns.snapshot)
                self._expect_dns(observed, state["source"])
                if op_id:
                    await asyncio.to_thread(self._transition, op_id, "ABORTED",
                                            "DNS_ROLLBACK_VERIFIED")
                await asyncio.to_thread(self._shared_finish, lock, completed=False)
            except Exception:
                if op_id:
                    try:
                        await asyncio.to_thread(self._transition, op_id, "HOLD",
                                                "MANUAL_DNS_DB_RECONCILIATION_REQUIRED")
                    except Exception:
                        pass
                try:
                    await asyncio.to_thread(
                        update_original_6g, self.db, lock,
                        detail={"phase": "EGRESS_RECOVERY_REQUIRED"},
                        require_running=True
                    )
                except Exception:
                    pass
                raise CutoverHold("DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD") from None
            raise CutoverHold("ROUTE_ABORTED_OR_PREFLIGHT_FAILED") from None

    async def _run_users(self, actor, chat, names, fp):
        if not self.enabled():
            raise CutoverHold(DEFAULT_LOCK)
        source, target, pid = await asyncio.to_thread(self._route_ready)
        rows, latest_fp = await asyncio.to_thread(self._migration_snapshot, source, target)
        if fp != latest_fp:
            raise CutoverHold("ACCOUNT_PREVIEW_EXPIRED")
        available = {r[0] for r in rows}
        if not names or not set(names).issubset(available):
            raise CutoverHold("ACCOUNT_SELECTION_INVALID")
        state = await asyncio.to_thread(self._ready_probe_state, source, target, pid)
        await self._fresh(state)
        live_dns = await asyncio.to_thread(self.dns.snapshot)
        self._expect_dns(live_dns, target)
        lock, busy = await self._acquire(source, target)
        if not lock:
            raise CutoverHold("SHARED_6G_BUSY")
        op_id = None
        committed = False
        try:
            # Confirm the route and account fingerprint under our shared lease
            # before reserving the account transaction.
            again = await asyncio.to_thread(self._route_ready)
            if again != (source, target, pid):
                raise CutoverHold("ROUTE_CHANGED_AFTER_LOCK")
            now_rows, now_fp = await asyncio.to_thread(
                self._migration_rows_locked, source,
            )
            if now_fp != fp:
                raise CutoverHold("ACCOUNT_SNAPSHOT_CHANGED_UNDER_LOCK")
            op_id = await asyncio.to_thread(
                self._reserve, "users", actor, chat, state, shared=lock,
                fingerprint=fp, names=names,
            )
            self._transition(op_id, "USERS_COMMITTING")
            await asyncio.to_thread(self._commit_users, op_id, state, fp, names)
            committed = True
            await asyncio.to_thread(self._shared_finish, lock, completed=True)
            return len(names)
        except Exception:
            if committed:
                if op_id:
                    try:
                        await asyncio.to_thread(self._hold_after_commit, op_id)
                    except Exception:
                        pass
                try:
                    await asyncio.to_thread(
                        update_original_6g, self.db, lock,
                        detail={"phase": "EGRESS_RECOVERY_REQUIRED"},
                        require_running=True,
                    )
                except Exception:
                    pass
                raise CutoverHold("USERS_POSTCOMMIT_SHARED_LEASE_UNCERTAIN") from None
            try:
                if op_id:
                    await asyncio.to_thread(
                        self._transition, op_id, "ABORTED", "USER_DB_TRANSACTION_ROLLED_BACK")
                await asyncio.to_thread(self._shared_finish, lock, completed=False)
            except Exception:
                if op_id:
                    try:
                        await asyncio.to_thread(
                            self._transition, op_id, "HOLD", "USER_DB_STATE_UNKNOWN"
                        )
                    except Exception:
                        pass
                raise CutoverHold("MIGRATION_LOCK_RECONCILIATION_REQUIRED") from None
            raise CutoverHold("MIGRATION_ABORTED") from None

    async def _display(self, query, text, rows, markup):
        await query.edit_message_text(text, reply_markup=markup(rows), parse_mode="HTML")

    @staticmethod
    def _session(context, actor, chat, now):
        session = context.user_data.get("cz5")
        if (not isinstance(session, dict) or session.get("actor") != actor
                or session.get("chat") != chat or now >= session.get("expires", 0)):
            raise CutoverHold("SESSION_EXPIRED")
        return session

    async def handle_callback(self, query, context, data, *, role, actor, chat, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ دسترسی مدیر لازم است.")
            return
        try:
            if data == "apps_cz5_home":
                targets = await asyncio.to_thread(self._targets)
                last = await asyncio.to_thread(self._latest)
                refs = {}
                buttons = []
                for ip, pid in targets[:25]:
                    key = secrets.token_hex(4)
                    refs[key] = (ip, pid)
                    buttons.append([("🎯 " + ip, "apps_cz5_target_" + key)])
                context.user_data["cz5"] = {
                    "actor": actor, "chat": chat,
                    "expires": self.now() + REF_TTL, "targets": refs,
                }
                await self._display(query,
                    "🔁 <b>CZ-04B | انتقال Relay و کاربران</b>\n\n"
                    f"Edgeهای Standby و Cloudzy تأییدشده: {len(targets)}\n"
                    f"انتقال واقعی: {'🟢 فعال با تأیید مدیر' if self.enabled() else '🔒 غیرفعال تا پذیرش عملیاتی'}\n"
                    f"آخرین Journal: {_esc(last[2]) if last else '—'}\n\n"
                    "۱) بررسی زنده SSH/WG/NAT و DNS\n"
                    "۲) تأیید مستقل تغییر مسیر\n"
                    "۳) انتقال انتخابی یا گروهی Host کاربران، با تأیید جداگانه\n"
                    "⚠️ اتصال واقعی از شبکه مشتری همچنان باید آزمایش شود.",
                    buttons + [
                        [("👥 انتقال Host کاربران", "apps_cz5_users_0")],
                        [("📋 وضعیت آخرین عملیات", "apps_cz5_status")],
                        [("↩️ Edge و Relay", "apps_cz_edge")],
                    ], markup)
                return
            if data.startswith("apps_cz5_target_"):
                session = self._session(context, actor, chat, self.now())
                token = data[len("apps_cz5_target_"):]
                target = session["targets"].get(token)
                if not target:
                    raise CutoverHold("TARGET_TOKEN_UNKNOWN")
                state = await asyncio.to_thread(self._state, target[0])
                await self._fresh(state)
                dns_snapshot = await asyncio.to_thread(self.dns.snapshot)
                self._expect_dns(dns_snapshot, state["source"])
                state_fp = _digest(state["users"])
                nonce = secrets.token_hex(8)
                session["confirm"] = {
                    "nonce": nonce, "action": "route", "target": target[0],
                    "source": state["source"], "users": state_fp,
                    "expires": self.now() + CONFIRM_TTL,
                }
                await self._display(query,
                    f"🔐 <b>بررسی تغییر Relay</b>\n\n"
                    f"مبدأ: <code>{_esc(state['source'])}</code>\n"
                    f"مقصد: <code>{_esc(target[0])}</code>\n"
                    f"کاربران SSH فعال مبدأ: {len(state['users'])}\n\n"
                    "✅ مالکیت Cloudzy، SSH، WireGuard، DNAT و DNS اکنون تأیید شدند.\n"
                    "⚠️ فقط مسیر دامنه و پیش‌فرض تغییر می‌کنند؛"
                    " Host کاربران هنوز منتقل نخواهد شد.\n"
                    "⚠️ پیش از تأیید باید اتصال واقعی مشتری به IP مقصد را مستقل تست کرده باشید.",
                    [[("✅ تأیید مستقل و اجرای تغییر مسیر", "apps_cz5_go_" + nonce)],
                     [("❌ انصراف", "apps_cz5_home")]], markup)
                return
            if data.startswith("apps_cz5_users_"):
                page_text = data[len("apps_cz5_users_"):]
                if not page_text.isascii() or not page_text.isdecimal() or len(page_text) > 3:
                    raise CutoverHold("INVALID_PAGE")
                source, target, pid = await asyncio.to_thread(self._route_ready)
                users, fingerprint = await asyncio.to_thread(
                    self._migration_snapshot, source, target
                )
                page = min(int(page_text), max(0, (len(users)-1)//PAGE_SIZE))
                shown = users[page*PAGE_SIZE:(page+1)*PAGE_SIZE]
                refs, buttons = {}, []
                for name, assigned, status in shown:
                    key = secrets.token_hex(4)
                    refs[key] = name
                    buttons.append([("👤 " + str(name)[:45], "apps_cz5_one_" + key)])
                session = {
                    "actor": actor, "chat": chat, "expires": self.now() + REF_TTL,
                    "users": refs, "source": source, "target": target,
                    "fingerprint": fingerprint, "all": [r[0] for r in users[:MAX_BATCH]],
                }
                context.user_data["cz5"] = session
                paging = []
                if page:
                    paging.append(("◀️ قبلی", "apps_cz5_users_" + str(page-1)))
                if (page+1)*PAGE_SIZE < len(users):
                    paging.append(("بعدی ▶️", "apps_cz5_users_" + str(page+1)))
                if paging:
                    buttons.append(paging)
                if users:
                    buttons.append([("👥 انتقال حداکثر ۲۰۰ کاربر باقیمانده", "apps_cz5_all")])
                buttons.append([("↩️ CZ-04B", "apps_cz5_home")])
                await self._display(query,
                    f"👥 <b>انتقال Host کاربران SSH</b>\n\n"
                    f"مبدأ قبلی: <code>{_esc(source)}</code>\n"
                    f"Relay جدید: <code>{_esc(target)}</code>\n"
                    f"کاربران فعال باقیمانده: {len(users)}\n"
                    f"صفحه {page+1} از {max(1,(len(users)+PAGE_SIZE-1)//PAGE_SIZE)}\n\n"
                    "انتقال مالکیت در دیتابیس؛ بدون دست‌زدن به رمز/اکانت لینوکس.",
                    buttons, markup)
                return
            if data == "apps_cz5_all" or data.startswith("apps_cz5_one_"):
                session = self._session(context, actor, chat, self.now())
                if not session.get("fingerprint"):
                    raise CutoverHold("USER_SELECTION_EXPIRED")
                if data == "apps_cz5_all":
                    names = list(session["all"])
                else:
                    names = [session["users"].get(data[len("apps_cz5_one_"):])]
                if not names or any(not x for x in names):
                    raise CutoverHold("EMPTY_OR_INVALID_SELECTION")
                current, fp = await asyncio.to_thread(
                    self._migration_snapshot, session["source"], session["target"]
                )
                if fp != session["fingerprint"]:
                    raise CutoverHold("ACCOUNT_SNAPSHOT_CHANGED")
                nonce = secrets.token_hex(8)
                session["confirm"] = {
                    "nonce": nonce, "action": "users", "names": names,
                    "source": session["source"], "target": session["target"],
                    "fingerprint": fp, "expires": self.now() + CONFIRM_TTL,
                }
                await self._display(query,
                    "👥 <b>تأیید مستقل انتقال کاربران</b>\n\n"
                    f"تعداد حساب SSH فعال: {len(names)}\n"
                    f"مبدأ: <code>{_esc(session['source'])}</code>\n"
                    f"مقصد: <code>{_esc(session['target'])}</code>\n\n"
                    "فقط host این حساب‌ها با CAS دیتابیس عوض می‌شود.\n"
                    "مسیر DNS و سایر کاربران دست‌نخورده‌اند.",
                    [[("✅ تأیید نهایی انتقال کاربران", "apps_cz5_go_" + nonce)],
                     [("❌ انصراف", "apps_cz5_users_0")]], markup)
                return
            if data.startswith("apps_cz5_go_"):
                session = self._session(context, actor, chat, self.now())
                confirm = session.pop("confirm", None)
                if (not isinstance(confirm, dict)
                    or confirm.get("nonce") != data[len("apps_cz5_go_"):]
                    or self.now() >= confirm.get("expires", 0)):
                    raise CutoverHold("CONFIRMATION_EXPIRED")
                if confirm["action"] == "route":
                    state = await asyncio.to_thread(
                        self._state, confirm["target"]
                    )
                    if state["source"] != confirm["source"] or _digest(state["users"]) != confirm["users"]:
                        raise CutoverHold("ROUTE_PREVIEW_CHANGED")
                    result = await self._run_route(actor, chat, confirm["target"])
                    await self._display(query,
                        "✅ <b>Relay پیش‌فرض و رکوردهای DNS تنظیم شدند.</b>\n\n"
                        "🔐 Journal مسیر READY است؛ Source قبلی فعال باقی ماند.\n"
                        "👥 کاربران هنوز جابه‌جا نشده‌اند؛ انتقال آن‌ها تأیید جدا دارد.\n"
                        "⚠️ تست واقعی اتصال و IP خروجی مشتری الزامی است.",
                        [[("👥 انتقال Host کاربران", "apps_cz5_users_0")],
                         [("📋 Journal", "apps_cz5_status")]], markup)
                    return
                if confirm["action"] == "users":
                    source, target, pid = await asyncio.to_thread(self._route_ready)
                    if source != confirm["source"] or target != confirm["target"]:
                        raise CutoverHold("ROUTE_CHANGED_AFTER_APPROVAL")
                    dns_snapshot = await asyncio.to_thread(self.dns.snapshot)
                    self._expect_dns(dns_snapshot, target)
                    count = await self._run_users(
                        actor, chat, confirm["names"], confirm["fingerprint"]
                    )
                    await self._display(query,
                        f"✅ <b>انتقال {count} حساب انجام شد.</b>\n"
                        "فقط مالکیت Host ثبت شد؛ عملیات به‌صورت اتمیک در SQLite انجام شده است.\n"
                        "اتصال و IP خروجی کاربر را مستقل بررسی کنید.",
                        [[("👥 کاربران باقیمانده", "apps_cz5_users_0")],
                         [("📋 Journal", "apps_cz5_status")]], markup)
                    return
                raise CutoverHold("UNKNOWN_ACTION")
            if data == "apps_cz5_status":
                last = await asyncio.to_thread(self._latest)
                if not last:
                    txt = "هیچ عملیات CZ-04B ثبت نشده است."
                else:
                    txt = (f"نوع: {_esc(last[1])}\nوضعیت: {_esc(last[2])}\n"
                           f"مبدأ: <code>{_esc(last[3])}</code>\n"
                           f"مقصد: <code>{_esc(last[4])}</code>\n"
                           f"کاربران: {last[6]}\n"
                           f"توضیح: {_esc(last[7])}")
                await self._display(query,
                    "📋 <b>آخرین عملیات CZ-04B</b>\n\n" + txt + "\n\n"
                    "در وضعیت HOLD یا RUNNING، عملیات دیگری انجام ندهید.",
                    [[("↩️ CZ-04B", "apps_cz5_home")]], markup)
                return
            raise CutoverHold("UNKNOWN_CALLBACK")
        except (CutoverHold, sqlite3.Error, ValueError, RuntimeError):
            await query.message.reply_text(
                "⛔️ عملیات متوقف شد؛ شرایط امنیت، وضعیت DNS/Relay یا Journal "
                "تأیید نشد. برای عملیات نیمه‌تمام وضعیت Journal و Core را بررسی کنید."
            )
        except Exception:
            await query.message.reply_text(
                "🚨 نتیجه عملیات نامشخص است؛ بدون بررسی Journal و DNS هیچ "
                "تلاش مجدد یا تغییر دستی مسیر انجام ندهید."
            )
