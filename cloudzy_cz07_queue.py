"""CZ-07: opt-in guarded CZ04B cutover with a durable, bounded SSH-host job.

The CZ04B route + per-batch CAS and original 6G lease remain authoritative.
A customer-path E2E test cannot be inferred from WG/NAT/SSH probes: the
operator must attest independent real-client evidence at the UI safety gate.
No host deletion, account rebuild, K2 mutation, paid Cloudzy action or blind
route retry is implemented here.
"""
from __future__ import annotations

import asyncio
from html import escape
import logging
import secrets
import sqlite3
import time

from cloudzy_cz04b import CutoverHold, _digest
from cloudzy_service import CloudzyError
from cloudzy_phase1_ui import cz07_issue

log = logging.getLogger(__name__)
BATCH_SIZE = 50
BATCH_PAUSE_SECONDS = 0.2
APPROVAL_TTL = 180
RECOVERY_STALE_SECONDS = 120
FINAL = ("DONE", "ABORTED")
PENDING = ("QUEUED", "ROUTING", "MIGRATING", "HOLD")


class CZ07Hold(RuntimeError):
    pass


def _short(value):
    return escape(str(value or "—")[:96])


class DurableCutoverQueue:
    """One durable job at a time, one in-process async worker, explicit safe resume."""

    def __init__(self, *, db_conn, cz04b, enabled=lambda: False,
                 now=time.time, pause=asyncio.sleep):
        self.db = db_conn
        self.cz04b = cz04b
        self.enabled = enabled
        self.now = now
        self.pause = pause
        self._running = set()

    @staticmethod
    def _init(db):
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz07_jobs (
            id TEXT PRIMARY KEY, cz06_operation TEXT NOT NULL UNIQUE,
            actor INTEGER NOT NULL, chat INTEGER NOT NULL,
            source TEXT NOT NULL, target TEXT NOT NULL,
            provider_id TEXT NOT NULL, status TEXT NOT NULL,
            source_fingerprint TEXT NOT NULL,
            total INTEGER NOT NULL, moved INTEGER NOT NULL DEFAULT 0,
            evidence TEXT NOT NULL, started_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, code TEXT NOT NULL DEFAULT ''
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz07_one_unresolved
            ON cloudzy_cz07_jobs ((1)) WHERE status NOT IN ('DONE','ABORTED')""")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz07_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
            at INTEGER NOT NULL, stage TEXT NOT NULL, code TEXT NOT NULL,
            moved INTEGER NOT NULL, remaining INTEGER NOT NULL
        )""")

    def _log(self, db, job, stage, code, moved, remaining):
        db.execute("INSERT INTO cloudzy_cz07_events "
                   "(job_id,at,stage,code,moved,remaining) VALUES (?,?,?,?,?,?)",
                   (job, int(self.now()), stage, code, moved, remaining))

    def latest(self):
        with self.db() as db:
            self._init(db)
            row = db.execute("SELECT id FROM cloudzy_cz07_jobs "
                             "ORDER BY started_at DESC,id DESC LIMIT 1").fetchone()
            return self.get(row[0]) if row else None

    def get(self, job):
        with self.db() as db:
            self._init(db)
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM cloudzy_cz07_jobs WHERE id=?",
                             (job,)).fetchone()
            return dict(row) if row else None

    def candidate(self):
        """Latest CZ06 READY only; no implicit adoption of manual/foreign servers."""
        with self.db() as db:
            self._init(db)
            row = db.execute("""
                SELECT c.operation_id,e.public_ipv4,e.provider_server_id,
                       c.actor_id,c.chat_id
                FROM cloudzy_cz06_runs c
                JOIN cloudzy_edge_operations e ON e.id=c.operation_id
                JOIN host_pool h ON h.host=e.public_ipv4
                  AND h.provider='cloudzy'
                  AND h.provider_instance_id=e.provider_server_id
                WHERE c.stage='READY' AND e.status='EDGE_READY'
                  AND h.active=1 AND h.is_standby=1 AND h.is_default=0
                ORDER BY c.updated_at DESC,c.operation_id DESC LIMIT 1
            """).fetchone()
            if not row or not all(row[:3]):
                raise CZ07Hold("NO_VERIFIED_CZ06_STANDBY")
            return tuple(row)

    def readiness(self):
        """Read-only explanation of the *real* CZ-07 prerequisites.

        Never treats a manual standby or an EDGE_READY receipt as a forged
        CZ-06 READY. The exact candidate() guard remains authoritative.
        """
        # A fresh installation may have no CZ-03/CZ-06 tables yet. This
        # navigation check must remain read-only and still explain what to do.
        with self.db() as db:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('cloudzy_cz06_runs','cloudzy_edge_operations','host_pool')"
            ).fetchall()}
        if len(tables) != 3:
            return {"ready": False, "code": "NO_CZ06_RUN",
                    "target": None, "manual_standby": False}
        try:
            candidate = self.candidate()
        except CZ07Hold as exc:
            if str(exc) != "NO_VERIFIED_CZ06_STANDBY":
                raise
        else:
            return {"ready": True, "code": "READY", "target": candidate[1],
                    "manual_standby": True, "owner": (candidate[3], candidate[4])}
        with self.db() as db:
            row = db.execute("""
                SELECT c.stage,e.status,e.public_ipv4,e.provider_server_id,
                       h.active,h.is_standby,h.is_default,h.provider,
                       h.provider_instance_id
                FROM cloudzy_cz06_runs c
                LEFT JOIN cloudzy_edge_operations e ON e.id=c.operation_id
                LEFT JOIN host_pool h ON h.host=e.public_ipv4
                ORDER BY c.updated_at DESC,c.operation_id DESC LIMIT 1
            """).fetchone()
        if not row:
            return {"ready": False, "code": "NO_CZ06_RUN", "target": None,
                    "manual_standby": False}
        stage, receipt, ip, pid, active, standby, default, provider, matched_pid = row
        manual_standby = (receipt == "EDGE_READY" and active == 1
                          and standby == 1 and default == 0
                          and provider == "cloudzy" and matched_pid == pid)
        if stage == "CANCELLED":
            code = "CZ06_CANCELLED"
        elif stage == "HOLD":
            code = "CZ06_HOLD"
        elif receipt != "EDGE_READY":
            code = "EDGE_NOT_VERIFIED"
        elif not ip or active is None:
            code = "HOST_NOT_REGISTERED"
        elif provider != "cloudzy" or pid != matched_pid:
            code = "PROVIDER_MISMATCH"
        elif default == 1:
            code = "STANDBY_ALREADY_DEFAULT"
        elif active != 1 or standby != 1:
            code = "STANDBY_NOT_READY"
        elif stage in ("INSTALLING", "EDGE_READY", "STANDBY_VERIFYING"):
            code = "CZ06_STANDBY_PENDING"
        else:
            code = "CZ06_NOT_READY"
        # A historical Quick Relay receipt is NOT a CZ-07 destination.
        # Only candidate() establishes a qualified transferable target.
        return {"ready": False, "code": code, "target": None,
                "last_quick_ip": ip, "last_quick_stage": stage,
                "manual_standby": manual_standby}

    def reserve(self, candidate, source, *, actor, chat, expected_fp, expected_count):
        opid, target, pid, original_actor, original_chat = candidate
        if actor != original_actor or chat != original_chat:
            raise CZ07Hold("CZ06_OWNER_MISMATCH")
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.cz04b.guard(db)
            self.cz04b._guard_settings(self.cz04b._settings(db))
            # CZ-08 durable delete fences a pending/uncertain provider operation.
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                          "AND name='cloudzy_cz08_deletions'").fetchone():
                if db.execute(
                    "SELECT 1 FROM cloudzy_cz08_deletions "
                    "WHERE provider_id=? AND status IN ('DELETING','HOLD') LIMIT 1",
                    (pid,)
                ).fetchone():
                    raise CZ07Hold("TARGET_PROVIDER_DELETE_UNRESOLVED")

            if db.execute("SELECT 1 FROM cloudzy_cz07_jobs WHERE status NOT IN ('DONE','ABORTED')").fetchone():
                raise CZ07Hold("ANOTHER_CZ07_JOB_UNRESOLVED")
            if self.cz04b._open(db):
                raise CZ07Hold("CZ04B_UNRESOLVED")
            if db.execute("SELECT 1 FROM failover_operations WHERE status='RUNNING'").fetchone():
                raise CZ07Hold("SHARED_6G_BUSY")
            if db.execute("SELECT 1 FROM cloudzy_cz04a_actions "
                          "WHERE status NOT IN ('DONE','REJECTED')").fetchone():
                raise CZ07Hold("CZ04A_UNRESOLVED")
            row = db.execute(
                "SELECT h.active,h.is_standby,h.is_default,e.status,c.stage "
                "FROM host_pool h JOIN cloudzy_edge_operations e "
                "ON h.host=e.public_ipv4 AND h.provider_instance_id=e.provider_server_id "
                "JOIN cloudzy_cz06_runs c ON c.operation_id=e.id "
                "WHERE h.host=? AND h.provider='cloudzy' AND e.id=? AND "
                "e.provider_server_id=?",
                (target, opid, pid)).fetchone()
            if row != (1, 1, 0, "EDGE_READY", "READY"):
                raise CZ07Hold("CZ06_STANDBY_CHANGED")
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            st = self.cz04b._settings(db)
            if (defaults != [(source,)] or st.get("dns_current_ip") != source
                    or st.get("hosts", "").split(",")[0] != source
                    or target == source):
                raise CZ07Hold("SOURCE_ROUTE_CHANGED")
            rows = self.cz04b._source_accounts(db, source)
            if _digest(rows) != expected_fp or len(rows) != expected_count:
                raise CZ07Hold("ACCOUNT_PREVIEW_CHANGED")
            # CZ06_OPERATION is UNIQUE: restart an explicitly, safely closed
            # pre-route attempt in-place rather than deleting history or
            # rewriting the CZ06 identity. All prior events remain durable.
            previous = db.execute(
                "SELECT id,status,code,moved FROM cloudzy_cz07_jobs "
                "WHERE cz06_operation=?", (opid,)
            ).fetchone()
            ts = int(self.now())
            if previous:
                job, previous_status, previous_code, moved = previous
                if (previous_status != "ABORTED"
                        or previous_code != "SAFE_STALE_ROUTING_CLOSED"
                        or moved != 0):
                    raise CZ07Hold("CZ06_OPERATION_ALREADY_USED")
                if db.execute(
                    "SELECT 1 FROM cloudzy_cz07_events WHERE job_id=? "
                    "AND stage IN ('MIGRATING','DONE') LIMIT 1", (job,)
                ).fetchone():
                    raise CZ07Hold("RESTART_AFTER_MIGRATION_FORBIDDEN")
                updated = db.execute(
                    "UPDATE cloudzy_cz07_jobs SET actor=?,chat=?,source=?,target=?,"
                    "provider_id=?,source_fingerprint=?,status='QUEUED',total=?,"
                    "moved=0,evidence='OPERATOR_ATTESTED_REAL_CLIENT_E2E',"
                    "started_at=?,updated_at=?,code='' WHERE id=? "
                    "AND status='ABORTED' AND code='SAFE_STALE_ROUTING_CLOSED'",
                    (actor, chat, source, target, pid, expected_fp, len(rows),
                     ts, ts, job)
                ).rowcount
                if updated != 1:
                    raise CZ07Hold("RESTART_CAS_FAILED")
                code = "RESTART_APPROVED_AFTER_SAFE_ABORT"
            else:
                job = secrets.token_hex(16)
                db.execute("""INSERT INTO cloudzy_cz07_jobs
                    (id,cz06_operation,actor,chat,source,target,provider_id,
                     source_fingerprint,status,total,evidence,started_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,'QUEUED',?,
                            'OPERATOR_ATTESTED_REAL_CLIENT_E2E',?,?)
                """, (job, opid, actor, chat, source, target, pid,
                      expected_fp, len(rows), ts, ts))
                code = "APPROVED_AFTER_EXTERNAL_E2E_ATTESTATION"
            self._log(db, job, "QUEUED", code, 0, len(rows))
            return job

    def transition(self, job, expected, next_status, *, code="", moved=None, remaining=None):
        if next_status not in PENDING + FINAL:
            raise CZ07Hold("INVALID_JOB_STATUS")
        if not isinstance(code, str) or len(code) > 90 or any(c not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in code):
            raise CZ07Hold("INVALID_LOG_CODE")
        before = (expected,) if isinstance(expected, str) else tuple(expected)
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            rec = db.execute("SELECT status,moved,total FROM cloudzy_cz07_jobs WHERE id=?",
                             (job,)).fetchone()
            if not rec or rec[0] not in before:
                raise CZ07Hold("JOB_STAGE_CHANGED")
            moved = rec[1] if moved is None else moved
            remaining = max(0, rec[2]-moved) if remaining is None else remaining
            if moved < rec[1] or moved > rec[2] or remaining != rec[2]-moved:
                raise CZ07Hold("JOB_COUNT_INCONSISTENT")
            updated = db.execute(
                "UPDATE cloudzy_cz07_jobs SET status=?,moved=?,updated_at=?,code=? "
                "WHERE id=? AND status=?",
                (next_status, moved, int(self.now()), code, job, rec[0])
            ).rowcount
            if updated != 1:
                raise CZ07Hold("JOB_CAS_FAILED")
            self._log(db, job, next_status, code or "OK", moved, remaining)
        log.info("CZ07 job=%s stage=%s code=%s moved=%d remaining=%d",
                 job[:16], next_status, code or "OK", moved, remaining)

    def _stale_route_guard(self, db, rec):
        """Fail closed unless this zero-move job provably never cut over."""
        if not rec or rec["status"] not in ("ROUTING", "HOLD") or rec["moved"] != 0:
            raise CZ07Hold("RECOVERY_NOT_ZERO_MOVE_ROUTE")
        if rec["id"] in self._running:
            raise CZ07Hold("RECOVERY_WORKER_STILL_ACTIVE")
        if int(self.now()) - int(rec["updated_at"]) < RECOVERY_STALE_SECONDS:
            raise CZ07Hold("RECOVERY_JOB_NOT_STALE")
        live = db.execute(
            "SELECT status,moved,updated_at,source,target,provider_id,started_at "
            "FROM cloudzy_cz07_jobs WHERE id=?", (rec["id"],)
        ).fetchone()
        if live != (rec["status"], 0, rec["updated_at"], rec["source"],
                    rec["target"], rec["provider_id"], rec["started_at"]):
            raise CZ07Hold("RECOVERY_JOB_CHANGED")
        if db.execute(
            "SELECT 1 FROM cloudzy_cz07_events WHERE job_id=? "
            "AND stage IN ('MIGRATING','DONE') LIMIT 1", (rec["id"],)
        ).fetchone():
            raise CZ07Hold("RECOVERY_MIGRATION_HISTORY_PRESENT")
        if self.cz04b._open(db):
            raise CZ07Hold("RECOVERY_CZ04B_UNRESOLVED")
        # A later CZ04B journal entry may indicate even a partial DNS write,
        # including an operation whose final state is ABORTED.
        if db.execute(
            "SELECT 1 FROM cloudzy_cz04b_operations WHERE started_at>=? "
            "AND (source=? OR target=?) LIMIT 1",
            (rec["started_at"], rec["source"], rec["target"])
        ).fetchone():
            raise CZ07Hold("RECOVERY_CZ04B_HISTORY_NEEDS_REVIEW")
        if db.execute(
            "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
        ).fetchone():
            raise CZ07Hold("RECOVERY_SHARED_LEASE_BUSY")
        if db.execute(
            "SELECT 1 FROM cloudzy_cz04a_actions "
            "WHERE status NOT IN ('DONE','REJECTED') LIMIT 1"
        ).fetchone():
            raise CZ07Hold("RECOVERY_CZ04A_UNRESOLVED")
        self.cz04b._guard_settings(self.cz04b._settings(db))
        settings = self.cz04b._settings(db)
        hosts = [h.strip() for h in (settings.get("hosts") or "").split(",") if h.strip()]
        if (settings.get("dns_current_ip") != rec["source"]
                or not hosts or hosts[0] != rec["source"]
                or rec["target"] in hosts):
            raise CZ07Hold("RECOVERY_SOURCE_METADATA_CHANGED")
        defaults = db.execute(
            "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
        ).fetchall()
        if defaults != [(rec["source"],)]:
            raise CZ07Hold("RECOVERY_DEFAULT_CHANGED")
        target = db.execute(
            "SELECT active,is_default,is_standby,provider,provider_instance_id "
            "FROM host_pool WHERE host=?", (rec["target"],)
        ).fetchone()
        if target != (1, 0, 1, "cloudzy", rec["provider_id"]):
            raise CZ07Hold("RECOVERY_STANDBY_CHANGED")
        if db.execute(
            "SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",
            (rec["target"],)
        ).fetchone():
            raise CZ07Hold("RECOVERY_TARGET_HAS_ACCOUNTS")

    def recovery_preview(self, job, actor, chat):
        """Read-only Cloudflare + SQLite checks; never infer DNS from cache."""
        rec = self.get(job)
        if not rec or (actor, chat) != (rec["actor"], rec["chat"]):
            raise CZ07Hold("RECOVERY_OWNER_MISMATCH")
        with self.db() as db:
            self._stale_route_guard(db, rec)
        try:
            self.cz04b._expect_dns(self.cz04b.dns.snapshot(), rec["source"])
        except Exception as exc:
            raise CZ07Hold("RECOVERY_LIVE_DNS_UNVERIFIED") from None
        with self.db() as db:
            self._stale_route_guard(db, rec)
        return rec

    def close_stale_route(self, job, actor, chat, expected_updated_at):
        """Explicit one-use operator action. Closes metadata only, no DNS write."""
        rec = self.recovery_preview(job, actor, chat)
        if rec["updated_at"] != expected_updated_at:
            raise CZ07Hold("RECOVERY_PREVIEW_EXPIRED")
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self._stale_route_guard(db, rec)
            updated = db.execute(
                "UPDATE cloudzy_cz07_jobs SET status='ABORTED',"
                "code='SAFE_STALE_ROUTING_CLOSED',updated_at=? "
                "WHERE id=? AND status=? AND updated_at=? AND moved=0",
                (int(self.now()), job, rec["status"], rec["updated_at"])
            ).rowcount
            if updated != 1:
                raise CZ07Hold("RECOVERY_CLOSE_CAS_FAILED")
            self._log(db, job, "ABORTED", "SAFE_STALE_ROUTING_CLOSED",
                      0, rec["total"])
        log.warning("CZ07 job=%s stage=ABORTED code=SAFE_STALE_ROUTING_CLOSED", job[:16])
        return rec

    def route_pin(self, job):
        """Fix issue #191 for CZ07 only: no new SSH buyer may choose old Relay."""
        rec = self.get(job)
        if not rec or rec["status"] != "MIGRATING":
            raise CZ07Hold("PIN_JOB_NOT_MIGRATING")
        source, target = rec["source"], rec["target"]
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.cz04b.guard(db)
            self.cz04b._guard_settings(self.cz04b._settings(db))
            if self.cz04b._open(db):
                raise CZ07Hold("CZ04B_UNRESOLVED")
            if db.execute("SELECT 1 FROM failover_operations WHERE status='RUNNING'").fetchone():
                raise CZ07Hold("SHARED_6G_BUSY")
            st = self.cz04b._settings(db)
            defaults = db.execute("SELECT host FROM host_pool WHERE active=1 AND is_default=1").fetchall()
            if defaults != [(target,)] or st.get("dns_current_ip") != target:
                raise CZ07Hold("TARGET_NOT_DEFAULT")
            hosts = [h.strip() for h in (st.get("hosts") or "").split(",") if h.strip()]
            if hosts == [target]:
                return
            # The source must still be the first legacy fallback. Historic
            # inactive Relays may follow it. Drop only their *eligibility*
            # after checking there are no active customers on any third host;
            # never disable/delete their host_pool rows.
            if not hosts or hosts[0] != target or source not in hosts[1:]:
                raise CZ07Hold("HOST_LIST_NOT_EXPECTED_ROUTE")
            if db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "AND host IS NOT NULL AND host<>'' AND host NOT IN (?,?)",
                (source, target)
            ).fetchone()[0]:
                raise CZ07Hold("OTHER_ACTIVE_CUSTOMER_HOST")
            if db.execute("UPDATE settings SET value=? WHERE key='hosts' AND value=?",
                          (target, st["hosts"])).rowcount != 1:
                raise CZ07Hold("HOST_LIST_CAS_FAILED")
        log.info("CZ07 job=%s stage=ROUTING code=NEW_ENROLLMENTS_TARGET_ONLY target=%s",
                 job[:16], target)

    def remaining(self, job):
        rec = self.get(job)
        if not rec:
            raise CZ07Hold("JOB_NOT_FOUND")
        with self.db() as db:
            rows = self.cz04b._source_accounts(db, rec["source"])
        remaining = len(rows)
        moved = rec["total"] - remaining
        if moved < 0:
            raise CZ07Hold("SOURCE_USER_COUNT_INCREASED")
        return rows, moved

    def complete_guard(self, job):
        rec = self.get(job)
        with self.db() as db:
            self.cz04b.guard(db)
            st = self.cz04b._settings(db)
            self.cz04b._guard_settings(st)
            if st.get("hosts") != rec["target"] or st.get("dns_current_ip") != rec["target"]:
                raise CZ07Hold("FINAL_ROUTE_METADATA_INVALID")
            if db.execute("SELECT host FROM host_pool WHERE active=1 AND is_default=1").fetchall() != [(rec["target"],)]:
                raise CZ07Hold("FINAL_DEFAULT_CHANGED")
            # Avoid claiming completion if ANY active ssh account is on Core/old Relay/NULL.
            foreign = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "AND COALESCE(host,'') != ?", (rec["target"],)
            ).fetchone()[0]
            if foreign:
                raise CZ07Hold("ACTIVE_SSH_OUTSIDE_TARGET")

    def events(self, job, count=8):
        with self.db() as db:
            self._init(db)
            return db.execute(
                "SELECT stage,code,moved,remaining,at FROM cloudzy_cz07_events "
                "WHERE job_id=? ORDER BY seq DESC LIMIT ?", (job, count)
            ).fetchall()

    async def _notify(self, app, chat, msg):
        try:
            await app.bot.send_message(chat, msg)
        except Exception:
            log.warning("CZ07 stage=TELEGRAM code=DELIVERY_FAILED chat=%s", chat)

    def launch(self, app, job, *, resume=False):
        if job in self._running:
            raise CZ07Hold("WORKER_ALREADY_RUNNING")
        if not self.enabled() or not self.cz04b.enabled():
            raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
        rec = self.get(job)
        if not rec or rec["status"] not in (("MIGRATING",) if resume else ("QUEUED",)):
            raise CZ07Hold("JOB_NOT_LAUNCHABLE")
        self._running.add(job)

        async def worker():
            try:
                await self._work(job, app, resume=resume)
            finally:
                self._running.discard(job)

        # An async bot task never blocks the Telegram callback; each DB write
        # runs in a thread and each batch yields. Durable state survives restart.
        asyncio.create_task(worker())

    async def _work(self, job, app, *, resume):
        rec = self.get(job)
        chat = rec["chat"]
        try:
            if not resume:
                state = await asyncio.to_thread(self.cz04b._state, rec["target"])
                if (state["source"] != rec["source"] or
                        state["provider_id"] != rec["provider_id"] or
                        _digest(state["users"]) != rec["source_fingerprint"]):
                    raise CZ07Hold("APPROVAL_SOURCE_SNAPSHOT_CHANGED")
                self.transition(job, "QUEUED", "ROUTING", code="ROUTE_START")
                log.info("CZ07 job=%s stage=ROUTING code=CZ04B_GUARDED_CUTOVER_START source=%s target=%s",
                         job[:16], rec["source"], rec["target"])
                result = await self.cz04b._run_route(rec["actor"], chat, rec["target"])
                if result != "READY":
                    raise CZ07Hold("CZ04B_ROUTE_NOT_READY")
                self.transition(job, "ROUTING", "MIGRATING", code="ROUTE_READY")
            # Never retry a ROUTING job after crash: unclear DNS/DB state.
            ready = await asyncio.to_thread(self.cz04b._route_ready)
            if ready != (rec["source"], rec["target"], rec["provider_id"]):
                raise CZ07Hold("READY_ROUTE_OWNERSHIP_CHANGED")
            dns = await asyncio.to_thread(self.cz04b.dns.snapshot)
            self.cz04b._expect_dns(dns, rec["target"])
            await asyncio.to_thread(self.route_pin, job)
            while True:
                rows, moved = await asyncio.to_thread(self.remaining, job)
                if not rows:
                    # Confirm provider, current routing and NAT once more.
                    state = await asyncio.to_thread(
                        self.cz04b._ready_probe_state,
                        rec["source"], rec["target"], rec["provider_id"])
                    await self.cz04b._fresh(state)
                    dns = await asyncio.to_thread(self.cz04b.dns.snapshot)
                    self.cz04b._expect_dns(dns, rec["target"])
                    await asyncio.to_thread(self.complete_guard, job)
                    self.transition(job, "MIGRATING", "DONE", code="ALL_CUSTOMERS_ON_TARGET",
                                    moved=rec["total"], remaining=0)
                    await self._notify(app, chat, f"✅ CZ-07 تکمیل شد. کاربران منتقل‌شده: {rec['total']}. "
                                               f"شناسه: {job[:16]}. سرور قبلی همچنان روشن است.")
                    break
                # Reuse CZ04B's original 6G lease, fresh SSH/WG/NAT/DNS
                # checks and account CAS for each small batch. No OS writes.
                names = [str(row[0]) for row in rows[:BATCH_SIZE]]
                fp = _digest(rows)
                started = time.monotonic()
                count = await self.cz04b._run_users(rec["actor"], chat, names, fp)
                if count != len(names):
                    raise CZ07Hold("BATCH_ACK_MISMATCH")
                fresh_rows, moved = await asyncio.to_thread(self.remaining, job)
                self.transition(job, "MIGRATING", "MIGRATING", code="BATCH_CAS_COMMITTED",
                                moved=moved, remaining=len(fresh_rows))
                log.info("CZ07 job=%s stage=MIGRATING batch=%d elapsed_ms=%d moved=%d remaining=%d",
                         job[:16], count, int((time.monotonic()-started)*1000),
                         moved, len(fresh_rows))
                await self.pause(BATCH_PAUSE_SECONDS)
        except Exception as exc:
            safe = (exc.args[0] if isinstance(exc, (CZ07Hold, CutoverHold)) and exc.args
                    else "CLOUDZY_PROVIDER_UNAVAILABLE" if isinstance(exc, CloudzyError)
                    else type(exc).__name__)
            # Persist only the exact ASCII enum accepted by transition().
            # Previously "CloudzyError" passed the weak alnum test, then
            # transition() rejected lowercase and left ROUTING unresolved.
            safe = "".join(c if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" else "_"
                           for c in str(safe).upper()).strip("_")[:85]
            safe = safe or "UNEXPECTED_ERROR"
            log.exception("CZ07 job=%s stage=%s code=%s hold=1 source=%s target=%s",
                          job[:16], self.get(job)["status"], safe,
                          rec["source"], rec["target"])
            current = self.get(job)["status"]
            if current not in FINAL + ("HOLD",):
                try:
                    self.transition(job, current, "HOLD", code=safe)
                except Exception:
                    log.exception("CZ07 job=%s code=JOURNAL_HOLD_WRITE_FAILED", job[:16])
            await self._notify(app, chat,
                f"⛔️ CZ-07 متوقف شد. شناسه: {job[:16]} | کد: {safe}. "
                "Journalهای CZ-04B، Failover و DNS را بررسی کنید. "
                "هیچ انتقال یا تغییر مسیر را بدون بررسی مجدد اجرا نکنید.")

    async def _display(self, query, text, rows, markup):
        try:
            await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup(rows))
        except Exception as exc:
            if type(exc).__name__ == "BadRequest" and "Message is not modified" in str(exc):
                return
            raise

    async def _show_readiness(self, query, markup, actor, chat):
        snapshot = await asyncio.to_thread(self.readiness)
        ready = snapshot["ready"]
        enabled = bool(self.enabled() and self.cz04b.enabled())
        same_owner = snapshot.get("owner") == (actor, chat)
        rows = []
        if ready and enabled and same_owner:
            rows.append([("🔍 بررسی زنده پیش از انتقال", "apps_cz7_preview")])
        if ready or snapshot["manual_standby"]:
            rows.append([("↪️ بررسی مسیر دستی CZ-04B", "apps_cz5_home")])
        else:
            rows.append([("🎯 بررسی و آماده‌سازی Standby", "apps_cz4_vps")])
        rows.extend([
            [("📋 وضعیت Quick Relay", "apps_cz_operations")],
            [("📋 وضعیت صف CZ-07", "apps_cz7_status")],
            [("🔄 بررسی مجدد آمادگی", "apps_cz7_home")],
            [("↩️ Cloudzy", "apps_cz_home")],
        ])
        if ready:
            summary = ("✅ <b>Standby معتبر CZ-06 آماده است.</b>\n"
                       "برای اجرای انتقال، بررسی زنده و تأیید مستقل اتصال واقعی "
                       "از شبکه مشتری هنوز الزامی است.")
        else:
            reason, action = cz07_issue(snapshot["code"])
            summary = (f"🟡 <b>{escape(reason)}</b>\n"
                       f"↪️ {escape(action)}\n"
                       f"کد بررسی: <code>{_short(snapshot['code'])}</code>")
        if ready and not same_owner:
            summary += ("\n\n🔒 شروع انتقال خودکار فقط برای مدیر و گفتگوی "
                        "ثبت‌کننده همان عملیات مجاز است.")
        if not enabled:
            summary += ("\n\n🔒 اجرای خودکار در تنظیمات مجاز نیست؛"
                        " برای انتقال، تنظیمات عملیاتی باید جداگانه تأیید شوند.")
        if ready:
            destination = f"✅ مقصد تأییدشده: <code>{_short(snapshot['target'])}</code>\n"
        else:
            destination = "⛔️ مقصد معتبر برای CZ-07: <b>وجود ندارد</b>\n"
            last_ip = snapshot.get("last_quick_ip")
            if last_ip:
                description = ("لغوشده" if snapshot["code"] == "CZ06_CANCELLED"
                               else "تأییدنشده")
                destination += (
                    f"📁 آخرین پرونده Quick Relay ({description}): "
                    f"<code>{_short(last_ip)}</code>\n"
                    "ℹ️ این IP مقصد انتقال نیست.\n"
                )
        text = (
            "🔎 <b>CZ-07 | آمادگی انتقال خودکار</b>\n\n"
            + destination + summary +
            "\n\n🛡 ورود به این صفحه هیچ DNS، Relay یا کاربری را تغییر نمی‌دهد."
        )
        await self._display(query, text, rows, markup)

    def _session(self, context, actor, chat):
        session = context.user_data.get("cz7")
        if (not isinstance(session, dict) or session.get("actor") != actor
                or session.get("chat") != chat or self.now() > session.get("expires", 0)):
            raise CZ07Hold("APPROVAL_SESSION_EXPIRED")
        return session

    async def handle_callback(self, query, context, data, *, role, actor, chat,
                              markup, app):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data == "apps_cz7_home":
                existing = await asyncio.to_thread(self.latest)
                if existing and existing["status"] not in FINAL:
                    await self._show_status(query, existing, markup, actor, chat)
                    return
                await self._show_readiness(query, markup, actor, chat)
                return
            if data.startswith("apps_cz7_recover_"):
                job = data[len("apps_cz7_recover_"):]
                rec = await asyncio.to_thread(self.recovery_preview, job, actor, chat)
                nonce = secrets.token_hex(8)
                context.user_data["cz7_recovery"] = {
                    "actor": actor, "chat": chat, "job": job,
                    "updated_at": rec["updated_at"],
                    "nonce": nonce, "expires": self.now() + APPROVAL_TTL,
                }
                await self._display(query,
                    "🛡 <b>بازیابی Job متوقف‌شده</b>\n\n"
                    f"مبدأ: <code>{_short(rec['source'])}</code>\n"
                    f"مقصد: <code>{_short(rec['target'])}</code>\n"
                    f"جابجایی ثبت‌شده: <b>{rec['moved']}</b>\n\n"
                    "✅ مسیر پیش‌فرض، DNS زنده Cloudflare، Journalهای CZ-04B و قفل 6G "
                    "بررسی شدند و اثری از شروع Cutover این Job دیده نشد.\n"
                    "با تأیید، فقط همین Job با حفظ تاریخچه ABORTED می‌شود. "
                    "هیچ DNS، اکانت یا Relay تغییر نمی‌کند. سپس از مرحله اول "
                    "بررسی و تأیید اتصال مشتری، انتقال جدید را آغاز کنید.",
                    [[("✅ بستن امن Job گیرکرده", "apps_cz7_close_"+nonce)],
                     [("❌ انصراف", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_close_"):
                session = context.user_data.pop("cz7_recovery", None)
                if (not session or session["actor"] != actor or session["chat"] != chat
                        or self.now() > session["expires"]
                        or data != "apps_cz7_close_"+session["nonce"]):
                    raise CZ07Hold("RECOVERY_CONFIRMATION_EXPIRED")
                await asyncio.to_thread(
                    self.close_stale_route, session["job"], actor, chat,
                    session["updated_at"])
                await self._display(query,
                    "✅ <b>Job گیرکرده با حفظ تاریخچه بسته شد.</b>\n\n"
                    "مسیر DNS و کاربران بدون تغییر باقی ماندند.\n"
                    "↪️ برای شروع دوباره از مرحله اول روی دکمه زیر بزنید. "
                    "بررسی زنده Cloudzy و تأیید واقعی مشتری همچنان الزامی است.",
                    [[("🔄 شروع دوباره از مرحله اول", "apps_cz7_home")],
                     [("📋 وضعیت صف", "apps_cz7_status")]], markup)
                return
            if data == "apps_cz7_preview":
                if not self.enabled() or not self.cz04b.enabled():
                    raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
                candidate = await asyncio.to_thread(self.candidate)
                if (candidate[3], candidate[4]) != (actor, chat):
                    raise CZ07Hold("CZ06_OWNER_MISMATCH")
                state = await asyncio.to_thread(self.cz04b._state, candidate[1])
                if state["provider_id"] != candidate[2]:
                    raise CZ07Hold("PROVIDER_OWNERSHIP_CHANGED")
                await self.cz04b._fresh(state)
                snap = await asyncio.to_thread(self.cz04b.dns.snapshot)
                self.cz04b._expect_dns(snap, state["source"])
                nonce = secrets.token_hex(8)
                context.user_data["cz7"] = {
                    "actor": actor, "chat": chat, "nonce": nonce,
                    "expires": self.now() + APPROVAL_TTL,
                    "candidate": candidate, "source": state["source"],
                    "count": len(state["users"]), "fingerprint": _digest(state["users"]),
                }
                await self._display(query,
                    "🔐 <b>گیت امنیتی اتصال مستقل مشتری</b>\n\n"
                    f"مبدأ: <code>{_short(state['source'])}</code>\n"
                    f"مقصد: <code>{_short(candidate[1])}</code>\n"
                    f"کاربران فعال مبدأ: {len(state['users'])}\n\n"
                    "با تأیید زیر گواهی می‌کنید که دسترسی واقعی از شبکه مشتری، "
                    "DNS و IP خروجی را روی این IP شخصاً آزموده‌اید. "
                    "این یک تأیید انسانی است، نه نتیجه خودکار تست منطقه‌ای.\n"
                    "بعد از تأیید، تغییر DNS و انتقال دسته‌ای بدون کلیک اضافی اجرا می‌شود.",
                    [[("✅ تست واقعی تأیید شد؛ شروع خودکار", "apps_cz7_go_"+nonce)],
                     [("❌ انصراف", "apps_cz7_home")]], markup)
                return
            if data.startswith("apps_cz7_go_"):
                if not self.enabled() or not self.cz04b.enabled():
                    raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
                session = self._session(context, actor, chat)
                context.user_data.pop("cz7", None)  # exactly one attempt
                if data != "apps_cz7_go_"+session["nonce"]:
                    raise CZ07Hold("APPROVAL_NONCE_CHANGED")
                # All live guards repeat again in route + atomic job reservation.
                job = await asyncio.to_thread(
                    self.reserve, session["candidate"], session["source"],
                    actor=actor, chat=chat,
                    expected_fp=session["fingerprint"],
                    expected_count=session["count"])
                self.launch(app, job)
                await self._display(query,
                    f"⏳ <b>CZ-07 در صف اجراست</b>\nشناسه: <code>{_short(job[:16])}</code>\n"
                    "مراحل DNS و کاربران با Journal و گیت‌های CZ-04B بررسی می‌شوند.",
                    [[("🔄 وضعیت", "apps_cz7_status")]], markup)
                return
            if data == "apps_cz7_status":
                job = await asyncio.to_thread(self.latest)
                if not job:
                    await self._display(query, "📋 هنوز Job انتقالی ثبت نشده است.",
                                        [[("↩️ Cloudzy", "apps_cz_home")]], markup)
                else:
                    await self._show_status(query, job, markup, actor, chat)
                return
            if data.startswith("apps_cz7_resume_"):
                job = data[len("apps_cz7_resume_"):]
                item = await asyncio.to_thread(self.get, job)
                if not item or (actor,chat) != (item["actor"], item["chat"]):
                    raise CZ07Hold("RESUME_OWNER_MISMATCH")
                if item["status"] != "MIGRATING":
                    raise CZ07Hold("RESUME_ONLY_AFTER_ROUTE_READY")
                if not self.enabled() or not self.cz04b.enabled():
                    raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
                # Post-restart safety: never replay a route or any unresolved
                # CZ04B lease. Per-user jobs use fresh CAS and read DB truth.
                ready = await asyncio.to_thread(self.cz04b._route_ready)
                if ready != (item["source"],item["target"],item["provider_id"]):
                    raise CZ07Hold("ROUTE_NO_LONGER_VERIFIED")
                await asyncio.to_thread(self.cz04b._migration_snapshot,
                                         item["source"], item["target"])
                snap = await asyncio.to_thread(self.cz04b.dns.snapshot)
                self.cz04b._expect_dns(snap, item["target"])
                self.launch(app, job, resume=True)
                await self._display(query,
                    f"▶️ ادامه صف پس از بررسی ایمن. شناسه: <code>{_short(job[:16])}</code>",
                    [[("🔄 وضعیت", "apps_cz7_status")]], markup)
                return
            raise CZ07Hold("UNKNOWN_CZ07_CALLBACK")
        except (CZ07Hold, CutoverHold, CloudzyError, sqlite3.Error, ValueError) as exc:
            code = ("CLOUDZY_PROVIDER_UNAVAILABLE" if isinstance(exc, CloudzyError)
                    else str(exc) if isinstance(exc, (CZ07Hold, CutoverHold))
                    else type(exc).__name__)
            code = code if code.isascii() and code.replace("_", "").isalnum() else "CHECK_FAILED"
            log.warning("CZ07 stage=UI actor=%s code=%s", actor, code[:90])
            if code in ("NO_VERIFIED_CZ06_STANDBY", "CZ06_STANDBY_CHANGED"):
                await self._show_readiness(query, markup, actor, chat)
                return
            reason, action = cz07_issue(code)
            try:
                await self._display(query,
                    "⚠️ <b>انتقال خودکار متوقف شد.</b>\n\n"
                    f"{escape(reason)}\n↪️ {escape(action)}\n"
                    f"کد فنی: <code>{_short(code)}</code>\n\n"
                    "هیچ تلاش تازه‌ای را بدون بررسی Journal آغاز نکنید.",
                    [[("🔎 بررسی آمادگی انتقال", "apps_cz7_home")],
                     [("📋 وضعیت صف", "apps_cz7_status")],
                     [("↩️ Cloudzy", "apps_cz_home")]], markup)
            except Exception:
                await query.message.reply_text(
                    "⚠️ انتقال متوقف شد؛ وضعیت را از بخش بررسی آمادگی پیگیری کنید.")
        except Exception:
            ref = secrets.token_hex(4)
            log.exception("CZ07 stage=UI ref=%s code=UNEXPECTED", ref)
            await query.message.reply_text(
                f"🚨 خطای نامشخص CZ-07؛ پیگیری {ref}. هیچ اقدام مجدد انجام ندهید.")

    async def _show_status(self, query, job, markup, actor, chat):
        """Read-only CZ-07 progress. The journal remains the only authority."""
        labels = {
            "QUEUED": "در صف بررسی و انتقال",
            "ROUTING": "در حال بررسی و تنظیم مسیر",
            "MIGRATING": "در حال انتقال مرحله‌ای کاربران",
            "HOLD": "توقف امن؛ نیازمند بررسی",
            "DONE": "انتقال ثبت‌شده به پایان رسید",
            "ABORTED": "عملیات متوقف و بسته شده است",
        }
        status = job["status"]
        events = await asyncio.to_thread(self.events, job["id"])
        lines = [f"▫️ {_short(stage)} · {_short(code)} | {moved}/{job['total']}"
                 for stage, code, moved, _remaining, _at in events[:5]]
        rows = [[("🔄 تازه‌سازی وضعیت", "apps_cz7_status")]]
        if ((actor, chat) == (job["actor"], job["chat"])
                and status == "MIGRATING"
                and job["id"] not in self._running):
            rows.insert(0, [("▶️ بررسی و ادامه امن صف", "apps_cz7_resume_"+job["id"])])
        if ((actor, chat) == (job["actor"], job["chat"])
                and status in ("ROUTING", "HOLD") and job["moved"] == 0
                and job["id"] not in self._running):
            rows.insert(0, [("🛠 بررسی و بستن امن Job گیرکرده",
                             "apps_cz7_recover_"+job["id"])])
        rows.append([("↩️ Cloudzy", "apps_cz_home")])
        elapsed = max(0, int(self.now()) - int(job.get("updated_at") or self.now()))
        minutes, seconds = divmod(elapsed, 60)
        note = (
            "🔒 عملیات در توقف امن قرار دارد. پیش از هر تغییر، وضعیت DNS،"
            " Journal و قفل 6G باید بررسی شوند."
            if status == "HOLD" else
            "⏳ این مرحله در جریان است؛ عملیات تازه یا انتقال دوم آغاز نکنید."
            if status in ("QUEUED", "ROUTING", "MIGRATING") else
            "ℹ️ نتیجه نهایی ثبت‌شده را با اتصال واقعی مشتری جداگانه کنترل کنید."
            if status == "DONE" else
            "ℹ️ پیش از اقدام جدید وضعیت سرور و منابع فعلی را بررسی کنید."
        )
        detail = (f"\nکد ثبت‌شده: <code>{_short(job['code'])}</code>"
                  if job.get("code") else "")
        await self._display(query,
            "📋 <b>CZ-07 | وضعیت انتقال</b>\n"
            f"شناسه: <code>{_short(job['id'][:16])}</code>\n"
            f"وضعیت: <b>{_short(labels.get(status, 'وضعیت نیازمند بررسی است'))}</b>\n"
            f"مبدأ: <code>{_short(job['source'])}</code>\n"
            f"مقصد: <code>{_short(job['target'])}</code>\n"
            f"کاربران ثبت‌شده: <b>{job['moved']}/{job['total']}</b>\n"
            + (f"⏱ زمان از آخرین ثبت مرحله: {minutes:02d}:{seconds:02d}\n"
               if status in ("QUEUED", "ROUTING", "MIGRATING") else "")
            + detail + "\n\n" + note
            + (("\n\n<b>سوابق اخیر</b>\n" + "\n".join(lines)) if lines else ""),
            rows, markup)
