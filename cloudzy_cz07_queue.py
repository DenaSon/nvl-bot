"""CZ-07: opt-in guarded CZ04B cutover with a durable, bounded SSH-host job.

The CZ04B route + per-batch CAS and original 6G lease remain authoritative.
A customer-path E2E test cannot be inferred from WG/NAT/SSH probes: the
operator must attest independent real-client evidence at the UI safety gate.
No host deletion, account rebuild, K2 mutation, paid Cloudzy action or blind
route retry is implemented here.
"""
from __future__ import annotations
from manual_edge_identity import assert_ref as assert_edge_ref


import asyncio
from html import escape
import logging
import secrets
import sqlite3
import time

from cloudzy_unified_native import observe_cz07_status
from cloudzy_cz04b import CutoverHold, _digest
from cloudzy_service import CloudzyError
from cloudzy_phase1_ui import cz07_issue
from cloudzy_cz07_acceptance import AcceptanceReview

log = logging.getLogger(__name__)
BATCH_SIZE = 200
BATCH_PAUSE_SECONDS = 0.2
APPROVAL_TTL = 180
RECOVERY_STALE_SECONDS = 120
FINAL = ("DONE", "ABORTED", "MOVED")  # MOVED is transport-complete, not business-accepted
PENDING = ("QUEUED", "ROUTING", "MIGRATING", "PAUSED_SAFE", "VERIFYING", "HOLD")


class CZ07Hold(RuntimeError):
    pass


def _short(value):
    return escape(str(value or "—")[:96])


class DurableCutoverQueue:
    """One durable job at a time, one in-process async worker, explicit safe resume."""

    def __init__(self, *, db_conn, cz04b, enabled=lambda: False,
                 now=time.time, pause=asyncio.sleep, acceptance_witness=None):
        self.db = db_conn
        self.cz04b = cz04b
        self.enabled = enabled
        self.now = now
        self.pause = pause
        self._running = set()
        self.acceptance_witness = acceptance_witness

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
        # Additive upgrade for existing CZ07 journals; never rewrite old jobs.
        columns = {row[1] for row in db.execute("PRAGMA table_info(cloudzy_cz07_jobs)")}
        if "cancel_requested" not in columns:
            db.execute("ALTER TABLE cloudzy_cz07_jobs "
                       "ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0")
        # Upgrade the durable one-inflight lock without ever dropping protection
        # first: create the narrower index, then retire the older broad index.
        # A MOVED job has a completed, independently rechecked transfer but
        # explicitly PENDING CREATE/RENEW/client postchecks.
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz07_one_inflight
            ON cloudzy_cz07_jobs ((1))
            WHERE status NOT IN ('DONE','ABORTED','MOVED')""")
        db.execute("DROP INDEX IF EXISTS cloudzy_cz07_one_unresolved")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz07_acceptance (
            job_id TEXT PRIMARY KEY, actor INTEGER NOT NULL, at INTEGER NOT NULL,
            create_ref TEXT NOT NULL, renew_ref TEXT NOT NULL,
            client_ref TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz07_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
            at INTEGER NOT NULL, stage TEXT NOT NULL, code TEXT NOT NULL,
            moved INTEGER NOT NULL, remaining INTEGER NOT NULL
        )""")

    def _log(self, db, job, stage, code, moved, remaining):
        db.execute("INSERT INTO cloudzy_cz07_events "
                   "(job_id,at,stage,code,moved,remaining) VALUES (?,?,?,?,?,?)",
                   (job, int(self.now()), stage, code, moved, remaining))
        # Native status and UO timeline MUST commit in the same SQLite TX.
        # Old CZ07 jobs without a UO purchase link remain legacy read-only.
        observe_cz07_status(db, job_id=job, expected_status=stage,
                            now=int(self.now()))

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

    def review_acceptance(self, job_id):
        """Read independently authenticated proof; no DB/provider writes."""
        job = self.get(job_id)
        if not job or job['status'] not in ('VERIFYING', 'MOVED'):
            return AcceptanceReview(False, 'EVIDENCE_JOB_NOT_ELIGIBLE')
        if self.acceptance_witness is None:
            return AcceptanceReview(False, 'TRUSTED_WITNESS_NOT_CONFIGURED')
        return self.acceptance_witness.review(job)

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

    def manual_candidate(self, actor, chat):
        """Explicitly adopted manual Standby; no Cloudzy purchase/GET."""
        with self.db() as db:
            self._init(db)
            row=db.execute(
                "SELECT id,ip,actor,chat FROM manual_edge_operations "
                "WHERE status='STANDBY' AND actor=? AND chat=? "
                "ORDER BY updated_at DESC LIMIT 1",(actor,chat),
            ).fetchone()
            if not row:
                raise CZ07Hold("NO_MANUAL_STANDBY")
            assert_edge_ref(db,row[1],"manual:"+row[0],require_standby=True)
            return (row[0],row[1],"manual:"+row[0],row[2],row[3])

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

            if db.execute("SELECT 1 FROM cloudzy_cz07_jobs WHERE status NOT IN ('DONE','ABORTED','MOVED')").fetchone():
                raise CZ07Hold("ANOTHER_CZ07_JOB_UNRESOLVED")
            if self.cz04b._open(db):
                raise CZ07Hold("CZ04B_UNRESOLVED")
            if db.execute("SELECT 1 FROM failover_operations WHERE status='RUNNING'").fetchone():
                raise CZ07Hold("SHARED_6G_BUSY")
            if db.execute("SELECT 1 FROM cloudzy_cz04a_actions "
                          "WHERE status NOT IN ('DONE','REJECTED') "
                          "AND host IN (?,?)", (source, target)).fetchone():
                raise CZ07Hold("CZ04A_UNRESOLVED")
            if pid.startswith("manual:"):
                if pid != "manual:"+opid:
                    raise CZ07Hold("MANUAL_IDENTITY_MISMATCH")
                assert_edge_ref(db,target,pid,require_standby=True)
                manual=db.execute(
                    "SELECT actor,chat,status FROM manual_edge_operations "
                    "WHERE id=? AND ip=?",(opid,target),
                ).fetchone()
                if manual != (actor,chat,"STANDBY"):
                    raise CZ07Hold("MANUAL_STANDBY_CHANGED")
            else:
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
                    "started_at=?,updated_at=?,code='',cancel_requested=0 WHERE id=? "
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
            rec = db.execute(
                "SELECT status,moved,total,cancel_requested "
                "FROM cloudzy_cz07_jobs WHERE id=?", (job,)
            ).fetchone()
            if not rec or rec[0] not in before:
                raise CZ07Hold("JOB_STAGE_CHANGED")
            if next_status in ("VERIFYING", "DONE") and rec[3]:
                raise CZ07Hold("CANCEL_PENDING_AT_FINAL_BOUNDARY")
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
            "WHERE status NOT IN ('DONE','REJECTED') "
            "AND host IN (?,?) LIMIT 1", (rec["source"], rec["target"])
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
        assert_edge_ref(db,rec["target"],rec["provider_id"],
                        require_standby=True)
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

    def _hold_evidence(self, db, rec):
        """Reconstruct only independently journaled SSH moves, never guesses.

        CZ04B DONE batches are durable local CAS receipts. The separate
        operator-approved emergency CAS has its own immutable one-job audit.
        Counts of new users on the target are NOT proof of old job moves.
        """
        total = rec["total"]
        source, target = rec["source"], rec["target"]
        remaining = len(self.cz04b._source_accounts(db, source))
        actual = total - remaining
        if not 0 <= actual <= total or actual < rec["moved"]:
            raise CZ07Hold("RECOVERY_SOURCE_COHORT_CHANGED")
        batches = db.execute(
            "SELECT COALESCE(SUM(count),0) FROM cloudzy_cz04b_operations "
            "WHERE kind='users' AND status='DONE' AND source=? AND target=? "
            "AND actor=? AND chat=? AND provider_id=? AND started_at>=?",
            (source, target, rec["actor"], rec["chat"], rec["provider_id"],
             rec["started_at"]),
        ).fetchone()[0]
        emergency = 0
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='nvl_emergency_migration_audit'"
        ).fetchone():
            audits = db.execute(
                "SELECT source,target,affected,event_code "
                "FROM nvl_emergency_migration_audit WHERE job_id=?",
                (rec["id"],),
            ).fetchall()
            if len(audits) > 1:
                raise CZ07Hold("RECOVERY_EMERGENCY_AUDIT_CONFLICT")
            if audits:
                original, destination, affected, code = audits[0]
                if ((original, destination, code) !=
                        (source, target, "EMERGENCY_LOCAL_CAS_E2E_PENDING")
                        or type(affected) is not int or affected <= 0):
                    raise CZ07Hold("RECOVERY_EMERGENCY_AUDIT_INVALID")
                emergency = affected
                if not db.execute(
                    "SELECT 1 FROM cloudzy_cz07_events "
                    "WHERE job_id=? AND stage='HOLD' "
                    "AND code='EMERGENCY_LOCAL_CAS_E2E_PENDING' "
                    "AND moved=? AND remaining=0 LIMIT 1",
                    (rec["id"], total),
                ).fetchone():
                    raise CZ07Hold("RECOVERY_EMERGENCY_EVENT_MISSING")
        if batches + emergency != actual:
            raise CZ07Hold("RECOVERY_COMMITTED_MOVES_UNVERIFIED")
        # Never accept vanished original accounts as successfully moved.
        # A new customer created on the destination increases this count,
        # but is not added to the immutable original job's total.
        dest_active = db.execute(
            "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
            "AND host=?", (target,),
        ).fetchone()[0]
        foreign = db.execute(
            "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
            "AND COALESCE(host,'') NOT IN (?,?)",
            (source, target),
        ).fetchone()[0]
        if dest_active < actual or foreign:
            raise CZ07Hold("RECOVERY_ACTIVE_ACCOUNT_LOCATION_MISMATCH")
        return {"moved": actual, "remaining": remaining,
                "batches": batches, "emergency": emergency,
                "extra_target": dest_active-actual}

    async def review_hold(self, job, *, actor, chat):
        """Network+ledger preflight with ZERO Cloudzy provider reads/writes."""
        rec = await asyncio.to_thread(self.get, job)
        if not rec or (rec["actor"], rec["chat"]) != (actor, chat):
            raise CZ07Hold("RECOVERY_OWNER_MISMATCH")
        if rec["status"] != "HOLD" or rec["cancel_requested"] or job in self._running:
            raise CZ07Hold("RECOVERY_HOLD_NOT_IDLE")
        ready = await asyncio.to_thread(self.cz04b._route_ready)
        if ready != (rec["source"], rec["target"], rec["provider_id"]):
            raise CZ07Hold("RECOVERY_ROUTE_CHANGED")
        state = await asyncio.to_thread(
            self.cz04b._ready_probe_state, rec["source"],
            rec["target"], rec["provider_id"])
        await self.cz04b._fresh(state, check_provider=False)
        dns = await asyncio.to_thread(self.cz04b.dns.snapshot)
        self.cz04b._expect_dns(dns, rec["target"])
        await asyncio.to_thread(
            self.cz04b._migration_snapshot, rec["source"], rec["target"])
        with self.db() as db:
            self._init(db)
            self.cz04b.guard(db)
            self.cz04b._guard_settings(self.cz04b._settings(db))
            proof = self._hold_evidence(db, rec)
        return rec, proof

    def reconcile_hold(self, job, *, actor, chat, updated_at, expected_moved,
                       expected_remaining):
        """Persist a reviewed HOLD recovery; do NOT mutate DNS or SSH accounts.

        Caller performs review_hold immediately before this CAS. The live
        SQLite identity, route, original 6G and source ledger are checked again.
        After full transfer, use VERIFYING -> MOVED (separate transport proof);
        otherwise resume only remaining accounts, never replay a completed batch.
        """
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            db.row_factory = sqlite3.Row
            row = db.execute(
                "SELECT * FROM cloudzy_cz07_jobs WHERE id=?", (job,)
            ).fetchone()
            if not row or (row["actor"], row["chat"]) != (actor, chat):
                raise CZ07Hold("RECOVERY_OWNER_MISMATCH")
            if (row["status"] != "HOLD" or row["updated_at"] != updated_at
                    or row["cancel_requested"] or job in self._running):
                raise CZ07Hold("RECOVERY_SNAPSHOT_CHANGED")
            self.cz04b.guard(db)
            self.cz04b._guard_settings(self.cz04b._settings(db))
            if self.cz04b._open(db) or db.execute(
                "SELECT 1 FROM failover_operations "
                "WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise CZ07Hold("RECOVERY_LOCK_BUSY")
            if db.execute(
                "SELECT 1 FROM cloudzy_cz04a_actions "
                "WHERE status NOT IN ('DONE','REJECTED') "
                "AND host IN (?,?) LIMIT 1",
                (row["source"], row["target"]),
            ).fetchone():
                raise CZ07Hold("RECOVERY_STANDBY_OPERATION_BUSY")
            st = self.cz04b._settings(db)
            if (st.get("hosts") != row["target"]
                    or st.get("dns_current_ip") != row["target"]):
                raise CZ07Hold("RECOVERY_ROUTE_METADATA_CHANGED")
            defaults = db.execute(
                "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
                "FROM host_pool WHERE is_default=1"
            ).fetchall()
            assert_edge_ref(
                db,row["target"],row["provider_id"],require_default=True)
            if len(defaults)!=1 or defaults[0][0]!=row["target"]:
                raise CZ07Hold("RECOVERY_DEFAULT_CHANGED")
            proof = self._hold_evidence(db, row)
            if ((proof["moved"], proof["remaining"]) !=
                    (expected_moved, expected_remaining)):
                raise CZ07Hold("RECOVERY_ACCOUNT_SNAPSHOT_CHANGED")
            status = "VERIFYING" if expected_remaining == 0 else "MIGRATING"
            code = ("RECOVERED_TRANSPORT_REVIEW_REQUIRED" if status == "VERIFYING"
                    else "RECOVERED_COMMITTED_CHECKPOINT")
            if db.execute(
                "UPDATE cloudzy_cz07_jobs SET status=?,moved=?,code=?,updated_at=? "
                "WHERE id=? AND status='HOLD' AND updated_at=? "
                "AND cancel_requested=0",
                (status, expected_moved, code, int(self.now()), job, updated_at),
            ).rowcount != 1:
                raise CZ07Hold("RECOVERY_CAS_FAILED")
            self._log(db, job, status, code,
                      expected_moved, expected_remaining)
        return status

    def request_cancel(self, job, *, actor, chat):
        """Record cancellation intent only; never stop an in-flight CZ04B write."""
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT actor,chat,status,cancel_requested,moved,total "
                "FROM cloudzy_cz07_jobs WHERE id=?", (job,)
            ).fetchone()
            if not row or (row[0], row[1]) != (actor, chat):
                raise CZ07Hold("CANCEL_OWNER_MISMATCH")
            if row[2] != "MIGRATING":
                raise CZ07Hold("CANCEL_NOT_AT_BATCH_STAGE")
            if row[3]:
                return False
            if db.execute(
                "UPDATE cloudzy_cz07_jobs SET cancel_requested=1,updated_at=? "
                "WHERE id=? AND status='MIGRATING' AND cancel_requested=0",
                (int(self.now()), job),
            ).rowcount != 1:
                raise CZ07Hold("CANCEL_REQUEST_CAS_FAILED")
            self._log(db, job, "MIGRATING", "CANCEL_REQUESTED",
                      row[4], row[5]-row[4])
        return True

    def pause_at_boundary(self, job):
        """Pause only between batches; compute committed progress from DB truth."""
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,cancel_requested,source,total FROM cloudzy_cz07_jobs "
                "WHERE id=?", (job,)
            ).fetchone()
            if not row or row[0] != "MIGRATING":
                raise CZ07Hold("BATCH_STAGE_CHANGED")
            if not row[1]:
                return False
            remaining = len(self.cz04b._source_accounts(db, row[2]))
            moved = row[3] - remaining
            if moved < 0 or moved > row[3]:
                raise CZ07Hold("PAUSE_ACCOUNT_COUNT_INVALID")
            if db.execute(
                "UPDATE cloudzy_cz07_jobs SET status='PAUSED_SAFE',moved=?,"
                "cancel_requested=0,updated_at=?,code='PAUSED_AT_BATCH_BOUNDARY' "
                "WHERE id=? AND status='MIGRATING' AND cancel_requested=1",
                (moved, int(self.now()), job)
            ).rowcount != 1:
                raise CZ07Hold("PAUSE_CAS_FAILED")
            self._log(db, job, "PAUSED_SAFE", "PAUSED_AT_BATCH_BOUNDARY",
                      moved, remaining)
        return True

    def resume_paused(self, job, *, actor, chat):
        """Called only AFTER fresh CZ04B route, DNS and 6G readiness checks."""
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT actor,chat,status,moved,total FROM cloudzy_cz07_jobs "
                "WHERE id=?", (job,)
            ).fetchone()
            if not row or (row[0], row[1]) != (actor, chat):
                raise CZ07Hold("RESUME_OWNER_MISMATCH")
            if row[2] != "PAUSED_SAFE":
                raise CZ07Hold("RESUME_NOT_PAUSED")
            if db.execute(
                "UPDATE cloudzy_cz07_jobs SET status='MIGRATING',updated_at=?,"
                "code='OPERATOR_RESUME_AFTER_PREFLIGHT' "
                "WHERE id=? AND status='PAUSED_SAFE' AND cancel_requested=0",
                (int(self.now()), job),
            ).rowcount != 1:
                raise CZ07Hold("RESUME_CAS_FAILED")
            self._log(db, job, "MIGRATING",
                      "OPERATOR_RESUME_AFTER_PREFLIGHT", row[3], row[4]-row[3])

    def accept_business(self, job, *, actor, chat, create_ref, renew_ref,
                        client_ref, independent_verify=None):
        """Accept ONLY verified SSH CREATE/RENEW and affected-ISP client evidence.

        No Telegram callback invokes this method. Phase-7 wiring needs an
        independently authenticated verifier; strings alone never certify E2E.
        """
        import re
        references = (create_ref, renew_ref, client_ref)
        if any(not isinstance(ref, str)
               or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,96}", ref)
               for ref in references):
            raise CZ07Hold("BUSINESS_EVIDENCE_REFERENCE_INVALID")
        if not callable(independent_verify):
            raise CZ07Hold("INDEPENDENT_BUSINESS_VERIFIER_REQUIRED")
        rec = self.get(job)
        if not rec or (actor, chat) != (rec["actor"], rec["chat"]):
            raise CZ07Hold("BUSINESS_ACCEPT_OWNER_MISMATCH")
        if rec["status"] not in ("VERIFYING", "MOVED"):
            raise CZ07Hold("BUSINESS_ACCEPT_NOT_READY")
        # The verifier must independently confirm real CREATE, RENEW and
        # affected-ISP client tests against this job/target; NEVER infer
        # success from operator-supplied text or local metadata.
        if independent_verify(job=job, target=rec["target"],
                              create_ref=create_ref, renew_ref=renew_ref,
                              client_ref=client_ref) is not True:
            raise CZ07Hold("BUSINESS_E2E_NOT_VERIFIED")
        if self.cz04b._route_ready() != (
                rec["source"], rec["target"], rec["provider_id"]):
            raise CZ07Hold("BUSINESS_ROUTE_CHANGED")
        self.cz04b._expect_dns(self.cz04b.dns.snapshot(), rec["target"])
        # The existing CZ04B preflight rejects an unresolved original 6G
        # lease or user journal; metadata-only final verification is weaker.
        self.cz04b._migration_snapshot(rec["source"], rec["target"])
        self.complete_guard(job)
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            live = db.execute(
                "SELECT status,total,moved,source,target FROM cloudzy_cz07_jobs "
                "WHERE id=?", (job,)
            ).fetchone()
            if not live or live != (
                    rec["status"], rec["total"], rec["total"],
                    rec["source"], rec["target"]):
                raise CZ07Hold("BUSINESS_ACCEPT_SNAPSHOT_CHANGED")
            if self.cz04b._open(db) or db.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise CZ07Hold("BUSINESS_ROUTE_LEASE_BUSY")
            st = self.cz04b._settings(db)
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if (st.get("hosts") != rec["target"]
                    or st.get("dns_current_ip") != rec["target"]
                    or defaults != [(rec["target"],)]):
                raise CZ07Hold("BUSINESS_ROUTE_SNAPSHOT_CHANGED")
            if self.cz04b._source_accounts(db, rec["source"]):
                raise CZ07Hold("BUSINESS_SOURCE_NOT_EMPTY")
            foreign = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "AND COALESCE(host,'') != ?", (rec["target"],)
            ).fetchone()[0]
            if foreign:
                raise CZ07Hold("BUSINESS_FOREIGN_ACTIVE_ACCOUNT")
            db.execute(
                "INSERT INTO cloudzy_cz07_acceptance "
                "(job_id,actor,at,create_ref,renew_ref,client_ref) "
                "VALUES (?,?,?,?,?,?)",
                (job, actor, int(self.now()), *references),
            )
            if db.execute(
                "UPDATE cloudzy_cz07_jobs SET status='DONE',updated_at=?,"
                "code='BUSINESS_E2E_ACCEPTED' "
                "WHERE id=? AND status=?",
                (int(self.now()), job, rec["status"])
            ).rowcount != 1:
                raise CZ07Hold("BUSINESS_ACCEPT_CAS_FAILED")
            self._log(db, job, "DONE", "BUSINESS_E2E_ACCEPTED",
                      rec["total"], 0)
        return True

    @staticmethod
    def _expected_target_role(row, ref):
        if ref.startswith("manual:"):
            return row==("manual",None,1,1,0)
        return row==("cloudzy",ref,1,1,0)

    def complete_transport(self, job, *, actor, chat, expected_updated_at):
        """Close ONLY the account-host transfer lock after verifying live route.

        This does not mint CREATE, RENEW or affected-ISP evidence. The separate
        business acceptance remains pending. It never changes DNS or accounts.
        Caller must have checked pinned SSH/WG/NAT and live DNS; no
        Cloudzy GET is required after the original verified route cutover.
        """
        rec = self.get(job)
        if not rec or (actor, chat) != (rec["actor"], rec["chat"]):
            raise CZ07Hold("TRANSPORT_OWNER_MISMATCH")
        if (rec["status"] != "VERIFYING" or rec["updated_at"] != expected_updated_at
                or rec.get("cancel_requested") or rec["moved"] != rec["total"]):
            raise CZ07Hold("TRANSPORT_NOT_READY")
        if self.cz04b._route_ready() != (
                rec["source"], rec["target"], rec["provider_id"]):
            raise CZ07Hold("TRANSPORT_ROUTE_CHANGED")
        self.cz04b._expect_dns(self.cz04b.dns.snapshot(), rec["target"])
        self.cz04b._migration_snapshot(rec["source"], rec["target"])
        self.complete_guard(job)
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.cz04b.guard(db)
            self.cz04b._guard_settings(self.cz04b._settings(db))
            row = db.execute(
                "SELECT actor,chat,status,source,target,provider_id,total,moved,"
                "updated_at,cancel_requested FROM cloudzy_cz07_jobs WHERE id=?",
                (job,)
            ).fetchone()
            if row != (
                    actor, chat, "VERIFYING", rec["source"], rec["target"],
                    rec["provider_id"], rec["total"], rec["total"],
                    expected_updated_at, 0):
                raise CZ07Hold("TRANSPORT_SNAPSHOT_CHANGED")
            if self.cz04b._open(db) or db.execute(
                    "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise CZ07Hold("TRANSPORT_LOCK_BUSY")
            if db.execute(
                    "SELECT 1 FROM cloudzy_cz04a_actions "
                    "WHERE status NOT IN ('DONE','REJECTED') "
                    "AND host IN (?,?) LIMIT 1", (rec["source"], rec["target"])
            ).fetchone():
                raise CZ07Hold("TRANSPORT_CZ04A_UNRESOLVED")
            settings = self.cz04b._settings(db)
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            target_role = db.execute(
                "SELECT provider,provider_instance_id,active,is_default,is_standby "
                "FROM host_pool WHERE host=?", (rec["target"],)
            ).fetchone()
            if (settings.get("hosts") != rec["target"]
                    or settings.get("dns_current_ip") != rec["target"]
                    or defaults != [(rec["target"],)]
                    or not self._expected_target_role(target_role,rec["provider_id"])):
                raise CZ07Hold("TRANSPORT_ROUTE_SNAPSHOT_CHANGED")
            if self.cz04b._source_accounts(db, rec["source"]):
                raise CZ07Hold("TRANSPORT_SOURCE_NOT_EMPTY")
            foreign = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "AND COALESCE(host,'') != ?", (rec["target"],)
            ).fetchone()[0]
            if foreign:
                raise CZ07Hold("TRANSPORT_ACTIVE_ACCOUNT_OUTSIDE_TARGET")
            updated = db.execute(
                "UPDATE cloudzy_cz07_jobs SET status='MOVED',"
                "code='TRANSPORT_VERIFIED_POSTCHECK_PENDING',updated_at=? "
                "WHERE id=? AND status='VERIFYING' AND updated_at=? "
                "AND moved=total AND cancel_requested=0",
                (int(self.now()), job, expected_updated_at)
            ).rowcount
            if updated != 1:
                raise CZ07Hold("TRANSPORT_CAS_FAILED")
            self._log(db, job, "MOVED", "TRANSPORT_VERIFIED_POSTCHECK_PENDING",
                      rec["total"], 0)
        return True

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
                # Same route/CAS/Cloudflare engine; manual identity performs
                # no Cloudzy ownership lookup anywhere on this path.
                result = await self.cz04b._run_route(
                    rec["actor"],chat,rec["target"])
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
                # A cancel request never interrupts a potentially effectful
                # account CAS; it is honoured at the next batch boundary only.
                if await asyncio.to_thread(self.pause_at_boundary, job):
                    await self._notify(app, chat,
                        f"⏸ CZ-07 در مرز Batch متوقف شد: {job[:16]}. "
                        "پس از بازبینی مسیر می‌توان انتقال را ادامه داد.")
                    break
                rows, moved = await asyncio.to_thread(self.remaining, job)
                if not rows:
                    # Confirm pinned SSH/WG/NAT and current routing, not Cloudzy.
                    # This final check is provider-independent by design.
                    state = await asyncio.to_thread(
                        self.cz04b._ready_probe_state,
                        rec["source"], rec["target"], rec["provider_id"])
                    await self.cz04b._fresh(state, check_provider=False)
                    dns = await asyncio.to_thread(self.cz04b.dns.snapshot)
                    self.cz04b._expect_dns(dns, rec["target"])
                    await asyncio.to_thread(self.complete_guard, job)
                    if await asyncio.to_thread(self.pause_at_boundary, job):
                        await self._notify(app, chat,
                            f"⏸ CZ-07 در مرز Batch متوقف شد: {job[:16]}. "
                            "تأیید نهایی پس از Resume انجام می‌شود.")
                        break
                    self.transition(job, "MIGRATING", "VERIFYING",
                                    code="AWAITING_BUSINESS_E2E",
                                    moved=rec["total"], remaining=0)
                    await self._notify(app, chat,
                        f"📋 انتقال {rec['total']} حساب در CZ-07 ثبت شد: {job[:16]}. "
                        "وضعیت: در انتظار تأیید مستقل ساخت، تمدید و اتصال واقعی مشتری. "
                        "سرور قبلی روشن می‌ماند؛ هنوز DONE نیست.")
                    break
                # Reuse CZ04B's original 6G lease, fresh SSH/WG/NAT/DNS
                # checks and account CAS for each small batch. No OS writes.
                names = [str(row[0]) for row in rows[:BATCH_SIZE]]
                fp = _digest(rows)
                started = time.monotonic()
                count = await self.cz04b._run_users(
                    rec["actor"], chat, names, fp, check_provider=False)
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
            if data.startswith("apps_cz7_transport_review_"):
                job_id = data[len("apps_cz7_transport_review_"):]
                rec = await asyncio.to_thread(self.get, job_id)
                if not rec or (rec["actor"], rec["chat"]) != (actor, chat):
                    raise CZ07Hold("TRANSPORT_OWNER_MISMATCH")
                if rec["status"] != "VERIFYING" or rec["moved"] != rec["total"]:
                    raise CZ07Hold("TRANSPORT_NOT_READY")
                # Recheck the actual provider, customer/admin probe, pinned
                # SSH/NAT/WireGuard, original route, DNS, 6G and account count.
                route = await asyncio.to_thread(self.cz04b._route_ready)
                if route != (rec["source"], rec["target"], rec["provider_id"]):
                    raise CZ07Hold("TRANSPORT_ROUTE_CHANGED")
                state = await asyncio.to_thread(
                    self.cz04b._ready_probe_state,
                    rec["source"], rec["target"], rec["provider_id"])
                await self.cz04b._fresh(state, check_provider=False)
                dns = await asyncio.to_thread(self.cz04b.dns.snapshot)
                self.cz04b._expect_dns(dns, rec["target"])
                await asyncio.to_thread(
                    self.cz04b._migration_snapshot, rec["source"], rec["target"])
                await asyncio.to_thread(self.complete_guard, job_id)
                nonce = secrets.token_hex(8)
                context.user_data["cz7_transport_confirm"] = {
                    "job": job_id, "actor": actor, "chat": chat,
                    "updated_at": rec["updated_at"], "nonce": nonce,
                    "expires": self.now() + APPROVAL_TTL,
                }
                await self._display(query,
                    "✅ <b>کنترل فنی انتقال حساب‌ها موفق بود.</b>\n\n"
                    f"از <code>{_short(rec['source'])}</code> "
                    f"به <code>{_short(rec['target'])}</code>\n"
                    f"حساب‌های منتقل‌شده: <b>{rec['moved']}/{rec['total']}</b>\n\n"
                    "مسیر، DNS، وضعیت ارائه‌دهنده، SSH/NAT، قفل‌ها و حساب‌های فعال "
                    "بررسی شدند.\n\n"
                    "این تأیید فقط انتقال Host حساب‌ها را می‌بندد و نوبت انتقال "
                    "بعدی را آزاد می‌کند. <b>سلامت CREATE/RENEW و اتصال مشتری "
                    "هنوز تأیید نشده</b> و باید جداگانه آزمایش شود.",
                    [[("✅ ثبت تکمیل انتقال حساب‌ها",
                       "apps_cz7_transport_go_"+nonce)],
                     [("❌ انصراف", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_transport_go_"):
                session = context.user_data.pop("cz7_transport_confirm", None)
                if (not isinstance(session, dict) or
                        session.get("actor") != actor or session.get("chat") != chat
                        or self.now() > session.get("expires", 0)
                        or data != "apps_cz7_transport_go_"+session.get("nonce", "")):
                    raise CZ07Hold("TRANSPORT_CONFIRMATION_EXPIRED")
                job_id = session["job"]
                rec = await asyncio.to_thread(self.get, job_id)
                if (not rec or rec["status"] != "VERIFYING"
                        or rec["updated_at"] != session["updated_at"]
                        or rec["moved"] != rec["total"]
                        or (rec["actor"], rec["chat"]) != (actor, chat)):
                    raise CZ07Hold("TRANSPORT_SNAPSHOT_CHANGED")
                route = await asyncio.to_thread(self.cz04b._route_ready)
                if route != (rec["source"], rec["target"], rec["provider_id"]):
                    raise CZ07Hold("TRANSPORT_ROUTE_CHANGED")
                state = await asyncio.to_thread(
                    self.cz04b._ready_probe_state,
                    rec["source"], rec["target"], rec["provider_id"])
                await self.cz04b._fresh(state, check_provider=False)
                await asyncio.to_thread(
                    self.complete_transport, job_id, actor=actor, chat=chat,
                    expected_updated_at=session["updated_at"])
                await self._display(query,
                    "✅ <b>انتقال حساب‌ها تکمیل و ثبت شد.</b>\n\n"
                    "قفل انتقال قبلی پس از کنترل فنی آزاد شده است. "
                    "آزمون ساخت، تمدید و اتصال مشتری در وضعیت <b>در انتظار بررسی</b> "
                    "باقی می‌ماند.\n\n"
                    "برای انتقال به Standby جدید، ابتدا آمادگی و مجوزهای انتقال "
                    "دوباره بررسی می‌شوند.",
                    [[("🚀 بررسی انتقال به Standby", "apps_cz7_home")],
                     [("📋 وضعیت انتقال قبلی", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_accept_review_"):
                job_id = data[len("apps_cz7_accept_review_"):]
                item = await asyncio.to_thread(self.get, job_id)
                if not item or (item["actor"], item["chat"]) != (actor, chat):
                    raise CZ07Hold("BUSINESS_ACCEPT_OWNER_MISMATCH")
                if item["status"] not in ("VERIFYING", "MOVED"):
                    raise CZ07Hold("BUSINESS_ACCEPT_NOT_READY")
                proof = await asyncio.to_thread(self.review_acceptance, job_id)
                if not proof.ready:
                    messages = {
                        "TRUSTED_WITNESS_NOT_CONFIGURED":
                            "منبع مستقل شواهد اتصال هنوز به NVL متصل نشده است.",
                        "TRUSTED_WITNESS_NOT_RECEIVED":
                            "هنوز گواه معتبر ساخت، تمدید و اتصال از ناظر مستقل دریافت نشده است.",
                        "TRUSTED_WITNESS_STALE":
                            "گواه موجود منقضی یا مربوط به وضعیت قدیمی انتقال است.",
                        "TRUSTED_WITNESS_SIGNATURE_INVALID":
                            "امضای گواه مستقل معتبر نیست.",
                        "TRUSTED_WITNESS_INCOMPLETE":
                            "گواه دریافت شده، همه آزمون‌های ساخت، تمدید و اتصال مشتری را پاس نکرده است.",
                    }
                    await self._display(query,
                        "🔍 <b>بررسی پذیرش نهایی انتقال</b>\n\n"
                        f"شناسه: <code>{_short(job_id[:16])}</code>\n"
                        f"مقصد: <code>{_short(item['target'])}</code>\n"
                        f"انتقال ثبت‌شده: <b>{item['moved']}/{item['total']}</b>\n\n"
                        f"⚠️ {escape(messages.get(proof.code, 'شواهد مستقل قابل پذیرش نیستند.'))}\n"
                        f"کد بررسی: <code>{_short(proof.code)}</code>\n\n"
                        "هیچ تغییری در وضعیت Job یا کاربران داده نشد. "
                        "پس از دریافت شواهد معتبر، دوباره بررسی کنید.",
                        [[("🔄 بررسی دوباره شواهد", "apps_cz7_accept_review_"+job_id)],
                         [("↩️ وضعیت انتقال", "apps_cz7_status")]], markup)
                    return
                nonce = secrets.token_hex(8)
                context.user_data["cz7_accept"] = {
                    "actor": actor, "chat": chat, "job": job_id,
                    "updated_at": item["updated_at"],
                    "fingerprint": proof.fingerprint,
                    "refs": proof.refs, "nonce": nonce,
                    "expires": self.now() + APPROVAL_TTL,
                }
                await self._display(query,
                    "✅ <b>شواهد مستقل تأیید شدند</b>\n\n"
                    f"مقصد: <code>{_short(item['target'])}</code>\n"
                    f"حساب‌ها: <b>{item['moved']}/{item['total']}</b>\n"
                    "ساخت حساب، تمدید حساب و اتصال واقعی مشتری: تأییدشده در گواه امضاشده.\n\n"
                    "مرحله بعد، بازبینی زنده DNS، مسیر، قفل 6G و شمارش حساب‌هاست. "
                    "تنها در صورت موفقیت همه کنترل‌ها عملیات DONE می‌شود.",
                    [[("✅ اجرای بررسی نهایی و ثبت پذیرش", "apps_cz7_accept_go_"+nonce)],
                     [("❌ انصراف", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_accept_go_"):
                session = context.user_data.pop("cz7_accept", None)
                if (not isinstance(session, dict) or
                        session.get("actor") != actor or session.get("chat") != chat
                        or self.now() > session.get("expires", 0)
                        or data != "apps_cz7_accept_go_"+session.get("nonce", "")):
                    raise CZ07Hold("BUSINESS_ACCEPT_SESSION_EXPIRED")
                item = await asyncio.to_thread(self.get, session["job"])
                if (not item or item["status"] not in ("VERIFYING", "MOVED")
                        or item["updated_at"] != session["updated_at"]
                        or (item["actor"], item["chat"]) != (actor, chat)):
                    raise CZ07Hold("BUSINESS_ACCEPT_SNAPSHOT_CHANGED")
                proof = await asyncio.to_thread(self.review_acceptance, session["job"])
                if (not proof.ready or proof.fingerprint != session["fingerprint"]
                        or proof.refs != session["refs"]):
                    raise CZ07Hold("BUSINESS_EVIDENCE_CHANGED")
                if self.acceptance_witness is None:
                    raise CZ07Hold("INDEPENDENT_BUSINESS_VERIFIER_REQUIRED")
                create_ref, renew_ref, client_ref = proof.refs
                def independently_confirm(**kwargs):
                    latest = self.get(session["job"])
                    return bool(latest and self.acceptance_witness.verify(
                        latest, create_ref=kwargs["create_ref"],
                        renew_ref=kwargs["renew_ref"],
                        client_ref=kwargs["client_ref"],
                        fingerprint=session["fingerprint"]))
                await asyncio.to_thread(
                    self.accept_business, session["job"], actor=actor,
                    chat=chat, create_ref=create_ref,
                    renew_ref=renew_ref, client_ref=client_ref,
                    independent_verify=independently_confirm)
                await self._display(query,
                    "✅ <b>انتقال کاربران به‌صورت رسمی تأیید شد.</b>\n\n"
                    "ثبت پذیرش و شواهد مستقل در Journal انجام شد. "
                    "برای انتقال بعدی، ابتدا آمادگی Standby جدید بررسی می‌شود.",
                    [[("🚀 بررسی انتقال بعدی", "apps_cz7_home")],
                     [("📋 مشاهده نتیجه", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_hold_review_"):
                job = data[len("apps_cz7_hold_review_"):]
                rec, proof = await self.review_hold(job, actor=actor, chat=chat)
                nonce = secrets.token_hex(8)
                context.user_data["cz7_hold_recovery"] = {
                    "job": job, "actor": actor, "chat": chat,
                    "updated_at": rec["updated_at"],
                    "moved": proof["moved"], "remaining": proof["remaining"],
                    "nonce": nonce, "expires": self.now() + APPROVAL_TTL,
                }
                complete = proof["remaining"] == 0
                action = ("✅ ثبت بررسی انتقال" if complete
                          else "▶️ ادامه حساب‌های باقی‌مانده")
                await self._display(query,
                    "🔎 <b>بررسی انتقال متوقف‌شده</b>\n\n"
                    f"مبدأ: <code>{_short(rec['source'])}</code>\n"
                    f"مقصد: <code>{_short(rec['target'])}</code>\n"
                    f"حساب‌های جابه‌جاشده: <b>{proof['moved']}/{rec['total']}</b>\n"
                    f"باقی‌مانده: <b>{proof['remaining']}</b>\n"
                    f"حساب‌های جدید مقصد: <b>{proof['extra_target']}</b>\n\n"
                    "هویت SSH، تونل، مسیر، DNS زنده و رسیدهای ثبت‌شده "
                    "بررسی شدند. هیچ درخواستی به Cloudzy ارسال نشده است.\n\n"
                    + ("تأیید، پرونده را برای کنترل نهایی انتقال آماده می‌کند؛ "
                       "پذیرش کامل سرویس همچنان جداست."
                       if complete else
                       "با تأیید فقط حساب‌های باقی‌مانده از آخرین وضعیت "
                       "معتبر انتقال داده می‌شوند؛ سرور قبلی حذف نمی‌شود."),
                    [[(action, "apps_cz7_hold_go_"+nonce)],
                     [("انصراف", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_hold_go_"):
                session = context.user_data.pop("cz7_hold_recovery", None)
                if (not isinstance(session, dict)
                        or (session.get("actor"), session.get("chat")) !=
                           (actor, chat)
                        or self.now() > session.get("expires", 0)
                        or data != "apps_cz7_hold_go_"+session.get("nonce", "")):
                    raise CZ07Hold("RECOVERY_CONFIRMATION_EXPIRED")
                job = session["job"]
                if (session["remaining"] and
                        (not self.enabled() or not self.cz04b.enabled())):
                    raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
                rec, proof = await self.review_hold(job, actor=actor, chat=chat)
                if (rec["updated_at"] != session["updated_at"]
                        or (proof["moved"], proof["remaining"]) !=
                           (session["moved"], session["remaining"])):
                    raise CZ07Hold("RECOVERY_PREVIEW_EXPIRED")
                status = await asyncio.to_thread(
                    self.reconcile_hold, job, actor=actor, chat=chat,
                    updated_at=session["updated_at"],
                    expected_moved=session["moved"],
                    expected_remaining=session["remaining"])
                if status == "MIGRATING":
                    self.launch(app, job, resume=True)
                await self._display(query,
                    ("✅ <b>انتقال برای کنترل نهایی ثبت شد.</b>\n"
                     "برای آزادکردن مسیر انتقال بعدی، "
                     "کنترل فنی تکمیل انتقال را اجرا کنید."
                     if status == "VERIFYING" else
                     "▶️ <b>انتقال باقی‌مانده از آخرین Checkpoint آغاز شد.</b>\n"
                     "پیشرفت واقعی از دیتابیس خوانده می‌شود."),
                    [[("🔄 وضعیت", "apps_cz7_status")]], markup)
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
                if item["status"] not in ("QUEUED", "MIGRATING", "PAUSED_SAFE"):
                    raise CZ07Hold("RESUME_ONLY_AFTER_ROUTE_READY")
                if item.get("cancel_requested"):
                    raise CZ07Hold("CANCEL_PENDING_RECONCILE_BEFORE_RESUME")
                if not self.enabled() or not self.cz04b.enabled():
                    raise CZ07Hold("CZ07_OR_CZ04B_DISABLED")
                # QUEUED is pre-route: verify the original source cohort
                # before starting the route once, never replay ROUTING.
                if item["status"] == "QUEUED":
                    state = await asyncio.to_thread(
                        self.cz04b._state, item["target"])
                    if (state["source"] != item["source"]
                            or state["provider_id"] != item["provider_id"]
                            or _digest(state["users"]) !=
                               item["source_fingerprint"]):
                        raise CZ07Hold("QUEUED_SOURCE_SNAPSHOT_CHANGED")
                    self.launch(app, job, resume=False)
                    await self._display(query,
                        "▶️ <b>درخواست ثبت‌شده از همان مرحله آغاز شد.</b>",
                        [[("🔄 وضعیت", "apps_cz7_status")]], markup)
                    return
                # Post-restart safety: never replay ROUTING or an uncertain
                # CZ04B cutover. Resumed batches derive account state from DB.
                ready = await asyncio.to_thread(self.cz04b._route_ready)
                if ready != (item["source"],item["target"],item["provider_id"]):
                    raise CZ07Hold("ROUTE_NO_LONGER_VERIFIED")
                await asyncio.to_thread(self.cz04b._migration_snapshot,
                                         item["source"], item["target"])
                snap = await asyncio.to_thread(self.cz04b.dns.snapshot)
                self.cz04b._expect_dns(snap, item["target"])
                if item["status"] == "PAUSED_SAFE":
                    await asyncio.to_thread(self.resume_paused, job,
                                            actor=actor, chat=chat)
                self.launch(app, job, resume=True)
                await self._display(query,
                    f"▶️ ادامه صف پس از بررسی ایمن. شناسه: <code>{_short(job[:16])}</code>",
                    [[("🔄 وضعیت", "apps_cz7_status")]], markup)
                return
            if data.startswith("apps_cz7_cancel_"):
                job = data[len("apps_cz7_cancel_"):]
                await asyncio.to_thread(self.request_cancel, job,
                                        actor=actor, chat=chat)
                await self._display(query,
                    "⏸ درخواست توقف ثبت شد. Batch جاری با CAS تکمیل می‌شود "
                    "و سپس عملیات در مرز امن متوقف خواهد شد.",
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
            "PAUSED_SAFE": "متوقف‌شده در مرز Batch؛ آماده بررسی و ادامه",
            "VERIFYING": "انتقال ۱۰۰٪ ثبت شده؛ آماده بررسی فنی تکمیل",
            "MOVED": "انتقال حساب‌ها تکمیل؛ تست ساخت/تمدید/اتصال باز است",
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
                and status == "HOLD" and job["id"] not in self._running):
            rows.insert(0, [("🔎 بررسی و ادامه انتقال",
                             "apps_cz7_hold_review_"+job["id"])])
        if ((actor, chat) == (job["actor"], job["chat"])
                and status == "VERIFYING"):
            rows.insert(0, [("✅ بررسی تکمیل انتقال حساب‌ها",
                             "apps_cz7_transport_review_"+job["id"])])
            rows.insert(1, [("🔎 بررسی پذیرش کامل سرویس",
                             "apps_cz7_accept_review_"+job["id"])])
        if status in ("DONE", "MOVED"):
            rows.insert(0, [("🚀 بررسی انتقال به Standby", "apps_cz7_home")])
        if ((actor, chat) == (job["actor"], job["chat"])
                and status == "MOVED"):
            rows.insert(1, [("🧪 بررسی تست‌های پس از انتقال",
                             "apps_cz7_accept_review_"+job["id"])])
        if ((actor, chat) == (job["actor"], job["chat"])
                and status in ("QUEUED", "MIGRATING", "PAUSED_SAFE")
                and not job.get("cancel_requested")
                and job["id"] not in self._running):
            rows.insert(0, [("▶️ بررسی و ادامه امن صف", "apps_cz7_resume_"+job["id"])])
        if ((actor, chat) == (job["actor"], job["chat"])
                and status == "MIGRATING" and not job.get("cancel_requested")):
            rows.insert(0, [("⏸ درخواست توقف پس از Batch", "apps_cz7_cancel_"+job["id"])])
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
            "⏸ توقف در مرز Batch ثبت شده است. پیش از ادامه، مسیر و Journal را بررسی کنید."
            if status == "PAUSED_SAFE" else
            "✅ انتقال Host حساب‌ها ثبت شده است. با «بررسی تکمیل انتقال حساب‌ها» "
            "کنترل فنی انجام دهید و نوبت انتقال بعدی را آزاد کنید؛ "
            "CREATE/RENEW و اتصال مشتری جداگانه بررسی می‌شوند."
            if status == "VERIFYING" else
            "✅ انتقال Host حساب‌ها کنترل و تکمیل شده است؛ تست ساخت، تمدید و "
            "اتصال مشتری هنوز در انتظار بررسی است. این وضعیت پذیرش کامل سرویس نیست."
            if status == "MOVED" else
            "⏳ درخواست توقف ثبت شده؛ منتظر مرز Batch باشید."
            if status == "MIGRATING" and job.get("cancel_requested") else
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
