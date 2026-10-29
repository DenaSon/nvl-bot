"""Provider-independent manual Edge quick cutover (source-only, no UI or auto-run).

Single-customer-host Legacy SSH: Core holds accounts and SSHD; Edge is a
WireGuard relay. No rebuild, per-user queue, Cloudzy API or purchase receipts.
DNS and SQLite cannot share a transaction: persist DNS intent + the ORIGINAL
6G lease in one SQLite transaction, reconcile observed DNS after crashes, and
never replay an uncertain Cloudflare write automatically.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time

from manual_edge_identity import resolve as resolve_edge

ACTIVE = "status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
FINAL = ("DONE", "ABORTED", "EXTERNAL_VERIFIED")
TTL = 180


class QuickSwitchHold(RuntimeError):
    pass


def _has(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _hash(rows):
    return hashlib.sha256(
        json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _exact_records(records, before, ip):
    return (
        isinstance(records, list) and len(records) == len(before) and bool(before)
        and {r["name"] for r in records} == {r["name"] for r in before}
        and all(
            any(
                all(r.get(k) == expected.get(k)
                    for k in ("name", "id", "ttl"))
                for expected in before
            ) and r.get("ip") == ip
            for r in records
        )
    )


class ManualQuickSwitch:
    """Inject the existing db_conn, CloudflareExactDNS and live manual probe.

    check_target(plan) MUST independently verify pinned Core SSH identity,
    management/customer path, WG, NAT and readiness; sync or async permitted.
    Actor confirmation and an independently observed customer witness are
    required at the calling UI boundary; no unattended switch is exposed.
    """

    def __init__(self, *, db_conn, dns, check_target, guard=None, now=time.time):
        self.db = db_conn
        self.dns = dns
        self.check_target = check_target
        self.guard = guard or (lambda db: None)
        self.now = now

    @staticmethod
    def _init(db):
        db.execute("""CREATE TABLE IF NOT EXISTS manual_quick_switch_jobs (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
            source TEXT NOT NULL, target TEXT NOT NULL, actor TEXT NOT NULL,
            evidence TEXT NOT NULL, account_fingerprint TEXT NOT NULL,
            account_count INTEGER NOT NULL, expected_hosts TEXT NOT NULL,
            dns_before_json TEXT NOT NULL, lease_id INTEGER,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            error_code TEXT NOT NULL DEFAULT ''
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS
            manual_quick_one_unresolved ON manual_quick_switch_jobs ((1))
            WHERE kind='QUICK' AND status NOT IN ('DONE','ABORTED')""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS
            manual_quick_one_external_pair
            ON manual_quick_switch_jobs(source,target)
            WHERE kind='EXTERNAL'""")
        db.execute("""CREATE TABLE IF NOT EXISTS manual_quick_switch_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL, status TEXT NOT NULL,
            code TEXT NOT NULL, at INTEGER NOT NULL
        )""")

    def _log(self, db, job, status, code):
        db.execute(
            "INSERT INTO manual_quick_switch_events "
            "(job_id,status,code,at) VALUES (?,?,?,?)",
            (job, status, code, int(self.now())),
        )

    def _conflicts(self, db, source, target, *, own_lease=None):
        if _has(db, "failover_operations"):
            rows = db.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchall()
            if any(row[0] != own_lease for row in rows):
                raise QuickSwitchHold("SHARED_6G_BUSY")
        else:
            raise QuickSwitchHold("SHARED_6G_SCHEMA_MISSING")
        # DNS is global: an active legacy route operation is never unrelated.
        if _has(db, "cloudzy_cz04b_operations") and db.execute(
            "SELECT 1 FROM cloudzy_cz04b_operations "
            "WHERE status NOT IN ('READY','DONE','ABORTED') LIMIT 1"
        ).fetchone():
            raise QuickSwitchHold("OTHER_DNS_ROUTE_OPERATION")
        if _has(db, "cloudzy_cz07_jobs") and db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE status NOT IN ('DONE','ABORTED','MOVED') "
            "AND (source IN (?,?) OR target IN (?,?) OR status != 'HOLD') "
            "LIMIT 1", (source, target, source, target)
        ).fetchone():
            raise QuickSwitchHold("RELEVANT_CZ07_OPERATION")
        if _has(db, "cloudzy_cz04a_actions") and db.execute(
            "SELECT 1 FROM cloudzy_cz04a_actions "
            "WHERE status NOT IN ('DONE','REJECTED') AND host IN (?,?) LIMIT 1",
            (source, target)
        ).fetchone():
            raise QuickSwitchHold("ENDPOINT_STANDBY_OPERATION")

    def _plan(self, db, target):
        self.guard(db)
        st = dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN "
            "('hosts','dns_current_ip','core_wg_public_ip',"
            "'phase6h_auto_failover_enabled','auto_failover_mode',"
            "'edge_egress_v1_onboard_enabled')"
        ).fetchall())
        if any(st.get(k) == "1" for k in
               ("phase6h_auto_failover_enabled", "auto_failover_mode",
                "edge_egress_v1_onboard_enabled")):
            raise QuickSwitchHold("AUTOMATIC_OR_K2_ROUTE_ENABLED")
        defaults = db.execute(
            "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
        ).fetchall()
        if len(defaults) != 1:
            raise QuickSwitchHold("DEFAULT_AMBIGUOUS")
        source = defaults[0][0]
        if not source or source == target or target == st.get("core_wg_public_ip"):
            raise QuickSwitchHold("INVALID_SOURCE_TARGET")
        if (not st.get("core_wg_public_ip") or
                source == st["core_wg_public_ip"] or
                st.get("dns_current_ip") != source or
                st.get("hosts") != source):
            raise QuickSwitchHold("SINGLE_HOST_ROUTE_NOT_COHERENT")
        source_port = db.execute(
            "SELECT service_port FROM host_pool WHERE host=?", (source,)
        ).fetchone()
        dest = db.execute(
            "SELECT active,is_default,is_standby,service_port,provider,"
            "provider_instance_id,admin_ssh_port FROM host_pool WHERE host=?",
            (target,)
        ).fetchone()
        if (not dest or dest[:3] != (1, 0, 1)
                or dest[4:6] != ("manual", None)
                or not source_port or source_port[0] != dest[3]):
            raise QuickSwitchHold("MANUAL_STANDBY_NOT_READY")
        identity = resolve_edge(db, target, require_standby=True)
        if identity["provider"] != "manual":
            raise QuickSwitchHold("TARGET_NOT_MANUAL")
        foreign = db.execute(
            "SELECT COUNT(*) FROM ssh_accounts "
            "WHERE service_type='ssh' AND " + ACTIVE +
            " AND COALESCE(host,'') NOT IN ('',?)",
            (source,)
        ).fetchone()[0]
        if foreign:
            raise QuickSwitchHold("OTHER_ACTIVE_CUSTOMER_HOSTS")
        if db.execute(
            "SELECT 1 FROM ssh_accounts WHERE service_type='ssh' "
            "AND host=? LIMIT 1", (target,)
        ).fetchone():
            raise QuickSwitchHold("TARGET_ALREADY_HAS_USERS")
        rows = db.execute(
            "SELECT username,host,status FROM ssh_accounts "
            "WHERE service_type='ssh' AND (host=? OR "
            "(COALESCE(host,'')='' AND " + ACTIVE + ")) "
            "ORDER BY username", (source,)
        ).fetchall()
        if len({row[0] for row in rows}) != len(rows):
            raise QuickSwitchHold("DUPLICATE_CUSTOMER_ID")
        return {
            "source": source, "target": target, "hosts": st["hosts"],
            "count": len(rows), "fingerprint": _hash(rows),
            "users": rows, "identity": identity, "service_port": dest[3],
            "admin_port": dest[6] or 22,
        }

    async def _check(self, plan):
        check = self.check_target(plan)
        if asyncio.iscoroutine(check):
            check = await check
        if check is not True:
            raise QuickSwitchHold("TARGET_NETWORK_NOT_VERIFIED")

    async def preview(self, target):
        with self.db() as db:
            plan = self._plan(db, target)
            self._conflicts(db, plan["source"], target)
            if _has(db, "manual_quick_switch_jobs") and db.execute(
                "SELECT 1 FROM manual_quick_switch_jobs "
                "WHERE kind='QUICK' AND status NOT IN ('DONE','ABORTED')"
            ).fetchone():
                raise QuickSwitchHold("QUICK_ROUTE_UNRESOLVED")
        await self._check(plan)
        dns = self.dns.snapshot()
        if not _exact_records(dns, dns, plan["source"]):
            raise QuickSwitchHold("DNS_NOT_ON_SOURCE")
        plan["dns"] = dns
        plan["issued_at"] = int(self.now())
        return plan

    def _reserve(self, plan, *, actor, evidence):
        job = secrets.token_hex(16)
        now = int(self.now())
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            live = self._plan(db, plan["target"])
            if any(live[k] != plan[k] for k in
                   ("source","target","hosts","fingerprint","count","identity")):
                raise QuickSwitchHold("PREVIEW_CHANGED")
            self._conflicts(db, plan["source"], plan["target"])
            if db.execute(
                "SELECT 1 FROM manual_quick_switch_jobs "
                "WHERE kind='QUICK' AND status NOT IN ('DONE','ABORTED')"
            ).fetchone():
                raise QuickSwitchHold("QUICK_ROUTE_UNRESOLVED")
            lock = db.execute(
                "INSERT INTO failover_operations "
                "(mode,source_host,target_host,status,started_at,updated_at,"
                "detail_json) VALUES ('MANUAL',?,?,'RUNNING',?,?,?)",
                (plan["source"], plan["target"],
                 time.strftime("%Y-%m-%d %H:%M:%S"),
                 time.strftime("%Y-%m-%d %H:%M:%S"),
                 json.dumps({"phase": "QUICK_SWITCH_DNS_INTENT", "job": job})),
            ).lastrowid
            db.execute(
                "INSERT INTO manual_quick_switch_jobs "
                "(id,kind,status,source,target,actor,evidence,"
                "account_fingerprint,account_count,expected_hosts,"
                "dns_before_json,lease_id,created_at,updated_at) "
                "VALUES (?,'QUICK','DNS_INTENT',?,?,?,?,?,?,?,?,?,?,?)",
                (job,plan["source"],plan["target"],str(actor),evidence,
                 plan["fingerprint"],plan["count"],plan["hosts"],
                 json.dumps(plan["dns"],sort_keys=True),lock,now,now),
            )
            self._log(db, job, "DNS_INTENT", "EXTERNAL_WRITE_INTENT")
        return job

    async def start(self, plan, *, actor, client_witness):
        if (not str(actor).strip() or not isinstance(client_witness, str)
                or not client_witness.strip()):
            raise QuickSwitchHold("OPERATOR_WITNESS_REQUIRED")
        if int(self.now()) - plan["issued_at"] not in range(0, TTL + 1):
            raise QuickSwitchHold("PREVIEW_EXPIRED")
        fresh = await self.preview(plan["target"])
        if any(fresh[k] != plan[k] for k in
               ("source","target","hosts","fingerprint","count","identity","dns")):
            raise QuickSwitchHold("PREVIEW_CHANGED")
        job = self._reserve(plan, actor=actor, evidence=client_witness)
        # Crashes after the durable intent are handled by explicit resume.
        await self.resume(job, actor=actor, retry_dns=True)
        return job

    def get(self, job):
        with self.db() as db:
            if not _has(db, "manual_quick_switch_jobs"):
                return None
            db.row_factory = __import__("sqlite3").Row
            rec = db.execute(
                "SELECT * FROM manual_quick_switch_jobs WHERE id=?", (job,)
            ).fetchone()
            return dict(rec) if rec else None

    def _hold(self, job, code):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "UPDATE manual_quick_switch_jobs SET status='HOLD',"
                "error_code=?,updated_at=? WHERE id=? AND "
                "status NOT IN ('DONE','ABORTED')",
                (code, int(self.now()), job)
            ).rowcount:
                self._log(db, job, "HOLD", code)

    def _commit(self, rec):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM manual_quick_switch_jobs "
                "WHERE id=? AND status IN ('DNS_INTENT','HOLD','DB_COMMITTED')",
                (rec["id"],)
            ).fetchone():
                raise QuickSwitchHold("JOURNAL_CHANGED")
            self._check_lease(db, rec)
            if rec["status"] == "DB_COMMITTED":
                return
            live = self._plan(db, rec["target"])
            if (live["source"] != rec["source"] or
                    live["fingerprint"] != rec["account_fingerprint"] or
                    live["count"] != rec["account_count"] or
                    live["hosts"] != rec["expected_hosts"]):
                raise QuickSwitchHold("ACCOUNT_OR_ROUTE_CHANGED")
            self._conflicts(db, rec["source"], rec["target"],
                            own_lease=rec["lease_id"])
            for username, old_host, status in live["users"]:
                updated = db.execute(
                    "UPDATE ssh_accounts SET host=? "
                    "WHERE username=? AND service_type='ssh' "
                    "AND COALESCE(host,'')=? AND status=?",
                    (rec["target"],username,old_host or "",status),
                ).rowcount
                if updated != 1:
                    raise QuickSwitchHold("ACCOUNT_CAS_CHANGED")
            if db.execute(
                "UPDATE host_pool SET is_default=0,is_standby=0 "
                "WHERE host=? AND is_default=1 AND active=1",
                (rec["source"],)
            ).rowcount != 1:
                raise QuickSwitchHold("SOURCE_DEFAULT_CHANGED")
            if db.execute(
                "UPDATE host_pool SET is_default=1,is_standby=0 "
                "WHERE host=? AND active=1 AND is_standby=1 AND is_default=0",
                (rec["target"],)
            ).rowcount != 1:
                raise QuickSwitchHold("TARGET_ROLE_CHANGED")
            manual = db.execute(
                "SELECT id,actor,chat FROM manual_edge_operations "
                "WHERE ip=? AND status='STANDBY'", (rec["target"],)
            ).fetchone()
            if not manual:
                raise QuickSwitchHold("MANUAL_OPERATION_CHANGED")
            if db.execute(
                "UPDATE manual_edge_operations SET status='ACTIVE',"
                "reason='QUICK_SWITCH_VERIFIED',updated_at=? "
                "WHERE id=? AND status='STANDBY'",
                (int(self.now()),manual[0]),
            ).rowcount != 1:
                raise QuickSwitchHold("MANUAL_OPERATION_CAS")
            db.execute(
                "INSERT INTO manual_edge_events "
                "(op_id,actor,status,code,happened) VALUES (?,?,?,?,?)",
                (manual[0],manual[1],"ACTIVE",
                 "QUICK_SWITCH_VERIFIED",int(self.now())),
            )
            for key, value in (
                ("hosts",rec["target"]),("dns_current_ip",rec["target"]),
                ("last_ip_switch_at",time.strftime("%Y-%m-%d %H:%M:%S")),
            ):
                db.execute(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
                    (key,value),
                )
            db.execute(
                "UPDATE manual_quick_switch_jobs SET status='DB_COMMITTED',"
                "updated_at=?,error_code='' WHERE id=?",
                (int(self.now()),rec["id"]),
            )
            self._log(db, rec["id"], "DB_COMMITTED", "ACCOUNT_ROUTE_CAS_OK")

    @staticmethod
    def _check_lease(db, rec):
        row = db.execute(
            "SELECT status,source_host,target_host,detail_json "
            "FROM failover_operations WHERE id=?", (rec["lease_id"],)
        ).fetchone()
        if not row or row[:3] != (
                "RUNNING", rec["source"],rec["target"]):
            raise QuickSwitchHold("LEASE_OWNERSHIP_LOST")
        try:
            detail = json.loads(row[3] or "{}")
        except ValueError:
            raise QuickSwitchHold("LEASE_IDENTITY_UNVERIFIED") from None
        if detail.get("job") != rec["id"]:
            raise QuickSwitchHold("LEASE_IDENTITY_UNVERIFIED")

    def _finish(self, rec):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._check_lease(db, rec)
            if db.execute(
                "SELECT status FROM manual_quick_switch_jobs WHERE id=?",
                (rec["id"],)
            ).fetchone() != ("DB_COMMITTED",):
                raise QuickSwitchHold("POSTCOMMIT_STATUS_CHANGED")
            default = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            st = dict(db.execute(
                "SELECT key,value FROM settings "
                "WHERE key IN ('hosts','dns_current_ip')"
            ).fetchall())
            foreign = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND " + ACTIVE + " AND COALESCE(host,'') != ?",
                (rec["target"],)
            ).fetchone()[0]
            if (default != [(rec["target"],)] or foreign
                    or st.get("hosts") != rec["target"]
                    or st.get("dns_current_ip") != rec["target"]):
                raise QuickSwitchHold("POSTCOMMIT_ROUTE_CHANGED")
            db.execute(
                "UPDATE manual_quick_switch_jobs SET status='DONE',"
                "updated_at=? WHERE id=?",
                (int(self.now()),rec["id"]),
            )
            db.execute(
                "UPDATE failover_operations SET status='SUCCEEDED',"
                "finished_at=?,updated_at=? WHERE id=? AND status='RUNNING'",
                (time.strftime("%Y-%m-%d %H:%M:%S"),
                 time.strftime("%Y-%m-%d %H:%M:%S"),rec["lease_id"]),
            )
            self._log(db, rec["id"], "DONE", "LIVE_DNS_DB_VERIFIED")

    async def resume(self, job, *, actor, retry_dns=False):
        rec = self.get(job)
        if not rec or rec["kind"] != "QUICK" or rec["actor"] != str(actor):
            raise QuickSwitchHold("OPERATOR_OR_JOB_MISMATCH")
        if rec["status"] == "DONE":
            return "DONE"
        if rec["status"] not in ("DNS_INTENT","HOLD","DB_COMMITTED"):
            raise QuickSwitchHold("UNSUPPORTED_RECOVERY_STATE")
        expected = json.loads(rec["dns_before_json"])
        with self.db() as db:
            self._check_lease(db, rec)
        actual = self.dns.snapshot()
        if (_exact_records(actual, expected, rec["source"])
                and rec["status"] != "DB_COMMITTED"):
            if not retry_dns:
                raise QuickSwitchHold("DNS_RETRY_REQUIRES_CONFIRMATION")
            # Re-probe before a new external write, even after a restart.
            with self.db() as db:
                plan = self._plan(db, rec["target"])
                if (plan["fingerprint"] != rec["account_fingerprint"]
                        or plan["count"] != rec["account_count"]):
                    raise QuickSwitchHold("ACCOUNT_SNAPSHOT_CHANGED")
            await self._check(plan)
            try:
                self.dns.set_all(expected,rec["target"])
            except Exception:
                self._hold(job, "DNS_WRITE_RESULT_UNCERTAIN")
                raise QuickSwitchHold("DNS_WRITE_RESULT_UNCERTAIN") from None
            actual = self.dns.snapshot()
        if not _exact_records(actual, expected,rec["target"]):
            self._hold(job, "DNS_UNCERTAIN_REVIEW_REQUIRED")
            raise QuickSwitchHold("DNS_UNCERTAIN_REVIEW_REQUIRED")
        if rec["status"] != "DB_COMMITTED":
            try:
                self._commit(rec)
            except Exception:
                self._hold(job, "DB_COMMIT_REVIEW_REQUIRED")
                raise
        rec = self.get(job)
        try:
            verified = self.dns.snapshot()
            if not _exact_records(verified,expected,rec["target"]):
                raise QuickSwitchHold("POSTCOMMIT_DNS_UNCERTAIN")
            self._finish(rec)
        except Exception:
            self._hold(job, "POSTCOMMIT_REVIEW_REQUIRED")
            raise
        return "DONE"

    async def record_external_cutover(self, *, source, target, actor,
                                      client_witness, expected_active):
        """One-time evidence of a previously completed manual rescue.

        No route/account/Cloudflare/6G/CZ07 mutations. Operator must provide a
        real client witness and independently observed active-account count.
        """
        if (not actor or not str(client_witness).strip()
                or type(expected_active) is not int or expected_active < 1):
            raise QuickSwitchHold("EXTERNAL_WITNESS_REQUIRED")
        with self.db() as db:
            defaults = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            st = dict(db.execute(
                "SELECT key,value FROM settings "
                "WHERE key IN ('hosts','dns_current_ip','core_wg_public_ip')"
            ).fetchall())
            roles = db.execute(
                "SELECT host,active,is_default,provider FROM host_pool "
                "WHERE host IN (?,?)", (source,target)
            ).fetchall()
            op = db.execute(
                "SELECT status FROM manual_edge_operations WHERE ip=?",
                (target,)
            ).fetchone()
            count = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND " + ACTIVE + " AND host=?", (target,)
            ).fetchone()[0]
            other = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND " + ACTIVE + " AND COALESCE(host,'') != ?", (target,)
            ).fetchone()[0]
            if (source == target or source == st.get("core_wg_public_ip")
                    or defaults != [(target,)] or
                    st.get("hosts") != target or st.get("dns_current_ip") != target
                    or op != ("ACTIVE",) or
                    (target,1,1,"manual") not in roles or
                    not any(r[0] == source and r[2] == 0 for r in roles)
                    or count != expected_active or other):
                raise QuickSwitchHold("EXTERNAL_ROUTE_UNVERIFIED")
        # Avoid a Cloudzy provider request; independent SSH/WG/NAT checks.
        await self._check({"source":source,"target":target,
                           "external":True})
        dns = self.dns.snapshot()
        if not _exact_records(dns,dns,target):
            raise QuickSwitchHold("EXTERNAL_DNS_UNVERIFIED")
        now = int(self.now())
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            # Snapshot must still be valid when attestation is appended.
            if db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall() != [(target,)]:
                raise QuickSwitchHold("EXTERNAL_DEFAULT_CHANGED")
            if db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND " + ACTIVE + " AND host=?", (target,)
            ).fetchone()[0] != expected_active:
                raise QuickSwitchHold("EXTERNAL_ACCOUNTS_CHANGED")
            existing = db.execute(
                "SELECT id FROM manual_quick_switch_jobs "
                "WHERE kind='EXTERNAL' AND source=? AND target=?",
                (source,target)
            ).fetchone()
            if existing:
                return existing[0]
            job = secrets.token_hex(16)
            db.execute(
                "INSERT INTO manual_quick_switch_jobs "
                "(id,kind,status,source,target,actor,evidence,"
                "account_fingerprint,account_count,expected_hosts,"
                "dns_before_json,lease_id,created_at,updated_at) "
                "VALUES (?,'EXTERNAL','EXTERNAL_VERIFIED',?,?,?,?,?,?,?,?,NULL,?,?)",
                (job,source,target,str(actor),client_witness,
                 "EXTERNAL_CURRENT_ROSTER",expected_active,target,
                 json.dumps(dns,sort_keys=True),now,now),
            )
            self._log(db, job, "EXTERNAL_VERIFIED",
                      "OPERATOR_ATTESTED_PREEXISTING_ROUTE")
        return job
