"""Durable non-Cloudzy identity and lifecycle for administrator-supplied Edges.

Manual adoption owns NO provider invoice or Cloudzy instance ID. The original
6G/Cloudflare route leases are shared and NOT superseded by this journal.
"""
from __future__ import annotations
import ipaddress
import secrets
import sqlite3
import time

from manual_edge_secure_form import public_ip, ssh_port


class ManualEdgeHold(RuntimeError):
    pass


ACTIVE = ("DRAFT", "IDENTITY_PENDING", "HOSTKEY_PENDING",
          "READY_INSTALL", "INSTALLING", "INSTALL_HOLD",
          "EDGE_READY", "STANDBY", "ROUTING", "MIGRATING", "ACTIVE", "HOLD")


class ManualEdgeJournal:
    def __init__(self, factory, *, now=time.time, guard=None,
                 install_lock_path=None):
        self.db, self.now, self.guard = factory, now, guard
        # Production always uses the shared installer lock. A private test
        # fixture can supply an isolated path without touching /run/lock.
        from legacy_wg_install_lease import LOCK_PATH
        self.install_lock_path = install_lock_path or LOCK_PATH

    def _protected(self, db):
        # Reuse original protected Core 6G/Legacy safety fence in the SAME
        # transaction as install intent and Standby registration.
        if self.guard is not None:
            self.guard(db)

    @staticmethod
    def initialize(db):
        db.execute("""CREATE TABLE IF NOT EXISTS manual_edge_operations(
            id TEXT PRIMARY KEY, actor INTEGER NOT NULL, chat INTEGER NOT NULL,
            ip TEXT, admin_port INTEGER,
            pin_type TEXT, pin_base64 TEXT, pin_fingerprint TEXT,
            status TEXT NOT NULL, reason TEXT,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            route_job TEXT,
            archived_at INTEGER
        )""")
        # Schema-only compatible extension for existing Core databases.
        columns={r[1] for r in db.execute("PRAGMA table_info(manual_edge_operations)")}
        if "archived_at" not in columns:
            db.execute("ALTER TABLE manual_edge_operations ADD COLUMN archived_at INTEGER")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS manual_edge_host_identity
            ON manual_edge_operations(ip)
            WHERE ip IS NOT NULL AND status != 'CANCELLED'""")
        # Upgrade the old per-admin lifetime lock in place. Only intake and
        # an actually running install are exclusive; READY/STANDBY/ROUTING
        # belong to different Edge identities and may coexist. Never drop the
        # unique IP identity index or any route/installer lease.
        existing = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' "
            "AND name='manual_edge_live_owner'"
        ).fetchone()
        if existing and any(status in (existing[0] or "") for status in
                            ("'EDGE_READY'", "'STANDBY'", "'ROUTING'",
                             "'MIGRATING'")):
            db.execute("DROP INDEX manual_edge_live_owner")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS manual_edge_live_owner
            ON manual_edge_operations(actor,chat)
            WHERE status IN ('DRAFT','IDENTITY_PENDING','HOSTKEY_PENDING',
                'READY_INSTALL','INSTALLING')""")
        db.execute("""CREATE TABLE IF NOT EXISTS manual_edge_events(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            op_id TEXT NOT NULL, actor INTEGER NOT NULL,
            status TEXT NOT NULL, code TEXT NOT NULL,
            happened INTEGER NOT NULL
        )""")

    def _log(self, db, op_id, actor, status, code):
        db.execute(
            "INSERT INTO manual_edge_events(op_id,actor,status,code,happened)"
            "VALUES (?,?,?,?,?)",
            (op_id,actor,status,code,int(self.now())),
        )

    def get(self, op_id):
        with self.db() as db:
            self.initialize(db)
            db.row_factory=sqlite3.Row
            row=db.execute("SELECT * FROM manual_edge_operations WHERE id=?",
                           (op_id,)).fetchone()
            return dict(row) if row else None

    def latest(self, actor, chat):
        with self.db() as db:
            self.initialize(db)
            row=db.execute(
                "SELECT id FROM manual_edge_operations WHERE actor=? AND chat=? "
                "AND status != 'CANCELLED' AND archived_at IS NULL "
                "ORDER BY created_at DESC,rowid DESC LIMIT 1",
                (actor,chat),
            ).fetchone()
            return self.get(row[0]) if row else None

    def list_by_owner(self, actor, chat, *, limit=7, offset=0):
        """Read-only paginated inventory, scoped to the private admin owner."""
        if type(actor) is not int or type(chat) is not int or actor <= 0 or chat <= 0:
            raise ManualEdgeHold("ADMIN_IDENTITY_INVALID")
        if type(limit) is not int or not 1 <= limit <= 20 or type(offset) is not int or offset < 0:
            raise ManualEdgeHold("INVALID_PAGE")
        with self.db() as db:
            self.initialize(db)
            db.row_factory = sqlite3.Row
            rows = db.execute(
                "SELECT * FROM manual_edge_operations "
                "WHERE actor=? AND chat=? AND status!='CANCELLED' "
                "AND archived_at IS NULL "
                "ORDER BY created_at DESC,rowid DESC LIMIT ? OFFSET ?",
                (actor, chat, limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]

    def display_state(self, op_id, actor, chat):
        """Actual route role for the UI; journal ACTIVE is only historical."""
        with self.db() as db:
            self.initialize(db)
            op=db.execute(
                "SELECT ip,status,archived_at FROM manual_edge_operations "
                "WHERE id=? AND actor=? AND chat=?",
                (op_id,actor,chat),
            ).fetchone()
            if op is None:
                raise ManualEdgeHold("OPERATOR_MISMATCH")
            ip,status,archived_at=op
            if archived_at is not None:
                return "ARCHIVED"
            if not ip:
                return "JOURNAL"
            pool=db.execute(
                "SELECT active,is_default,is_standby,provider "
                "FROM host_pool WHERE host=?", (ip,),
            ).fetchone()
            if pool and pool[1] == 1:
                st=dict(db.execute(
                    "SELECT key,value FROM settings "
                    "WHERE key IN ('hosts','dns_current_ip')"
                ).fetchall())
                defaults=db.execute(
                    "SELECT COUNT(*) FROM host_pool "
                    "WHERE active=1 AND is_default=1"
                ).fetchone()[0]
                if (pool==(1,1,0,"manual") and defaults==1
                        and st.get("hosts")==ip
                        and st.get("dns_current_ip")==ip
                        and status=="ACTIVE"):
                    return "DEFAULT"
                return "ROUTE_REVIEW"
            if status=="ACTIVE":
                if pool and pool[2]:
                    return "ROUTE_REVIEW"
                return "FORMER" if pool and pool[3]=="manual" else "POOL_REVIEW"
            if status=="STANDBY":
                return ("STANDBY" if pool==(1,0,1,"manual")
                        else "POOL_REVIEW")
            if status=="EDGE_READY":
                if pool is None:
                    return "POOL_MISSING"
                return ("EDGE_READY" if pool==(0,0,0,"manual")
                        else "POOL_REVIEW")
            return "JOURNAL"

    @staticmethod
    def _table_exists(db, name):
        return db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone() is not None

    def _archive_checks(self, db, op_id, actor, chat):
        """Read only, called again under BEGIN IMMEDIATE at commit."""
        op=db.execute(
            "SELECT ip,status,archived_at FROM manual_edge_operations "
            "WHERE id=? AND actor=? AND chat=?",
            (op_id,actor,chat),
        ).fetchone()
        if not op:
            raise ManualEdgeHold("OPERATOR_MISMATCH")
        ip,status,archived=op
        if archived is not None:
            raise ManualEdgeHold("ALREADY_ARCHIVED")
        if not ip or status not in ("ACTIVE","EDGE_READY"):
            raise ManualEdgeHold("ARCHIVE_STATUS_UNSAFE")
        pool=db.execute(
            "SELECT active,is_default,is_standby,provider FROM host_pool "
            "WHERE host=?", (ip,),
        ).fetchone()
        if pool and (pool[1] or pool[2] or pool[3]!="manual"):
            raise ManualEdgeHold("ARCHIVE_HOST_IS_ROUTED_OR_STANDBY")
        if status=="ACTIVE" and (not pool or pool[:3]!=(1,0,0)):
            raise ManualEdgeHold("ARCHIVE_ROLE_UNVERIFIED")
        if status=="EDGE_READY" and pool and pool[:3]!=(0,0,0):
            raise ManualEdgeHold("ARCHIVE_ROLE_UNVERIFIED")
        settings=dict(db.execute(
            "SELECT key,value FROM settings "
            "WHERE key IN ('dns_current_ip','hosts')"
        ).fetchall())
        if (ip==settings.get("dns_current_ip")
                or ip in (settings.get("hosts") or "").split(",")):
            raise ManualEdgeHold("ARCHIVE_HOST_IS_ROUTED_OR_STANDBY")
        if db.execute(
            "SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",(ip,)
        ).fetchone():
            raise ManualEdgeHold("ARCHIVE_USERS_STILL_ASSIGNED")
        if self._table_exists(db,"manual_quick_switch_jobs") and db.execute(
            "SELECT 1 FROM manual_quick_switch_jobs "
            "WHERE (source=? OR target=?) AND kind='QUICK' "
            "AND status NOT IN ('DONE','ABORTED') LIMIT 1",
            (ip,ip),
        ).fetchone():
            raise ManualEdgeHold("ARCHIVE_ROUTE_JOB_UNRESOLVED")
        if self._table_exists(db,"cloudzy_cz07_jobs") and db.execute(
            "SELECT 1 FROM cloudzy_cz07_jobs "
            "WHERE (source=? OR target=?) "
            "AND status NOT IN ('DONE','ABORTED','MOVED') LIMIT 1",
            (ip,ip),
        ).fetchone():
            raise ManualEdgeHold("ARCHIVE_ROUTE_JOB_UNRESOLVED")
        if self._table_exists(db,"failover_operations") and db.execute(
            "SELECT 1 FROM failover_operations "
            "WHERE status='RUNNING' AND (source_host=? OR target_host=?) "
            "LIMIT 1",(ip,ip),
        ).fetchone():
            raise ManualEdgeHold("ARCHIVE_ROUTE_JOB_UNRESOLVED")
        return {"id":op_id,"ip":ip,"status":status,
                "pool_registered":pool is not None}

    def archive_preview(self, op_id, actor, chat):
        """Read-only preview for removing an inactive card from the UI."""
        with self.db() as db:
            self.initialize(db)
            return self._archive_checks(db,op_id,actor,chat)

    def archive_inactive(self, op_id, actor, chat):
        """Hide only the retired operation, preserving identity and all effects.

        This NEVER removes host_pool, accounts, DNS, WG peers or external VPS.
        """
        with self.db() as db:
            self.initialize(db)
            db.execute("BEGIN IMMEDIATE")
            snapshot=self._archive_checks(db,op_id,actor,chat)
            changed=db.execute(
                "UPDATE manual_edge_operations SET archived_at=? "
                "WHERE id=? AND actor=? AND chat=? AND archived_at IS NULL "
                "AND status=?",
                (int(self.now()),op_id,actor,chat,snapshot["status"]),
            ).rowcount
            if changed!=1:
                raise ManualEdgeHold("MANUAL_CAS_FAILED")
            self._log(db,op_id,actor,snapshot["status"],"REMOVED_FROM_EDGE_LIST")
            return snapshot

    def assert_standby_candidate(self, op_id, actor, chat, customer_port):
        """Reject missing/stale inventory *before* expensive network probes."""
        with self.db() as db:
            self.initialize(db)
            row = db.execute(
                "SELECT ip,admin_port FROM manual_edge_operations "
                "WHERE id=? AND actor=? AND chat=? AND status='EDGE_READY'",
                (op_id, actor, chat),
            ).fetchone()
            if not row:
                raise ManualEdgeHold("EDGE_NOT_READY")
            pool = db.execute(
                "SELECT active,is_default,is_standby,provider,provider_instance_id,"
                "service_port,admin_ssh_port FROM host_pool WHERE host=?",
                (row[0],),
            ).fetchone()
            if (not pool or tuple(pool[:5]) != (0,0,0,"manual",None)
                    or pool[5] != customer_port or pool[6] != row[1]):
                raise ManualEdgeHold("MANUAL_HOST_POOL_MISMATCH")

    def start(self, actor, chat):
        if type(actor) is not int or type(chat) is not int or actor <= 0 or chat <= 0:
            raise ManualEdgeHold("ADMIN_IDENTITY_INVALID")
        with self.db() as db:
            self.initialize(db)
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM manual_edge_operations WHERE actor=? AND chat=? "
                "AND status IN ('DRAFT','IDENTITY_PENDING','HOSTKEY_PENDING',"
                "'READY_INSTALL','INSTALLING')",
                (actor,chat),
            ).fetchone():
                raise ManualEdgeHold("ACTIVE_MANUAL_OPERATION_EXISTS")
            op=secrets.token_hex(16)
            now=int(self.now())
            db.execute(
                "INSERT INTO manual_edge_operations "
                "(id,actor,chat,status,created_at,updated_at) "
                "VALUES (?,?,?,'DRAFT',?,?)",
                (op,actor,chat,now,now),
            )
            self._log(db,op,actor,"DRAFT","CREATED")
            return op

    def _cas(self,db,op_id,actor,chat,expected,next_state,code,fields=None):
        if fields is None:
            fields={}
        allowed = {
            "ip","admin_port","pin_type","pin_base64",
            "pin_fingerprint","reason","route_job",
        }
        if not set(fields).issubset(allowed):
            raise ManualEdgeHold("INVALID_FIELD")
        row=db.execute(
            "SELECT status FROM manual_edge_operations WHERE id=? AND actor=? AND chat=?",
            (op_id,actor,chat),
        ).fetchone()
        if not row or row[0]!=expected:
            raise ManualEdgeHold("MANUAL_OPERATION_CHANGED")
        stmt="status=?,updated_at=?"
        values=[next_state,int(self.now())]
        for key,value in fields.items():
            stmt+=","+key+"=?";values.append(value)
        try:
            changed=db.execute(
                "UPDATE manual_edge_operations SET "+stmt+
                " WHERE id=? AND actor=? AND chat=? AND status=?",
                (*values,op_id,actor,chat,expected),
            ).rowcount
        except sqlite3.IntegrityError as exc:
            raise ManualEdgeHold("EDGE_IDENTITY_OR_OPERATOR_BUSY") from exc
        if changed!=1:
            raise ManualEdgeHold("MANUAL_CAS_FAILED")
        self._log(db,op_id,actor,next_state,code)

    def set_server(self,op_id,actor,chat,ip,port):
        ip=public_ip(ip);port=ssh_port(port)
        with self.db() as db:
            self.initialize(db)
            db.execute("BEGIN IMMEDIATE")
            current_core=db.execute(
                "SELECT value FROM settings WHERE key='core_wg_public_ip'"
            ).fetchone()
            if current_core and str(current_core[0] or "").strip()==ip:
                raise ManualEdgeHold("CORE_IP_CANNOT_BE_EDGE")
            if db.execute("SELECT 1 FROM host_pool WHERE host=?", (ip,)).fetchone():
                raise ManualEdgeHold("EDGE_IP_ALREADY_REGISTERED")
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cloudzy_edge_operations'",
            ).fetchone() and db.execute(
                "SELECT 1 FROM cloudzy_edge_operations "
                "WHERE public_ipv4=? AND status NOT IN ('REJECTED','CANCELLED')",
                (ip,),
            ).fetchone():
                raise ManualEdgeHold("EDGE_IP_HAS_CLOUDZY_RECEIPT")
            self._cas(db,op_id,actor,chat,"DRAFT","HOSTKEY_PENDING",
                      "SERVER_VALIDATED",{"ip":ip,"admin_port":port})

    def pin(self,op_id,actor,chat,key_type,key_base64,fingerprint):
        if not (isinstance(key_type,str) and isinstance(key_base64,str)
                and isinstance(fingerprint,str)
                and 3<len(key_type)<40 and 20<len(key_base64)<4096
                and fingerprint.startswith("SHA256:")):
            raise ManualEdgeHold("INVALID_SSH_HOSTKEY")
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            self._cas(db,op_id,actor,chat,"HOSTKEY_PENDING","READY_INSTALL",
                      "OPERATOR_HOSTKEY_APPROVED",
                      {"pin_type":key_type,"pin_base64":key_base64,
                       "pin_fingerprint":fingerprint})

    def begin_install(self,op_id,actor,chat):
        # A stale Cloudzy HOLD is not proof of a *live* worker. Coordinate
        # against the very same flock used by all real Legacy installers.
        # Any still-running old worker holds it and must stop this new one.
        import fcntl, os, stat
        flags=os.O_RDWR|os.O_CREAT|getattr(os,"O_CLOEXEC",0)
        flags |= getattr(os,"O_NOFOLLOW",0)
        try:
            fd=os.open(self.install_lock_path,flags,0o600)
        except OSError as exc:
            raise ManualEdgeHold("CORE_WG_INSTALL_LOCK_UNAVAILABLE") from exc
        try:
            st=os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid()
                    or stat.S_IMODE(st.st_mode)&0o077):
                raise ManualEdgeHold("CORE_WG_INSTALL_LOCK_UNTRUSTED")
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ManualEdgeHold("CORE_WG_INSTALL_BUSY") from exc
            finally:
                # The sync installer itself reacquires this lock and holds it
                # through its entire remote/Core WG mutation. If a competing
                # worker starts meanwhile it will fail closed on that mutex.
                fcntl.flock(fd,fcntl.LOCK_UN)
        finally:
            os.close(fd)
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            # This is an isolated, inactive installation (no route or customer
            # mutation). The protected-route gate applies at mark_standby and
            # transfer, not before a new VPS can be prepared. The shared WG
            # installer mutex still prevents concurrent peer writes.
            # Legacy installer allocates Core WG peer IPs and appends Core WG
            # config. That is a truly shared resource across both pathways.
            # Do not admit concurrent/uncertain installers until reconciled.
            if db.execute(
                "SELECT 1 FROM manual_edge_operations "
                "WHERE id!=? AND status='INSTALLING' LIMIT 1",
                (op_id,),
            ).fetchone():
                raise ManualEdgeHold("CORE_WG_INSTALL_LEASE_BUSY")
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cloudzy_edge_operations'"
            ).fetchone() and db.execute(
                "SELECT 1 FROM cloudzy_edge_operations "
                "WHERE status='PROVISIONING' LIMIT 1"
            ).fetchone():
                raise ManualEdgeHold("CORE_WG_INSTALL_LEASE_BUSY")
            self._cas(db,op_id,actor,chat,"READY_INSTALL","INSTALLING",
                      "REMOTE_EFFECT_INTENT")
        return self.get(op_id)

    def install_hold(self,op_id,actor,chat,reason):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            self._cas(db,op_id,actor,chat,"INSTALLING","INSTALL_HOLD",
                      "REQUIRES_REMOTE_INSPECTION",
                      {"reason":str(reason)[:90]})

    def mark_edge_ready(self,op_id,actor,chat,customer_port):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            row=db.execute(
                "SELECT ip,admin_port,pin_type,pin_base64 FROM manual_edge_operations "
                "WHERE id=? AND actor=? AND chat=? AND status='INSTALLING'",
                (op_id,actor,chat),
            ).fetchone()
            if not row or not all(row):
                raise ManualEdgeHold("INSTALL_PROOF_MISSING")
            pool=db.execute(
                "SELECT active,is_default,is_standby,provider,provider_instance_id,"
                "service_port,admin_ssh_port FROM host_pool WHERE host=?",
                (row[0],),
            ).fetchone()
            if (not pool or tuple(pool[:5])!=(0,0,0,"manual",None)
                    or pool[5] != customer_port or pool[6] != row[1]):
                raise ManualEdgeHold("MANUAL_HOST_POOL_MISMATCH")
            self._cas(db,op_id,actor,chat,"INSTALLING","EDGE_READY",
                      "LEGACY_EDGE_VERIFIED")

    def mark_standby(self,op_id,actor,chat):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            self._protected(db)
            row=db.execute(
                "SELECT ip FROM manual_edge_operations "
                "WHERE id=? AND actor=? AND chat=? AND status='EDGE_READY'",
                (op_id,actor,chat),
            ).fetchone()
            if not row:
                raise ManualEdgeHold("EDGE_NOT_READY")
            ip=row[0]
            st=dict(db.execute(
                "SELECT key,value FROM settings WHERE key IN "
                "('hosts','dns_current_ip','auto_failover_mode',"
                "'phase6h_auto_failover_enabled','edge_egress_v1_onboard_enabled')"
            ).fetchall())
            if any(st.get(x)=="1" for x in
                   ("auto_failover_mode","phase6h_auto_failover_enabled",
                    "edge_egress_v1_onboard_enabled")):
                raise ManualEdgeHold("AUTO_FAILOVER_OR_K2_BUSY")
            if ip==st.get("dns_current_ip") or ip in (st.get("hosts") or "").split(","):
                raise ManualEdgeHold("TARGET_ALREADY_ROUTED")
            if db.execute("SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",(ip,)).fetchone():
                raise ManualEdgeHold("TARGET_ALREADY_HAS_ACCOUNTS")
            changed=db.execute(
                "UPDATE host_pool SET active=1,is_standby=1,is_default=0 "
                "WHERE host=? AND provider='manual' AND provider_instance_id IS NULL "
                "AND active=0 AND is_default=0 AND is_standby=0",
                (ip,),
            ).rowcount
            if changed!=1:
                raise ManualEdgeHold("STANDBY_ROLE_CHANGED")
            self._cas(db,op_id,actor,chat,"EDGE_READY","STANDBY",
                      "STANDBY_NETWORK_VERIFIED")

    def bind_route(self,op_id,actor,chat,job):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            self._cas(db,op_id,actor,chat,"STANDBY","ROUTING",
                      "TRANSFER_APPROVED",{"route_job":job})

    def finish(self,op_id,actor,chat,job):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            row=db.execute(
                "SELECT ip,route_job FROM manual_edge_operations "
                "WHERE id=? AND actor=? AND chat=? AND status='ROUTING'",
                (op_id,actor,chat),
            ).fetchone()
            if not row or row[1]!=job:
                raise ManualEdgeHold("ROUTE_JOB_MISMATCH")
            pool=db.execute("SELECT active,is_default,is_standby,provider "
                            "FROM host_pool WHERE host=?",(row[0],)).fetchone()
            if pool!=(1,1,0,"manual"):
                raise ManualEdgeHold("ACTIVE_RELAY_NOT_VERIFIED")
            self._cas(db,op_id,actor,chat,"ROUTING","ACTIVE",
                      "TECHNICAL_TRANSFER_COMPLETE")

    def cancel_draft(self,op_id,actor,chat):
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            rec=db.execute(
                "SELECT status FROM manual_edge_operations WHERE id=? "
                "AND actor=? AND chat=?", (op_id,actor,chat),
            ).fetchone()
            if not rec or rec[0] not in ("DRAFT","HOSTKEY_PENDING","READY_INSTALL"):
                raise ManualEdgeHold("CANCEL_REQUIRES_SAFE_RECONCILIATION")
            self._cas(db,op_id,actor,chat,rec[0],"CANCELLED",
                      "NO_EXTERNAL_EFFECT_CANCELLED")
