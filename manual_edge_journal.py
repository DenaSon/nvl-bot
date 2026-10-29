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
    def __init__(self, factory, *, now=time.time, guard=None):
        self.db, self.now, self.guard = factory, now, guard

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
            route_job TEXT
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS manual_edge_host_identity
            ON manual_edge_operations(ip)
            WHERE ip IS NOT NULL AND status != 'CANCELLED'""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS manual_edge_live_owner
            ON manual_edge_operations(actor,chat)
            WHERE status IN ('DRAFT','IDENTITY_PENDING','HOSTKEY_PENDING',
                'READY_INSTALL','INSTALLING','EDGE_READY','STANDBY','ROUTING',
                'MIGRATING')""")
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
                "AND status != 'CANCELLED' ORDER BY created_at DESC,rowid DESC LIMIT 1",
                (actor,chat),
            ).fetchone()
            return self.get(row[0]) if row else None

    def start(self, actor, chat):
        if type(actor) is not int or type(chat) is not int or actor <= 0 or chat <= 0:
            raise ManualEdgeHold("ADMIN_IDENTITY_INVALID")
        with self.db() as db:
            self.initialize(db)
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM manual_edge_operations WHERE actor=? AND chat=? "
                "AND status IN ('DRAFT','IDENTITY_PENDING','HOSTKEY_PENDING',"
                "'READY_INSTALL','INSTALLING','EDGE_READY','STANDBY','ROUTING','MIGRATING')",
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
        with self.db() as db:
            self.initialize(db);db.execute("BEGIN IMMEDIATE")
            self._protected(db)
            # Legacy installer allocates Core WG peer IPs and appends Core WG
            # config. That is a truly shared resource across both pathways.
            # Do not admit concurrent/uncertain installers until reconciled.
            if db.execute(
                "SELECT 1 FROM manual_edge_operations "
                "WHERE id!=? AND status IN ('INSTALLING','INSTALL_HOLD') LIMIT 1",
                (op_id,),
            ).fetchone():
                raise ManualEdgeHold("CORE_WG_INSTALL_LEASE_BUSY")
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cloudzy_edge_operations'"
            ).fetchone() and db.execute(
                "SELECT 1 FROM cloudzy_edge_operations "
                "WHERE status IN ('PROVISIONING','HOLD_PROVISION') LIMIT 1"
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
