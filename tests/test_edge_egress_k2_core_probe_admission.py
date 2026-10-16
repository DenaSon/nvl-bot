"""Actual original 6G SQL and scoped PAM probe admission, virtual kernel only."""
import asyncio
from hashlib import sha256
import json
import sqlite3
import unittest
from unittest.mock import patch

import edge_egress_k2_runtime_release as release
import edge_egress_p3_executor as p3
from edge_egress_k2_a_6g_shared import Original6GRootCallbacks
from edge_egress_k2_core_prerequisites import CoreGuardBootstrap
from edge_egress_k2_m4_bootstrap import DeferredCrossEdgeOriginal6GHostPort
from edge_egress_uid_admission import decide_account, AdmissionResult
from edge_egress_uid_runtime_store import install_runtime_schema, read_binding
from edge_egress_protected_mapping import install_protected_mapping_schema
from ops.k2_p3_module_stage import REQUIRED, validate_module_bundle
from tests.test_edge_egress_k2_migration_inventory import NOW, SOURCE, TARGET


class CoreProbeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE failover_operations(
              id INTEGER PRIMARY KEY AUTOINCREMENT,mode TEXT,status TEXT,
              source_host TEXT,target_host TEXT,detail_json TEXT,
              started_at TEXT,updated_at TEXT,finished_at TEXT,error TEXT);
        """)
        install_runtime_schema(self.db)
        install_protected_mapping_schema(self.db)
        self.conn = lambda: self.db
        self.scope = p3.ExecutionScope("UID_ATTACH", "e9", SOURCE, TARGET,
                                      username="nvl0555", uid=1636)
        self.fresh = p3.FreshEvidence("b"*64, NOW, p3.BASE_GATES | p3.ATTACH_GATES)
        self.ticket = p3.issue_execution_ticket(self.scope, self.fresh,
                                               actor_id=11, chat_id=11, now=NOW)
        blobs = {n: b"from __future__ import annotations\n" for n in REQUIRED}
        pins = {n: sha256(b).hexdigest() for n, b in blobs.items()}
        boot = CoreGuardBootstrap(self.scope, self.ticket, "FIRST_UID",
                                  {"db_conn": self.conn}, blobs, pins,
                                  validate_module_bundle(blobs, pins))
        self.port = DeferredCrossEdgeOriginal6GHostPort(
            scope=self.scope, ticket=self.ticket, db_conn=self.conn,
            bootstrap=boot, port_factory=lambda *args: None, release_enabled=True,
        )
        for name in ("P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED", "P3_UID_POST_COMMIT_PROBE_ENABLED"):
            setting = patch.object(p3, name, True)
            setting.start()
            self.addCleanup(setting.stop)
        setting = patch.object(release, "pam_cross_edge_released", return_value=True)
        setting.start()
        self.addCleanup(setting.stop)
        self.db.commit()

    def add_user(self, name="nvl0555", uid=1636, op=1):
        self.db.execute("INSERT INTO edge_egress_uid_runtime "
            "(username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,state,last_operation_id) "
            "VALUES(?,?, 'e9',?,20009,?,?,'PROTECTED',?)", (name, uid, TARGET, 10000+uid, 40000+uid, op))
        self.db.execute("INSERT INTO edge_egress_uid_bindings "
                        "(username,uid,edge_id,edge_ipv4,status) VALUES(?,?,'e9',?,'PROTECTED')",
                        (name, uid, TARGET))
        self.db.commit()

    def intent(self, **changes):
        detail = dict(kind="K2_P3A", phase=p3.INTENT_PHASE, action="UID_ATTACH",
                      edge_id="e9", username="nvl0555", uid=1636, single_uid=True,
                      scope_digest=p3._scope_digest(self.scope),
                      nonce_hash=sha256(self.ticket.nonce.encode()).hexdigest())
        detail.update(changes)
        self.db.execute("DELETE FROM failover_operations")
        self.db.execute("INSERT INTO failover_operations(id,status,source_host,target_host,detail_json) "
                        "VALUES(1,'RUNNING',?,?,?)", (SOURCE, TARGET, json.dumps(detail)))
        self.db.commit()

    def decide(self, name="nvl0555", uid=1636, verified=True):
        return decide_account(self.db, name, uid, lambda row: verified,
                              scoped_busy_probe=lambda row: release.core_single_busy_admission(self.db, row))

    def test_selected_uid_denied_until_protected_post_commit_probe_phase(self):
        self.add_user()
        self.intent()
        self.assertEqual(self.decide().result, AdmissionResult.DENY)
        self.intent(probe_only=True)
        self.assertEqual(self.decide().result, AdmissionResult.ALLOW_PROTECTED)
        self.assertEqual(self.decide(verified=False).result, AdmissionResult.DENY)
        self.db.execute("UPDATE edge_egress_uid_runtime SET state='ROUTED_UNVERIFIED'")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_other_uid_keeps_its_own_guard_and_selected_uid_recovery_stays_denied(self):
        self.add_user()
        self.add_user("nvl0557", 1644, 42)
        self.intent()
        self.assertEqual(self.decide("nvl0557", 1644).result, AdmissionResult.ALLOW_PROTECTED)
        self.assertEqual(self.decide("nvl0557", 1644, False).result, AdmissionResult.DENY)
        self.intent(phase=p3.RECOVERY_PHASE, probe_only=True)
        self.assertEqual(self.decide().result, AdmissionResult.DENY)
        self.assertEqual(self.decide("nvl0557", 1644).result, AdmissionResult.ALLOW_PROTECTED)

    def test_unknown_or_unscoped_or_tampered_6g_never_opens_probe_admission(self):
        self.add_user()
        for changes in (
            {"single_uid": False}, {"uid": 1644}, {"username": "other"},
            {"scope_digest": "f"*64}, {"nonce_hash": "invalid"},
            {"phase": "UNKNOWN"}, {"probe_only": 1},
        ):
            self.intent(probe_only=True, **changes) if "probe_only" not in changes else self.intent(**changes)
            self.assertEqual(self.decide().result, AdmissionResult.DENY, changes)
        self.intent(probe_only=True)
        self.db.execute("UPDATE edge_egress_uid_runtime SET last_operation_id=42")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_release_off_retains_original_global_busy_denial(self):
        self.add_user()
        self.intent(probe_only=True)
        with patch.object(release, "pam_cross_edge_released", return_value=False):
            self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def executor(self, fail=False):
        async def apply(scope):
            self.assertEqual(scope, self.scope)
            detail = json.loads(self.db.execute(
                "SELECT detail_json FROM failover_operations WHERE status='RUNNING'").fetchone()[0])
            self.assertIs(detail["single_uid"], True)
            self.assertNotIn("probe_only", detail)
            self.add_user()
            self.assertEqual(self.decide().result, AdmissionResult.DENY)
        async def verify(scope):
            detail = json.loads(self.db.execute(
                "SELECT detail_json FROM failover_operations WHERE status='RUNNING'").fetchone()[0])
            self.assertIs(detail["probe_only"], True)
            self.assertEqual(self.decide().result, AdmissionResult.ALLOW_PROTECTED)
            return not fail
        async def freeze(scope):
            self.db.execute("UPDATE edge_egress_uid_runtime SET state='HOLD' WHERE username=?", (scope.username,))
            self.db.commit()
        # Only OS/packet actions are synthetic; the original 6G executor,
        # journal, typed deferred port, identity and PAM admission are real.
        self.port.apply, self.port.verify, self.port.freeze_or_hold = apply, verify, freeze
        original = Original6GRootCallbacks(self.conn)
        return p3.Existing6GGuardedExecutor(
            db_conn=self.conn, acquire_fn=original.acquire, journal_fn=original.journal,
            review_fn=lambda scope: self.fresh, host_port=self.port,
            release_enabled=True, geteuid=lambda: 0, clock=lambda: NOW,
        )

    def test_original_6g_retains_lease_while_customer_probe_runs_then_commits(self):
        result = asyncio.run(self.executor().execute(self.scope, self.ticket, actor_id=11, chat_id=11))
        self.assertEqual(result.result, "SUCCEEDED")
        self.assertEqual(self.db.execute("SELECT status FROM failover_operations").fetchone(), ("SUCCEEDED",))
        self.assertEqual(self.db.execute("SELECT value FROM settings").fetchone(), ("0",))

    def test_failed_customer_probe_freezes_uid_and_keeps_original_6g_recovery(self):
        result = asyncio.run(self.executor(fail=True).execute(self.scope, self.ticket, actor_id=11, chat_id=11))
        self.assertNotEqual(result.result, "SUCCEEDED")
        state, detail = self.db.execute("SELECT status,detail_json FROM failover_operations").fetchone()
        self.assertEqual(state, "RUNNING")
        self.assertEqual(json.loads(detail)["phase"], p3.RECOVERY_PHASE)
        self.assertEqual(read_binding(self.db, "nvl0555").state, "HOLD")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)


if __name__ == "__main__":
    unittest.main()
