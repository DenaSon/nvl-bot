"""M42 postcommit proof must reference exact existing F2 PROTECTED CAS and 6G.

All SQLite records are disposable and no root, PAM, or network action runs.
"""
import json
import unittest

from edge_egress_k2_m42_bindings import (
    HostReviewedPorts, RootAdminPolicy, RootM42Bindings,
)
from edge_egress_p3_executor import ExecutionScope, INTENT_PHASE, _scope_digest
from tests.test_edge_egress_p3_uid import P3CUIDTests
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class M42ExactPostCommitTests(unittest.TestCase):
    def setUp(self):
        self.fx=P3CUIDTests(
            methodName="test_source_never_defaults_to_live_release",
        )
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.make_binding("PROTECTED")
        self.scope=ExecutionScope(
            "UID_ATTACH","fra1",SOURCE,TARGET,
            username="nvl0557",uid=1644,
        )
        with self.fx.db() as db:
            self.op=db.execute(
                "SELECT last_operation_id FROM edge_egress_uid_runtime "
                "WHERE username='nvl0557'"
            ).fetchone()[0]
            db.execute(
                "UPDATE failover_operations SET status='RUNNING',detail_json=? "
                "WHERE id=?",
                (json.dumps({
                    "kind":"K2_P3A","phase":INTENT_PHASE,
                    "edge_id":"fra1","action":"UID_ATTACH",
                    "scope_digest":_scope_digest(self.scope),
                    "nonce_hash":"f"*64,
                }),self.op),
            )
        self.bindings=RootM42Bindings(
            ports=HostReviewedPorts(
                db_conn=self.fx.conn_factory,
                acquire_6g=lambda *a:None,
                journal_6g=lambda *a,**k:None,
                port_factory=lambda *a:None,
                live_admin_role=lambda *a:False,
                protected_mode=lambda:"0",
                external_evidence=lambda:None,
                ingress_provider=lambda **k:None,
                os_uid=self.fx.unix_lookup,
                now=lambda:1000,geteuid=lambda:0,
            ),
            root_secret=b"x"*48,
            admin_policy=RootAdminPolicy(frozenset()),
        )

    def test_exact_committed_uid_still_under_p3_6g_intent(self):
        self.assertTrue(
            self.bindings._post_commit_under_current_6g(self.scope)
        )

    def test_succeeded_lease_cannot_authorize_fresh_final_evidence(self):
        with self.fx.db() as db:
            db.execute("UPDATE failover_operations SET status='SUCCEEDED'")
        self.assertFalse(
            self.bindings._post_commit_under_current_6g(self.scope)
        )

    def test_missing_protected_mapping_fails_closed(self):
        with self.fx.db() as db:
            db.execute(
                "DELETE FROM edge_egress_uid_bindings WHERE username='nvl0557'"
            )
        self.assertFalse(
            self.bindings._post_commit_under_current_6g(self.scope)
        )

    def test_wrong_scope_or_journal_phase_rejected(self):
        changed=ExecutionScope(
            "UID_ATTACH","fra1","172.86.105.67",TARGET,
            username="nvl0557",uid=1644,
        )
        self.assertFalse(
            self.bindings._post_commit_under_current_6g(changed)
        )
        with self.fx.db() as db:
            db.execute(
                "UPDATE failover_operations SET detail_json='{}'"
            )
        self.assertFalse(
            self.bindings._post_commit_under_current_6g(self.scope)
        )


if __name__=="__main__":
    unittest.main()
