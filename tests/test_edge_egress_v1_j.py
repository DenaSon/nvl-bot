"""J: fast offline manual/auto failover gating regression tests."""
import sqlite3
import unittest

from edge_egress_v1_6h import (
    evaluate_j_switch, review_protected_switch,
    HOLD_MODE, HOLD_MISSING_SCHEMA, HOLD_TARGET_NOT_REGISTERED,
    HOLD_TARGET_NOT_READY, HOLD_MAPPING_UNCERTAIN, HOLD_PINNED,
    HOLD_NEEDS_EXECUTOR,
)
from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema

SOURCE = "144.172.84.76"
TARGET = "144.172.84.82"


class JGateTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)

    def evaluate(self, mode="1"):
        return evaluate_j_switch(
            lambda: self.db, mode, SOURCE, TARGET, now=1500
        )

    def schema(self):
        install_readiness_schema(self.db)
        install_runtime_schema(self.db)
        install_protected_mapping_schema(self.db)

    def candidate(self, state="READY", witness="F4_PRODUCTION_ACCEPTANCE",
                  probed=1200, expires=1700):
        self.db.execute(
            "INSERT INTO edge_egress_f3_ingress_candidates "
            "(edge_ipv4,state) VALUES(?,'INGRESS_ONLY')", (TARGET,)
        )
        self.db.execute(
            "INSERT INTO edge_egress_readiness "
            "(edge_id,edge_ipv4,state,observed_ipv4,witness,"
            "probed_at,expires_at,last_operation_id) "
            "VALUES('e9',?,?,?,?,?,?,1)",
            (TARGET, state, TARGET, witness, probed, expires),
        )

    def user(self, state="PROTECTED", with_binding=True):
        self.db.execute(
            "INSERT INTO edge_egress_uid_runtime "
            "(username,uid,edge_id,edge_ipv4,route_table,priority,"
            "dns_port,state,last_operation_id) VALUES"
            "('nvl0557',1644,'e8',?,20008,20008,10553,?,1)",
            (SOURCE, state),
        )
        if with_binding:
            self.db.execute(
                "INSERT INTO edge_egress_uid_bindings "
                "(username,uid,edge_id,edge_ipv4,status) "
                "VALUES('nvl0557',1644,'e8',?,'PROTECTED')",
                (SOURCE,),
            )

    def test_legacy_paths_unchanged_but_still_require_6g_preflight(self):
        decision = self.evaluate("0")
        self.assertTrue(decision.allowed_legacy)
        self.assertFalse(decision.protected)
        self.assertEqual(decision.reason, "LEGACY_6G_PREFLIGHT_REQUIRED")

    def test_invalid_mode_and_missing_migrations_fail_closed(self):
        self.assertEqual(self.evaluate("bad").reason, HOLD_MODE)
        self.assertEqual(self.evaluate().reason, HOLD_MISSING_SCHEMA)
        self.schema()
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_REGISTERED)

    def test_staged_lab_and_expired_evidence_are_not_ready(self):
        self.schema()
        self.candidate(state="STAGED")
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_READY)
        self.db.execute(
            "UPDATE edge_egress_readiness SET state='VERIFIED_LAB'"
        )
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_READY)
        self.db.execute(
            "UPDATE edge_egress_readiness SET state='READY',"
            "witness='F4_PRODUCTION_ACCEPTANCE',expires_at=1400"
        )
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_READY)

    def test_wrong_witness_or_observed_ip_never_promotes(self):
        self.schema()
        self.candidate(witness="PINNED_SHADOW_NAMESPACE")
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_READY)
        self.db.execute(
            "UPDATE edge_egress_readiness SET witness='F4_PRODUCTION_ACCEPTANCE',"
            "observed_ipv4='144.172.84.76'"
        )
        self.assertEqual(self.evaluate().reason, HOLD_TARGET_NOT_READY)

    def test_protected_uid_pinned_blocks_ready_global_switch(self):
        self.schema()
        self.candidate()
        self.user()
        decision = self.evaluate()
        self.assertEqual(decision.reason, HOLD_PINNED)
        self.assertFalse(decision.allowed_legacy)
        self.assertTrue(decision.target_ready)
        self.assertEqual(decision.pinned_users, 1)

    def test_unsettled_runtime_or_missing_binding_blocks_switch(self):
        self.schema()
        self.candidate()
        self.user(state="BLOCKED", with_binding=False)
        self.assertEqual(self.evaluate().reason, HOLD_MAPPING_UNCERTAIN)
        self.db.execute("DELETE FROM edge_egress_uid_runtime")
        self.db.execute(
            "INSERT INTO edge_egress_uid_bindings "
            "(username,uid,edge_id,edge_ipv4,status) "
            "VALUES('nvl0557',1644,'e8',?,'PROTECTED')", (SOURCE,)
        )
        self.assertEqual(self.evaluate().reason, HOLD_MAPPING_UNCERTAIN)

    def test_ready_without_pinned_users_is_not_legacy_authorization(self):
        self.schema()
        self.candidate()
        result = self.evaluate()
        self.assertEqual(result.reason, HOLD_NEEDS_EXECUTOR)
        self.assertTrue(result.target_ready)
        self.assertFalse(result.allowed_legacy)

    def test_wrong_source_target_pair_and_schema_corruption(self):
        self.schema()
        self.candidate()
        self.assertFalse(review_protected_switch(
            self.db, source_host=TARGET, target_host=TARGET
        ).allowed_legacy)
        self.db.execute("DROP TABLE edge_egress_uid_runtime")
        self.assertEqual(self.evaluate().reason, HOLD_MISSING_SCHEMA)

    def test_gate_does_not_write_database_or_touch_default_dns(self):
        self.schema()
        self.candidate()
        before = self.db.total_changes
        self.evaluate()
        self.assertEqual(before, self.db.total_changes)


if __name__ == "__main__":
    unittest.main()
