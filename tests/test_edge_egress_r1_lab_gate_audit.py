"""R1 LAB audit regression: real SQLite schema, no host modifications."""
import sqlite3
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_gate_audit import audit_db, audit_pam, collect
from edge_egress_r1_lab_pam import PAM_ACCOUNT_LINE
from edge_egress_r1_lab_6g_bootstrap import JOURNAL_SCHEMA
from edge_egress_inventory import SCHEMA as ALLOCATION_SCHEMA
from edge_egress_f3_readiness import READINESS_SCHEMA
from edge_egress_uid_runtime_store import RUNTIME_SCHEMA
from edge_egress_protected_mapping import MAPPING_SCHEMA


class LabGateAuditTests(unittest.TestCase):
    def make_db(self):
        conn = sqlite3.connect(":memory:")
        for ddl in (
            JOURNAL_SCHEMA, ALLOCATION_SCHEMA, READINESS_SCHEMA,
            RUNTIME_SCHEMA, MAPPING_SCHEMA
        ):
            conn.executescript(ddl)
        return conn

    def test_registered_live_edge_is_staged_not_ready(self):
        conn = self.make_db()
        conn.execute(
            "INSERT INTO failover_operations "
            "(mode,source_host,target_host,status,started_at,updated_at,detail_json) "
            "VALUES ('manual','107.189.16.36','216.126.229.12',"
            "'SUCCEEDED','2026-10-12','2026-10-12',"
            "'{\"kind\": \"EGRESS_LAB_ALLOCATION\", \"phase\": \"STAGED\"}')"
        )
        conn.execute(
            "INSERT INTO edge_egress_allocations "
            "(edge_id,edge_public_ipv4,core_public_ipv4,tunnel_network,"
            "veth_network,route_table,edge_listen_port,edge_uplink,"
            "core_public_key,edge_public_key,status) "
            "VALUES ('lab1','216.126.229.12','107.189.16.36',"
            "'10.78.120.0/30','10.78.121.0/30',1791,51852,'eth0',"
            "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',"
            "'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','STAGED')"
        )
        conn.execute(
            "INSERT INTO edge_egress_readiness "
            "(edge_id,edge_ipv4,state,last_operation_id) "
            "VALUES ('lab1','216.126.229.12','STAGED',1)"
        )
        flags = audit_db(conn)
        for key in (
            "real_6g_f1_f3_schema", "last_6g_staged_operation",
            "no_active_6g_lock", "live_edge_registry_staged",
            "edge_is_staged_not_ready", "protected_uid_mapping_absent",
        ):
            self.assertTrue(flags[key], key)
        self.assertFalse(flags["ingress_customer_schema_present"])
        conn.close()

    def test_running_lock_or_fake_ready_does_not_pass_stage_checks(self):
        conn = self.make_db()
        conn.execute(
            "INSERT INTO failover_operations "
            "(mode,source_host,target_host,status,started_at,updated_at) "
            "VALUES ('manual','107.189.16.36','216.126.229.12',"
            "'RUNNING','2026-10-12','2026-10-12')"
        )
        flags = audit_db(conn)
        self.assertFalse(flags["no_active_6g_lock"])
        self.assertFalse(flags["last_6g_staged_operation"])
        self.assertFalse(flags["edge_is_staged_not_ready"])
        conn.close()

    def test_pam_exact_first_account_line_and_backup(self):
        original = b"auth required pam_unix.so\naccount required pam_unix.so\n"
        active = (PAM_ACCOUNT_LINE + "\n").encode() + original
        with patch(
            "edge_egress_r1_lab_gate_audit.owned_data",
            side_effect=[active, original, b"reviewed-wrapper"],
        ), patch(
            "edge_egress_r1_lab_gate_audit.verified_runtime_module",
            return_value=True,
        ):
            checks = audit_pam()
        self.assertTrue(all(checks.values()))
        with patch(
            "edge_egress_r1_lab_gate_audit.owned_data",
            side_effect=[original + (PAM_ACCOUNT_LINE + "\n").encode(),
                         original, b"reviewed-wrapper"],
        ), patch(
            "edge_egress_r1_lab_gate_audit.verified_runtime_module",
            return_value=True,
        ):
            checks = audit_pam()
        self.assertFalse(checks["pam_original_backup_exact"])
        self.assertFalse(checks["pam_first_account_rule"])

    def test_even_all_green_evidence_never_enables_customer(self):
        with patch(
            "edge_egress_r1_lab_gate_audit.os.geteuid", return_value=0,
        ), patch(
            "edge_egress_r1_lab_gate_audit.audit_host",
            return_value={
                "pinned_disposable_core": True,
                "uid_blackhole_only": True,
                "pam_original_backup_exact": True,
            },
        ), patch(
            "edge_egress_r1_lab_gate_audit.DB",
        ) as path, patch(
            "edge_egress_r1_lab_gate_audit.sqlite3.connect",
        ) as connect, patch(
            "edge_egress_r1_lab_gate_audit.audit_db",
            return_value={
                "last_6g_staged_operation": True,
                "edge_is_staged_not_ready": True,
                "ingress_customer_schema_present": False,
            },
        ):
            import stat
            path.lstat.return_value.st_mode = stat.S_IFREG | 0o600
            path.lstat.return_value.st_uid = 0
            path.absolute.return_value.as_uri.return_value = "file:///fake/lab.db"
            report = collect()
        self.assertFalse(report["protected_ssh_enabled"])
        self.assertFalse(report["customer_ready"])
        self.assertEqual(report["host_mutations"], 0)
        self.assertIn("F4_READY_NOT_EVIDENCED", report["blockers"])
        self.assertIn(
            "REAL_LAB_INGRESS_ACCOUNT_METADATA_MISSING",
            report["blockers"],
        )


if __name__ == "__main__":
    unittest.main()
