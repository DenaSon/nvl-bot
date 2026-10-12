"""Existing 6G/PAM LAB composition tests: all ports and hosts are mocked."""
import hashlib
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_integration import (
    Existing6GLabPilot, LabCompositionUnsafe, ReviewedLabPAMGate,
    LabUIDGuardProbe,
)
from edge_egress_r1_lab_topology import TwoHostCoreIngress
from edge_egress_r1_lab_launcher import LabSSHExecutor
from edge_egress_r1_lab_pam import PAM_ACCOUNT_LINE
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from tests.test_edge_egress_r1_lab_launcher import host, spec
from edge_egress_uid_policy import UIDPolicyRequest


def req():
    return UIDPolicyRequest(spec(), "nvlr1test", 1555, 1780)


class LabAssemblyTests(unittest.TestCase):
    def make(self, enabled=False):
        return Existing6GLabPilot(
            db_conn=lambda: sqlite3.connect(":memory:"),
            acquire_fn=lambda source, target: (1, None),
            update_fn=lambda *a, **kw: None,
            session_gate=ReviewedLabPAMGate("a" * 64),
            idle_probe=lambda request: True,
            kernel=LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True),
            ssh=LabSSHExecutor(Path("/root/id"), Path("/root/hosts")),
            edge=host("edge"), core=host("core"),
            topology=TwoHostCoreIngress(), guard=LabUIDGuardProbe(),
            enabled=enabled, disposable_vps=True,
        )

    def test_default_off_refuses_without_reading_db_or_mutation(self):
        pilot = self.make()
        with self.assertRaisesRegex(LabCompositionUnsafe, "DEFAULT_OFF"):
            pilot.build(req())

    def test_no_real_lab_source_refuses_before_db(self):
        pilot = self.make(True)
        with self.assertRaisesRegex(LabCompositionUnsafe, "INGRESS_NOT_ATTESTED"):
            pilot.build(req())

    def test_no_real_db_tables_refuses_without_acquire(self):
        pilot = self.make(True)
        with patch.object(TwoHostCoreIngress, "for_request", return_value=True), patch.object(
            ReviewedLabPAMGate, "__call__", return_value=True
        ), patch.object(LabUIDGuardProbe, "__call__", return_value=True):
            with self.assertRaisesRegex(LabCompositionUnsafe, "SCHEMA_MISSING"):
                pilot.build(req())

    def test_even_populated_schema_refuses_if_f4_is_not_ready(self):
        pilot = self.make(True)
        conn = sqlite3.connect(":memory:")
        for name in (
            "failover_operations", "ssh_accounts", "host_pool", "settings",
            "edge_egress_allocations", "edge_egress_readiness",
            "edge_egress_uid_runtime", "edge_egress_uid_bindings",
        ):
            conn.execute(f"CREATE TABLE {name} (id INTEGER)")
        pilot.db_conn = lambda: conn
        with patch.object(TwoHostCoreIngress, "for_request", return_value=True), patch.object(
            ReviewedLabPAMGate, "__call__", return_value=True
        ), patch.object(LabUIDGuardProbe, "__call__", return_value=True), patch(
            "edge_egress_r1_lab_integration.read_readiness",
            return_value=SimpleNamespace(state="VERIFIED_LAB")
        ), patch(
            "edge_egress_r1_lab_integration.admission_eligible",
            return_value=False,
        ):
            with self.assertRaisesRegex(LabCompositionUnsafe, "F4_READY_REQUIRED"):
                pilot.build(req())

    def test_ready_real_ports_bind_to_existing_f2_without_lock_acquire(self):
        pilot = self.make(True)
        conn = sqlite3.connect(":memory:")
        for name in (
            "failover_operations", "ssh_accounts", "host_pool", "settings",
            "edge_egress_allocations", "edge_egress_readiness",
            "edge_egress_uid_runtime", "edge_egress_uid_bindings",
        ):
            conn.execute(f"CREATE TABLE {name} (id INTEGER)")
        pilot.db_conn = lambda: conn
        with patch.object(TwoHostCoreIngress, "for_request", return_value=True), patch.object(
            ReviewedLabPAMGate, "__call__", return_value=True
        ), patch.object(LabUIDGuardProbe, "__call__", return_value=True), patch(
            "edge_egress_r1_lab_integration.read_readiness",
            return_value=SimpleNamespace(state="READY"),
        ), patch(
            "edge_egress_r1_lab_integration.admission_eligible",
            return_value=True,
        ):
            bridge = pilot.build(req())
        self.assertIsNotNone(bridge.shadow)
        self.assertIs(bridge.acquire_fn, pilot.acquire_fn)
        self.assertIs(bridge.update_fn, pilot.update_fn)
        self.assertIs(bridge.db_conn, pilot.db_conn)
        self.assertTrue(bridge.shadow.accept_verified_running_transport)
        self.assertTrue(bridge.shadow.explicitly_enabled)
        self.assertIsNone(bridge.operation_id)


class PamFileAttestationTests(unittest.TestCase):
    def test_requires_first_account_rule_and_reviewed_bytes(self):
        code = b"reviewed lab scoped PAM code"
        gate = ReviewedLabPAMGate(hashlib.sha256(code).hexdigest())
        text = "auth required pam_unix.so\n" + PAM_ACCOUNT_LINE + "\naccount required pam_unix.so\n"
        with patch("edge_egress_r1_lab_integration.os.geteuid", return_value=0), patch.object(
            Path, "is_symlink", return_value=False
        ), patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)
        ), patch.object(Path, "read_bytes", return_value=code), patch.object(
            Path, "read_text", return_value=text
        ), patch(
            "edge_egress_r1_lab_integration.subprocess.run",
            return_value=SimpleNamespace(stdout="usepam yes\npubkeyauthentication yes\n"),
        ):
            self.assertTrue(gate(req()))
        with patch("edge_egress_r1_lab_integration.os.geteuid", return_value=1000):
            self.assertFalse(gate(req()))

    def test_no_late_pam_hook_bypass(self):
        code = b"reviewed lab scoped PAM code"
        gate = ReviewedLabPAMGate(hashlib.sha256(code).hexdigest())
        text = "account sufficient pam_permit.so\n" + PAM_ACCOUNT_LINE + "\n"
        with patch("edge_egress_r1_lab_integration.os.geteuid", return_value=0), patch.object(
            Path, "is_symlink", return_value=False
        ), patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)
        ), patch.object(Path, "read_bytes", return_value=code), patch.object(
            Path, "read_text", return_value=text
        ):
            self.assertFalse(gate(req()))


if __name__ == "__main__":
    unittest.main()
