"""Automatic plans and strict deferred preparation; no real host actions."""
from contextlib import ExitStack
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import edge_egress_k2_core_prerequisites as pre
from edge_egress_k2_a3_host_plans import RootHostSafetyGates
from edge_egress_k2_m4_bootstrap import GuardBootstrap
from edge_egress_k2_m4_root_worker import PINNED_SOURCE_FILES
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest, INTENT_PHASE
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_v1_admission import render_roster
from ops.edge_egress_provision import EgressSpec
from ops.k2_p3_module_stage import REQUIRED, ModuleStageHold, validate_module_bundle
from tests import test_edge_egress_k2_migration_inventory as inv_fixture
from tests.test_edge_egress_k2_migration_inventory import SOURCE, TARGET, NOW


def bundle():
    return {n: b"from __future__ import annotations\n" for n in REQUIRED}


class AutomaticUIDPlanTests(unittest.TestCase):
    def setUp(self):
        self.fx = inv_fixture.K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.scope = ExecutionScope("UID_ATTACH", "e9", SOURCE, TARGET,
                                    username="nvl0555", uid=1636)
        self.ticket = ExecutionTicket(11, 11, "a"*32, NOW+90,
                                      _scope_digest(self.scope), "b"*64)
        self.spec = EgressSpec("e9", TARGET, "209.200.246.198",
                                "10.79.9.0/30", "10.80.9.0/30", "eth0",
                                route_table=20009)
        self.pam = b"# original sshd PAM\naccount required pam_unix.so\n"
        self.gates = RootHostSafetyGates(
            safety=object(), independent_rescue_ok=lambda: True,
            independent_f4_ok=lambda scope: True, mixed_legacy_pam_ok=lambda: True,
            account_idle_ok=lambda name, uid: True,
            sshd_effective_probe=lambda: "usepam yes\n",
            guard_frozen_ok=lambda man: True, dns_ipv6_ok=lambda man: True,
        )
        self.source = pre.CoreUIDSnapshotSource(
            db_conn=self.fx.db, os_uid=lambda name: self.fx.uids[name],
            inventory_provider=lambda selected: self.fx.preview(),
            gates_provider=lambda *args: self.gates,
            module_blobs=bundle(), geteuid=lambda: 0,
        )

    def readers(self, current=None, guards=None):
        stack = ExitStack()
        stack.enter_context(patch.object(pre, "load_stage_pin", return_value=object()))
        stack.enter_context(patch.object(pre, "_check_stage", return_value=(self.spec, "peer", Path("/unused"))))
        stack.enter_context(patch.object(pre, "_installed_guards", return_value=(current, guards or {})))
        stack.enter_context(patch.object(pre, "_read_checked", return_value=self.pam))
        stack.enter_context(patch.object(self.source, "_resources", return_value=({10000, 10001}, {40000, 40001})))
        return stack

    def test_first_uid_plan_is_built_without_a_manually_staged_uid_file(self):
        with self.readers(), patch.object(pre, "stage_module_bundle") as install:
            spec = self.source(self.scope, self.ticket)
        self.assertIsInstance(spec.bootstrap, pre.CoreGuardBootstrap)
        self.assertEqual(spec.bootstrap.kind, "FIRST_UID")
        self.assertEqual((spec.request.priority, spec.dns_port), (10002, 40002))
        self.assertEqual(spec.request.spec.edge_public_ipv4, TARGET)
        self.assertEqual(spec.bootstrap.kwargs["plan"].uid, 1636)
        install.assert_not_called()
        self.assertFalse(self.fx.c.execute("SELECT * FROM failover_operations").fetchall())

    def test_next_uid_keeps_the_exact_previous_roster_and_guard(self):
        req = UIDPolicyRequest(self.spec, "pool_user", 1666, 10100)
        prior = asdict(req)
        prior.update(mode="PROTECTED_BOOT_GUARD", dns_port=40100,
                     ingress_return=True, shared_edge=True)
        raw = json.dumps(prior).encode()
        guards = {"pool_user": raw}
        current = render_roster(guards).encode()
        self.pam += (pre.plan_guard_install.__globals__["PAM_LINE"] + "\n").encode()
        with self.readers(current, guards):
            spec = self.source(self.scope, self.ticket)
        plan = spec.bootstrap.kwargs["plan"]
        self.assertEqual(spec.bootstrap.kind, "NEXT_UID")
        self.assertEqual(plan.current_roster, current)
        members = json.loads(plan.next_roster)["protected"]
        old = next(m for m in members if m["username"] == "pool_user")
        self.assertEqual(old["guard_sha256"], sha256(raw).hexdigest())

    def test_stage_allocation_mismatch_stops_before_any_install(self):
        self.fx.c.execute("UPDATE edge_egress_allocations SET route_table=20010 WHERE edge_id='e9'")
        with self.readers(), self.assertRaisesRegex(pre.CorePrerequisiteHold, "F3_STAGE"):
            self.source(self.scope, self.ticket)

    def test_linux_uid_drift_does_not_build_a_guard(self):
        self.source.os_uid = lambda name: 1644
        with self.assertRaisesRegex(pre.CorePrerequisiteHold, "EXACT_UID"):
            self.source(self.scope, self.ticket)

    def test_resource_parser_handles_tcp_and_udp_and_refuses_unknown_output(self):
        results = [SimpleNamespace(returncode=0, stdout='[{"priority":0},{"priority":10000}]'),
                   SimpleNamespace(returncode=0, stdout="tcp LISTEN 0 1 0.0.0.0:40000 0.0.0.0:*\nudp UNCONN 0 0 [::]:40001 [::]:*\n")]
        self.source.run = lambda *a, **k: results.pop(0)
        self.assertEqual(self.source._resources(), ({0, 10000}, {40000, 40001}))
        self.source.run = lambda *a, **k: SimpleNamespace(returncode=0, stdout="unknown")
        with self.assertRaises(ValueError):
            self.source._resources()

    def test_old_uid_kernel_rule_is_not_silently_adopted_or_overridden(self):
        for value in ("1636-1636", {"start": 1600, "end": 1700}):
            replies = [SimpleNamespace(returncode=0, stdout=json.dumps([
                {"priority": 1782, "uidrange": value},
            ])), SimpleNamespace(returncode=0, stdout="")]
            self.source.run = lambda *a, **k: replies.pop(0)
            with self.assertRaisesRegex(pre.CorePrerequisiteHold, "KERNEL_POLICY"):
                self.source._resources(1636)

    def test_actual_repository_bundle_includes_transitive_ops_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        pins = {n: sha256((root / n).read_bytes()).hexdigest() for n in PINNED_SOURCE_FILES}
        with patch.object(pre, "_verify_root_directory"), patch.object(
            pre, "_read_checked", side_effect=lambda path, **k: path.read_bytes(),
        ):
            blobs = pre.read_reviewed_module_bundle(root, pins)
            self.assertIn("ops/k2_p3_guard_installer.py", tuple(blobs))
            self.assertIn("ops/k2_m2_first_uid.py", tuple(blobs))
            self.assertIn("edge_egress_k2_runtime_release.py", tuple(blobs))
            incomplete = dict(pins)
            del incomplete["ops/k2_p3_guard_installer.py"]
            with self.assertRaisesRegex(pre.CorePrerequisiteHold, "UNPINNED"):
                pre.read_reviewed_module_bundle(root, incomplete)
        # Import the actual installed closure in a separate interpreter,
        # without accidentally borrowing root checkout modules from sys.path.
        with tempfile.TemporaryDirectory() as folder:
            for name, raw in blobs.items():
                path = Path(folder) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            result = subprocess.run([
                __import__("sys").executable, "-I", "-c",
                "import sys;sys.path.insert(0,sys.argv[1]);import edge_egress_v1_admission;import edge_egress_uid_dns",
                folder,
            ], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_ops_k2_imports_must_not_be_silently_omitted_from_the_bundle(self):
        blobs = bundle()
        blobs["edge_egress_v1_admission.py"] = b"from ops import k2_missing\n"
        with self.assertRaisesRegex(ModuleStageHold, "MISSING_LOCAL"):
            validate_module_bundle(blobs, {n: sha256(b).hexdigest() for n, b in blobs.items()})


class DeferredPreparationLeaseTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE failover_operations(id INTEGER,status TEXT,source_host TEXT,target_host TEXT,detail_json TEXT)")
        self.scope = ExecutionScope("UID_ATTACH", "e9", SOURCE, TARGET, username="nvl0555", uid=1636)
        self.ticket = ExecutionTicket(11, 11, "a"*32, NOW+90, _scope_digest(self.scope), "b"*64)
        blobs = bundle()
        pins = {n: sha256(b).hexdigest() for n, b in blobs.items()}
        self.boot = pre.CoreGuardBootstrap(
            self.scope, self.ticket, "FIRST_UID", {"db_conn": lambda: self.db},
            blobs, pins, validate_module_bundle(blobs, pins),
        )

    def acquire(self):
        detail = {"kind": "K2_P3A", "phase": INTENT_PHASE,
                  "scope_digest": _scope_digest(self.scope),
                  "nonce_hash": sha256(self.ticket.nonce.encode()).hexdigest()}
        self.db.execute("INSERT INTO failover_operations VALUES(1,'RUNNING',?,?,?)",
                        (SOURCE, TARGET, json.dumps(detail)))
        self.db.commit()

    def test_no_original_6g_intent_means_no_module_or_host_write(self):
        with patch.object(pre, "stage_module_bundle") as stage, self.assertRaises(ValueError):
            self.boot.run(self.scope, self.ticket)
        stage.assert_not_called()

    def test_existing_unverified_module_tree_is_held_without_overwriting_it(self):
        self.acquire()
        with tempfile.TemporaryDirectory() as folder, patch.object(pre, "TARGET", Path(folder)), patch.object(
            pre, "inspect_installed_module_bundle", side_effect=ValueError("DRIFT"),
        ), patch.object(GuardBootstrap, "run") as uid:
            with self.assertRaisesRegex(ValueError, "DRIFT"):
                self.boot.run(self.scope, self.ticket)
            uid.assert_not_called()
        self.assertEqual(self.db.execute("SELECT status FROM failover_operations").fetchone(), ("RUNNING",))


if __name__ == "__main__":
    unittest.main()
