"""Original P3 precommit ordering for a single cross-Edge UID.

Real SQLite F2 CAS and an isolated temporary policy file; all SSH, PAM,
kernel, WireGuard and network actions are fake/injected. No deployment.
"""
import asyncio
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_edge_egress_k2_cross_edge_store as fixture
from edge_egress_k2_uid_ingress_egress import (
    IngressEgressHold, parse_uid_ingress_egress_bindings,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_uid_runtime_store import read_binding
from tests.test_edge_egress_uid_runtime_store import SOURCE


class OriginalP3CrossEdgeStagingTests(unittest.TestCase):
    def setUp(self):
        self.harness = fixture.CrossEdgeStoreTests(
            methodName="test_default_off_blocks_before_any_uid_mutation"
        )
        self.harness.setUp()
        self.addCleanup(self.harness.doCleanups)
        self.base = self.harness.fx
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.policy_path = Path(self.work.name)/"uid-ingress-egress.json"
        self.policy_path.write_bytes(b'{"version":2,"bindings":[]}\n')
        self.store = self.harness.store()
        self.port = GuardedProtectedUIDPort(
            db_conn=self.base.conn_factory, plan=self.harness.plan,
            ticket=self.harness.ticket, store=self.store,
            kernel=self.base.kernel, safety=self.base.safety,
            roster_loader=self.base.roster_loader,
            guard_loader=self.base.guard_loader,
            os_uid_for_username=self.base.unix_lookup,
            release_enabled=True,
        )

    def pinned(self):
        stack = ExitStack()
        stack.enter_context(patch(
            "edge_egress_uid_runtime_store.K2_CROSS_EDGE_RUNTIME_STORE_ENABLED",
            True,
        ))
        stack.enter_context(patch(
            "edge_egress_k2_uid_ingress_egress.K2_M4_POLICY_STAGE_ENABLED",
            True,
        ))
        stack.enter_context(patch(
            "edge_egress_k2_uid_ingress_egress.ROOT_BINDINGS",
            self.policy_path,
        ))
        stack.enter_context(patch(
            "edge_egress_k2_uid_ingress_egress._trusted_directory",
        ))
        stack.enter_context(patch(
            "edge_egress_k2_uid_ingress_egress._trusted_bytes",
            side_effect=lambda path, maximum: path.read_bytes(),
        ))
        stack.enter_context(patch(
            "edge_egress_v1_admission.load_roster",
            return_value=self.base.roster,
        ))
        stack.enter_context(patch(
            "edge_egress_v1_admission.checked_guard",
            side_effect=self.base.guard_loader,
        ))
        return stack

    def test_p3_stages_future_policy_after_packet_before_f2_commit(self):
        real_replace = os.replace
        seen = []
        def observe_replace(src, dst):
            with self.base.db() as db:
                row = read_binding(db, "nvl0557")
                seen.append((row.state, row.generation))
            return real_replace(src, dst)
        with self.pinned(), patch("os.replace", side_effect=observe_replace):
            asyncio.run(self.port.apply(self.harness.scope))
            self.assertTrue(asyncio.run(
                self.port.verify(self.harness.scope)))
        self.assertEqual(seen, [("ROUTED_UNVERIFIED", 2)])
        record = parse_uid_ingress_egress_bindings(
            self.policy_path.read_bytes()
        )["nvl0557"]
        with self.base.db() as db:
            row = read_binding(db, "nvl0557")
            self.assertIsNone(read_binding(db, "nvl0558"))
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone(), ("8.8.8.8",))
        self.assertTrue(record.matches_runtime(
            row, installed_guard_sha256=self.base.roster["nvl0557"].guard_sha256,
        ))
        self.assertEqual(record.ingress_edge, "s8")
        self.assertEqual(record.egress_edge, "fra1")
        self.assertEqual(row.state, "PROTECTED")
        self.assertIn("packet", self.base.safety.events)

    def test_disabled_policy_writer_keeps_f2_uncommitted_and_6g_running(self):
        with self.pinned(), patch(
            "edge_egress_k2_uid_ingress_egress.K2_M4_POLICY_STAGE_ENABLED",
            False,
        ):
            with self.assertRaises(IngressEgressHold):
                asyncio.run(self.port.apply(self.harness.scope))
            asyncio.run(self.port.freeze_or_hold(self.harness.scope))
        with self.base.db() as db:
            self.assertEqual(read_binding(db, "nvl0557").state, "HOLD")
            self.assertEqual(db.execute(
                "SELECT status FROM failover_operations WHERE id=?",
                (self.harness.op,),
            ).fetchone(), ("RUNNING",))
        self.assertEqual(
            parse_uid_ingress_egress_bindings(self.policy_path.read_bytes()),
            {},
        )

    def test_file_replace_failure_holds_not_false_protected(self):
        with self.pinned(), patch(
            "os.replace", side_effect=OSError("disk failure"),
        ):
            with self.assertRaises(OSError):
                asyncio.run(self.port.apply(self.harness.scope))
            asyncio.run(self.port.freeze_or_hold(self.harness.scope))
        with self.base.db() as db:
            self.assertEqual(read_binding(db, "nvl0557").state, "HOLD")
        self.assertEqual(
            parse_uid_ingress_egress_bindings(self.policy_path.read_bytes()),
            {},
        )

    def test_replay_and_stale_nonce_do_not_modify_root_policy(self):
        with self.pinned():
            asyncio.run(self.port.apply(self.harness.scope))
            old_bytes = self.policy_path.read_bytes()
            with self.assertRaises(IngressEgressHold):
                self.store.stage_pam_admission(
                    self.base.uid_req, source=SOURCE,
                )
            self.assertEqual(self.policy_path.read_bytes(), old_bytes)


if __name__ == "__main__":
    unittest.main()
