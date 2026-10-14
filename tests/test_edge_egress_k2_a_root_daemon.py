"""Sealed K2 M4A daemon launch tests — no real root listener or systemd."""
from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ops.k2_m4_root_daemon as daemon
from edge_egress_k2_a_root_assembly import RootAssembly
from edge_egress_k2_m4_root_worker import WorkerPaths,RootWorkerHold


class ReviewedDaemonTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.paths=WorkerPaths(
            source_root=Path("/srv/nvl/reviewed"),
            manifest_file=Path("/etc/nvl-egress/k2-m4/release.json"),
            secret_file=Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
            runtime_dir=Path("/run/nvl-k2-m4"),
            bot_uid=12001,ipc_gid=12002,
        )
        self.worker=SimpleNamespace(
            paths=self.paths,
            transport=SimpleNamespace(bot_uid=12001,released=True),
            release_enabled=True,
            geteuid=lambda:0,
            serve=AsyncMock(return_value=1),
        )
        self.assembly=RootAssembly(self.worker,"a"*40,12001)

    async def test_entrypoint_always_inert_without_vetted_root_composition(self):
        self.assertEqual(daemon.main(),78)
        self.assertFalse(daemon.M4A_ROOT_DAEMON_RELEASED)
        with self.assertRaisesRegex(RootWorkerHold,"NOT_ACCEPTED"):
            await daemon.serve_reviewed_assembly(self.assembly)
        self.worker.serve.assert_not_awaited()

    async def test_wrong_identity_inert_no_listener(self):
        with patch.object(daemon,"M4A_ROOT_DAEMON_RELEASED",True),\
             patch.object(daemon,"M4_ROOT_WORKER_ENABLED",True):
            self.assembly=RootAssembly(self.worker,"a"*40,0)
            with self.assertRaisesRegex(RootWorkerHold,"NOT_ACCEPTED"):
                await daemon.serve_reviewed_assembly(self.assembly)
        self.worker.serve.assert_not_awaited()

    async def test_source_drift_fails_before_listener(self):
        with patch.object(daemon,"M4A_ROOT_DAEMON_RELEASED",True),\
             patch.object(daemon,"M4_ROOT_WORKER_ENABLED",True),\
             patch.object(daemon,"verify_reviewed_release",return_value="b"*40):
            with self.assertRaisesRegex(RootWorkerHold,"SOURCE_CHANGED"):
                await daemon.serve_reviewed_assembly(self.assembly)
        self.worker.serve.assert_not_awaited()

    async def test_explicit_sealed_reviewed_assembly_only(self):
        with patch.object(daemon,"M4A_ROOT_DAEMON_RELEASED",True),\
             patch.object(daemon,"M4_ROOT_WORKER_ENABLED",True),\
             patch.object(daemon,"verify_reviewed_release",return_value="a"*40):
            result=await daemon.serve_reviewed_assembly(
                self.assembly,max_connections=1,
            )
        self.assertEqual(result,1)
        self.worker.serve.assert_awaited_once_with(max_connections=1)
        # This tests the control boundary, not an installed root service.
        self.assertEqual(daemon.main(),78)


if __name__=="__main__":
    unittest.main()
