"""Shared file-lock regression: Legacy Settings, Manual and Cloudzy installers.

All routes run through the same decorated Core WG sync provisioning function.
No live SSH, WG, file-system service or customer mutation is performed.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import stat
import threading
import unittest

from legacy_wg_install_lease import (
    exclusive_legacy_edge_install, LegacyWGLeaseHold,
)


class SharedWGInstallLeaseTests(unittest.TestCase):
    def test_parallel_different_installers_cannot_select_same_wg_ip(self):
        with TemporaryDirectory() as d:
            lock = str(Path(d) / "wg-install.lock")
            entered, release = threading.Event(), threading.Event()
            allocations = []

            @exclusive_legacy_edge_install(lock_path=lock)
            def legacy_install():
                entered.set()
                self.assertTrue(release.wait(3))
                allocations.append("10.77.0.2")
                return True, "", {"tunnel_ok": True}

            @exclusive_legacy_edge_install(lock_path=lock)
            def manual_or_cloudzy_install():
                allocations.append("10.77.0.2")
                return True, "", {"tunnel_ok": True}

            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(legacy_install)
                self.assertTrue(entered.wait(3))
                rejected = manual_or_cloudzy_install()
                self.assertEqual(
                    rejected, (False, "CORE_WG_INSTALL_BUSY", None))
                self.assertEqual(allocations, [])
                release.set()
                self.assertTrue(first.result(timeout=3)[0])
                self.assertEqual(allocations, ["10.77.0.2"])
                self.assertTrue(manual_or_cloudzy_install()[0])
                self.assertEqual(len(allocations), 2)
            self.assertEqual(stat.S_IMODE(os.stat(lock).st_mode),0o600)

    def test_exception_does_not_leave_stale_live_lock(self):
        with TemporaryDirectory() as d:
            lock = str(Path(d) / "wg-install.lock")

            @exclusive_legacy_edge_install(lock_path=lock)
            def broken():
                raise ValueError("simulated install failure")

            @exclusive_legacy_edge_install(lock_path=lock)
            def next_install():
                return True, "", {"tunnel_ok": True}

            with self.assertRaises(ValueError):
                broken()
            self.assertTrue(next_install()[0])

    def test_symlink_and_insecure_lock_files_fail_closed(self):
        with TemporaryDirectory() as d:
            dest = Path(d) / "target"
            dest.write_text("sensitive")
            path = Path(d) / "wg-install.lock"
            path.symlink_to(dest)
            wrapper=exclusive_legacy_edge_install(
                lambda:(True,"",None),lock_path=str(path))
            with self.assertRaises(LegacyWGLeaseHold):
                wrapper()
            path.unlink()
            path.write_text("")
            path.chmod(0o644)
            with self.assertRaisesRegex(LegacyWGLeaseHold, "UNTRUSTED"):
                wrapper()

    def test_all_bot_paths_share_a_single_decorated_sync_installer(self):
        path=Path(__file__).resolve().parents[1]/"bot_final_v49-2.py"
        source=path.read_text(encoding="utf-8")
        self.assertEqual(
            source.count("def _provision_new_edge_sync("),1)
        self.assertIn(
            "@exclusive_legacy_edge_install\ndef _provision_new_edge_sync(",
            source)
        self.assertIn(
            "async def _provision_new_edge(",source)
        self.assertIn(
            "_provision_new_edge_sync, edge_ip, root_password",
            source)
        self.assertIn("EDGE_NEW_PORT",source)
