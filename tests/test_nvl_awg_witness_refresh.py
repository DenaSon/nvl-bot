"""Hermetic tests for independent per-Edge Limiter witness refresh."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from nvl_awg_witness_refresh import refresh, WitnessRefreshHold
from nvl_awg_target import core_limiter_canary_ready


HOST1 = "130.94.64.120"
HOST2 = "130.94.64.67"
EDGE1 = "10.203.77.5"
EDGE2 = "10.203.77.4"


def make_db(path):
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE manual_edge_operations(
            ip TEXT,status TEXT,archived_at INTEGER,tunnel_backend TEXT
        );
        CREATE TABLE host_pool(
            host TEXT,active INTEGER,is_standby INTEGER,is_default INTEGER,
            provider TEXT,provider_instance_id TEXT
        );
        CREATE TABLE edge_tunnel_bindings(
            host TEXT,edge_tunnel_ip TEXT,backend TEXT,interface TEXT,state TEXT
        );
        """)
        for host, tunnel in ((HOST1, EDGE1), (HOST2, EDGE2)):
            db.execute("INSERT INTO manual_edge_operations VALUES (?, 'STANDBY', NULL, 'amneziawg')",
                       (host,))
            db.execute("INSERT INTO host_pool VALUES (?,1,1,0,'manual',NULL)", (host,))
            db.execute("INSERT INTO edge_tunnel_bindings VALUES (?,?,'amneziawg','awg0','VERIFIED')",
                       (host, tunnel))


class WitnessRefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "nvl.db"
        self.directory = Path(self.tmp.name) / "markers"
        make_db(self.db)
        self._real_lstat = Path.lstat

    def _as_root(self, path, *args, **kwargs):
        info = self._real_lstat(path, *args, **kwargs)
        if path == self.directory:
            class PretendRoot:
                st_uid = 0
                st_mode = stat.S_IFDIR | 0o700
            return PretendRoot()
        return info

    @staticmethod
    def fake_attest(host, *, marker):
        tunnel = {HOST1: EDGE1, HOST2: EDGE2}[host]
        marker.write_text("NVL_AWG_LIMITER_READY " + tunnel + "\n")
        marker.chmod(0o600)
        return tunnel

    def test_two_standbys_have_separate_markers(self):
        with patch.object(Path, "lstat",
                              lambda path, *a, **kw: self._as_root(path, *a, **kw)):
            ready, failed = refresh(
                db_path=self.db,marker_dir=self.directory,
                attest_fn=self.fake_attest,root_check=lambda:0)
        self.assertEqual((ready, failed), (2, 0))
        self.assertTrue((self.directory / EDGE1).exists())
        self.assertTrue((self.directory / EDGE2).exists())
        self.assertNotEqual((self.directory / EDGE1).read_text(),
                            (self.directory / EDGE2).read_text())

    def test_failed_candidate_revokes_only_its_marker(self):
        with patch.object(Path, "lstat",
                              lambda path, *a, **kw: self._as_root(path, *a, **kw)):
            refresh(db_path=self.db,marker_dir=self.directory,
                    attest_fn=self.fake_attest,root_check=lambda:0)

            def fail_second(host, *, marker):
                if host == HOST2:
                    raise RuntimeError("probe failure")
                return self.fake_attest(host, marker=marker)

            ready, failed = refresh(
                db_path=self.db,marker_dir=self.directory,
                attest_fn=fail_second,root_check=lambda:0)
        self.assertEqual((ready, failed), (1, 1))
        self.assertTrue((self.directory / EDGE1).exists())
        self.assertFalse((self.directory / EDGE2).exists())

    def test_retired_edge_is_pruned_and_never_attested(self):
        with patch.object(Path, "lstat",
                              lambda path, *a, **kw: self._as_root(path, *a, **kw)):
            refresh(db_path=self.db,marker_dir=self.directory,
                    attest_fn=self.fake_attest,root_check=lambda:0)
            with sqlite3.connect(self.db) as db:
                db.execute("UPDATE manual_edge_operations SET status='ACTIVE' WHERE ip=?",
                           (HOST2,))
                db.execute("UPDATE host_pool SET is_default=1,is_standby=0 WHERE host=?",
                           (HOST2,))
            ready, failed = refresh(
                db_path=self.db,marker_dir=self.directory,
                attest_fn=self.fake_attest,root_check=lambda:0)
        self.assertEqual((ready, failed), (1, 0))
        self.assertFalse((self.directory / EDGE2).exists())

    def test_unauthorized_cannot_write_witnesses(self):
        with self.assertRaisesRegex(WitnessRefreshHold, "WITNESS_ROOT_REQUIRED"):
            refresh(db_path=self.db,marker_dir=self.directory,
                    attest_fn=self.fake_attest,root_check=lambda:1001)
        self.assertFalse(self.directory.exists())

    def test_fail_closed_on_ambiguous_standby(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO manual_edge_operations VALUES (?, 'STANDBY',NULL,'amneziawg')",
                       (HOST1,))
        with patch.object(Path, "lstat",
                              lambda path, *a, **kw: self._as_root(path, *a, **kw)):
            with self.assertRaisesRegex(WitnessRefreshHold,"WITNESS_CANDIDATE_AMBIGUOUS"):
                refresh(db_path=self.db,marker_dir=self.directory,
                        attest_fn=self.fake_attest,root_check=lambda:0)
        self.assertFalse((self.directory / EDGE1).exists())

    def test_gate_accepts_exact_per_edge_witness_and_rejects_stale(self):
        with patch.object(Path, "lstat",
                              lambda path, *a, **kw: self._as_root(path, *a, **kw)):
            refresh(db_path=self.db,marker_dir=self.directory,
                    attest_fn=self.fake_attest,root_check=lambda:0)

        def root_stat(original):
            def fn(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path == self.directory or path in (self.directory/EDGE1, self.directory/EDGE2):
                    class R:
                        st_uid = 0
                        st_mode = (stat.S_IFDIR|0o700) if path == self.directory else (stat.S_IFREG|0o600)
                        st_size = result.st_size
                        st_mtime = time.time()
                    return R()
                return result
            return fn

        real = Path.stat
        live=lambda *_a,**_kw:subprocess.CompletedProcess([],0,"","")
        with patch.object(Path, "stat", root_stat(real)):
            self.assertTrue(core_limiter_canary_ready(
                EDGE1, marker_path=str(Path(self.tmp.name)/"absent"),
                marker_dir=str(self.directory),runner=live))
            self.assertTrue(core_limiter_canary_ready(
                EDGE2, marker_path=str(Path(self.tmp.name)/"absent"),
                marker_dir=str(self.directory),runner=live))
            self.assertFalse(core_limiter_canary_ready(
                "10.203.77.99", marker_path=str(Path(self.tmp.name)/"absent"),
                marker_dir=str(self.directory),runner=live))


if __name__ == "__main__":
    unittest.main()
