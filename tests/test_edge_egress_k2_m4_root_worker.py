"""M4.1 root worker packaging, owner/mode/manifest and release safety tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

from edge_egress_k2_m4_root_worker import (
    M4_ROOT_WORKER_ENABLED, PINNED_SOURCE_FILES, RootWorkerHold,
    RootWorkerService, WorkerPaths, SOCKET_NAME, _bind_socket,
    _check_socket_directory, _read_checked, load_root_secret,
    verify_reviewed_release,
)


class RootWorkerSealingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        source = root / "source"
        source.mkdir(mode=0o700)
        (source / "ops").mkdir(mode=0o755)
        security = root / "secrets"
        security.mkdir(mode=0o700)
        runtime = root / "run"
        runtime.mkdir(mode=0o750)
        runtime.chmod(0o750)  # Exact fixture mode, independent of caller umask.
        self.owner = os.getuid()
        self.gid = os.getgid()
        self.paths = WorkerPaths(
            source_root=source, manifest_file=security/"release.json",
            secret_file=security/"root-hmac.key",
            runtime_dir=runtime, bot_uid=20001, ipc_gid=self.gid,
        )
        self.payload = {}
        for name in PINNED_SOURCE_FILES:
            target = source/name
            target.write_text(name+"\n", encoding="utf-8")
            target.chmod(0o644)
            self.payload[name] = hashlib.sha256(target.read_bytes()).hexdigest()
        self.write_manifest()
        self.paths.secret_file.write_bytes(b"k"*48)
        self.paths.secret_file.chmod(0o600)

    def write_manifest(self, files=None):
        value = {"git_sha": "a"*40, "files": self.payload if files is None else files}
        self.paths.manifest_file.write_text(json.dumps(value))
        self.paths.manifest_file.chmod(0o600)

    def verify(self):
        return verify_reviewed_release(self.paths, owner_uid=self.owner)

    def test_complete_release_and_root_only_secret(self):
        self.assertEqual(self.verify(), "a"*40)
        self.assertEqual(load_root_secret(self.paths, owner_uid=self.owner),b"k"*48)

    def test_content_drift_never_accepted(self):
        self.verify()
        target=self.paths.source_root/"edge_egress_k2_m4_ipc.py"
        target.write_bytes(b"tampered code")
        with self.assertRaisesRegex(RootWorkerHold, "HASH_MISMATCH"):
            self.verify()

    def test_missing_extra_or_malformed_pins_hold(self):
        names=sorted(self.payload)
        for changes in (
            {k:v for k,v in self.payload.items() if k!=names[0]},
            {**self.payload, "unreviewed.py":"a"*64},
            {**self.payload, names[0]:"not-a-sha"},
        ):
            with self.subTest(n=len(changes)):
                self.write_manifest(changes)
                with self.assertRaises(RootWorkerHold):
                    self.verify()

    def test_untrusted_mode_and_symlink_hold(self):
        self.paths.secret_file.chmod(0o644)
        with self.assertRaises(RootWorkerHold):
            load_root_secret(self.paths, owner_uid=self.owner)
        self.paths.secret_file.unlink()
        outside=self.paths.manifest_file
        self.paths.secret_file.symlink_to(outside)
        with self.assertRaises(RootWorkerHold):
            load_root_secret(self.paths, owner_uid=self.owner)
        self.paths.secret_file.unlink()
        self.paths.manifest_file.chmod(0o666)
        with self.assertRaises(RootWorkerHold):
            self.verify()

    def test_source_symlink_is_not_followed_even_if_digest_matches(self):
        path=self.paths.source_root/"edge_egress_k2_m4_ipc.py"
        contents=path.read_bytes()
        path.unlink()
        target=self.paths.source_root/"test-target"
        target.write_bytes(contents)
        path.symlink_to(target)
        with self.assertRaises(RootWorkerHold):
            self.verify()

    def test_runtime_directory_needs_exact_mode_group_and_owner(self):
        _check_socket_directory(self.paths, owner_uid=self.owner)
        self.paths.runtime_dir.chmod(0o777)
        with self.assertRaises(RootWorkerHold):
            _check_socket_directory(self.paths, owner_uid=self.owner)

    def test_socket_never_overwrites_stale_path(self):
        path=self.paths.runtime_dir/SOCKET_NAME
        path.write_text("existing socket marker")
        with self.assertRaisesRegex(RootWorkerHold, "OCCUPIED"):
            _bind_socket(path,gid=self.gid)
        self.assertEqual(path.read_text(),"existing socket marker")

    def test_unix_listener_permission_and_single_socket_creation(self):
        path=self.paths.runtime_dir/SOCKET_NAME
        with patch("edge_egress_k2_m4_root_worker.os.chown"):
            listener=_bind_socket(path,gid=self.gid)
            self.addCleanup(listener.close)
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode),0o660)
            self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
            with self.assertRaises(RootWorkerHold):
                _bind_socket(path,gid=self.gid)

    def test_default_off_refuses_even_before_files_or_socket(self):
        self.assertFalse(M4_ROOT_WORKER_ENABLED)
        worker=RootWorkerService(
            paths=self.paths,transport=None,release_enabled=True,
            geteuid=lambda:0,
        )
        with self.assertRaisesRegex(RootWorkerHold, "DISABLED"):
            worker.open_listener()
        self.assertFalse((self.paths.runtime_dir/SOCKET_NAME).exists())

    def test_production_paths_and_nonroot_identity_required(self):
        with self.assertRaisesRegex(RootWorkerHold, "UNTRUSTED"):
            self.paths.validate()
        bad=WorkerPaths(Path("/root"),Path("/etc/nvl-egress/k2-m4/release.json"),
                        Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
                        Path("/run/nvl-k2-m4"),0,1001)
        with self.assertRaisesRegex(RootWorkerHold, "NONROOT"):
            bad.validate()


if __name__=="__main__":
    unittest.main()
