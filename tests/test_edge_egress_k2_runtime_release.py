"""Real release bytes/modes and PAM digest refresh, emulated root ownership."""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import edge_egress_k2_runtime_release as release


class RootReleaseProfileTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.profile = self.root / "core-runtime.json"
        self.module = self.root / "edge_egress_v1_admission.py"
        self.module.write_bytes(b"# reviewed fixture source\n")
        self.module.chmod(0o644)
        self.body = {"version": 1, "single_enabled": True,
                     "pam_module_sha256": sha256(self.module.read_bytes()).hexdigest()}
        self.write()

    def write(self):
        self.profile.write_text(json.dumps(self.body))
        self.profile.chmod(0o600)

    def owned(self):
        stack = ExitStack()
        real_lstat, real_fstat = Path.lstat, os.fstat
        def root_info(info):
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        stack.enter_context(patch.object(release, "CORE_PROFILE", self.profile))
        stack.enter_context(patch.object(release, "INSTALLED_PAM", self.module))
        stack.enter_context(patch.object(Path, "lstat", lambda path: root_info(real_lstat(path))))
        stack.enter_context(patch("os.fstat", side_effect=lambda fd: root_info(real_fstat(fd))))
        stack.enter_context(patch("os.geteuid", return_value=0))
        return stack

    def test_same_profile_is_read_by_a_separate_pam_interpreter_context(self):
        with self.owned():
            self.assertTrue(release.pam_cross_edge_released())
            self.module.write_bytes(b"# changed after release\n")
            self.assertFalse(release.pam_cross_edge_released())

    def test_missing_and_disabled_profiles_never_enable_single(self):
        with self.owned():
            self.profile.unlink()
            self.assertFalse(release.load_core_profile().enabled)
            self.assertFalse(release.pam_cross_edge_released())
            self.body["single_enabled"] = False
            self.write()
            self.assertFalse(release.pam_cross_edge_released())

    def test_duplicates_boolean_version_and_integer_switch_are_not_accepted(self):
        with self.owned():
            for raw in (
                '{"version":1,"version":1}',
                json.dumps({**self.body, "version": True}),
                json.dumps({**self.body, "single_enabled": 1}),
                json.dumps({**self.body, "extra": True}),
            ):
                self.profile.write_text(raw)
                with self.assertRaises(release.CoreReleaseHold):
                    release.load_core_profile()
                self.assertFalse(release.pam_cross_edge_released())

    def test_publicly_readable_or_symlink_profile_is_not_root_authority(self):
        with self.owned():
            self.profile.chmod(0o644)
            with self.assertRaises(release.CoreReleaseHold):
                release.load_core_profile()
            self.profile.unlink()
            self.profile.symlink_to(self.module)
            self.assertFalse(release.pam_cross_edge_released())


if __name__ == "__main__":
    unittest.main()
