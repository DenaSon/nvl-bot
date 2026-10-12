"""No live PAM host changes. Verify narrow wrapper, rollback and defaults."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from edge_egress_r1_lab_pam_runtime import (
    verified_runtime_module, main as runtime_main,
    REVIEWED_GIT_BLOB, MODULE as REVIEWED_MODULE,
)
from edge_egress_r1_lab_pam_install import (
    LabPAMUnsafe, git_blob, root_owned_regular, atomic_root_file, 
    pam_witness, main as install_main, restore, PAM_ACCOUNT_LINE,
)


class PAMRuntimeTests(unittest.TestCase):
    def test_exact_bundle_gate_matches_git_blob(self):
        content = (Path(__file__).resolve().parents[1] /
                   "edge_egress_r1_lab_pam.py").read_bytes()
        self.assertEqual(git_blob(content), REVIEWED_GIT_BLOB)

    def test_runtime_is_default_deny_when_not_root(self):
        with patch("edge_egress_r1_lab_pam_runtime.os.geteuid", return_value=1000):
            self.assertFalse(verified_runtime_module())
            self.assertEqual(runtime_main(), 1)

    def test_wrapper_source_matches_installer_pin(self):
        from edge_egress_r1_lab_pam_install import MODULE_GIT_BLOB
        content = (Path(__file__).resolve().parents[1] /
                   "edge_egress_r1_lab_pam_runtime.py").read_bytes()
        self.assertEqual(git_blob(content), MODULE_GIT_BLOB)


class PAMInstallTests(unittest.TestCase):
    def test_install_refuses_without_cloud_console_before_host_probe(self):
        with patch("edge_egress_r1_lab_pam_install.lab_preflight") as preflight:
            self.assertEqual(install_main(["install"]), 2)
            self.assertEqual(install_main(["restore"]), 2)
            preflight.assert_not_called()

    def test_pam_witness_refuses_root_denial_and_pilot_allow(self):
        with patch(
            "edge_egress_r1_lab_pam_install.subprocess.run",
            side_effect=[
                SimpleNamespace(returncode=1),
            ],
        ):
            with self.assertRaisesRegex(LabPAMUnsafe, "root"):
                pam_witness(Path("/tmp/mock"))
        with patch(
            "edge_egress_r1_lab_pam_install.subprocess.run",
            side_effect=[
                SimpleNamespace(returncode=0),
                SimpleNamespace(returncode=0),
            ],
        ):
            with self.assertRaisesRegex(LabPAMUnsafe, "nvlr1test"):
                pam_witness(Path("/tmp/mock"))

    def test_atomic_root_file_writes_expected_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pam-test"
            atomic_root_file(path, b"original-pam-bytes\n", 0o600)
            self.assertEqual(path.read_bytes(), b"original-pam-bytes\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_restore_requires_exact_prefix_before_mutation(self):
        with patch(
            "edge_egress_r1_lab_pam_install.lab_host_attested",
            return_value=True,
        ), patch(
            "edge_egress_r1_lab_pam_install.pwd.getpwnam",
            return_value=SimpleNamespace(
                pw_uid=1555, pw_shell="/usr/sbin/nologin"
            ),
        ), patch(
            "edge_egress_r1_lab_pam_install.root_owned_regular",
            side_effect=[b"original\n", b"some unrelated PAM change"],
        ), patch(
            "edge_egress_r1_lab_pam_install.atomic_root_file",
        ) as write:
            with self.assertRaisesRegex(LabPAMUnsafe, "CHANGED_SINCE"):
                restore()
            write.assert_not_called()

    def test_restore_matches_newline_prefixed_pam_line(self):
        installed = (PAM_ACCOUNT_LINE + "\n").encode() + b"original\n"
        with patch(
            "edge_egress_r1_lab_pam_install.lab_host_attested",
            return_value=True,
        ), patch(
            "edge_egress_r1_lab_pam_install.pwd.getpwnam",
            return_value=SimpleNamespace(
                pw_uid=1555, pw_shell="/usr/sbin/nologin"
            ),
        ), patch(
            "edge_egress_r1_lab_pam_install.root_owned_regular",
            side_effect=[b"original\n", installed],
        ), patch(
            "edge_egress_r1_lab_pam_install.MODULE",
        ) as path, patch(
            "edge_egress_r1_lab_pam_install.atomic_root_file"
        ) as write, patch(
            "edge_egress_r1_lab_pam_install.subprocess.run",
            return_value=SimpleNamespace(returncode=0),
        ):
            path.is_symlink.return_value = False
            path.is_file.return_value = True
            restore()
            self.assertEqual(write.call_args.args[1], b"original\n")


if __name__ == "__main__":
    unittest.main()
