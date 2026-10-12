"""R1 disabled-only filesystem installer tests (temporary directories; no systemctl)."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from edge_egress_r1_install import (
    prepare_bundle, install_disabled, rollback_disabled,
)
from edge_egress_r1_systemd import R1BootContract, R1ServiceUnsafe, render_unit
from ops.edge_egress_provision import EgressSpec


def sample():
    spec = EgressSpec(
        edge_id="fra1", core_public_ipv4="209.200.246.198",
        edge_public_ipv4="216.126.229.12",
        tunnel_network="10.78.110.0/30",
        veth_network="10.78.111.0/30", edge_uplink="eth0",
        edge_listen_port=51842, route_table=1790
    )
    c = R1BootContract(spec, "core", {
        "manifest.json": "a"*64, "wg.conf": "b"*64,
        "up.sh": "c"*64, "down.sh": "d"*64
    }, "f"*32, "1"*64)
    raw = json.dumps({
        "spec": asdict(spec), "role": c.role,
        "stage_sha256": c.stage_sha256,
        "machine_id": c.machine_id,
        "disposable_marker_sha256": c.disposable_marker_sha256,
        "mode": c.mode
    }, sort_keys=True).encode()
    sha = hashlib.sha256(raw).hexdigest()
    uhash = hashlib.sha256(render_unit(c, sha).encode()).hexdigest()
    return prepare_bundle(raw, expected_manifest_sha256=sha,
                          expected_unit_sha256=uhash)


class R1InstallTests(unittest.TestCase):
    def setUp(self):
        self.bundle = sample()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.manifest_dir = root / "etc-nvl-egress"
        self.unit_dir = root / "systemd-units"
        self.manifest_dir.mkdir()
        self.unit_dir.mkdir()
        self.unit = self.unit_dir / "nvl-egress-fra1-transport.service"
        self.manifest = self.manifest_dir / "r1-fra1-core.json"

    def install(self, **kw):
        with patch("edge_egress_r1_install.os.geteuid", return_value=0), \
             patch("edge_egress_r1_install._check_install_dirs"), \
             patch("edge_egress_r1_install._stage_owned", return_value=True):
            return install_disabled(
                self.bundle, manifest_root=self.manifest_dir,
                unit_root=self.unit_dir, stage_root=self.manifest_dir,
                explicitly_authorized=True,
                identity_check=lambda _: None, agent_check=lambda: True,
                **kw
            )

    def rollback(self, *, check=lambda _: True):
        with patch("edge_egress_r1_install.os.geteuid", return_value=0), \
             patch("edge_egress_r1_install._check_install_dirs"), \
             patch("edge_egress_r1_systemd._owned", return_value=True), \
             patch("edge_egress_r1_install._owned", return_value=True):
            return rollback_disabled(
                self.bundle, manifest_root=self.manifest_dir,
                unit_root=self.unit_dir, explicitly_authorized=True,
                identity_check=lambda _: None, inactive_disabled_check=check
            )

    def test_unreviewed_bundle_rejected(self):
        with self.assertRaisesRegex(R1ServiceUnsafe, "REVIEWED_MANIFEST_SHA"):
            prepare_bundle(self.bundle.manifest_bytes,
                           expected_manifest_sha256="0"*64,
                           expected_unit_sha256=self.bundle.unit_sha256)
        with self.assertRaisesRegex(R1ServiceUnsafe, "REVIEWED_UNIT_SHA"):
            prepare_bundle(self.bundle.manifest_bytes,
                           expected_manifest_sha256=self.bundle.manifest_sha256,
                           expected_unit_sha256="0"*64)

    def test_unauthorized_install_is_off_by_default(self):
        with self.assertRaisesRegex(R1ServiceUnsafe, "EXPLICIT_ROOT_GATE"):
            install_disabled(self.bundle)
        self.assertFalse(self.unit.exists())

    def test_install_creates_only_disabled_files_and_exact_rollback(self):
        result = self.install()
        self.assertEqual(result, (str(self.manifest), str(self.unit)))
        self.assertEqual(self.unit.read_bytes(), self.bundle.unit_bytes)
        self.assertEqual(self.manifest.read_bytes(), self.bundle.manifest_bytes)
        self.assertEqual(self.unit.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"start --manifest", self.unit.read_bytes())
        self.assertIn(b"verify --manifest", self.unit.read_bytes())
        self.assertEqual(self.rollback(), (str(self.unit), str(self.manifest)))
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.manifest.exists())

    def test_duplicate_install_never_overwrites(self):
        self.install()
        with self.assertRaisesRegex(R1ServiceUnsafe, "ALREADY_EXISTS"):
            self.install()
        self.assertEqual(self.unit.read_bytes(), self.bundle.unit_bytes)

    def test_foreign_target_symlink_never_modified(self):
        target = self.unit_dir / "foreign"
        target.write_text("important")
        self.unit.symlink_to(target)
        with self.assertRaisesRegex(R1ServiceUnsafe, "ALREADY_EXISTS"):
            self.install()
        self.assertEqual(target.read_text(), "important")
        self.assertFalse(self.manifest.exists())

    def test_rollback_refuses_running_or_enabled_unit(self):
        self.install()
        with self.assertRaisesRegex(R1ServiceUnsafe, "NOT_INACTIVE_DISABLED"):
            self.rollback(check=lambda _: False)
        self.assertTrue(self.unit.exists())
        self.assertTrue(self.manifest.exists())

    def test_rollback_refuses_tampered_unit_without_partial_delete(self):
        self.install()
        self.unit.write_text("different")
        with self.assertRaisesRegex(R1ServiceUnsafe, "OWNERSHIP_OR_BYTES"):
            self.rollback()
        self.assertTrue(self.unit.exists())
        self.assertTrue(self.manifest.exists())

    def test_rollback_recovers_interrupted_install_manifest_only(self):
        self.manifest.write_bytes(self.bundle.manifest_bytes)
        self.assertEqual(self.rollback(), (str(self.manifest),))
        self.assertFalse(self.manifest.exists())

    def test_rollback_refuses_unowned_symlink_even_if_dangling(self):
        self.manifest.symlink_to(self.manifest_dir / "missing")
        with self.assertRaisesRegex(R1ServiceUnsafe, "OWNERSHIP_OR_BYTES"):
            self.rollback()
        self.assertTrue(self.manifest.is_symlink())

    def test_install_agent_and_provenance_mandatory(self):
        with patch("edge_egress_r1_install.os.geteuid", return_value=0):
            with self.assertRaisesRegex(R1ServiceUnsafe, "REVIEWED_ROOT_AGENT"):
                install_disabled(self.bundle, explicitly_authorized=True,
                                 agent_check=None)
        with patch("edge_egress_r1_install.os.geteuid", return_value=0), \
             patch("edge_egress_r1_install._check_install_dirs"), \
             patch("edge_egress_r1_install._stage_owned", return_value=False):
            with self.assertRaisesRegex(R1ServiceUnsafe, "STAGED_BYTES"):
                install_disabled(
                    self.bundle, explicitly_authorized=True,
                    manifest_root=self.manifest_dir, unit_root=self.unit_dir,
                    stage_root=self.manifest_dir,
                    identity_check=lambda _: None, agent_check=lambda: True
                )
        self.assertFalse(self.manifest.exists())


if __name__ == "__main__":
    unittest.main()
