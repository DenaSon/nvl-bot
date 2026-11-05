import os
import subprocess
import unittest
from unittest.mock import patch

import marzban_node_xray_core as core


class XrayCoreBootstrapTests(unittest.TestCase):
    def test_default_pinned_version(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(core.target_version(), "26.6.1")

    def test_version_override_is_validated(self):
        with patch.dict(os.environ, {core.VERSION_ENV: "26.6.22"}):
            self.assertEqual(core.target_version(), "26.6.22")
        for bad in ("latest", "26.6.1;touch /tmp/hacked", "v26.6.1", "", "26.6.1\n"):
            with self.subTest(bad=bad):
                with patch.dict(os.environ, {core.VERSION_ENV: bad}):
                    with self.assertRaises(ValueError):
                        core.target_version()

    def test_architecture_mapping(self):
        for architecture in ("amd64", "x86_64"):
            self.assertEqual(
                core.archive_for_architecture(architecture), "Xray-linux-64.zip"
            )
        for architecture in ("aarch64", "arm64"):
            self.assertEqual(
                core.archive_for_architecture(architecture),
                "Xray-linux-arm64-v8a.zip",
            )
        for architecture in ("i386", "", "riscv64", "x86_64;rm -rf /"):
            with self.assertRaises(ValueError):
                core.archive_for_architecture(architecture)

    def test_versioned_executable_path(self):
        self.assertEqual(
            core.executable_path("26.6.1"),
            "/var/lib/marzban-node/xray-core/xray-v26.6.1",
        )
        with self.assertRaises(ValueError):
            core.executable_path("../../usr/bin/xray")

    def test_official_versioned_release_and_integrity_gate(self):
        source = core.INSTALL_SCRIPT
        self.assertIn("releases/download/v", source)
        self.assertIn("core.dgst", source)
        self.assertIn("sha256sum -c -", source)
        self.assertIn('actual="$("$stage/xray" version', source)
        self.assertLess(source.index("sha256sum -c -"), source.index('install -m 0755 "$stage/xray"'))
        self.assertNotIn("releases/latest/download", source)
        self.assertNotIn("curl | sh", source)
        result = subprocess.run(
            ["/bin/sh", "-n"], input=source, text=True,
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
