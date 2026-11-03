"""Preflight/import-path, preservation and rollback of R3 code-only publisher."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops"))
import denaprobe_r3_publish_core as publisher


class PublisherTests(unittest.TestCase):
    def test_source_imports_from_release_not_old_root_package(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            src = base / "source"
            root = base / "root"
            (src / "denaprobe_ingest").mkdir(parents=True)
            (root / "denaprobe_ingest").mkdir(parents=True)
            (src / "denaprobe_ingest" / "__init__.py").write_text("")
            (src / "denaprobe_ingest" / "collector.py").write_text("PASS=True")
            (src / "denaprobe_alerts.py").write_text(
                "from denaprobe_ingest import collector\nassert collector.PASS")
            (root / "denaprobe_ingest" / "__init__.py").write_text("")
            command = ("import denaprobe_alerts; from denaprobe_ingest import collector")
            env = {**os.environ, "PYTHONPATH": f"{src}:{root}"}
            broken = subprocess.run(
                (sys.executable, "-c", command),
                cwd=root, env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(broken.returncode, 0)
            good = subprocess.run(
                (sys.executable, "-c", command),
                cwd=src, env=env, capture_output=True, text=True,
            )
            self.assertEqual(good.returncode, 0, good.stderr)

    def test_existing_r2_and_r3_are_in_release_source(self):
        source = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn('"apps_dpt_24"', source)
        self.assertIn('"apps_dpt_168"', source)
        self.assertIn('"apps_dp3_home"', source)
        self.assertIn("NVL_DENAPROBE_R3_ALERTS_ENABLED", source)

    def test_compatibility_holds_unrelated_code_modifications(self):
        old = "def foo():\n    return 3\n\ndef _post_init(app):\n    return 1\n"
        new = "def foo():\n    return 4\n\ndef _post_init(app):\n    return 2\n"
        old_defs = publisher.definitions(old)
        new_defs = publisher.definitions(new)
        changed = [name for name in old_defs.keys() & new_defs.keys()
                   if old_defs[name] != new_defs[name]
                   and name not in publisher.ALLOWED_BOT_CHANGES]
        self.assertEqual(changed, ["foo"])

    def test_known_live_r2_baseline_is_compatible_with_r3_release(self):
        release = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        live = release
        a = live.index("# DenaProbe R3: optional admin dashboard")
        b = live.index("def _cloudzy_markup(rows):", a)
        live = live[:a] + live[b:]
        a = live.index('        if globals().get("_DP3_ENABLED", False):')
        b = live.index("    return rows", a)
        live = live[:a] + live[b:]
        a = live.index('    if d == "apps_dp3_home" or d.startswith("dp3:"):')
        b = live.index('    if d in ("apps_cz_rich_home", ', a)
        live = live[:a] + live[b:]
        a = live.index("async def _post_init(app):\n")
        b = live.index(
            "    # K2 Single shares this application's existing root process",
            a,
        )
        live = live[:a] + "async def _post_init(app):\n" + live[b:]
        live = live.replace(
            ", ('dp3_monitor_task', '📡 DenaProbe R3')", "", 1
        )
        self.assertNotIn("NVL_DENAPROBE_R3_ENABLED", live)
        self.assertIn("apps_dpt_24", live)
        publisher.verify_compatible(live, release)

    def test_env_is_idempotent_and_preserves_unrelated_settings(self):
        original = (b"FOO=safe\nNVL_DENAPROBE_R3_ENABLED=0\n"
                    b"NVL_DENAPROBE_DB_PATH=/old/db\nBAR=present\n")
        once = publisher.build_env(original)
        twice = publisher.build_env(once)
        self.assertEqual(once, twice)
        self.assertIn(b"FOO=safe", once)
        self.assertIn(b"BAR=present", once)
        for flag in publisher.FLAGS:
            self.assertEqual(once.decode().count(flag), 1)

    def test_file_backup_restore_exact_original_and_removes_new_modules(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root, backup = base / "root", base / "backup"
            root.mkdir()
            backup.mkdir()
            for rel in publisher.RELEASE:
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("new")
            for rel in publisher.RELEASE[:2]:
                b = backup / "code" / rel
                b.parent.mkdir(parents=True, exist_ok=True)
                b.write_text("old")
            (backup / "nvlbot.env").write_bytes(b"FOO=safe\n")
            env = base / "nvlbot.env"
            env.write_bytes(b"FOO=changed\n")
            publisher.revert(root, env, backup,
                             set(publisher.RELEASE[:2]))
            self.assertEqual((root / publisher.RELEASE[0]).read_text(),
                             "old")
            self.assertEqual((root / publisher.RELEASE[1]).read_text(),
                             "old")
            self.assertFalse((root / publisher.RELEASE[2]).exists())
            self.assertEqual(env.read_bytes(), b"FOO=safe\n")


if __name__ == "__main__":
    unittest.main()
