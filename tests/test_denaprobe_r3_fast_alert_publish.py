"""Regression: update fast R3 alerts only, preserving the running bot and DB."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops"))
from denaprobe_r3_fast_alert_publish import FILES, atomic_replace, digest, REQUIRED_SOURCE


class TestFastAlertPublisher(unittest.TestCase):
    def test_exact_two_module_allowlist(self):
        self.assertEqual(FILES, ("denaprobe_ingest/detector.py",
                                 "denaprobe_rich_admin.py"))
        self.assertNotIn("bot_final_v49-2.py", FILES)
        self.assertNotIn("denaprobe_alerts.py", FILES)

    def test_reviewed_detector_contains_fast_classification(self):
        text = (ROOT / FILES[0]).read_text(encoding="utf-8")
        for token in REQUIRED_SOURCE:
            self.assertIn(token, text)
        self.assertIn("threshold = 1 if observed == D0 else CONFIRM", text)

    def test_atomic_updates_and_restores_independent_of_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.py"
            target = root / "target.py"
            original = b"OLD_R3_CONTENT"
            source.write_bytes(b"NEW_FAST_R3_CONTENT")
            target.write_bytes(original)
            before = digest(target)
            atomic_replace(source, target)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            backup = root / "backup.py"
            backup.write_bytes(original)
            atomic_replace(backup, target)
            self.assertEqual(digest(target), before)

    def test_symlink_target_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.py"
            real = root / "original.py"
            link = root / "link.py"
            source.write_text("new")
            real.write_text("old")
            link.symlink_to(real)
            with self.assertRaises(RuntimeError):
                atomic_replace(source, link)
            self.assertEqual(real.read_text(), "old")


if __name__ == "__main__":
    unittest.main()
