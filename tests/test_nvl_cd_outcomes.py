"""Regression for durable outcome transfer and no-restart notice."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ops import nvl_cd_observer as obs
from ops import nvl_cd_publisher as pub

A, B = "a" * 40, "b" * 40


class OutcomeTests(unittest.TestCase):
    def test_docs_only_label_not_runtime_success(self):
        _, msg = obs.event({"phase": "COMMITTED", "candidate": A,
                            "deployed": A, "restart_required": False})
        self.assertIn("بدون نیاز به Restart", msg)

    def test_archive_delivered_even_after_next_release_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(obs.p, "trusted", side_effect=lambda path, **kw: path):
            state = Path(tmp)
            pub.set_phase(state, {"candidate": A, "deployed": A}, "COMMITTED")
            pub.set_phase(state, {"candidate": B, "deployed": B}, "COMMITTED")
            delivered = []
            for now in (100, 101, 102):
                obs.observe(state, now=now, sender=lambda msg: delivered.append(msg) or True)
            self.assertEqual(len(delivered), 2)
            self.assertTrue(any(A[:12] in msg for msg in delivered))
            self.assertTrue(any(B[:12] in msg for msg in delivered))
            self.assertEqual(list((state / "outcomes").iterdir()), [])
