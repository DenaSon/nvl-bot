"""Static inventory tests; no imports of candidate source."""
import unittest
from pathlib import Path
from unittest.mock import patch
from ops import nvl_cd_inventory as inv


class InventoryTests(unittest.TestCase):
    def test_static_transitive_and_literal_imports(self):
        source = {
            "bot_final_v49-2.py": b"from pkg import helper\nimport ui\nimport_module('extra')\n",
            "pkg/__init__.py": b"",
            "pkg/helper.py": b"from . import nested\n",
            "pkg/nested.py": b"import shared\n",
            "ui.py": b"import shared\n",
            "extra.py": b"",
            "shared.py": b"",
        }
        self.assertEqual(inv.closure([inv.ENTRY], source, source.__getitem__), set(source))

    def test_review_excludes_shared_and_packages_and_reports_drift(self):
        source = {
            inv.ENTRY: b"import ui, shared, new, drift\nfrom pkg import item\n",
            "ui.py": b"",
            "shared.py": b"",
            "new.py": b"",
            "drift.py": b"",
            "pkg/item.py": b"",
            "nvl_awg_core_routes.py": b"import shared\n",
            "nvl_awg_witness_refresh.py": b"",
            "unclassified.py": b"",
        }
        hashes = {name: format(i + 1, "040x") for i, name in enumerate(source)}
        tree = {name: ("100644", "blob", oid) for name, oid in hashes.items()}
        reverse = {oid: source[name] for name, oid in hashes.items()}
        def live(runtime, name):
            return {"new.py": "ABSENT", "drift.py": None}.get(name, hashes[name])
        with patch.object(inv.p, "tree", return_value=tree), \
                patch.object(inv.p, "git", side_effect=lambda repo, *args: reverse[args[-1]]), \
                patch.object(inv.p, "live_blob", side_effect=live), \
                patch.object(inv.os.path, "lexists", return_value=False):
            report = inv.review(Path("/repo"), "a" * 40, Path("/root"))
        self.assertEqual(report["matched_candidate"], [inv.ENTRY, "ui.py"])
        self.assertEqual(report["absent_candidate"], ["new.py"])
        self.assertEqual(report["drift_candidate"], ["drift.py"])
        self.assertEqual(report["shared_manual"], ["shared.py"])
        self.assertEqual(report["package_manual"], ["pkg/item.py"])
        self.assertIn("unclassified.py", report["unclassified_root"])
        self.assertFalse(report["inventory_written"])
