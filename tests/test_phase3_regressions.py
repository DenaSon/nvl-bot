import ast
import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase3DeletionRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        cls.delete_fn = next(
            node for node in cls.tree.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_delete_marzban_user_consistent"
        )

    def test_preferences_cleanup_exists(self):
        fn_source = ast.get_source_segment(self.source, self.delete_fn) or ""
        self.assertIn(
            'DELETE FROM marzban_user_prefs WHERE username=?',
            fn_source,
        )

    def test_preferences_cleanup_is_not_scoped_to_local_v2(self):
        local_v2_if = next(
            node for node in ast.walk(self.delete_fn)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "local_v2"
        )
        local_if_source = ast.get_source_segment(self.source, local_v2_if) or ""
        self.assertNotIn(
            'DELETE FROM marzban_user_prefs WHERE username=?',
            local_if_source,
            "Imported/legacy Marzban users must also have presentation prefs cleaned.",
        )

    def test_preferences_cleanup_happens_after_remote_delete_guard(self):
        fn_source = ast.get_source_segment(self.source, self.delete_fn) or ""
        remote_guard = fn_source.index("if not ok_del:")
        cleanup = fn_source.index('DELETE FROM marzban_user_prefs WHERE username=?')
        self.assertGreater(cleanup, remote_guard)


if __name__ == "__main__":
    unittest.main()
