import ast
import os
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class RuntimeConfigContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def _phase6c_env_int_node(self):
        for node in self.tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "_phase6c_env_int":
                return node
        self.fail("_phase6c_env_int definition not found")

    def test_all_phase6c_env_int_keywords_are_supported(self):
        fn = self._phase6c_env_int_node()
        accepted = {arg.arg for arg in fn.args.args}
        has_var_keyword = fn.args.kwarg is not None

        unsupported = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name):
                continue
            if node.func.id != "_phase6c_env_int":
                continue
            for kw in node.keywords:
                if kw.arg is not None and kw.arg not in accepted and not has_var_keyword:
                    unsupported.append(kw.arg)

        self.assertEqual(unsupported, [])

    def test_phase6c_env_int_applies_minimum_and_maximum(self):
        fn = self._phase6c_env_int_node()
        module = ast.Module(
            body=[
                ast.Import(names=[ast.alias(name="os")]),
                fn,
            ],
            type_ignores=[],
        )
        ast.fix_missing_locations(module)

        namespace = {}
        exec(compile(module, str(BOT_PATH), "exec"), namespace)
        helper = namespace["_phase6c_env_int"]

        key = "NVL_TEST_BOUNDED_INT"
        old = os.environ.get(key)
        try:
            os.environ[key] = "999"
            self.assertEqual(helper(key, 120, minimum=30, maximum=600), 600)

            os.environ[key] = "5"
            self.assertEqual(helper(key, 120, minimum=30, maximum=600), 30)

            os.environ[key] = "120"
            self.assertEqual(helper(key, 120, minimum=30, maximum=600), 120)
        finally:
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


if __name__ == "__main__":
    unittest.main()
