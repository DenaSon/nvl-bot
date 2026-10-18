"""Check required bot imports without executing the bot's application body."""
import ast
import os
from pathlib import Path
import sys


def check_imports(entrypoint):
    entrypoint = Path(entrypoint).resolve(strict=True)
    tree = ast.parse(entrypoint.read_bytes(), filename=str(entrypoint))
    # Use the transferred code, never the caller's source checkout or cwd.
    os.chdir(entrypoint.parent)
    sys.path[0] = str(entrypoint.parent)
    namespace = {"__name__": "__bot_import_preflight__", "__file__": str(entrypoint)}
    count = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            statement = ast.Module(body=[node], type_ignores=[])
            exec(compile(statement, str(entrypoint), "exec"), namespace)
            count += 1
    return count


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: bot_import_preflight.py ENTRYPOINT")
    print(f"BOT_IMPORTS_OK={check_imports(sys.argv[1])}")
