#!/usr/bin/env python3
"""Stage an additive DenaProbe R3 integration into the *actual* Core bot.

Never overwrites the live bot, restarts services, edits env or reads secrets.
Uses function-scoped checks instead of counting user-facing labels globally.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path


class IntegrationError(RuntimeError):
    pass


def once(source: str, anchor: str, label: str) -> int:
    count = source.count(anchor)
    if count != 1:
        raise IntegrationError(f"{label}: anchor occurrences={count}: {anchor[:65]!r}")
    return source.index(anchor)


def section(source: str, start: str, end: str, label: str) -> str:
    pos = once(source, start, label)
    stop = source.find(end, pos + len(start))
    if stop < 0:
        raise IntegrationError(f"{label}: end anchor missing: {end[:65]!r}")
    return source[pos:stop]


def integrate(live: str, release: str) -> str:
    if any(token in live for token in (
        "_DP3_ENABLED", "NVL_DENAPROBE_R3_ENABLED", "apps_dp3_home",
        "dp3_monitor_task",
    )):
        raise IntegrationError("live bot already contains an R3 integration; manual diff required")

    result = live
    glue = section(
        release, "# DenaProbe R3: optional admin dashboard",
        "def _cloudzy_markup(rows):", "R3 definitions",
    )
    anchor = "def _cloudzy_markup(rows):"
    once(result, anchor, "cloudzy integration")
    result = result.replace(anchor, glue + anchor, 1)

    menu_begin = "def _build_admin_programs_kb("
    menu_end = "async def _show_admin_programs_hub"
    old_menu = section(result, menu_begin, menu_end, "live admin programs")
    new_menu = section(release, menu_begin, menu_end, "release admin programs")
    addition = section(
        new_menu, '        if globals().get("_DP3_ENABLED", False):',
        "    return rows", "R3 menu entry",
    )
    if "apps_edge_quick_home" not in old_menu:
        raise IntegrationError("live admin programs lack expected Edge entry")
    if "📡 پایش DenaProbe" in old_menu:
        raise IntegrationError("live admin programs already have a DenaProbe label; inspect callback")
    if old_menu.count("    return rows\n") != 1:
        raise IntegrationError("live admin programs return anchor is ambiguous")
    updated_menu = old_menu.replace("    return rows\n", addition + "    return rows\n", 1)
    result = result.replace(old_menu, updated_menu, 1)

    next_callback = ('    if d in ("apps_cz_rich_home", '
                     '"apps_cz_rich_migration")')
    new_callback = section(
        release, '    if d == "apps_dp3_home" or d.startswith("dp3:"):',
        next_callback, "R3 callback",
    )
    once(result, next_callback, "existing callback")
    result = result.replace(next_callback, new_callback + next_callback, 1)

    init_anchor = "async def _post_init(app):\n"
    init_block = section(
        release, init_anchor,
        "    # K2 Single shares this application's existing root process",
        "R3 startup",
    )[len(init_anchor):]
    once(result, init_anchor, "existing startup")
    result = result.replace(init_anchor, init_anchor + init_block, 1)

    shutdown_anchor = "async def _post_shutdown(app):\n"
    once(result, shutdown_anchor, "existing shutdown")
    shutdown_block = (
        '    dp3_task = app.bot_data.get("dp3_monitor_task")\n'
        '    if dp3_task is not None and not dp3_task.done():\n'
        '        dp3_task.cancel()\n'
        '        try:\n'
        '            await dp3_task\n'
        '        except asyncio.CancelledError:\n'
        '            pass\n\n'
    )
    result = result.replace(shutdown_anchor,
                            shutdown_anchor + shutdown_block, 1)

    # Verify the five specific locations: an unrelated pre-existing text
    # label elsewhere in the bot must not cause a false negative.
    tree = ast.parse(result)
    funcs = {
        node.name: ast.get_source_segment(result, node) or ""
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    expected = {
        "_dp3_monitor_loop": ["_DP3_ALERTS_ENABLED"],
        "_build_admin_programs_kb": ["📡 پایش DenaProbe", "_DP3_ENTRY"],
        "callback_handler": ["_dp3_handle_callback", "apps_dp3_home"],
        "_post_init": ['app.bot_data["dp3_monitor_task"]'],
        "_post_shutdown": ['app.bot_data.get("dp3_monitor_task")'],
    }
    for name, tokens in expected.items():
        body = funcs.get(name)
        if not body:
            raise IntegrationError(f"required function not found: {name}")
        for token in tokens:
            if token not in body:
                raise IntegrationError(f"{name}: missing token {token!r}")

    # The live code, excluding exactly the additive blocks, is retained.
    # No historical routines or external services are modified here.
    if "NVL_DENAPROBE_R3_ENABLED" not in result:
        raise IntegrationError("R3 feature gate missing after merge")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in (args.live.resolve(), args.release.resolve()):
        parser.error("output may not overwrite either source file")
    if args.output.exists():
        parser.error("output exists; refusing overwrite")
    try:
        before = args.live.read_text(encoding="utf-8")
        candidate = args.release.read_text(encoding="utf-8")
        merged = integrate(before, candidate)
        args.output.write_text(merged, encoding="utf-8")
        args.output.chmod(0o600)
    except (IntegrationError, OSError, SyntaxError) as exc:
        parser.exit(2, f"STOP: {exc}\n")
    print("MERGE_READY")
    print("AST_PASS")
    print("DENA_PROBE_HOOKS=5")
    print(f"LIVE_LINES={len(before.splitlines())}")
    print(f"MERGED_LINES={len(merged.splitlines())}")
    print(f"STAGED_FILE={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
