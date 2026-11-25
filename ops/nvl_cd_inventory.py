"""Read-only Core inventory review; never writes config or imports candidate code."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

if __package__:
    from . import nvl_cd_planner as p
else:
    import nvl_cd_planner as p

ENTRY = "bot_final_v49-2.py"
# Core acceptance audit: these have their own runtime lifecycle. The first
# two are tracked root Python entrypoints; sampler may be local-only.
INDEPENDENT = ("nvl_awg_core_routes.py", "nvl_awg_witness_refresh.py",
               "nvl_network_sampler.py")
MANUAL = {"02_recreate_ssh_users.py", "bot_import_preflight.py",
          "promote_standby_for_filtered_edge.py"}


def source_imports(raw, name, tracked):
    """Resolve statically named imports without importing any module."""
    syntax = ast.parse(raw, filename=name)
    result = set()
    package = name.split("/")[:-1]

    def add(parts):
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            for candidate in (prefix + ".py", prefix + "/__init__.py"):
                if candidate in tracked:
                    result.add(candidate)

    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > len(package):
                    continue
                base = package[:len(package) - node.level + 1]
            else:
                base = []
            parts = base + (node.module.split(".") if node.module else [])
            add(parts)
            for alias in node.names:
                if alias.name != "*":
                    add(parts + alias.name.split("."))
        elif isinstance(node, ast.Call):
            # Recognize literal dynamic imports; variable-driven imports
            # and shell/subprocess file references still require review.
            fn = node.func
            if ((isinstance(fn, ast.Name) and fn.id in ("__import__", "import_module"))
                    or (isinstance(fn, ast.Attribute) and fn.attr == "import_module")):
                if node.args and isinstance(node.args[0], ast.Constant):
                    value = node.args[0].value
                    if isinstance(value, str) and not value.startswith("."):
                        add(value.split("."))
    return result


def closure(roots, tracked, read):
    found = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        pending.extend(source_imports(read(name), name, tracked) - found)
    return found


def expand(repo, old, new, approved, runtime):
    """Derive additional root bot dependencies from pinned Git blobs.

    Existing reviewed entries are retained. Newly reachable shared, package
    and operator scripts are not admitted to the bot-only publisher.
    Both sides of the release are inspected to protect shared ownership.
    """
    cache = {}

    def graph(tree):
        tracked = {name: item for name, item in tree.items()
                   if name.endswith(".py") and not name.startswith("tests/")}

        def read(name):
            mode, kind, oid = tracked[name]
            if (mode, kind) != ("100644", "blob"):
                raise p.Hold("DEPENDENCY_MODE_UNSUPPORTED")
            p.exact_sha(oid)
            if oid not in cache:
                raw = p.git(repo, "cat-file", "blob", oid)
                if len(raw) > p.MAX_BYTES:
                    raise p.Hold("SOURCE_TOO_LARGE")
                if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != oid:
                    raise p.Hold("DEPENDENCY_HASH_MISMATCH")
                cache[oid] = raw
            return cache[oid]

        if ENTRY not in tracked:
            raise p.Hold("ENTRYPOINT_MISSING")
        bot = closure([ENTRY], tracked, read)
        independent = closure([name for name in INDEPENDENT if name in tracked],
                              tracked, read)
        for name in INDEPENDENT:
            if name not in tracked and os.path.lexists(runtime / name):
                raw = p.trusted(runtime / name).read_bytes()
                if len(raw) > p.MAX_BYTES:
                    raise p.Hold("SOURCE_TOO_LARGE")
                independent |= closure(source_imports(raw, name, tracked), tracked, read)
        return bot, independent

    try:
        old_bot, old_independent = graph(old)
        new_bot, new_independent = graph(new)
    except (SyntaxError, UnicodeError, RecursionError) as exc:
        raise p.Hold("DEPENDENCY_ANALYSIS_FAILED") from exc

    excluded = set(INDEPENDENT) | MANUAL | old_independent | new_independent
    # Recompute on every release so a discovered dependency stays managed.
    # Old-only dependencies remain in the plan for the transition; deletion
    # is still rejected by the existing publisher. Never auto-delete files.
    additions = {name for name in old_bot | new_bot
                 if "/" not in name and name not in excluded}
    if additions:
        p.inventory_paths(sorted(additions))
    return set(approved) | additions


def review(repo, sha, runtime):
    sha = p.exact_sha(sha)
    tracked = {name: oid for name, (mode, kind, oid) in p.tree(repo, sha).items()
               if name.endswith(".py") and (mode, kind) == ("100644", "blob")
               and not name.startswith("tests/")}
    if ENTRY not in tracked:
        raise p.Hold("ENTRYPOINT_MISSING")

    def read(name):
        raw = p.git(repo, "cat-file", "blob", tracked[name])
        if len(raw) > p.MAX_BYTES:
            raise p.Hold("SOURCE_TOO_LARGE")
        return raw

    core = closure([ENTRY], tracked, read)
    shared = closure([name for name in INDEPENDENT if name in tracked], tracked, read)
    unknown_independent = []
    for name in INDEPENDENT:
        path = runtime / name
        if name not in tracked:
            if os.path.lexists(path):
                p.trusted(path)
                raw = path.read_bytes()
                if len(raw) > p.MAX_BYTES:
                    raise p.Hold("SOURCE_TOO_LARGE")
                shared |= closure(source_imports(raw, name, tracked), tracked, read)
                unknown_independent.append(name)
            else:
                unknown_independent.append(name + ":ABSENT")
    # Imported package files and independent/shared code remain manual.
    excluded = set(INDEPENDENT) | shared | MANUAL
    candidates = sorted(name for name in core if "/" not in name and name not in excluded)
    matched, absent, drift = [], [], []
    for name in candidates:
        actual = p.live_blob(runtime, name)
        if actual == tracked[name]:
            matched.append(name)
        elif actual == "ABSENT":
            absent.append(name)
        else:
            drift.append(name)
    return {
        "candidate_sha": sha,
        "matched_candidate": matched,
        "absent_candidate": absent,
        "drift_candidate": drift,
        "shared_manual": sorted(core & excluded),
        "package_manual": sorted(name for name in core if "/" in name),
        "unclassified_root": sorted(name for name in tracked
                                    if "/" not in name and name not in core),
        "local_only_independent": unknown_independent,
        "mode": "REVIEW_ONLY",
        "inventory_written": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        repo = p.trusted(Path("/var/lib/nvl-deploy/repository.git"), directory=True)
        runtime = p.trusted(Path("/root"), directory=True)
        print(json.dumps(review(repo, args.sha, runtime), indent=2, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"HOLD","reason":"INVENTORY_REVIEW_FAILED"}')
        return 2


if __name__ == "__main__":
    sys.exit(main())
