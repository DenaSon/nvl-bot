"""Fail-closed, deterministic GitHub CI test-impact selector.

Changed files -> curated domain suites + matching test files. Unknown or
cross-cutting changes always select the full suite. No external dependencies.
The runner writes a plan once, then both unprivileged and root jobs consume
exactly that plan. Nightly/manual runs use complete suites.
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

# Policy: rules are deliberately conservative. An unclassified source file
# runs ALL tests rather than silently omitting an impacted integration.
GLOBAL_FILES = frozenset({
    "bot_final_v49-2.py",
    "requirements.txt",
    "bot_import_preflight.py",
    "cloudzy_operation_coordinator.py",
    "dns_route_guard.py",
    "safe_failover.py",
    "automatic_failover.py",
    "core_side_failover.sh",
    "setup_edge_relay.sh",
    "ops/k2_release_bundle.py",
    "ops/ci_test_selector.py",
})
GLOBAL_PREFIXES = (
    ".github/", "server_migration/",
    "tests/support/", "tests/fixtures/",
)
# Production module prefixes and explicit smoke tests. The patterns include
# ALL tests in a feature family, including its integration/regression tests.
DOMAIN_RULES = (
    (("manual_edge_", "manual_quick_switch", "legacy_manual_host_registration.py"),
     ("test_manual_*.py", "test_legacy_manual_host_registration.py",
      "test_nvl_legacy_manual_route_audit.py")),
    (("edge_egress_",), ("test_edge_egress_*.py",
                           "test_manual_edge_phase3.py")),
    (("cloudzy_",), ("test_cloudzy_*.py", "test_manual_quick_switch.py",
                      "test_manual_quick_switch_ui.py")),
    (("marzban_",), ("test_marzban_*.py",)),
    (("radar_", "cloudflare_radar.py", "incident_", "regional_",
      "filtering_", "differential_", "checkhost_", "standby_"),
     ("test_radar_*.py", "test_incident_*.py", "test_regional_*.py",
      "test_filtering_*.py", "test_differential_*.py",
      "test_standby_*.py", "test_checkhost_*.py")),
)
# Critical privileged protections that run in every focused build. Extra
# domain-specific privileged tests are added only if the domain changes.
ROOT_BASELINE = ("test_edge_egress_k2_release_bundle.py",
                 "test_edge_egress_k2_runtime_release.py")
ROOT_DOMAIN = {
    "manual": ("test_manual_edge_phase3.py", "test_manual_quick_switch.py"),
    "egress": ("test_edge_egress_provision.py",
               "test_edge_egress_shared_lock.py",
               "test_edge_egress_k2_canary_backup_gate.py"),
    "cloudzy": ("test_manual_quick_switch.py",
                "test_cloudzy_cz07_acceptance.py"),
    "marzban": ("test_marzban_node_bootstrap.py",),
    "radar": ("test_radar_runtime.py",),
}
SHA = re.compile(r"^[0-9a-f]{40}$")


def decide(changed, available):
    """Pure, testable selector. Returns (mode, tests, root, reason)."""
    available = set(available)
    selected = set()
    domains = set()
    if not changed:
        return "full", sorted(available), sorted(available), "empty diff"
    for raw in changed:
        name = raw.replace("\\", "/")
        if name.startswith("docs/") and name.endswith(".md"):
            continue
        if name in ("README.md", "LICENSE", ".gitignore"):
            continue
        if name in GLOBAL_FILES or name.startswith(GLOBAL_PREFIXES):
            return "full", sorted(available), sorted(available), "shared: " + name
        if name.startswith("tests/test_") and name.endswith(".py"):
            test = Path(name).name
            if test not in available:
                return "full", sorted(available), sorted(available), "test removed: " + name
            selected.add(test)
            continue
        if name.startswith("ops/"):
            # Ops scripts affect the release, provisioning or privileged host.
            return "full", sorted(available), sorted(available), "ops: " + name
        if "/" in name or not name.endswith(".py"):
            return "full", sorted(available), sorted(available), "unclassified: " + name
        matched = False
        for i, (prefixes, patterns) in enumerate(DOMAIN_RULES):
            if any(name.startswith(p) for p in prefixes):
                matched = True
                domains.add(("manual", "egress", "cloudzy", "marzban", "radar")[i])
                for pattern in patterns:
                    selected.update(x for x in available
                                    if Path(x).match(pattern))
                break
        if not matched:
            return "full", sorted(available), sorted(available), "unknown module: " + name
    if not selected:
        return "skip", [], [], "documentation only"
    # Selectors that don't match a test indicate a broken configuration.
    root = set(ROOT_BASELINE) & available
    for domain in domains:
        root.update(x for x in ROOT_DOMAIN[domain] if x in available)
    return "targeted", sorted(selected), sorted(root), (
        "domains: " + ",".join(sorted(domains)) if domains else "changed tests")


def changed_files(base, head):
    if not (SHA.fullmatch(base or "") and SHA.fullmatch(head or "")):
        raise ValueError("unverified Git SHA")
    out = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", "--no-ext-diff", base, head],
        stderr=subprocess.DEVNULL)
    return [x.decode("utf-8") for x in out.split(b"\0") if x]


def make_plan(event, base, head, root=Path(".")):
    available = sorted(p.name for p in (root / "tests").glob("test_*.py"))
    if not available:
        raise ValueError("no test files found; cannot skip CI")
    if event in ("schedule", "workflow_dispatch"):
        return {"mode": "full", "tests": available, "root": available,
                "reason": event + " complete nightly/manual regression"}
    try:
        files = changed_files(base, head)
    except (OSError, subprocess.CalledProcessError, ValueError):
        mode, tests, privilege, why = (
            "full", available, available, "unavailable/invalid diff")
    else:
        mode, tests, privilege, why = decide(files, available)
    return {"mode": mode, "tests": tests, "root": privilege,
            "reason": why}


def run_plan(plan, root_tests=False):
    files = plan["root" if root_tests else "tests"]
    if not files:
        print("CI: no Python tests affected; release verification still required")
        return 0
    available = {p.name for p in Path("tests").glob("test_*.py")}
    if any(f not in available or "/" in f or "\\" in f for f in files):
        raise ValueError("test selector plan is invalid")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for file in files:
        suite.addTests(loader.discover("tests", pattern=file))
    print(f"CI {('ROOT' if root_tests else 'PYTHON')} "
          f"{plan['mode']} - {len(files)} test modules "
          f"({plan['reason']})", flush=True)
    outcome = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if outcome.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--event", required=True)
    p.add_argument("--base", default="")
    p.add_argument("--head", default="")
    p.add_argument("--output", required=True)
    r = sub.add_parser("run")
    r.add_argument("--plan", required=True)
    r.add_argument("--root", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "plan":
        plan = make_plan(args.event, args.base, args.head)
        target = Path(args.output)
        target.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
        print(f"CI test impact: {plan['mode']} / "
              f"{len(plan['tests'])} modules; {plan['reason']}")
        return 0
    return run_plan(json.loads(Path(args.plan).read_text(encoding="utf-8")),
                    root_tests=args.root)


if __name__ == "__main__":
    sys.exit(main())
