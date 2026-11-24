"""Offline gate and plan regressions."""
import unittest
from copy import deepcopy
from ops.nvl_cd_planner import (Hold, REQUIRED, REPO, WORKFLOW, select_run,
                                verify_jobs, build_plan, inventory_paths)

A, B = "a" * 40, "b" * 40


def item(sha):
    return ("100644", "blob", sha)


def run(**overrides):
    return dict(id=10, run_attempt=1, head_sha=B, head_branch="master",
                event="push", path=WORKFLOW, head_repository={"full_name": REPO},
                repository={"full_name": REPO}, status="completed",
                conclusion="success") | overrides


class GateTests(unittest.TestCase):
    def select(self, *runs):
        return select_run({"total_count": len(runs), "workflow_runs": list(runs)}, B)

    def test_exact_master_push(self):
        self.assertEqual(self.select(run())["id"], 10)

    def test_reject_wrong_identity(self):
        for override in ({"head_sha": A}, {"event": "pull_request"},
                         {"event": "schedule"}, {"event": "workflow_dispatch"},
                         {"head_branch": "feature"}, {"path": "other.yml"},
                         {"head_repository": {"full_name": "other/repo"}}):
            with self.subTest(override=override), self.assertRaises(Hold):
                self.select(run(**override))

    def test_newer_failed_or_pending_attempt_blocks_old_success(self):
        for override in ({"id": 11, "status": "in_progress", "conclusion": None},
                         {"id": 11, "conclusion": "failure"},
                         {"run_attempt": 2, "conclusion": "cancelled"}):
            with self.subTest(override=override), self.assertRaises(Hold):
                self.select(run(), run(**override))

    def test_no_runs_or_incomplete_list(self):
        with self.assertRaises(Hold):
            self.select()
        with self.assertRaises(Hold):
            select_run({"total_count": 2, "workflow_runs": [run()]}, B)

    def jobs(self):
        return [dict(name=name, run_id=10, head_sha=B, status="completed",
                     conclusion="success", run_attempt=1) for name in sorted(REQUIRED)]

    def verify(self, jobs):
        verify_jobs({"total_count": len(jobs), "jobs": jobs}, run())

    def test_complete_jobs(self):
        self.verify(self.jobs())

    def test_missing_duplicate_failed_skipped_wrong_sha(self):
        base = self.jobs()
        samples = [base[:-1], base + [base[0]]]
        for key, value in (("conclusion", "failure"), ("conclusion", "skipped"),
                           ("head_sha", A), ("run_id", 11), ("run_attempt", 2), ("status", "queued")):
            jobs = deepcopy(base)
            jobs[0][key] = value
            samples.append(jobs)
        for jobs in samples:
            with self.assertRaises(Hold):
                self.verify(jobs)


class PlanTests(unittest.TestCase):
    def plan(self, old, new, live=A):
        return build_plan(old, new, {"bot.py"}, lambda name: live)

    def test_update_and_docs_only(self):
        a = {"bot.py": item(A)}
        p = self.plan(a, {"bot.py": item(B)})
        self.assertEqual((p["status"], p["updates"], p["restart_required"]),
                         ("PLAN_READY", ["bot.py"], True))
        p = self.plan(a, a | {"docs/readme.md": item(B)})
        self.assertEqual((p["status"], p["updates"], p["restart_required"]),
                         ("PLAN_READY", [], False))

    def test_drift_even_on_unchanged_files(self):
        a = {"bot.py": item(A)}
        self.assertEqual(self.plan(a, a, B)["drift"], ["bot.py"])
        self.assertEqual(self.plan(a, a, None)["status"], "HOLD")

    def test_unknown_paths_deletions_and_modes_hold(self):
        a = {"bot.py": item(A)}
        for b in ({}, {"bot.py": ("120000", "blob", B)},
                  a | {"new.py": item(B)}, a | {"requirements.txt": item(B)},
                  a | {"ops/install.sh": item(B)}, a | {".github/workflows/x.yml": item(B)}):
            self.assertEqual(self.plan(a, b)["status"], "HOLD")

    def test_inventory_only_explicit_root_python(self):
        self.assertEqual(inventory_paths(["bot.py"]), {"bot.py"})
        for paths in ([], ["../bot.py"], ["ops/x.py"], ["a.sh"],
                      ["bot.py", "bot.py"], [".secret.py"]):
            with self.assertRaises(Hold):
                inventory_paths(paths)
