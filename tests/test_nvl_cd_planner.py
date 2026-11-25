"""Offline gate and plan regressions."""
import unittest
from copy import deepcopy
from unittest.mock import patch
from ops import nvl_cd_planner as planner
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

    def test_reviewed_ui02_nonruntime_transitions_allow_only_exact_blobs(self):
        matrix = "cloudzy_phase8_matrix.py"
        staging = "ops/denaprobe_r3_stage_bot.py"
        old = {
            "bot.py": item(A),
            matrix: item("da4d245ddd7b3def54eda31a7f345524146f5f5a"),
            staging: item("9251cbe62214539ea7dec74e6889c3d5f91cf391"),
        }
        new = {
            "bot.py": item(B),
            staging: item("5044a4c67c27e7d6b65814c3cc1c30fa38418dad"),
        }
        plan = self.plan(old, new)
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertEqual(plan["manual"], [])
        self.assertEqual(plan["updates"], ["bot.py"])
        self.assertTrue(plan["restart_required"])
        only_tools = self.plan(old, new | {"bot.py": item(A)})
        self.assertEqual(only_tools["status"], "PLAN_READY")
        self.assertFalse(only_tools["restart_required"])

        for before, after, expected in (
            (old | {matrix: item(A)}, new, matrix),
            (old, new | {matrix: item(B)}, matrix),
            (new, new | {matrix: old[matrix]}, matrix),
            (old | {staging: item(A)}, new, staging),
            (old, new | {staging: item(B)}, staging),
            (old, {k: v for k, v in new.items() if k != staging}, staging),
            (old, new | {staging: ("100755", "blob", new[staging][2])}, staging),
            (old, new | {"ops/another_stage.py": item(B)}, "ops/another_stage.py"),
        ):
            with self.subTest(expected=expected, before=before, after=after):
                blocked = self.plan(before, after)
                self.assertEqual(blocked["status"], "HOLD")
                self.assertIn(expected, blocked["manual"])

        managed = build_plan(old, new, {"bot.py", matrix}, lambda _: A)
        self.assertEqual(managed["status"], "HOLD")
        self.assertIn(matrix, managed["manual"])
        self.assertEqual(self.plan(old, new, B)["status"], "HOLD")

    def test_control_plane_update_requires_exact_installed_candidate(self):
        old = {"bot.py": item(A), "ops/nvl_cd_publisher.py": item(A)}
        new = {"bot.py": item(B), "ops/nvl_cd_publisher.py": item(B)}

        plan = build_plan(
            old, new, {"bot.py"}, lambda _: A,
            lambda name: B if name == "ops/nvl_cd_publisher.py" else None,
        )
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertEqual(plan["updates"], ["bot.py"])
        self.assertEqual(plan["manual"], [])

    def test_control_plane_mismatch_or_missing_stays_hold(self):
        old = {"bot.py": item(A), "ops/nvl_cd_publisher.py": item(A)}
        new = {"bot.py": item(B), "ops/nvl_cd_publisher.py": item(B)}

        for installed in (A, None):
            with self.subTest(installed=installed):
                plan = build_plan(
                    old, new, {"bot.py"}, lambda _: A,
                    lambda _: installed,
                )
                self.assertEqual(plan["status"], "HOLD")
                self.assertEqual(plan["manual"], ["ops/nvl_cd_publisher.py"])

    def test_control_plane_deletion_and_mode_change_stay_hold(self):
        old = {"ops/nvl_cd_publisher.py": item(A)}
        for new in ({}, {"ops/nvl_cd_publisher.py": ("100755", "blob", B)}):
            with self.subTest(new=new):
                plan = build_plan(old, new, set(), lambda _: "ABSENT", lambda _: B)
                self.assertEqual(plan["status"], "HOLD")
                self.assertEqual(plan["manual"], ["ops/nvl_cd_publisher.py"])

    def test_apply_unit_requires_exact_installed_candidate(self):
        name = planner.APPLY_UNIT_TEMPLATE
        old = {"bot.py": item(A), name: item(A)}
        new = {"bot.py": item(B), name: item(B)}
        for installed in (None, A, B):
            plan = build_plan(old, new, {"bot.py"}, lambda _: A, lambda _: installed)
            self.assertEqual(plan["status"], "PLAN_READY" if installed == B else "HOLD")
            self.assertEqual(plan["manual"], [] if installed == B else [name])
        other = "systemd/nvl-deploy-observer.service.example"
        self.assertEqual(build_plan(old, new | {other: item(B)}, {"bot.py"},
                                    lambda _: A, lambda _: B)["manual"], [other])

    def test_apply_unit_requires_effective_reloaded_hardened_config(self):
        expected = {"FragmentPath": str(planner.APPLY_UNIT), "DropInPaths": "",
                    "NeedDaemonReload": "no", "ProtectHome": "no",
                    "ProtectSystem": "strict", "PrivateTmp": "yes",
                    "NoNewPrivileges": "yes",
                    "ReadWritePaths": "/root /var/lib/nvl-deploy /var/backups/nvl /opt/nvl-network-alerts /etc/systemd/system"}
        def render(fields):
            return "\n".join(f"{key}={value}" for key, value in fields.items())
        with patch.object(planner, "live_blob", return_value=B), \
                patch.object(planner.subprocess, "check_output", return_value=render(expected)) as show:
            self.assertEqual(planner.control_plane_blob(planner.APPLY_UNIT_TEMPLATE), B)
            for changes in ({"ProtectHome": "read-only"}, {"NeedDaemonReload": "yes"},
                            {"DropInPaths": "/etc/systemd/system/override.conf"},
                            {"ReadWritePaths": "/root /etc"}, {"ProtectSystem": "no"}):
                show.return_value = render(expected | changes)
                self.assertIsNone(planner.control_plane_blob(planner.APPLY_UNIT_TEMPLATE))

    def test_apply_unit_race_or_missing_fragment_holds(self):
        with patch.object(planner, "live_blob", return_value="ABSENT"), \
                patch.object(planner.subprocess, "check_output") as show:
            self.assertIsNone(planner.apply_unit_blob())
            show.assert_not_called()
        expected = {"FragmentPath": str(planner.APPLY_UNIT), "DropInPaths": "",
                    "NeedDaemonReload": "no", "ProtectHome": "no",
                    "ProtectSystem": "strict", "PrivateTmp": "yes",
                    "NoNewPrivileges": "yes",
                    "ReadWritePaths": "/root /var/lib/nvl-deploy /var/backups/nvl /opt/nvl-network-alerts /etc/systemd/system"}
        with patch.object(planner, "live_blob", side_effect=[B, A]), \
                patch.object(planner.subprocess, "check_output",
                             return_value="\n".join(f"{k}={v}" for k, v in expected.items())):
            self.assertIsNone(planner.apply_unit_blob())

    def test_inventory_only_explicit_root_python(self):
        self.assertEqual(inventory_paths(["bot.py"]), {"bot.py"})
        for paths in ([], ["../bot.py"], ["ops/x.py"], ["a.sh"],
                      ["bot.py", "bot.py"], [".secret.py"]):
            with self.assertRaises(Hold):
                inventory_paths(paths)
