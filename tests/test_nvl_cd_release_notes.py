"""Release note attribution, bounded fallback and plain-text group notices."""
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops import nvl_cd_release_notes as notes
from ops import nvl_cd_observer as obs

A, B, C, D = (letter * 40 for letter in "abcd")


def pr(sha=B, number=42, **overrides):
    return dict(number=number, merge_commit_sha=sha, merged_at="2026-11-24",
                base={"ref": "master", "repo": {"full_name": notes.p.REPO}},
                title="بهبود گزارش‌ها",
                body="## Release Summary\nخلاصه فارسی\n## Changes\n- گزارش جدید\n"
                     "## Acceptance Tests\n- ورود به گزارش‌ها\n## Technical Notes\ninternal",
                **overrides)


class ReleaseNotesTests(unittest.TestCase):
    def test_exact_merge_and_repository_only(self):
        self.assertEqual(notes.exact_pr([pr()], B)["number"], 42)
        self.assertIsNone(notes.exact_pr([pr(A)], B))
        self.assertIsNone(notes.exact_pr([pr(), pr(number=43)], B))
        wrong = pr()
        wrong["base"]["repo"]["full_name"] = "elsewhere/repo"
        self.assertIsNone(notes.exact_pr([wrong], B))
        wrong = pr()
        wrong["merged_at"] = None
        self.assertIsNone(notes.exact_pr([wrong], B))

    def test_multiple_merges_in_deployment_order(self):
        fetch = Mock(side_effect=[[pr(B)], [pr(C, 43)]])
        with patch.object(notes.p, "git", side_effect=[b"Merge release\n", (C + "\n" + B + "\n" + A).encode()]):
            result = notes.collect(Path("/repo"), A, C, fetch)
        self.assertTrue(result["complete"])
        self.assertEqual([x["number"] for x in result["entries"]], [42, 43])
        self.assertEqual(fetch.call_count, 2)

    def test_missing_baseline_and_api_failure_fallback(self):
        fetch = Mock(side_effect=OSError)
        with patch.object(notes.p, "git", side_effect=[b"Subject\nBody", (C + "\n" + B).encode()]):
            self.assertEqual(notes.collect(Path("/repo"), A, C, fetch),
                             {"entries": [], "complete": False, "commit_message": "Subject", "commit_changes": ["Body"]})
        fetch.assert_not_called()
        with patch.object(notes.p, "git", side_effect=[b"Subject\nBody", (B + "\n" + A).encode()]):
            self.assertEqual(notes.collect(Path("/repo"), A, B, fetch),
                             {"entries": [], "complete": False, "commit_message": "Subject", "commit_changes": ["Body"]})

    def test_sections_ignore_comments_code_and_technical_notes(self):
        body = "## Release Summary\n<!-- hidden -->\nسلام\u200cدنیا\n## Changes\n- first\n" \
               "## Acceptance Tests\n~~~python\nsecret\n~~~\n- /start\n## Technical Notes\nprivate"
        result = notes.sections(body)
        self.assertEqual(result, {"summary": ["سلام\u200cدنیا"], "changes": ["first"], "tests": ["/start"]})

    def test_clean_removes_external_urls_tokens_and_controls(self):
        value = notes.clean("abc\u202e https://evil.example abc 123456:" + "X" * 30, 150)
        self.assertNotIn("\u202e", value)
        self.assertNotIn("evil.example", value)
        self.assertNotIn("123456:", value)

    def test_success_notice_has_real_metrics_and_acceptance_not_passed(self):
        state = dict(phase="COMMITTED", candidate=B, deployed=B, previous_deployed=A,
                     restart_required=True, file_count=2, started_at=100, finished_at=119,
                     release_notes={"complete": True, "commit_message": "fix: reports", "entries": [notes.exact_pr([pr()], B)]})
        _, text = obs.event(state)
        for item in ("19 ثانیه", "در انتظار انجام", "fix: reports", "گزارش جدید", "Changelog"):
            self.assertIn(item, text)
        for forbidden in ("internal", "ورود به گزارش‌ها", "github.com", "/pull/42", "/compare/", notes.p.REPO):
            self.assertNotIn(forbidden, text)
        for phase in ("HOLD", "ROLLED_BACK"):
            _, text = obs.event(state | {"phase": phase})
            self.assertNotIn("ورود به گزارش‌ها", text)
            self.assertNotIn("CI موفق", text)

    def test_fallback_is_not_a_deployment_failure(self):
        state = dict(phase="COMMITTED", candidate=B, deployed=B, previous_deployed=A,
                     restart_required=False)
        _, text = obs.event(state)
        self.assertIn("در دسترس نیست", text)
        self.assertNotIn("/compare/", text)
        self.assertNotIn("GitHub", text)
        self.assertNotIn("بکاپ تأیید شد", text)

    def test_commit_fallback_has_no_repository_links(self):
        state = dict(phase="COMMITTED", candidate=B, deployed=B,
                     release_notes={"complete": False, "entries": [],
                                    "commit_message": "fix: " + notes.p.REPO,
                                    "commit_changes": ["Improve notices", "git@github.com:" + notes.p.REPO,
                                                       "github.com/" + notes.p.REPO]})
        _, text = obs.event(state)
        self.assertIn("fix:", text)
        self.assertIn("Improve notices", text)
        for forbidden in ("github.com", notes.p.REPO, "git@", "https://"):
            self.assertNotIn(forbidden, text)

    def test_title_only_pr_uses_commit_body_fallback(self):
        state = dict(phase="COMMITTED", candidate=B, deployed=B,
                     release_notes={"complete": False, "entries": [{"number": 1, "title": "PR title"}],
                                    "commit_message": "Merge release", "commit_changes": ["Actual change"]})
        _, text = obs.event(state)
        self.assertIn("Actual change", text)
        self.assertNotIn("github.com", text)

    def test_message_bounded_for_three_large_prs(self):
        item = {"number": 1, "title": "😀" * 100, "summary": ["😀" * 150],
                "changes": ["😀" * 150] * 2, "tests": ["😀" * 150] * 2}
        state = dict(phase="COMMITTED", candidate=B, deployed=B, restart_required=True,
                     release_notes={"complete": True, "entries": [item] * 3})
        _, text = obs.event(state)
        self.assertLessEqual(len(text.encode("utf-16-le")) // 2, 3900)
