"""Regression tests for the NVL Core health UI and on-demand large-file scan."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from nvl_server_health import (
    LARGE_FILE_THRESHOLD_BYTES,
    collect_extra_metrics,
    render_health,
    render_large_files,
    scan_large_files,
)


def sample_health(cpu=19.5, ram=43.9, load=0.87):
    return {
        "cpu_count": 2, "cpu_pct": cpu,
        "ram_used_mb": 864, "ram_total_mb": 1968, "ram_pct": ram,
        "load1": load, "load5": 0.78, "load15": 0.81,
    }


def sample_extra(disk_pct=17.0):
    return {
        "disk": {"total_gb": 48.0, "used_gb": 7.9,
                 "available_gb": 40.0, "pct": disk_pct},
        "uptime_seconds": 172800.0,
        "swap": {"total_mb": 0, "used_mb": 0, "pct": 0.0},
    }


class ServerHealthPresentationTests(unittest.TestCase):
    def test_threshold_is_exactly_three_gib(self):
        self.assertEqual(LARGE_FILE_THRESHOLD_BYTES, 3 * 1024 ** 3)

    def test_collect_metrics_uses_read_only_filesystem_sources(self):
        values = collect_extra_metrics()
        self.assertIn("disk", values)
        self.assertIn("swap", values)
        self.assertIn("uptime_seconds", values)

    def test_rich_dashboard_readable_and_has_unique_accounts(self):
        text = render_health(
            sample_health(), sample_extra(), sessions=167, unique_accounts=103,
        )
        self.assertIn("<blockquote>", text)
        self.assertIn("🟢", text)
        self.assertIn("۱۹.۵٪", text)
        self.assertIn("۴۰.۰ آزاد", text)
        self.assertIn("۱۶۷", text)
        self.assertIn("۱۰۳", text)
        self.assertIn("۲ روز", text)
        self.assertNotIn("/dev/vda1", text)

    def test_disk_is_included_in_health_alerts(self):
        text = render_health(sample_health(), sample_extra(93),
                             sessions=4, unique_accounts=2)
        self.assertIn("🔴", text)
        self.assertIn("فضای دیسک", text)

    def test_incomplete_ssh_monitor_is_not_reported_as_zero(self):
        text = render_health(sample_health(), sample_extra(),
                             sessions=None, unique_accounts=None,
                             connection_error="sudo failed")
        self.assertIn("⚪", text)
        self.assertIn("نامشخص", text)
        self.assertNotIn("نشست‌های SSH  <b>۰</b>", text)

    def test_details_mention_socket_count_and_load_intervals(self):
        text = render_health(sample_health(), sample_extra(),
                             sessions=3, unique_accounts=2,
                             details=True, socket_count=9)
        self.assertIn("جزئیات فنی", text)
        self.assertIn("۱ / ۵ / ۱۵", text)
        self.assertIn("سوکت‌های TCP", text)

    def test_large_file_render_html_escapes_paths(self):
        report = render_large_files({
            "files": [(4 * 1024 ** 3, "/root/hello<token>&.bak")],
            "total": 1, "complete": True, "error": "",
        })
        self.assertIn("&lt;token&gt;&amp;", report)
        self.assertNotIn("<token>", report)
        self.assertIn("۴.۰ GB", report)
        self.assertIn("اسکن کامل شد", report)

    def test_partial_scan_never_claims_full_coverage(self):
        report = render_large_files({
            "files": [], "total": 0, "complete": False,
            "error": "خطای دسترسی", "timed_out": False,
        })
        self.assertIn("اسکن ناقص", report)
        self.assertIn("مسیرهای بررسی‌شده", report)
        self.assertNotIn("✅ اسکن کامل شد", report)


@unittest.skipUnless(shutil.which("find"), "GNU find unavailable")
class ServerHealthLargeFileScanTests(unittest.TestCase):
    def test_strictly_over_threshold_and_sorted(self):
        with tempfile.TemporaryDirectory() as tempdir:
            folder = Path(tempdir)
            (folder / "equal.bin").write_bytes(b"\0" * 4096)
            (folder / "larger.bin").write_bytes(b"\0" * 4097)
            (folder / "biggest.bin").write_bytes(b"\0" * 8192)
            (folder / "link.bin").symlink_to(folder / "biggest.bin")
            result = asyncio.run(scan_large_files(
                root=tempdir, threshold_bytes=4096, timeout_seconds=5,
            ))
            self.assertTrue(result["complete"], result)
            self.assertEqual(result["total"], 2)
            self.assertEqual([Path(p).name for _, p in result["files"]],
                             ["biggest.bin", "larger.bin"])
            self.assertEqual((folder / "biggest.bin").stat().st_size, 8192)

    def test_limit_results_but_keep_total(self):
        with tempfile.TemporaryDirectory() as tempdir:
            for number in range(12):
                (Path(tempdir) / f"large{number}.bin").write_bytes(b"\0" * (101 + number))
            result = asyncio.run(scan_large_files(
                root=tempdir, threshold_bytes=100, max_results=3,
            ))
            self.assertTrue(result["complete"], result)
            self.assertEqual(result["total"], 12)
            self.assertEqual(len(result["files"]), 3)
            self.assertEqual(result["files"][0][0], 112)


class ServerHealthCallbackWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (
            Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
        ).read_text(encoding="utf-8")

    def test_health_and_file_scan_have_separate_admin_only_callbacks(self):
        start = self.source.index(
            'elif d in ("srv_health", "srv_health_details") and role == \'admin\''
        )
        end = self.source.index(
            'elif d == "srv_health_files" and role == \'admin\'', start
        )
        health_region = self.source[start:end]
        self.assertIn('parse_mode="HTML"', health_region)
        self.assertIn('render_health(', health_region)
        self.assertNotIn("scan_large_files(", health_region)
        files_region = self.source[end:self.source.index(
            'elif d == "srv_brand"', end
        )]
        self.assertIn("await scan_large_files()", files_region)
        self.assertIn("render_large_files(result)", files_region)
        self.assertIn("srv_health", files_region)


if __name__ == "__main__":
    unittest.main()
