"""Hermetic tests of the one-shot deploy script's read-only restart guard."""
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


class LimiterUIDeployGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "test.db"
        with sqlite3.connect(self.db) as con:
            for table in ("failover_operations", "manual_quick_switch_jobs"):
                con.execute(f"CREATE TABLE {table} (id TEXT, status TEXT)")
        script = (Path(__file__).resolve().parents[1] /
                  "ops/nvl_awg_limiter_ui_quick_deploy.sh").read_text()
        self.guard = script.split("check_deploy_idle() {", 1)[1].split(
            "<<'PY'\n", 1)[1].split("\nPY\n", 1)[0].replace(
                "file:/root/master_bot.db?mode=ro",
                self.db.as_uri() + "?mode=ro")
        self.assertNotIn("/root/master_bot.db", self.guard)

    def check(self, expected):
        result = subprocess.run([sys.executable, "-B", "-c", self.guard],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr)

    def insert(self, table, status):
        with sqlite3.connect(self.db) as con:
            con.execute(f"INSERT INTO {table} VALUES (?,?)", ("test", status))

    def test_shared_running_lease_blocks_deploy(self):
        self.insert("failover_operations", "RUNNING")
        self.check(2)

    def test_quick_switch_dns_intent_blocks_deploy(self):
        self.insert("manual_quick_switch_jobs", "DNS_INTENT")
        self.check(2)

    def test_quick_switch_postcommit_blocks_deploy(self):
        self.insert("manual_quick_switch_jobs", "DB_COMMITTED")
        self.check(2)

    def test_historical_rows_without_running_lease_allow_deploy(self):
        self.insert("failover_operations", "SUCCEEDED")
        for state in ("DONE", "ABORTED", "HOLD", "EXTERNAL_VERIFIED"):
            self.insert("manual_quick_switch_jobs", state)
        self.check(0)

    def test_hold_with_running_lease_blocks_deploy(self):
        self.insert("manual_quick_switch_jobs", "HOLD")
        self.insert("failover_operations", "RUNNING")
        self.check(2)

    def test_empty_tables_allow_deploy(self):
        self.check(0)
