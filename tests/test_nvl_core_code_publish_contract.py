"""Guarded Core release script syntax and non-effectful default contract."""
from pathlib import Path
import shutil
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "ops" / "nvl_core_code_publish.sh"


class CorePublishContractTests(unittest.TestCase):
    def test_publisher_has_valid_bash_syntax(self):
        if shutil.which("bash") is None:
            self.skipTest("bash unavailable")
        result = subprocess.run(["bash", "-n", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_publisher_stages_by_default_and_requires_explicit_approval(self):
        text = SCRIPT.read_text()
        self.assertIn('APPROVAL="$(printenv NVL_APPROVE_CODE_DEPLOY || true)"', text)
        self.assertIn('if [[ "$APPROVAL" != APPLY ]]; then', text)
        self.assertIn('echo "STAGE_ONLY=YES"', text)
        self.assertIn('systemctl stop "$SERVICE"', text)
        self.assertLess(text.index('echo "STAGE_ONLY=YES"'),
                        text.index('systemctl stop "$SERVICE"'))
        self.assertIn('PIN_SHA="$(printenv NVL_PIN_SHA || true)"', text)
        self.assertIn('PRAGMA quick_check', text)
        self.assertIn('src.backup(dst', text)
        self.assertIn('git -C "$SRC" rev-parse HEAD', text)
        self.assertIn('find "$SRC/ops" "$SRC/server_migration"', text)
        self.assertIn('install -D -m "$mode" "$SRC/$rel" "$ROOT/$rel"', text)
        self.assertIn('done < "$RELEASE/manifest.txt"', text)
        self.assertIn('cp -p "$RELEASE/previous/$rel" "$ROOT/$rel"', text)

    def test_does_not_write_accounts_routes_dns_or_auto_enable_flags(self):
        script = SCRIPT.read_text()
        self.assertNotIn("sqlite3 /root/master_bot.db", script)
        self.assertNotIn("UPDATE ssh_accounts", script)
        self.assertNotIn("UPDATE cloudzy_cz07_jobs", script)
        self.assertNotIn("NVL_EDGE_MANUAL_ENABLED=1", script)
        self.assertNotIn("NVL_CZ07_HISTORICAL_RECOVERY_A0B997_ENABLED=1", script)
        self.assertIn('fail() { echo "STOP: $*" >&2; return 1; }', script)
        self.assertIn('trap on_failure ERR', script)
        self.assertIn('CODE_RESTORED; SERVICE_STOPPED_FOR_COMPATIBILITY_REVIEW',
                      script)


if __name__ == "__main__":
    unittest.main()
