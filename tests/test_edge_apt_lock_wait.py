"""Hermetic tests for the APT lock guard in the legacy Edge installer.

Only the APT function is executed with a fake apt-get binary. The installer
never touches WG, iptables, packages, or any host paths during these tests.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "setup_edge_relay.sh"


class AptLockGuardTests(unittest.TestCase):
    def test_full_installer_bash_syntax(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _run_guard(self, mode):
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("apt_with_lock_wait() {")
        end = source.index('\necho "🔹 ۱) نصب WireGuard', start)
        guard = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "apt-get"
            count = root / "attempts"
            fake.write_text(
                "#!/bin/sh\n"
                'printf "x\\n" >> "$TEST_APT_CALLS"\n'
                'n=$(wc -l < "$TEST_APT_CALLS")\n'
                'case "$TEST_APT_MODE" in\n'
                '  transient) [ "$n" -lt 3 ] || exit 0 ;;\n'
                '  fatal) echo "E: 404 invalid package" >&2; exit 100 ;;\n'
                'esac\n'
                'echo "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 982 (apt-get)" >&2\n'
                'exit 100\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{root}:{env['PATH']}", TEST_APT_CALLS=str(count),
                       TEST_APT_MODE=mode)
            shell = "set -euo pipefail\nsleep() { :; }\n" + guard + (
                "\napt_with_lock_wait update apt-get update -qq\n"
            )
            result = subprocess.run(["bash", "-c", shell], capture_output=True,
                                    text=True, env=env, timeout=15)
            attempts = count.read_text().count("x") if count.exists() else 0
            return result, attempts

    def test_transient_lock_retries_only_apt_and_succeeds(self):
        result, attempts = self._run_guard("transient")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 3)
        self.assertIn("APT_LOCK_WAIT", result.stderr)

    def test_persistent_lock_exits_with_explicit_code(self):
        result, attempts = self._run_guard("permanent")
        self.assertEqual(result.returncode, 75)
        self.assertEqual(attempts, 10)
        self.assertIn("APT_LOCK_BUSY", result.stderr)

    def test_unrelated_package_failure_does_not_retry(self):
        result, attempts = self._run_guard("fatal")
        self.assertEqual(result.returncode, 100)
        self.assertEqual(attempts, 1)
        self.assertNotIn("APT_LOCK_WAIT", result.stderr)


if __name__ == "__main__":
    unittest.main()
