"""Safe, fully mocked regression tests for the P1 Core limiter deploy utility.

These tests run with synthetic sources and mock systemctl/curl; they do not
connect to GitHub, require root, or change any real service or firewall.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = REPO_ROOT / "ops" / "nvl_p1_edge_limiter_hotfix.sh"
BASE = "38a635fd296a2893cf92bce2957ce2050463c7bb"
FIXED = "8312b14edad72a2638af6719f156bc8609c368f3"
HEREDOC = "cat << 'EOF' > /root/ip_limiter.py\n"

BASE_PYTHON = """\
#!/usr/bin/env python3
from __future__ import annotations

def apply_cooldown(ip: str):
    return ip
"""

FIXED_PYTHON = """\
#!/usr/bin/env python3
from __future__ import annotations
import ipaddress
SHARED_EDGE_NETWORK = ipaddress.ip_network("10.77.0.0/24")

def is_shared_edge_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip) in SHARED_EDGE_NETWORK

def apply_cooldown(ip: str):
    if is_shared_edge_ip(ip): return
    return ip

def tick(ips):
    for peer_ip in ips:
        if is_shared_edge_ip(peer_ip): continue
"""


def wrapper_for_python(body: str) -> str:
    return "#!/bin/bash\n" + HEREDOC + body + "EOF\n"


class P1LimiterDeployScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nvl-limiter-deploy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.live = self.root / "ip_limiter.py"
        self.live.write_text(BASE_PYTHON, encoding="utf-8")
        self.raw = self.root / "raw"
        for sha, body in [(BASE, BASE_PYTHON), (FIXED, FIXED_PYTHON)]:
            version = self.raw / sha
            version.mkdir(parents=True)
            (version / "promote_edge_to_core.sh").write_text(
                wrapper_for_python(body), encoding="utf-8"
            )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "systemctl.log"
        self.fail_once = self.root / "fail-first-restart"
        self._make_executable(
            "systemctl",
            """#!/usr/bin/env bash
set -e
if [[ "$1" == 'is-active' ]]; then
  if [[ "${2:-}" != '--quiet' ]]; then echo active; fi
  exit 0
fi
if [[ "$1" == 'show' ]]; then echo 0; exit 0; fi
if [[ "$1" == 'restart' ]]; then
  echo restart >> "$MOCK_SYSTEMCTL_LOG"
  if [[ -f "$MOCK_FAIL_ONCE" ]]; then rm "$MOCK_FAIL_ONCE"; exit 1; fi
  exit 0
fi
exit 90
""",
        )
        self._make_executable(
            "curl",
            """#!/usr/bin/env bash
set -euo pipefail
url=''; target=''
while (( $# )); do
  case "$1" in
    -o) target="$2"; shift 2;;
    file://*) url="$1"; shift;;
    *) shift;;
  esac
done
[[ -n "$url" && -n "$target" ]]
cp -- "${url#file://}" "$target"
""",
        )
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        substitutions = {
            'if [[ "$(id -u)" -ne 0 ]]; then': 'if [[ "0" -ne 0 ]]; then',
            'LIVE=/root/ip_limiter.py': f'LIVE={self.live}',
            'REPO=https://raw.githubusercontent.com/DenaSon/nvl-bot':
                f'REPO=file://{self.raw}',
            'mktemp -d /root/nvl-p1-limiter.XXXXXX':
                f'mktemp -d {self.root}/work.XXXXXX',
            'mktemp /root/ip_limiter.py.bak.p1.XXXXXX':
                f'mktemp {self.root}/backup.XXXXXX',
            'mktemp /root/.ip_limiter.py.p1.XXXXXX':
                f'mktemp {self.root}/new.XXXXXX',
            'sleep 7': 'sleep 0',
        }
        for old, new in substitutions.items():
            self.assertEqual(source.count(old), 1, f"expected unique pattern: {old}")
            source = source.replace(old, new)
        self.script = self.root / "script-under-test.sh"
        self.script.write_text(source, encoding="utf-8")
        syntax = subprocess.run(["bash", "-n", str(self.script)], capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())

    def _make_executable(self, name: str, content: str):
        path = self.bin / name
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(0o755)

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({
            "PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
            "MOCK_SYSTEMCTL_LOG": str(self.log),
            "MOCK_FAIL_ONCE": str(self.fail_once),
        })
        return subprocess.run(
            ["bash", str(self.script), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def _restart_count(self) -> int:
        return len(self.log.read_text().splitlines()) if self.log.exists() else 0

    def test_default_check_is_read_only_and_reports_ready(self):
        before = self.live.read_bytes()
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("P1_PRECHECK=READY", result.stdout)
        self.assertIn("NO_FILES_CHANGED=YES", result.stdout)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(self._restart_count(), 0)
        self.assertEqual(list(self.root.glob("backup.*")), [])

    def test_unexpected_live_version_holds_without_mutation(self):
        self.live.write_text("# unexpected runtime customization\n", encoding="utf-8")
        before = self.live.read_bytes()
        result = self._run("--apply")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("HOLD:", result.stderr)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(self._restart_count(), 0)

    def test_apply_replaces_only_limiter_after_preflight(self):
        result = self._run("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("P1_DEPLOY=PASS", result.stdout)
        self.assertEqual(self.live.read_text(encoding="utf-8"), FIXED_PYTHON)
        self.assertEqual(self._restart_count(), 1)
        self.assertEqual(len(list(self.root.glob("backup.*"))), 1)

    def test_failed_restart_rolls_back_previous_limiter(self):
        self.fail_once.touch()
        before = self.live.read_bytes()
        result = self._run("--apply")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("ROLLBACK:", result.stderr)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(self._restart_count(), 2)

    def test_already_applied_requires_no_restart(self):
        self.live.write_text(FIXED_PYTHON, encoding="utf-8")
        result = self._run("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ALREADY_PATCHED", result.stdout)
        self.assertEqual(self._restart_count(), 0)


if __name__ == "__main__":
    unittest.main()
