"""A3 static privilege inventory: always HOLD pending full host review."""
from __future__ import annotations

from pathlib import Path
import unittest

import edge_egress_k2_a3_privilege_audit as audit


class A3PrivilegeAuditTests(unittest.TestCase):
    def test_privileged_sinks_are_detected_without_any_execution(self):
        raw=b"""import subprocess
def create_account(name):
    subprocess.run(["useradd", name])
def sudo_cmd():
    __import__("subprocess")
    os.system("systemctl restart ssh")
async def command():
    await asyncio.create_subprocess_exec("ip","rule")
"""
        report=audit.scan_legacy_bot_source(raw)
        self.assertFalse(report.ready_for_nonroot)
        self.assertEqual(report.functions_scanned,3)
        self.assertIn("subprocess.run",{h.sink for h in report.callsites})
        self.assertIn("os.system",{h.sink for h in report.callsites})
        self.assertIn("__import__",{h.sink for h in report.callsites})
        self.assertIn("asyncio.create_subprocess_exec",
                      {h.sink for h in report.callsites})

    def test_aliased_privileged_imports_remain_visible_for_a3_cutover(self):
        raw=b"""import subprocess as sp
import os as operating_system
from subprocess import run as execute_program
from os import chmod as file_mode
from asyncio import create_subprocess_exec as spawn
def create_user():
    sp.run(["useradd", "test"])
    execute_program(["chpasswd"])
    operating_system.system("systemctl restart ssh")
    file_mode("/etc/ssh/sshd_config", 0o600)
    spawn("ip", "route")
def inner():
    from subprocess import Popen as launch
    launch(["sudo", "true"])
"""
        report=audit.scan_legacy_bot_source(raw)
        self.assertFalse(report.ready_for_nonroot)
        roots={h.sink for h in report.callsites if h.risk=="root-or-command"}
        self.assertTrue({
            "subprocess.run","os.system","os.chmod",
            "asyncio.create_subprocess_exec","subprocess.Popen",
        } <= roots)
        self.assertGreaterEqual(
            sum(h.sink=="subprocess.run" for h in report.callsites),2
        )

    def test_wildcard_imports_never_silently_certify_nonroot(self):
        report=audit.scan_legacy_bot_source(
            b"from subprocess import *\ndef call():\n    run(['useradd','test'])\n"
        )
        self.assertFalse(report.ready_for_nonroot)
        self.assertIn("subprocess.*",{h.sink for h in report.callsites})
        self.assertIn("manual-review",{h.risk for h in report.callsites})

    def test_invalid_source_holds_and_simple_source_does_not_certify_nonroot(self):
        for raw in (b"",b"\xff",b"def bad("):
            with self.subTest(raw=raw),self.assertRaises(audit.A3AuditHold):
                audit.scan_legacy_bot_source(raw)
        r=audit.scan_legacy_bot_source(b"def simple():\n    return 42\n")
        self.assertFalse(r.ready_for_nonroot)
        self.assertEqual(r.functions_scanned,1)

    def test_current_legacy_bot_never_gets_implicit_privilege_split_approval(self):
        current=Path(__file__).resolve().parents[1]/"bot_final_v49-2.py"
        # The legacy bot uses Python 3.12+ f-string grammar in places.
        # A 3.11 AST parse failure is an explicit HOLD, never a pass.
        self.assertFalse(audit.A3_PRIVILEGE_SPLIT_APPROVED)
        try:
            report=audit.audit_legacy_bot_file(current)
        except audit.A3AuditHold as exc:
            self.assertIn("CANNOT_BE_AUDITED",str(exc))
        else:
            self.assertFalse(report.ready_for_nonroot)
            self.assertGreater(report.functions_scanned,100)
            self.assertGreater(len(report.callsites),10)
            self.assertEqual(len(report.source_sha256),64)


if __name__=="__main__":
    unittest.main()
