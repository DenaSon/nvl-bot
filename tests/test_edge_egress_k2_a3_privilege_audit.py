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

    def test_invalid_source_holds_and_simple_source_does_not_certify_nonroot(self):
        for raw in (b"",b"\xff",b"def bad("):
            with self.subTest(raw=raw),self.assertRaises(audit.A3AuditHold):
                audit.scan_legacy_bot_source(raw)
        r=audit.scan_legacy_bot_source(b"def simple():\n    return 42\n")
        self.assertFalse(r.ready_for_nonroot)
        self.assertEqual(r.functions_scanned,1)

    def test_current_legacy_bot_never_gets_implicit_privilege_split_approval(self):
        current=Path(__file__).resolve().parents[1]/"bot_final_v49-2.py"
        report=audit.audit_legacy_bot_file(current)
        self.assertFalse(audit.A3_PRIVILEGE_SPLIT_APPROVED)
        self.assertFalse(report.ready_for_nonroot)
        self.assertGreater(report.functions_scanned,100)
        self.assertGreater(len(report.callsites),10)
        self.assertEqual(len(report.source_sha256),64)


if __name__=="__main__":
    unittest.main()
