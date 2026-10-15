"""Read-only cutover audit of actual legacy root bot and static safety gates.

Never invokes sudo, systemctl, PAM changes, root worker, or live SSH.
"""
from pathlib import Path
from unittest.mock import patch
import unittest

from edge_egress_k2_m4_root_worker import WorkerPaths, RootWorkerHold
from edge_egress_k2_a_root_assembly import M4AAssemblyHold
from ops.k2_m4_cutover_audit import (
    CutoverAudit, CutoverAuditHold, LegacyPrivilegeUse,
    inspect_legacy_source, inspect_cutover,
)


def worker_paths():
    return WorkerPaths(
        source_root=Path("/srv/nvl/reviewed"),
        manifest_file=Path("/etc/nvl-egress/k2-m4/release.json"),
        secret_file=Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
        runtime_dir=Path("/run/nvl-k2-m4"),
        bot_uid=12001,ipc_gid=12002,
    )


class AuditLegacyBotSourceTests(unittest.TestCase):
    def test_real_repo_legacy_bot_has_privileged_dependencies(self):
        # The bot contains Python 3.12+ f-string grammar. 3.11 cannot parse
        # its AST, so the audit MUST report HOLD there, not guess clearance.
        import sys
        root=Path(__file__).resolve().parents[1]
        source=(root / "bot_final_v49-2.py").read_bytes()
        if sys.version_info < (3, 12):
            with self.assertRaisesRegex(
                CutoverAuditHold,"LEGACY_BOT_SOURCE_UNPARSABLE"
            ):
                inspect_legacy_source(source)
            return
        digest,uses=inspect_legacy_source(source)
        self.assertEqual(len(digest),64)
        self.assertGreater(len(uses),5)
        categories={entry.expression for entry in uses}
        self.assertTrue(
            "run_cmd" in categories
            or "asyncio.create_subprocess_exec" in categories
        )
        self.assertTrue(all(entry.line>0 for entry in uses))
        self.assertEqual(tuple(sorted(uses,key=lambda x:(x.line,x.expression))),uses)

    def test_untrusted_or_empty_source_cannot_be_classified_as_safe(self):
        for source in (b"",b"not valid python !!!",b"\xff"):
            with self.subTest(source=source),self.assertRaises(CutoverAuditHold):
                inspect_legacy_source(source)
        digest, uses=inspect_legacy_source(
            b"async def run():\n    await run_cmd('sudo','systemctl')\n"
        )
        self.assertEqual(len(digest),64)
        self.assertIn(LegacyPrivilegeUse("run_cmd",2),uses)
        self.assertIn(LegacyPrivilegeUse("system-command-literal",2),uses)


class ReviewedRootCutoverGateTests(unittest.TestCase):
    def test_root_bot_is_hold_even_with_verified_manifest(self):
        audit_src=b"async def run():\n    await run_cmd('sudo')\n"
        with patch("ops.k2_m4_cutover_audit.verify_reviewed_release",
                   return_value="e"*40),\
             patch("ops.k2_m4_cutover_audit._read_checked",
                   return_value=audit_src),\
             patch("ops.k2_m4_cutover_audit.assert_nonroot_bot_identity",
                   side_effect=M4AAssemblyHold("CURRENT_ROOT_BOT")):
            result=inspect_cutover(worker_paths())
        self.assertEqual(result.reviewed_git_sha,"e"*40)
        self.assertFalse(result.safe_for_cutover)
        self.assertIn("NONROOT_BOT_PROCESS_IDENTITY_NOT_ATTESTED",result.blockers)
        self.assertIn("LEGACY_PRIVILEGED_CALLS_NEED_COMPATIBILITY_REVIEW",result.blockers)

    def test_nonroot_unit_alone_is_not_functional_compatibility_proof(self):
        with patch("ops.k2_m4_cutover_audit.verify_reviewed_release",
                   return_value="c"*40),\
             patch("ops.k2_m4_cutover_audit._read_checked",
                   return_value=b"def f():\n    return 1\n"),\
             patch("ops.k2_m4_cutover_audit.assert_nonroot_bot_identity"):
            result=inspect_cutover(worker_paths())
        self.assertEqual(result.reviewed_git_sha,"c"*40)
        self.assertEqual(result.privileged_uses,())
        self.assertEqual(result.blockers,(
            "INDEPENDENT_LEGACY_FUNCTIONAL_AND_VPS_PROOF_PENDING",
        ))
        self.assertFalse(result.safe_for_cutover)

    def test_source_pin_failure_and_root_uid_error_fail_closed(self):
        with patch("ops.k2_m4_cutover_audit.verify_reviewed_release",
                   side_effect=RootWorkerHold("SOURCE_SWAPPED")),\
             patch("ops.k2_m4_cutover_audit._read_checked") as read,\
             patch("ops.k2_m4_cutover_audit.assert_nonroot_bot_identity",
                   side_effect=M4AAssemblyHold("ROOT_BOT")):
            result=inspect_cutover(worker_paths())
        read.assert_not_called()
        self.assertIsNone(result.bot_sha256)
        self.assertIn("REVIEWED_ROOT_SOURCE_NOT_ATTESTED",result.blockers)
        self.assertFalse(result.safe_for_cutover)

    def test_readonly_lab_cli_never_returns_a_release_success(self):
        import io
        import json
        from contextlib import redirect_stdout
        from ops.k2_m4_cutover_audit import main
        report=CutoverAudit(
            "a"*40,"b"*64,(LegacyPrivilegeUse("run_cmd",51),),
            ("LEGACY_PRIVILEGED_CALLS_NEED_COMPATIBILITY_REVIEW",),
        )
        output=io.StringIO()
        with patch("ops.k2_m4_cutover_audit.inspect_cutover",return_value=report) as checker,\
             redirect_stdout(output):
            code=main([
                "--source-root","/srv/nvl/reviewed",
                "--bot-uid","12001","--ipc-gid","12002",
            ])
        checker.assert_called_once()
        self.assertEqual(code,78)
        payload=json.loads(output.getvalue())
        self.assertEqual(payload["status"],"HOLD")
        self.assertFalse(payload["can_deploy"])
        self.assertFalse(payload["can_release"])
        self.assertEqual(payload["legacy_privileged_call_sites"],1)
        self.assertNotIn("source_root",payload)

    def test_readonly_lab_cli_bad_source_is_a_sanitized_hold(self):
        import io
        import json
        from contextlib import redirect_stdout
        from ops.k2_m4_cutover_audit import main
        output=io.StringIO()
        with patch("ops.k2_m4_cutover_audit.inspect_cutover",
                   side_effect=RootWorkerHold("SECRET_PATH=/root/key")),\
             redirect_stdout(output):
            code=main([
                "--source-root","/srv/nvl/reviewed",
                "--bot-uid","12001","--ipc-gid","12002",
            ])
        self.assertEqual(code,78)
        result=json.loads(output.getvalue())
        self.assertEqual(result["blockers"],["CUTOVER_AUDIT_NOT_ATTESTED"])
        self.assertNotIn("SECRET_PATH",output.getvalue())

    def test_forged_audit_result_cannot_claim_production_approval(self):
        with self.assertRaisesRegex(CutoverAuditHold,"FIELD_ACCEPTANCE"):
            CutoverAudit("a"*40,"b"*64,(),(),safe_for_cutover=True)


if __name__=="__main__":
    unittest.main()
