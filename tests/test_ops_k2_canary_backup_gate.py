"""Production canary backup: real SQLite + tarball integrity, NO live release."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from ops.k2_canary_backup_gate import (
    CORE_REQUIRED,CanaryBackupHold,audit_backup,main,
)


class CanaryBackupAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.backup=self.base/"core-20261014T100000Z-test"
        self.backup.mkdir(mode=0o700)
        (self.backup/"diagnostics").mkdir(mode=0o700)
        self.uid=os.geteuid()
        self.roots=("etc/nvl-egress","etc/pam.d","etc/passwd",
                    "etc/shadow","etc/ssh","opt/nvl-egress")
        self.tree=self.base/"inputs"
        self.tree.mkdir()
        for item in self.roots:
            path=self.tree/item
            if item in ("etc/passwd","etc/shadow"):
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text("protected fixture\n")
            else:
                path.mkdir(parents=True,exist_ok=True)
                (path/"identity").write_text("test only")
        (self.backup/"diagnostics/archived-roots.txt").write_text(
            "\n".join(self.roots)+"\n"
        )
        (self.backup/"diagnostics/host-state.txt").write_text(
            "diagnostics not a proof of actual network rollback\n"
        )
        (self.backup/"diagnostics/db-tables.txt").write_text(
            "failover_operations\nhost_pool\nsettings\nssh_accounts\n"
        )
        self.db=self.backup/"master_bot.sqlite3"
        with sqlite3.connect(self.db) as con:
            for t in ("settings","ssh_accounts","host_pool","failover_operations"):
                con.execute(f'CREATE TABLE "{t}" (id INTEGER)')
        self.retar()
        self.sign()

    def retar(self, malicious=None):
        with tarfile.open(self.backup/"system-configs.tar.gz","w:gz") as t:
            for name in self.roots:
                t.add(self.tree/name,arcname=name)
            if malicious:
                obj=tarfile.TarInfo(malicious)
                obj.size=0
                t.addfile(obj)

    def sign(self):
        import hashlib
        self.backup.joinpath("SHA256SUMS").write_text("".join(
            hashlib.sha256((self.backup/name).read_bytes()).hexdigest()
            + "  "+name+"\n"
            for name in sorted(CORE_REQUIRED)
        ))
        # Mirror the production script's 0600/0700 secret permissions.
        for file in self.backup.rglob("*"):
            if file.is_dir():
                file.chmod(0o700)
            elif file.is_file() and not file.is_symlink():
                file.chmod(0o600)

    def check(self,**kwargs):
        return audit_backup(self.backup,owner_uid=self.uid,
                            active_protected_dirs=("etc/nvl-egress",
                                                   "opt/nvl-egress"),
                            **kwargs)

    def test_local_consistent_never_certifies_live_rollback(self):
        r=self.check()
        self.assertTrue(r.local_consistency,r.blockers)
        self.assertTrue(r.archive_ok)
        self.assertTrue(r.core_db_ok)
        self.assertTrue(r.protected_paths_covered)
        self.assertFalse(r.authorizes_customer_change)
        self.assertFalse(r.independent_offhost_copy_verified)
        self.assertFalse(r.provider_volume_snapshot_verified)
        self.assertFalse(r.independent_restore_drill_verified)
        self.assertFalse(r.live_kernel_rollback_verified)

    def test_corrupted_database_backup_is_hold_even_with_updated_hash(self):
        self.db.write_bytes(b"not a database")
        self.sign()
        r=self.check()
        self.assertFalse(r.local_consistency)
        self.assertIn("BACKUP_SQLITE_NOT_READABLE",r.blockers)

    def test_different_sha_detected(self):
        (self.backup/"diagnostics/host-state.txt").write_text("tampered")
        r=self.check()
        self.assertFalse(r.local_consistency)
        self.assertIn("BACKUP_DIGEST_MISMATCH",r.blockers)

    def test_incomplete_manifest_rejected(self):
        with (self.backup/"SHA256SUMS").open("a") as f:
            f.write("0"*64+"  fake-file\n")
        r=self.check()
        self.assertIn("INCOMPLETE_BACKUP_CHECKSUM_COVERAGE",r.blockers)

    def test_symlink_checksum_file_or_backup_archive_is_hold(self):
        path=self.backup/"diagnostics/db-tables.txt"
        path.unlink()
        path.symlink_to("/etc/passwd")
        self.assertIn("BACKUP_UNTRUSTED_OWNERSHIP",self.check().blockers)

    def test_existing_protected_root_not_in_backup_cannot_be_considered_safe(self):
        r=audit_backup(
            self.backup,owner_uid=self.uid,
            active_protected_dirs=("etc/nvl-egress","root/nvl-egress-keys"),
        )
        self.assertIn("ACTIVE_K2_PROTECTION_NOT_SNAPSHOTTED",r.blockers)
        self.assertFalse(r.protected_paths_covered)

    def test_missing_identity_path_in_archive_is_hold(self):
        self.roots=tuple(r for r in self.roots if r!="etc/shadow")
        (self.backup/"diagnostics/archived-roots.txt").write_text(
            "\n".join(self.roots)+"\n"
        )
        self.retar()
        self.sign()
        self.assertIn("CORE_ACCOUNT_RECOVERY_FILES_NOT_ARCHIVED",
                      self.check().blockers)

    def test_traversal_tar_member_rejected(self):
        self.retar(malicious="../../escape")
        self.sign()
        self.assertIn("ARCHIVE_PATH_UNTRUSTED",self.check().blockers)

    def test_missing_tar_source_item_rejected_even_with_matching_manifest(self):
        self.roots=self.roots+("opt/nvl-egress/phantom",)
        (self.backup/"diagnostics/archived-roots.txt").write_text(
            "\n".join(sorted(self.roots))+"\n"
        )
        # manifest claims phantom but file is missing inside archive.
        with tarfile.open(self.backup/"system-configs.tar.gz","w:gz") as t:
            for name in self.roots:
                if name.endswith("phantom"):
                    continue
                t.add(self.tree/name,arcname=name)
        self.sign()
        self.assertIn("ARCHIVE_ROOTS_NOT_ACTUALLY_COVERED",
                      self.check().blockers)

    def test_cli_nonroot_rejects_before_reading_any_host_backup(self):
        out=io.StringIO()
        with patch("ops.k2_canary_backup_gate.os.geteuid",return_value=1001),\
             redirect_stdout(out):
            code=main(["--backup","/root/nvl-emergency-backups/test"])
        self.assertEqual(code,2)
        r=json.loads(out.getvalue())
        self.assertEqual(r["status"],"HOLD")
        self.assertFalse(r["authorizes_customer_change"])

    def test_invalid_backup_scopes_are_rejected(self):
        with self.assertRaises(CanaryBackupHold):
            audit_backup(Path("relative"),owner_uid=self.uid)
        with self.assertRaises(CanaryBackupHold):
            audit_backup(self.backup,owner_uid=self.uid,
                         active_protected_dirs=("etc/ssh",))


if __name__=="__main__":
    unittest.main()
