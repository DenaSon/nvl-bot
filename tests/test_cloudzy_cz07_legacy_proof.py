"""One-job historical CZ07 identity proof: no SSH/Cloudflare/provider effects."""
import hashlib
import json
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cloudzy_cz07_legacy_proof import (
    HISTORICAL_JOB_ID, HISTORICAL_SOURCE, HISTORICAL_TARGET,
    HistoricalProofHold, _digest_rows, verify_historical_job,
)


class HistoricalSnapshotProofTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.before = str(self.home / "before.db")
        self.after = str(self.home / "after_batch.db")
        self.last = str(self.home / "before_emergency.db")
        self.paths = (self.before, self.after, self.last)
        self.names = [f"user{i:04d}" for i in range(468)]
        self.rows = [(name, HISTORICAL_SOURCE, "🟢 فعال")
                     for name in self.names]
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE ssh_accounts(
                username TEXT PRIMARY KEY,host TEXT,status TEXT,
                service_type TEXT);
            CREATE TABLE cloudzy_cz04b_operations(
                kind TEXT,status TEXT,source TEXT,target TEXT,
                actor INTEGER,chat INTEGER,provider_id TEXT,
                started_at INTEGER,count INTEGER,payload_json TEXT);
            CREATE TABLE nvl_emergency_migration_audit(
                job_id TEXT PRIMARY KEY,source TEXT,target TEXT,
                affected INTEGER,previous_status TEXT,previous_code TEXT,
                event_code TEXT);
            CREATE TABLE cloudzy_cz07_events(
                job_id TEXT,stage TEXT,code TEXT,moved INTEGER,
                remaining INTEGER);
        """)
        self.record = {
            "id":HISTORICAL_JOB_ID,"source":HISTORICAL_SOURCE,
            "target":HISTORICAL_TARGET,"total":468,"moved":468,
            "status":"HOLD","code":"EMERGENCY_LOCAL_CAS_E2E_PENDING",
            "cancel_requested":0,"source_fingerprint":_digest_rows(self.rows),
            "actor":7,"chat":7,"provider_id":"provider-1","started_at":100,
        }
        for p, is_before in [(self.before,True),(self.after,False),(self.last,False)]:
            with sqlite3.connect(p) as snapshot:
                snapshot.execute(
                    "CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,"
                    "host TEXT,status TEXT,service_type TEXT)")
                snapshot.executemany(
                    "INSERT INTO ssh_accounts VALUES(?,?,?,'ssh')",
                    [(name,
                      HISTORICAL_SOURCE if is_before or i >= 400
                      else HISTORICAL_TARGET,
                      "🟢 فعال")
                     for i,name in enumerate(self.names)])
        self.db.executemany(
            "INSERT INTO ssh_accounts VALUES(?,?,?,'ssh')",
            [(name,HISTORICAL_TARGET,
              "🔴 غیرفعال" if i in (0,1,2,3,4,5,6,7,8,460)
              else "🟢 فعال")
             for i,name in enumerate(self.names)]
            + [(f"extra{i}",HISTORICAL_TARGET,
                "🔴 غیرفعال" if i == 0 else "🟢 فعال")
               for i in range(4)],
        )
        for i in (0,200):
            self.db.execute(
                "INSERT INTO cloudzy_cz04b_operations VALUES "
                "('users','DONE',?,?,?,?,?,?,?,?)",
                (HISTORICAL_SOURCE,HISTORICAL_TARGET,7,7,
                 "provider-1",101+i,200,json.dumps(self.names[i:i+200])),
            )
        self.db.execute(
            "INSERT INTO nvl_emergency_migration_audit VALUES(?,?,?,?,?,?,?)",
            (HISTORICAL_JOB_ID,HISTORICAL_SOURCE,HISTORICAL_TARGET,68,
             "HOLD","CLOUDZY_PROVIDER_UNAVAILABLE",
             "EMERGENCY_LOCAL_CAS_E2E_PENDING"),
        )
        self.db.execute(
            "INSERT INTO cloudzy_cz07_events VALUES(?,?,?,?,?)",
            (HISTORICAL_JOB_ID,"HOLD",
             "EMERGENCY_LOCAL_CAS_E2E_PENDING",468,0),
        )

    def proof(self):
        return verify_historical_job(
            self.db,self.record,snapshots=self.paths)

    def test_inactive_accounts_and_four_extra_are_not_false_missing(self):
        result=self.proof()
        self.assertEqual(
            (result["moved"],result["remaining"],result["batches"],
             result["emergency"],result["extra_target"]),
            (468,0,400,68,4),
        )
        self.assertTrue(result["historical_identity_verified"])
        self.assertEqual(len(result["historical_proof_sha256"]),64)
        self.assertEqual(len(result["historical_snapshots_sha256"]),3)
        self.assertNotIn("user0001",str(result))

    def test_new_account_cannot_replace_missing_original(self):
        self.db.execute("DELETE FROM ssh_accounts WHERE username='user0467'")
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES(?,?,?,'ssh')",
            ("replacement",HISTORICAL_TARGET,"🟢 فعال"))
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_ORIGINAL_ACCOUNT_NOT_AT_TARGET"):
            self.proof()

    def test_bad_prejob_fingerprint_fails_closed(self):
        with sqlite3.connect(self.before) as old:
            old.execute("UPDATE ssh_accounts SET status='🔴 غیرفعال' "
                        "WHERE username='user0000'")
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_ORIGINAL_COHORT_FINGERPRINT_MISMATCH"):
            self.proof()

    def test_changed_emergency_snapshot_fails_closed(self):
        with sqlite3.connect(self.last) as old:
            old.execute("DELETE FROM ssh_accounts WHERE username='user0467'")
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_EMERGENCY_COHORT_MISMATCH"):
            self.proof()

    def test_duplicate_batch_identity_fails_closed(self):
        row=self.db.execute(
            "SELECT rowid,payload_json FROM cloudzy_cz04b_operations LIMIT 1",
        ).fetchone()
        names=json.loads(row["payload_json"])
        names[1]=names[0]
        self.db.execute(
            "UPDATE cloudzy_cz04b_operations SET payload_json=? WHERE rowid=?",
            (json.dumps(names),row["rowid"]),
        )
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_BATCH_COHORT_MISMATCH"):
            self.proof()

    def test_missing_audit_and_wrong_job_are_rejected(self):
        self.db.execute("DELETE FROM nvl_emergency_migration_audit")
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_EMERGENCY_AUDIT_MISMATCH"):
            self.proof()
        self.record["id"]="other-job"
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_JOB_IDENTITY_CHANGED"):
            self.proof()

    def test_foreign_active_account_and_missing_snapshot_rejected(self):
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES(?,?,?,'ssh')",
            ("foreign","different-host","🟢 فعال"),
        )
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_ACTIVE_ACCOUNT_ROUTE_CHANGED"):
            self.proof()
        self.db.execute("DELETE FROM ssh_accounts WHERE username='foreign'")
        Path(self.last).unlink()
        with self.assertRaisesRegex(
                HistoricalProofHold,"EVIDENCE_SNAPSHOT_UNAVAILABLE"):
            self.proof()


if __name__ == "__main__":
    unittest.main()
