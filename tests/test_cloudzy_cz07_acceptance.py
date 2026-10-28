"""No-network acceptance evidence tests: only an independent signed receipt can pass."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest

from cloudzy_cz07_acceptance import IndependentCZ07Witness


class TrustedWitnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        os.chmod(self.directory, 0o700)
        self.key = b"separate-producer-secret-for-unit-testing-123456789"
        self.job = {
            "id": "a" * 32, "status": "VERIFYING",
            "target": "104.194.141.63", "moved": 485, "total": 485,
            "updated_at": 100,
        }
        self.witness = IndependentCZ07Witness(
            str(self.directory), self.key, now=lambda: 350)
        self.content = {
            "version": 1, "producer": "independent-customer-observer",
            "source_id": "denaprobe-mci-01", "job_id": self.job["id"],
            "target": self.job["target"], "issued_at": 250,
            "create": {"reference": "created-ssh-1001", "verified": True,
                       "target": self.job["target"], "observed_at": 210,
                       "ssh_login_success": True},
            "renew": {"reference": "renewed-ssh-1002", "verified": True,
                      "target": self.job["target"], "observed_at": 220,
                      "ssh_login_success": True},
            "client": {"reference": "mci-client-1003", "verified": True,
                       "target": self.job["target"], "observed_at": 230,
                       "isp": "MCI-LTE", "ssh_handshake": True,
                       "ssh_auth": True, "traffic_passed": True}
        }

    def write(self, payload=None, key=None):
        payload = self.content if payload is None else payload
        canonical = json.dumps(payload, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False).encode()
        signature = hmac.new(key or self.key, canonical, hashlib.sha256).hexdigest()
        path = self.directory / (self.job["id"] + ".json")
        path.write_text(json.dumps({**payload, "signature": signature}))
        path.chmod(0o600)
        return path

    def test_missing_and_incomplete_are_not_accepted(self):
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_NOT_RECEIVED")
        bad = {**self.content, "client": {**self.content["client"], "traffic_passed": False}}
        self.write(bad)
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_INCOMPLETE")
        self.assertFalse(self.witness.review(self.job).ready)

    def test_signed_distinct_real_observations_and_fingerprint(self):
        self.write()
        proof = self.witness.review(self.job)
        self.assertTrue(proof.ready)
        self.assertEqual(proof.refs, ("created-ssh-1001", "renewed-ssh-1002",
                                      "mci-client-1003"))
        self.assertTrue(self.witness.verify(self.job,
                        create_ref=proof.create_ref, renew_ref=proof.renew_ref,
                        client_ref=proof.client_ref, fingerprint=proof.fingerprint))
        self.assertFalse(self.witness.verify(self.job,
                         create_ref="forged-create", renew_ref=proof.renew_ref,
                         client_ref=proof.client_ref, fingerprint=proof.fingerprint))

    def test_post_transfer_checks_can_be_recorded_after_moved(self):
        self.write()
        proof = self.witness.review({**self.job, "status": "MOVED"})
        self.assertTrue(proof.ready)
        self.assertEqual(proof.code, "TRUSTED_WITNESS_VERIFIED")

    def test_modified_and_wrong_target_or_stale_evidence_rejected(self):
        path = self.write()
        data = json.loads(path.read_text())
        data["client"]["traffic_passed"] = False
        path.write_text(json.dumps(data))
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_SIGNATURE_INVALID")
        self.write({**self.content, "target": "104.194.141.64"})
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_IDENTITY_MISMATCH")
        self.write({**self.content, "issued_at": 80})
        self.assertEqual(self.witness.review(self.job).code, "TRUSTED_WITNESS_STALE")

    def test_replayed_old_receipt_and_unsafe_file_denied(self):
        self.write()
        changed = {**self.job, "updated_at": 260}
        self.assertEqual(self.witness.review(changed).code, "TRUSTED_WITNESS_STALE")
        path = self.directory / (self.job["id"] + ".json")
        path.chmod(0o644)
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_FILE_INVALID")
        path.unlink()
        path.symlink_to(self.directory / "fake.json")
        self.assertEqual(self.witness.review(self.job).code,
                         "TRUSTED_WITNESS_FILE_INVALID")

    def test_no_done_without_all_evidence(self):
        self.write()
        self.assertEqual(self.witness.review({**self.job, "moved": 484}).code,
                         "EVIDENCE_JOB_NOT_ELIGIBLE")
        self.assertEqual(self.witness.review({**self.job, "status": "HOLD"}).code,
                         "EVIDENCE_JOB_NOT_ELIGIBLE")


if __name__ == "__main__":
    unittest.main()
