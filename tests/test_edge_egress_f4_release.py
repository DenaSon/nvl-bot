"""F4 acceptance contract is strict and never mints READY itself."""
import copy
import time
import unittest

from edge_egress_f4_release import (
    ACCEPTANCE_PROBES, ReleaseEvidenceUnsafe, check_release_evidence,
    parse_evidence_json,
)


def complete_evidence():
    return {
        "version":1,
        "run_id":"external-vm-20261012-001",
        "edge_id":"fra1","username":"nvl0557","uid":1644,
        "core_ipv4":"209.200.246.198","edge_ipv4":"216.126.229.12",
        "environment":"disposable-vps",
        "observed_edge_ipv4":"216.126.229.12",
        "observed_at":1800000000,
        "probe_results":{k:True for k in ACCEPTANCE_PROBES},
    }


class ReleaseEvidenceTests(unittest.TestCase):
    def evaluate(self,payload,now=1800000020):
        return check_release_evidence(
            payload,now=now,expected_edge_id="fra1",
            expected_uid=1644,expected_username="nvl0557",
            expected_core_ipv4="209.200.246.198",
            expected_edge_ipv4="216.126.229.12",
        )

    def test_complete_hypothetical_checklist_is_not_customer_authority(self):
        verdict=self.evaluate(complete_evidence())
        self.assertTrue(verdict.accepted)
        self.assertFalse(verdict.customer_ready)
        self.assertEqual(verdict.code,"CANDIDATE_FOR_INDEPENDENT_REVIEW")

    def test_every_required_probe_blocks_release_when_failed(self):
        for name in ACCEPTANCE_PROBES:
            with self.subTest(name=name):
                evidence=complete_evidence()
                evidence["probe_results"][name]=False
                verdict=self.evaluate(evidence)
                self.assertFalse(verdict.accepted)
                self.assertFalse(verdict.customer_ready)
                self.assertIn(name,verdict.failures)

    def test_core_ip_or_foreign_exit_is_never_accepted(self):
        for ip in ("209.200.246.198","8.8.8.8","127.0.0.1","bad-ip"):
            with self.subTest(ip=ip):
                evidence=complete_evidence()
                evidence["observed_edge_ipv4"]=ip
                self.assertFalse(self.evaluate(evidence).accepted)

    def test_stale_future_and_identity_change_are_rejected(self):
        changes=(
            ("observed_at",1800000000-5000),
            ("observed_at",1800000000+9999),
            ("edge_id","fra2"),
            ("username","nvl0558"),
            ("uid",1645),
            ("core_ipv4","8.8.8.8"),
            ("edge_ipv4","8.8.8.8"),
            ("environment","CI-namespace"),
            ("run_id","short"),
        )
        for key,value in changes:
            with self.subTest(key=key,value=value):
                evidence=complete_evidence()
                evidence[key]=value
                self.assertFalse(self.evaluate(evidence).accepted)

    def test_unknown_fields_missing_probes_and_nonboolean_flags_denied(self):
        for kind in ("extra","missing","nonboolean"):
            evidence=complete_evidence()
            if kind=="extra": evidence["authorize_production"]=True
            if kind=="missing": del evidence["probe_results"]["ipv6_no_core_leak"]
            if kind=="nonboolean": evidence["probe_results"]["ipv6_no_core_leak"]=1
            with self.subTest(kind=kind):
                self.assertFalse(self.evaluate(evidence).accepted)

    def test_json_parser_size_and_invalid_bytes(self):
        for b in (b"x"*16385,b"not-json",b"\xff"):
            with self.assertRaises(ReleaseEvidenceUnsafe):
                parse_evidence_json(b)


if __name__=="__main__":
    unittest.main()
