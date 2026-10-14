"""Off-Core A4 measurement envelope and real detached signature integration tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import edge_egress_k2_a4_observer as a4
from edge_egress_k2_m42_evidence import REQUIRED_CHECKS, decode_evidence

NOW=1792010100
TARGET="45.61.163.75"
RUN="observerrun7"
D="c"*64


def receipts():
    return tuple(
        a4.IndependentProbeReceipt(
            check=check,domain=a4._DOMAINS[check],
            probe_id="probe"+str(i).zfill(3),run_id=RUN,
            observed_at=NOW-2,target_edge="e9",target_ipv4=TARGET,
            raw_result_sha256=D,outcome="PASS",
            observed_public_ipv4=TARGET
            if check=="ssh_socks_ipv4" else None,
        )
        for i,check in enumerate(sorted(REQUIRED_CHECKS))
    )


def sessions():
    return (a4.IndependentSessionReceipt(
        username="nvl0555",uid=1636,source_edge="e9",source_ipv4=TARGET,
        active_sessions=0,observed_at=NOW-3,
        raw_result_sha256="b"*64,run_id=RUN,
    ),)


class WitnessEnvelopeTests(unittest.TestCase):
    def render(self,probes=None,accounts=None,**changes):
        return a4.build_observation_report(
            probes=receipts() if probes is None else probes,
            sessions=sessions() if accounts is None else accounts,
            target_edge=changes.get("target_edge","e9"),
            target_ipv4=changes.get("target_ipv4",TARGET),
            now=changes.get("now",NOW),
        )

    def test_full_independent_typed_receipt_roundtrip(self):
        data=self.render()
        obj=decode_evidence(data,now=NOW)
        self.assertEqual(obj.target_edge,"e9")
        self.assertEqual(obj.target_ipv4,TARGET)
        self.assertEqual(obj.accounts[0].active_sessions,0)
        self.assertEqual(obj.checks,REQUIRED_CHECKS)
        self.assertEqual(json.loads(data)["expires_at"],NOW+27)

    def test_missing_duplicate_and_failed_independent_probes_hold(self):
        items=receipts()
        for changed in (
            items[:-1],
            items[:-1]+(items[0],),
            items[:-1]+(a4.IndependentProbeReceipt(
                **{**items[-1].__dict__,"outcome":"FAIL"}),),
            items[:-1]+(a4.IndependentProbeReceipt(
                **{**items[-1].__dict__,"domain":"bot"}),),
            items[:-1]+(a4.IndependentProbeReceipt(
                **{**items[-1].__dict__,"observed_at":NOW-31}),),
            items[:-1]+(a4.IndependentProbeReceipt(
                **{**items[-1].__dict__,"run_id":"differentrun"}),),
        ):
            with self.subTest(size=len(changed)),self.assertRaises(
                a4.A4ObserverHold
            ):
                self.render(probes=changed)

    def test_socks_ip_and_sessions_not_inferred_from_source_or_db(self):
        items=receipts()
        changed=tuple(
            a4.IndependentProbeReceipt(**{
                **item.__dict__,"observed_public_ipv4":"209.200.246.198",
            }) if item.check=="ssh_socks_ipv4" else item
            for item in items
        )
        with self.assertRaises(a4.A4ObserverHold):
            self.render(probes=changed)
        for cnt in (1,-1,None,True):
            candidate=a4.IndependentSessionReceipt(**{
                **sessions()[0].__dict__,"active_sessions":cnt,
            })
            with self.subTest(count=cnt),self.assertRaises(a4.A4ObserverHold):
                self.render(accounts=(candidate,))

    def test_stale_replay_and_other_edge_hold(self):
        for kwargs in (
            {"now":NOW+30},
            {"now":NOW-5},
            {"target_edge":"e8"},
            {"target_ipv4":"209.200.246.198"},
        ):
            with self.subTest(kwargs=kwargs),self.assertRaises(
                a4.A4ObserverHold
            ):
                self.render(**kwargs)

    def test_signer_unchanged_default_off(self):
        self.assertFalse(a4.A4_OFFCORE_SIGNING_ENABLED)
        with self.assertRaisesRegex(a4.A4ObserverHold,"NOT_RELEASED"):
            a4.sign_offcore_observation(probes=receipts(),sessions=sessions(),target_edge="e9",target_ipv4=TARGET,clock=lambda:NOW)
        with patch.object(a4,"A4_OFFCORE_SIGNING_ENABLED",True):
            with self.assertRaisesRegex(a4.A4ObserverHold,"NOT_RELEASED"):
                a4.sign_offcore_observation(probes=receipts(),sessions=sessions(),target_edge="e9",target_ipv4=TARGET,clock=lambda:NOW,geteuid=lambda:0)

    @unittest.skipUnless(shutil.which("openssl"),"OpenSSL unavailable")
    def test_real_offcore_openssl_signature_and_tamper_detection(self):
        # This key is a THROWAWAY CI fixture, never a release signing key.
        if os.geteuid()==0:
            self.skipTest("Nonroot signer must refuse root")
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            key=folder/"observer-private.pem"
            public=folder/"public.pem"
            subprocess.run(
                ["openssl","genpkey","-algorithm","RSA",
                 "-pkeyopt","rsa_keygen_bits:2048","-out",str(key)],
                check=True,capture_output=True,timeout=20,
            )
            os.chmod(key,0o600)
            subprocess.run(
                ["openssl","pkey","-in",str(key),"-pubout","-out",str(public)],
                check=True,capture_output=True,timeout=10,
            )
            raw=self.render()
            with patch.object(a4,"A4_OFFCORE_SIGNING_ENABLED",True),\
                 patch.object(a4,"PRIVATE_KEY",key),\
                 patch.object(a4.time,"time",return_value=NOW):
                observed,signed=a4.sign_offcore_observation(
                    probes=receipts(),sessions=sessions(),target_edge="e9",
                    target_ipv4=TARGET,key_path=key,clock=lambda:NOW,
                )
                self.assertEqual(observed,raw)
            sig=folder/"report.sig"
            sig.write_bytes(signed)
            result=subprocess.run(
                ["openssl","dgst","-sha256","-verify",str(public),
                 "-signature",str(sig),"-"],
                input=raw,capture_output=True,timeout=10,
            )
            self.assertEqual(result.returncode,0,result.stderr)
            bad=subprocess.run(
                ["openssl","dgst","-sha256","-verify",str(public),
                 "-signature",str(sig),"-"],
                input=raw+b"tampered",capture_output=True,timeout=10,
            )
            self.assertNotEqual(bad.returncode,0)


if __name__=="__main__":
    unittest.main()
