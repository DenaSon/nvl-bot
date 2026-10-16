"""M4.2 signed external witness: strict provenance, account scope and freshness.

All positive fixtures here are synthetic; a valid signature is not itself an
actual physical F4 packet/SSH/SOCKS proof.
"""
from __future__ import annotations
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import edge_egress_k2_m42_evidence as ev

NOW = 1792010100
TARGET = "45.61.163.75"


def report(**replace):
    obj = {
        "version": 1,
        "generation": "a"*64,
        "observed_at": NOW-1,
        "expires_at": NOW+10,
        "target_edge": "e9",
        "target_ipv4": TARGET,
        "checks": {key: True for key in ev.REQUIRED_CHECKS},
        "accounts": [{
            "username": "nvl0555", "uid": 1636,
            "source_edge": "e9", "source_ipv4": TARGET,
            "active_sessions": 0,
        }],
    }
    obj.update(replace)
    return json.dumps(obj,separators=(",", ":")).encode()


class SignedWitnessContractTests(unittest.TestCase):
    def test_valid_synthetic_schema_and_exact_account(self):
        proof=ev.decode_evidence(report(),now=NOW)
        self.assertEqual(proof.verify_account("nvl0555",1636),0)
        self.assertEqual(proof.target_ipv4,TARGET)
        proof.verify_target("e9",TARGET,("nvl0555",))

    def test_cannot_infer_zero_from_other_identity(self):
        proof=ev.decode_evidence(report(),now=NOW)
        for username,uid in (("nvl0557",1636),("nvl0555",1644)):
            with self.assertRaises(ev.M42EvidenceHold):
                proof.verify_account(username,uid)
        with self.assertRaises(ev.M42EvidenceHold):
            proof.verify_account("nvl0555",1636,source_ipv4="172.86.111.69")

    def test_active_session_never_ready(self):
        x=json.loads(report())
        x["accounts"][0]["active_sessions"]=1
        proof=ev.decode_evidence(json.dumps(x).encode(),now=NOW)
        with self.assertRaises(ev.M42EvidenceHold):
            proof.verify_account("nvl0555",1636)

    def test_expired_future_replayed_and_oversized_hold(self):
        for raw,now in (
            (report(),NOW+10),
            (report(),NOW-3),
            (report(observed_at=NOW-40,expires_at=NOW+1),NOW),
            (b"x"*(ev.MAX_EVIDENCE_BYTES+1),NOW),
        ):
            with self.subTest(now=now,size=len(raw)):
                with self.assertRaises(ev.M42EvidenceHold):
                    ev.decode_evidence(raw,now=now)

    def test_missing_or_false_checks_cannot_make_f4(self):
        for m in (
            {"f4_accepted":True},
            {**{k:True for k in ev.REQUIRED_CHECKS},"no_core_leak":False},
        ):
            with self.assertRaises(ev.M42EvidenceHold):
                ev.decode_evidence(report(checks=m),now=NOW)

    def test_signature_record_strict_duplicate_field_and_boolean_uid(self):
        duplicates=b'{"version":1,"version":1}'
        with self.assertRaises(ev.M42EvidenceHold):
            ev.decode_evidence(duplicates,now=NOW)
        bad=json.loads(report())
        bad["accounts"][0]["uid"]=True
        with self.assertRaises(ev.M42EvidenceHold):
            ev.decode_evidence(json.dumps(bad).encode(),now=NOW)
        with self.assertRaises(ev.M42EvidenceHold):
            ev.decode_evidence(report(version=True),now=NOW)

    def test_target_and_unselected_users_not_authorized(self):
        proof=ev.decode_evidence(report(),now=NOW)
        for edge,ipv4,names in (
            ("e7",TARGET,("nvl0555",)),
            ("e9","209.200.246.198",("nvl0555",)),
            ("e9",TARGET,("nvl0555","nvl0557")),
        ):
            with self.assertRaises(ev.M42EvidenceHold):
                proof.verify_target(edge,ipv4,names)

    def test_external_loader_disabled_even_for_valid_data(self):
        self.assertFalse(ev.M42_EVIDENCE_ENABLED)
        with self.assertRaisesRegex(ev.M42EvidenceHold,"NOT_RELEASED"):
            ev.load_external_evidence(now=NOW,geteuid=lambda:0)

    @unittest.skipUnless(shutil.which("openssl"),"OpenSSL not installed")
    def test_real_openssl_detached_signature_tamper_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            private=root/"offhost-private.pem"
            public=root/"observer-public.pem"
            data=root/"report.json"
            signature=root/"report.sig"
            def openssl(*args):
                return subprocess.run(["openssl",*args],check=True,
                                      capture_output=True,text=True,timeout=15)
            openssl("genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048",
                    "-out",str(private))
            openssl("pkey","-in",str(private),"-pubout","-out",str(public))
            data.write_bytes(report())
            openssl("dgst","-sha256","-sign",str(private),"-out",str(signature),str(data))
            paths=(data,signature,public)
            # Test-only fixture paths (no /etc files touched): the real
            # detached OpenSSL verification still runs against real RSA key.
            with patch.object(ev,"WITNESS_DIR",root),patch.object(ev,"WITNESS_JSON",data),\
                 patch.object(ev,"WITNESS_SIG",signature),patch.object(ev,"WITNESS_PUB",public),\
                 patch.object(ev,"_verify_root_directory"),\
                 patch.object(ev,"_read_checked",side_effect=lambda p,**k:p.read_bytes()):
                self.assertEqual(ev.verify_external_signature(paths=paths),report())
                data.write_bytes(report(target_edge="e7"))
                with self.assertRaisesRegex(ev.M42EvidenceHold,"INVALID"):
                    ev.verify_external_signature(paths=paths)


    def test_loader_decodes_only_bytes_used_for_signature(self):
        original=report()
        impostor=report(target_edge="e7")
        with patch.object(ev,"M42_EVIDENCE_ENABLED",True),\
             patch.object(ev,"verify_external_signature",return_value=original),\
             patch.object(ev,"_read_checked",side_effect=AssertionError("RE_READ_REPORT")):
            proof=ev.load_external_evidence(now=NOW,geteuid=lambda:0)
            self.assertEqual(proof.target_edge,"e9")
            self.assertNotEqual(original,impostor)


if __name__=="__main__":
    unittest.main()
