"""Concrete cross-Edge P3 PAM safety contract (hermetic, no host writes).

Exercise actual CrossEdgeIndependentSafety with typed authenticated PAM/WG
journal fixtures and the original IndependentSafety interface. Mock only
machine-dependent binary/syscalls and offhost F4, never bypass the source
identity comparisons inside the method.
"""
from types import SimpleNamespace
from unittest.mock import patch
import unittest

import edge_egress_k2_m4_cross_edge_port as cross
from ops.k2_p3_uid_worker import LiveUIDHold
from tests.test_edge_egress_k2_cross_edge_store import CrossEdgeStoreTests
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class CrossEdgePAMSafetyTests(unittest.TestCase):
    def setUp(self):
        self.fx=CrossEdgeStoreTests(
            methodName="test_default_off_blocks_before_any_uid_mutation"
        )
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.req=self.fx.fx.uid_req

    def safety(self, provider):
        return cross.CrossEdgeIndependentSafety(
            db_conn=self.fx.fx.conn_factory,
            target_edge_id="fra1",
            source_ipv4=SOURCE,
            ingress_rhost="10.77.0.8",
            ssh_local_addr="10.77.0.1",
            ssh_local_port=22,
            reviewed_module_sha256="a"*64,
            packet_witness=lambda req:True,
            neighbour_witness=lambda req:True,
            now=lambda:1000,
            ingress_edge_id="s8",
            source_evidence=provider,
        )

    def gates(self, provider):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(
            patch.object(cross,"CROSS_EDGE_PAM_SAFETY_ENABLED",True)
        )
        stack.enter_context(
            patch.object(cross,"root_fresh_source_evidence",provider)
        )
        stack.enter_context(patch(
            "edge_egress_f4_pam.verify_installed_gate_digest",
            return_value=True,
        ))
        stack.enter_context(patch(
            "ops.k2_p3_host_readonly.trusted_pam_config",
            return_value="account required pam_unix.so",
        ))
        stack.enter_context(patch(
            "ops.k2_p3_uid_worker._checked",
            return_value="usepam yes",
        ))
        stack.enter_context(patch(
            "edge_egress_v1_admission.inspect_pam",return_value=True
        ))
        stack.enter_context(patch(
            "edge_egress_f3_readiness.read_readiness",
            return_value=SimpleNamespace(edge_ipv4=TARGET),
        ))
        stack.enter_context(patch(
            "edge_egress_f3_readiness.admission_eligible",
            return_value=True,
        ))
        stack.enter_context(patch(
            "edge_egress_uid_boot.BootGuardApplier"
        ))
        stack.enter_context(patch.object(
            cross.CrossEdgeIndependentSafety,"_manifest",
            return_value=SimpleNamespace(),
        ))
        return stack

    def test_exact_pam_root_journal_and_wg_peer_accepted(self):
        source=lambda:self.fx.evidence
        with self.gates(source):
            self.safety(source).assert_pam_ingress_boot(self.req)

    def test_source_changed_peer_or_key_cannot_pass(self):
        from edge_egress_k2_m2_ingress_journal import (
            IngressRecord, RootReadOnlyIngressEvidence, encode_records,
        )
        from edge_egress_v1_ingress import IngressPeer
        wrong_key="z"*44
        mismatched=RootReadOnlyIngressEvidence(
            encode_records({"nvl0557":IngressRecord(
                "nvl0557",1644,"s8",SOURCE,"10.77.0.8",
                wrong_key,1000,
            )}),
            (self.fx.peer,),
            self.fx.evidence.allowed_ips,1000,self.fx.fx.unix_lookup,
        )
        with self.gates(lambda:self.fx.evidence):
            wrong_identity=lambda:mismatched
        with self.gates(wrong_identity):
            with self.assertRaises(LiveUIDHold):
                self.safety(wrong_identity).assert_pam_ingress_boot(self.req)

    def test_legacy_same_edge_claim_is_rejected(self):
        source=lambda:self.fx.evidence
        with self.gates(source):
            safety=self.safety(source)
            safety.ingress_edge_id="fra1"
            with self.assertRaisesRegex(LiveUIDHold,"NOT_ATTESTED"):
                safety.assert_pam_ingress_boot(self.req)

    def test_disabled_release_holds_before_host_probes(self):
        source=lambda:self.fx.evidence
        safety=self.safety(source)
        with self.assertRaisesRegex(LiveUIDHold,"NOT_ATTESTED"):
            safety.assert_pam_ingress_boot(self.req)


if __name__=="__main__":
    unittest.main()
