"""P3 live-host read-only candidate: real SQLite + fake independent probes.

These are NOT packet captures, a privileged Linux test or F4 approval.
"""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from edge_egress_v1_admission import PAM_LINE
from ops.k2_p3_host_readonly import (
    HostUIDWitness, inspect_uid_host, trusted_v1_gate_sha, main,
)
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class KernelWitness:
    def __init__(self, ok=True):
        self.locally_consistent=ok


class RootOnlyHostWitnessTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        plan,ticket,engine,_=self.fx.engine()
        receipt=self.fx.execute(plan,ticket,engine)
        self.assertTrue(receipt.allowed,receipt)
        self.ingress=True
        self.kernel=True
        self.gate=True
        self.pam=PAM_LINE+"\n@include common-account\n"
        self.sshd="usepam yes\n"
        self.rhost="10.77.0.8"

    def review(self, **kwargs):
        options=dict(
            db_conn=self.fx.conn_factory,
            username="nvl0557",edge_id="src1",
            ingress_source=SOURCE,expected_edge=SOURCE,
            pam_rhost=self.rhost,pam_text=self.pam,
            sshd_effective=self.sshd,
            gate_digest_verified=self.gate,
            os_uid=self.fx.lookup,
            roster_loader=lambda:self.fx.roster,
            guard_loader=lambda m:self.fx.manifest,
            ingress_probe=lambda row,rhost: self.ingress and rhost==self.rhost,
            kernel_check=lambda manifest,expected_state: KernelWitness(
                self.kernel and expected_state=="PROTECTED"
            ),
            now=self.fx.now,
        )
        options.update(kwargs)
        return inspect_uid_host(**options)

    def assert_hold(self, expected: str, **kwargs):
        r=self.review(**kwargs)
        self.assertFalse(r.local_preflight)
        self.assertIn(expected,r.blockers)
        self.assertIs(r.customer_ready,False)
        self.assertIs(r.packet_proof,False)
        return r

    def test_readonly_local_pass_never_f4_packet_or_customer_ready(self):
        # Existing account remains Linux/Core-owned; this is a probe ONLY.
        before=self.fx.state()
        r=self.review()
        self.assertTrue(r.local_preflight,r.blockers)
        self.assertEqual(r.blockers,())
        self.assertFalse(r.customer_ready)
        self.assertFalse(r.packet_proof)
        self.assertTrue(r.f4_candidate_only)
        self.assertEqual(self.fx.state(),before)

    def test_unknown_or_unpinned_os_uid_is_hold(self):
        self.fx.uid=1655
        self.assert_hold("PROTECTED_UID_MAPPING_NOT_CURRENT")
        self.fx.uid=1644
        self.assert_hold("OS_UID_NOT_TRUSTED",
                         os_uid=lambda n:True)

    def test_root_owned_pam_module_and_sshd_context_required(self):
        self.assert_hold("V1_ROOT_PAM_GATE_NOT_PINNED",
                         gate_digest_verified=False)
        self.assert_hold("LIVE_PAM_SSHD_CONTEXT_NOT_VERIFIED",
                         pam_text="")
        self.assert_hold("LIVE_PAM_SSHD_CONTEXT_NOT_VERIFIED",
                         sshd_effective="usepam no\n")

    def test_live_kernel_guard_and_ingress_wg0_both_required(self):
        self.kernel=False
        self.assert_hold("LIVE_KERNEL_BOOT_DNS_UID_UNVERIFIED")
        self.kernel=True
        self.ingress=False
        self.assert_hold("LIVE_WG0_INGRESS_PEER_UNVERIFIED")
        self.ingress=True
        self.assert_hold("LIVE_WG0_INGRESS_PEER_UNVERIFIED",
                         pam_rhost="10.77.0.88")

    def test_stale_f4_does_not_create_new_ready_witness(self):
        with self.fx.db() as db:
            db.execute(
                "UPDATE edge_egress_readiness SET expires_at=1 "
                "WHERE edge_id='src1'"
            )
        self.assert_hold("F4_CURRENT_ACCEPTANCE_REQUIRED")

    def test_source_ssh_dns_or_default_identity_drift(self):
        with self.fx.db() as db:
            db.execute("UPDATE ssh_accounts SET host=?",(TARGET,))
        self.assert_hold("ACTIVE_SSH_INGRESS_NOT_PINNED")
        with self.fx.db() as db:
            db.execute(
                "UPDATE settings SET value=? WHERE key='dns_current_ip'",
                (TARGET,),
            )
        self.assert_hold("PUBLIC_DNS_SOURCE_NOT_PINNED")

    def test_unpinned_route_or_wireguard_allocation_blocks(self):
        with self.fx.db() as db:
            db.execute(
                "UPDATE edge_egress_allocations SET veth_network=? "
                "WHERE edge_id='src1'",
                ("10.79.200.0/30",),
            )
        self.assert_hold("ROOT_MANIFEST_F3_UID_ROUTE_MISMATCH")

    def test_corrupt_mapping_and_unrostered_intent_hold(self):
        with self.fx.db() as db:
            db.execute(
                "UPDATE edge_egress_uid_bindings SET edge_id='other' "
                "WHERE username='nvl0557'"
            )
        self.assert_hold("PROTECTED_UID_MAPPING_NOT_CURRENT")
        with self.fx.db() as db:
            db.execute(
                "UPDATE edge_egress_uid_bindings SET edge_id='src1' "
                "WHERE username='nvl0557'"
            )
            db.execute(
                "INSERT INTO edge_egress_uid_runtime"
                "(username,uid,edge_id,edge_ipv4,route_table,priority,"
                "dns_port,state,last_operation_id)"
                " VALUES('orphan',1650,'src1',?,1780,1888,10661,'HOLD',88)",
                (SOURCE,),
            )
        self.assert_hold("UNROSTERED_PROTECTED_INTENT")

    def test_running_shared_6g_blocks_pam_and_host_witness(self):
        with self.fx.db() as db:
            db.execute(
                "INSERT INTO failover_operations "
                "(source_host,target_host,status,detail_json) "
                "VALUES(?,?,'RUNNING','{}')",(SOURCE,TARGET),
            )
        self.assert_hold("SHARED_6G_BUSY")
        self.assert_hold("V1_PAM_PROTECTED_ADMISSION_DENIED")

    def test_roster_mismatch_cannot_be_legacy(self):
        self.assert_hold("HOST_EVIDENCE_UNAVAILABLE",
                         roster_loader=lambda:{})
        self.assert_hold("HOST_EVIDENCE_UNAVAILABLE",
                         guard_loader=lambda _:None)

    def test_untrusted_global_mode_is_hold(self):
        with self.fx.db() as db:
            db.execute("UPDATE settings SET value='9' "
                       "WHERE key='edge_egress_protected_mode'")
        self.assert_hold("GLOBAL_PROTECTED_MODE_INVALID")

    def test_false_identity_and_nonpublic_ip_rejected_before_probes(self):
        for kw in (
            {"username":"root"}, {"username":"bad;sh"},
            {"edge_id":"../unsafe"}, {"expected_edge":"10.0.0.1"},
            {"ingress_source":"127.0.0.1"},
            {"gate_digest_verified":1},
        ):
            with self.subTest(kw=kw),self.assertRaises(ValueError):
                self.review(**kw)

    def test_v1_fixed_module_no_path_override_or_malformed_digest(self):
        self.assertFalse(trusted_v1_gate_sha("z"*64))
        self.assertFalse(trusted_v1_gate_sha("a"*64,
                          path=__import__("pathlib").Path("/tmp/fake.py")))

    def test_cli_unprivileged_rejected_before_any_host_subprocess(self):
        out=io.StringIO()
        with patch("ops.k2_p3_host_readonly.os.geteuid",return_value=1000),\
             patch("ops.k2_p3_host_readonly.subprocess.run") as run,\
             redirect_stdout(out):
            result=main([
                "--username","nvl0557","--edge-id","src1",
                "--ingress-source",SOURCE,"--edge-ip",SOURCE,
                "--pam-rhost","10.77.0.8",
                "--ssh-local-addr","10.77.0.1",
                "--ssh-local-port","2252",
                "--reviewed-v1-gate-sha256","a"*64,
            ])
        self.assertEqual(result,2)
        run.assert_not_called()
        payload=json.loads(out.getvalue())
        self.assertEqual(payload["status"],"HOLD")
        self.assertFalse(payload["customer_ready"])
        self.assertFalse(payload["changes"])
        self.assertFalse(payload["packet_no_core_leak_proven"])


if __name__=="__main__":
    unittest.main()
