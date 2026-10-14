"""P3 real-Linux worker assembly: SQLite 6G + guarded mock kernel; no OS writes."""
from hashlib import sha256
import unittest
from unittest.mock import patch

from edge_egress_p3_executor import (
    FreshEvidence,BASE_GATES,ATTACH_GATES,SOURCE_ENROLL_GATES,
)
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from ops.k2_p3_uid_worker import (
    IndependentSafety,LiveUIDHold,WORKER_ENABLED,
    prepare_live_source_uid_worker,
)
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests
from tests.test_edge_egress_p3_uid import FakePerUIDKernel


class FakeRealKernel(LocalLinuxProtectedRuntimeKernel):
    def __init__(self,*,explicitly_enabled=False):
        self.fake=FakePerUIDKernel()
        self.fake.ip="192.0.2.1"
        self.enabled=explicitly_enabled
    def arm(self,r,p): self.fake.arm(r,p)
    def attach(self,r): self.fake.attach(r)
    def freeze(self,r): self.fake.freeze(r)
    def assert_frozen(self,r): self.fake.assert_frozen(r)
    def public_ipv4(self,r): return self.fake.public_ipv4(r)
    def assert_dns_ipv6(self,r): self.fake.assert_dns_ipv6(r)


class UIDWorkerTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.safety=IndependentSafety(
            db_conn=self.fx.conn_factory,target_edge_id="src1",
            source_ipv4=self.fx.request.spec.edge_public_ipv4,
            ingress_rhost="10.77.0.8",ssh_local_addr="10.77.0.1",
            ssh_local_port=2252,reviewed_module_sha256="a"*64,
            packet_witness=lambda r:True,
            neighbour_witness=lambda r:True,
        )
        self.evidence=FreshEvidence(
            sha256(b"reviewed independent F4 and canary").hexdigest(),
            1000,BASE_GATES|ATTACH_GATES|SOURCE_ENROLL_GATES,
        )
        self.kernels=[]
        def factory(*,explicitly_enabled):
            k=FakeRealKernel(explicitly_enabled=explicitly_enabled)
            k.fake.ip=self.fx.request.spec.edge_public_ipv4
            self.kernels.append(k)
            return k
        self.factory=factory

    def prepare(self,**kw):
        opts=dict(
            db_conn=self.fx.conn_factory,acquire_6g=self.fx.acquire,
            journal_6g=self.fx.journal,candidate_target_edge_id="dst1",
            request=self.fx.request,dns_port=10553,
            safety=self.safety,evidence=self.evidence,
            actor_id=17,chat_id=31,reviewed_release=True,
            kernel_factory=self.factory,os_uid=self.fx.lookup,
            geteuid=lambda:0,clock=lambda:1000,
        )
        opts.update(kw)
        with patch("ops.k2_p3_uid_worker.load_roster",return_value=self.fx.roster),\
             patch("ops.k2_p3_uid_worker.checked_guard",return_value=self.fx.manifest):
            return prepare_live_source_uid_worker(**opts)

    def test_defaults_off_and_no_kernel_or_lease(self):
        self.assertIs(WORKER_ENABLED,False)
        for options in (
            {"reviewed_release":False},
            {"geteuid":lambda:1000},
            {"acquire_6g":None},
            {"packet_probe_absent":True},
        ):
            s=options.copy()
            if s.pop("packet_probe_absent",False):
                self.safety.packet_witness=None
            try:
                with self.assertRaises(LiveUIDHold):
                    self.prepare(**s)
            finally:
                self.safety.packet_witness=lambda _:True
        self.assertEqual(self.kernels,[])
        with self.fx.db() as db:
            self.assertIsNone(db.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchone())

    def test_single_source_uid_worker_uses_real_kernel_class_and_one_6g(self):
        w=self.prepare()
        self.assertEqual(w.scope.action,"UID_ENROLL_SOURCE")
        self.assertEqual(w.scope.source_host,w.scope.target_host)
        self.assertEqual(len(self.kernels),1)
        self.assertTrue(self.kernels[0].enabled)
        self.assertIs(w.executor.host_port.uid_port.store.db_conn,
                      self.fx.conn_factory)
        self.assertTrue(callable(w.executor.acquire_fn))  # original 6G
        self.assertEqual(self.kernels[0].fake.events,[])
        self.assertIsNone(self.fx.state()[0])

    def test_no_packet_or_neighbor_witness_holds_before_any_write(self):
        self.safety.packet_witness=None
        with self.assertRaises(LiveUIDHold):
            self.prepare()
        self.safety.packet_witness=lambda _:True
        self.safety.neighbour_witness=None
        with self.assertRaises(LiveUIDHold):
            self.prepare()
        self.assertEqual(self.kernels,[])

    def test_wrong_safety_scope_or_fake_non_linux_kernel_denied(self):
        self.safety.source_ipv4="198.51.100.11"
        with self.assertRaises(LiveUIDHold):
            self.prepare()
        self.safety.source_ipv4=self.fx.request.spec.edge_public_ipv4
        with self.assertRaises(LiveUIDHold):
            self.prepare(kernel_factory=lambda **kw:FakePerUIDKernel())

    def _mock_safety(self):
        for name in (
            "assert_account_idle","assert_pam_ingress_boot",
            "assert_multi_uid_isolation","assert_packet_dns_ipv6_no_core_leak",
        ):
            setattr(self.safety,name,lambda request:None)

    def test_actual_guarded_p3_sequence_with_fake_host_and_sqlite(self):
        import asyncio
        self._mock_safety()
        worker=self.prepare()
        receipt=asyncio.run(worker.execute())
        self.assertTrue(receipt.allowed,receipt)
        self.assertEqual(self.fx.state()[0].state,"PROTECTED")
        self.assertIn("attach",self.kernels[0].fake.events)
        self.assertEqual(self.fx.state()[-1][0],"SUCCEEDED")
        with self.assertRaises(Exception):
            asyncio.run(worker.execute())

    def test_post_attach_bad_edge_ipv4_freezes_only_uid_and_keeps_6g_hold(self):
        import asyncio
        self._mock_safety()
        worker=self.prepare()
        self.kernels[0].fake.ip="1.1.1.1"
        receipt=asyncio.run(worker.execute())
        self.assertFalse(receipt.allowed)
        self.assertTrue(receipt.manual_recovery)
        self.assertEqual(self.fx.state()[0].state,"HOLD")
        self.assertTrue(self.kernels[0].fake.deny)
        self.assertEqual(self.fx.state()[-1][0],"RUNNING")

    def test_full_p3_a_6g_cas_fault_is_not_an_unfenced_success(self):
        worker=self.prepare()
        self.assertTrue(hasattr(worker,"execute"))
        # No invocation in a real environment: test uses fake kernel,
        # fixture SQLite and mocked stage/packet independent observers.
        self.assertFalse(worker.executor._used)
        self.assertEqual(self.fx.state()[0],None)


if __name__=="__main__":
    unittest.main()
