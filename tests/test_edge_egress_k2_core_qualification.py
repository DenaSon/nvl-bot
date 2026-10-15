"""The existing F2 store admits a release-qualified trial, never fake READY."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from edge_egress_k2_core_observer import CorePhysicalObservations
from edge_egress_uid_runtime_store import RuntimeStoreUnsafe
from tests import test_edge_egress_uid_runtime_store as store_fixture
from tests.test_edge_egress_uid_runtime_store import req,SOURCE,TARGET


class NativeStoreQualificationTests(unittest.TestCase):
    def setUp(self):
        self.fx=store_fixture.StoreTests();self.fx.setUp();self.addCleanup(self.fx.tearDown)
        with self.fx.conn() as db:db.execute("UPDATE edge_egress_readiness SET state='STAGED'")
        self.observer=CorePhysicalObservations(db_conn=self.fx.conn,host=object(),
            qualification_sha256='a'*64,release_sha='b'*40)
        self.observer.qualify_target=Mock(return_value=(SimpleNamespace(edge_ipv4=TARGET),'a'*64))

    def test_typed_native_collector_reaches_original_f2_reserve_without_promoting_readiness(self):
        self.fx.store.qualified_target=self.observer.target_qualified
        with patch('edge_egress_k2_core_operations.CORE_OPERATIONS_ENABLED',True):
            row=self.fx.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)
        self.assertEqual(row.state,'BLOCKED')
        with self.fx.conn() as db:
            self.assertEqual(db.execute('SELECT state FROM edge_egress_readiness').fetchone(),('STAGED',))

    def test_default_off_and_generic_true_callback_cannot_bypass_f4(self):
        self.fx.store.qualified_target=self.observer.target_qualified
        with self.assertRaisesRegex(RuntimeStoreUnsafe,'F4_PRODUCTION'):
            self.fx.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)
        with patch('edge_egress_k2_core_operations.CORE_OPERATIONS_ENABLED',True):
            self.fx.store.qualified_target=lambda r:True
            with self.assertRaisesRegex(RuntimeStoreUnsafe,'F4_PRODUCTION'):
                self.fx.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)

    def test_wrong_target_ip_cannot_use_a_qualification_for_another_edge(self):
        self.observer.qualify_target.return_value=(SimpleNamespace(edge_ipv4=SOURCE),'a'*64)
        self.fx.store.qualified_target=self.observer.target_qualified
        with patch('edge_egress_k2_core_operations.CORE_OPERATIONS_ENABLED',True):
            with self.assertRaisesRegex(RuntimeStoreUnsafe,'F4_PRODUCTION'):
                self.fx.store.reserve_blocked(42,req(),source=SOURCE,dns_port=10553)


if __name__=='__main__':unittest.main()
