"""Pinned Edge preparation: existing 6G and dedicated boot artifacts only."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from edge_egress_k2_core_edge_operations import prepare_edge
from edge_egress_p3_executor import ExecutionScope,ExecutionTicket,INTENT_PHASE,_scope_digest
from hashlib import sha256
import ops.edge_egress_v1_transport as transport
from edge_egress_k2_p1_worker import probe_phase1
from tests.test_edge_egress_k2_core_operations import CoreFixture,SOURCE,TARGET,NOW


class NativeEdgePreparationTests(CoreFixture):
    def test_existing_phase1_uses_original_callbacks_without_missing_finished_argument(self):
        self.root.observations._qualification=Mock()
        pin=SimpleNamespace(core_ipv4='209.200.246.198',edge_ipv4=TARGET)
        with self.db() as db:db.execute("DELETE FROM edge_egress_allocations WHERE edge_id='e9'")
        def activate(edge_id,*,db_conn,acquire,journal,register_f3):
            self.assertTrue(callable(register_f3))
            op,_=acquire(SOURCE,TARGET)
            journal(op,status='RUNNING',detail={'kind':'K2_P1','phase':'EGRESS_P1_ACTIVATE_INTENT'})
            journal(op,status='SUCCEEDED',detail={'kind':'K2_P1','phase':'EGRESS_P1_TRANSPORT_PROVEN'},finished=True)
            return {'observed_ipv4':TARGET,'customer_ready':False}
        with patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=pin),\
             patch('edge_egress_k2_p1_worker.activate_phase1',side_effect=activate):
            result=prepare_edge(self.root,'e9',actor_id=11,chat_id=11)
        self.assertFalse(result['customer_ready'])
        with self.db() as db:
            self.assertEqual(db.execute('SELECT status FROM failover_operations').fetchall(),[('SUCCEEDED',)])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM edge_egress_uid_runtime').fetchone(),(0,))

    def test_in_lease_transport_measurement_accepts_only_exact_uid_nonce(self):
        scope=ExecutionScope('UID_ATTACH','e9',SOURCE,TARGET,'nvl0555',1636)
        ticket=ExecutionTicket(11,11,'a'*32,NOW+60,_scope_digest(scope),'b'*64)
        op,_=self.callbacks.acquire(SOURCE,TARGET)
        self.callbacks.journal(op,status='RUNNING',finished=False,require_running=True,
            detail=dict(kind='K2_P3A',phase=INTENT_PHASE,scope_digest=_scope_digest(scope),
                        nonce_hash=sha256(ticket.nonce.encode()).hexdigest()))
        pin=SimpleNamespace(edge_id='e9',edge_ipv4=TARGET,core_sha='c'*64)
        spec=SimpleNamespace(edge_id='e9')
        with patch('edge_egress_k2_p1_worker._check_stage',return_value=(spec,'peer',Path('/unused'))),\
             patch('edge_egress_k2_p1_worker.observe',return_value='UP'):
            kwargs=dict(db_conn=self.db,load_pin=lambda eid:pin,
                remote_transport=lambda p,a:'UP',ipv4_proof=lambda s:TARGET)
            with self.assertRaisesRegex(ValueError,'SHARED_6G_BUSY'):
                probe_phase1('e9',**kwargs)
            self.assertEqual(probe_phase1('e9',uid_intent=(scope,ticket),**kwargs)['observed_ipv4'],TARGET)
            wrong=ExecutionTicket(11,11,'d'*32,NOW+60,_scope_digest(scope),'b'*64)
            with self.assertRaises(ValueError):probe_phase1('e9',uid_intent=(scope,wrong),**kwargs)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT status FROM failover_operations').fetchall(),[('RUNNING',)])


class DedicatedPersistenceTests(unittest.TestCase):
    def setUp(self):
        work=tempfile.TemporaryDirectory();self.addCleanup(work.cleanup)
        self.units=Path(work.name)
        self.stage=Path('/root/nvl-egress-v1/core-e9')
        self.spec=SimpleNamespace(edge_id='e9')
        self.unit='nvl-egress-transport-e9.service'
        def owned(info):
            fields=list(info);fields[4]=0;return os.stat_result(fields)
        lstat,fstat=Path.lstat,os.fstat
        for setting in (
            patch.object(transport,'UNIT_ROOT',self.units),
            patch.object(transport,'pinned',return_value=(self.spec,'peer')),
            patch.object(transport,'render_unit',return_value='[Service]\nExecStart=/fixed/pinned\n'),
            patch.object(Path,'lstat',new=lambda path:owned(lstat(path))),
            patch('os.fstat',side_effect=lambda fd:owned(fstat(fd))),
            patch('os.geteuid',return_value=0),
        ):
            setting.start();self.addCleanup(setting.stop)
        self.run=Mock(return_value=SimpleNamespace(returncode=0))
        setting=patch.object(transport.subprocess,'run',self.run);setting.start();self.addCleanup(setting.stop)

    def test_exact_persistent_unit_is_reused_and_only_that_unit_is_enabled(self):
        guard=Mock()
        transport.install_persistence(self.stage,'core','a'*64,guard=guard)
        before=(self.units/self.unit).read_bytes()
        transport.install_persistence(self.stage,'core','a'*64,guard=guard)
        self.assertEqual((self.units/self.unit).read_bytes(),before)
        commands=[c.args[0] for c in self.run.call_args_list]
        self.assertIn(['systemctl','enable','--now',self.unit],commands)
        self.assertFalse(any('ssh.service' in cmd or 'wg0' in cmd for cmd in commands))
        self.assertGreater(guard.call_count,len(commands))

    def test_unknown_existing_unit_or_lost_6g_guard_cannot_be_overwritten(self):
        path=self.units/self.unit;path.write_bytes(b'foreign unit\n')
        with self.assertRaisesRegex(ValueError,'DRIFT'):
            transport.install_persistence(self.stage,'core','a'*64,guard=lambda:None)
        self.run.assert_not_called()
        self.assertEqual(path.read_bytes(),b'foreign unit\n')
        path.unlink()
        with self.assertRaisesRegex(ValueError,'lease lost'):
            transport.install_persistence(self.stage,'core','a'*64,guard=Mock(side_effect=ValueError('lease lost')))
        self.assertFalse(path.exists())


if __name__=='__main__':unittest.main()
