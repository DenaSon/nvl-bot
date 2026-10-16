"""Fixed probe commands and trust boundaries; synthetic SSH/packet fixtures."""
import ast
from contextlib import nullcontext
from dataclasses import replace
import base64
from hashlib import sha256
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

import edge_egress_k2_core_observer as observer
from edge_egress_p3_executor import ExecutionScope,INTENT_PHASE,_scope_digest
from tests import test_edge_egress_k2_core_operations as fixture
from edge_egress_f4_release import ACCEPTANCE_PROBES


class AutomaticObservationTests(fixture.CoreFixture):
    def setUp(self):
        super().setUp()
        from contextlib import nullcontext
        p=patch('edge_egress_k2_m2_ingress_journal.serialized_root_journal',side_effect=nullcontext)
        p.start();self.addCleanup(p.stop)
        p=patch('edge_egress_k2_m2_ingress_journal.create_root_journal_if_absent')
        p.start();self.addCleanup(p.stop)
        p=patch('edge_egress_k2_runtime_release.load_core_profile',return_value=SimpleNamespace(
            enabled=True,operations_enabled=True,field_acceptance_sha256='a'*64))
        p.start();self.addCleanup(p.stop)
    def make(self):
        host=SimpleNamespace(now=lambda:self.now,os_uid=lambda n:self.names[n],local_idle=lambda n,u:True)
        return observer.CorePhysicalObservations(db_conn=self.db,host=host,
            qualification_sha256='a'*64,release_sha='b'*40)

    def test_release_qualification_is_sha_and_release_bound(self):
        evidence=dict(version=1,edge_id='e9',username='nvl0555',uid=1636,
            core_ipv4='209.200.246.198',edge_ipv4=fixture.TARGET,environment='disposable-vps',
            observed_edge_ipv4=fixture.TARGET,observed_at=self.now-90000,
            probe_results={c:True for c in ACCEPTANCE_PROBES},run_id='fixture-qualification-001')
        raw=json.dumps({'release_sha':'b'*40,'evidence':evidence}).encode()
        runner=self.make();runner.qualification_sha256=sha256(raw).hexdigest()
        with patch.object(observer,'_root_bytes',return_value=raw):
            runner._qualification('209.200.246.198')
            runner.release_sha='c'*40
            with self.assertRaisesRegex(ValueError,'RELEASE_MISMATCH'):
                runner._qualification('209.200.246.198')
        evidence['probe_results']['boot_deny_before_ssh']=False
        raw=json.dumps({'release_sha':'b'*40,'evidence':evidence}).encode()
        runner.release_sha='b'*40;runner.qualification_sha256=sha256(raw).hexdigest()
        with patch.object(observer,'_root_bytes',return_value=raw):
            with self.assertRaisesRegex(ValueError,'QUALIFICATION_REQUIRED'):
                runner._qualification('209.200.246.198')

    def test_pre_attach_measures_and_never_promotes_staged_edge(self):
        runner=self.make()
        pin=SimpleNamespace(core_ipv4='209.200.246.198',edge_id='e9',edge_ipv4=fixture.TARGET,
                            core_sha='c'*64,edge_sha='d'*64,ssh_host_key='fixture')
        selected=fixture.select_migration('SINGLE',('nvl0555',),'e9')
        with patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=pin),\
             patch('edge_egress_k2_p1_worker.probe_phase1',return_value={'observed_ipv4':fixture.TARGET}) as probe,\
             patch.object(observer,'root_fresh_source_evidence',return_value=lambda n:SimpleNamespace(edge_id='s8',edge_ipv4=fixture.SOURCE)),\
             patch.object(runner,'_qualification'),patch.object(runner,'_neighbours',return_value=()):
            with patch('edge_egress_k2_core_observer.time.time',return_value=self.now):
                proof=runner.pre(selected)
                runner.pre(selected)
                self.assertEqual(probe.call_count,1)
                self.assertEqual(proof.phase,'PRE_ATTACH')
                with self.db() as db:db.execute("UPDATE edge_egress_readiness SET state='STAGED'")
                self.assertEqual(runner.pre(selected).checks,observer.CORE_PRE_CHECKS)
                with self.db() as db:
                    self.assertEqual(db.execute('SELECT state FROM edge_egress_readiness').fetchone(),('STAGED',))
                    db.execute("UPDATE edge_egress_readiness SET state='REVOKED'")
                with self.assertRaisesRegex(ValueError,'REQUIRES_REPAIR'):
                    runner.pre(selected)

    def test_pre_attach_does_not_guess_zero_sessions(self):
        runner=self.make();runner.host.local_idle=lambda n,u:False
        pin=SimpleNamespace(core_ipv4='209.200.246.198',edge_id='e9',edge_ipv4=fixture.TARGET,
                            core_sha='c'*64,edge_sha='d'*64,ssh_host_key='fixture')
        with patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=pin),\
             patch('edge_egress_k2_p1_worker.probe_phase1',return_value={'observed_ipv4':fixture.TARGET}),\
             patch.object(observer,'root_fresh_source_evidence',return_value=lambda n:SimpleNamespace(edge_id='s8',edge_ipv4=fixture.SOURCE)),\
             patch.object(runner,'_qualification'),patch.object(runner,'_neighbours',return_value=()),\
             patch('time.time',return_value=self.now):
            with self.assertRaisesRegex(ValueError,'ACTIVE_SESSIONS'):
                runner.pre(fixture.select_migration('SINGLE',('nvl0555',),'e9'))

    def test_native_staged_target_uses_release_qualification_without_faking_f4_ready(self):
        runner=self.make()
        self.root.observations=runner
        self.root.ports=replace(self.root.ports,external_evidence=runner.current)
        pin=SimpleNamespace(core_ipv4='209.200.246.198',edge_id='e9',edge_ipv4=fixture.TARGET,
                            core_sha='c'*64,edge_sha='d'*64,ssh_host_key='fixture')
        with self.db() as db:db.execute("UPDATE edge_egress_readiness SET state='STAGED'")
        with patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=pin),\
             patch('edge_egress_k2_p1_worker.probe_phase1',return_value={'observed_ipv4':fixture.TARGET}),\
             patch.object(observer,'root_fresh_source_evidence',return_value=lambda n:SimpleNamespace(
                 edge_id='s8',edge_ipv4=fixture.SOURCE)),\
             patch.object(runner,'_qualification'),patch.object(runner,'_neighbours',return_value=()):
            inventory=self.root.review(fixture.select_migration('SINGLE',('nvl0555',),'e9'))
            self.assertFalse(inventory.target_f4_accepted)
            self.assertTrue(inventory.target_accepted)
            self.assertEqual(inventory.global_issues,())
            self.assertEqual(len(inventory.target_qualification_digest),64)
            with self.db() as db:
                self.assertEqual(db.execute('SELECT state FROM edge_egress_readiness').fetchone(),('STAGED',))

    def test_native_operation_profile_revocation_prevents_even_transport_measurement(self):
        runner=self.make()
        with patch('edge_egress_k2_runtime_release.load_core_profile',return_value=SimpleNamespace(
            enabled=True,operations_enabled=False,field_acceptance_sha256='a'*64)),\
             patch('edge_egress_k2_p1_worker.load_stage_pin') as pin:
            with self.assertRaisesRegex(ValueError,'REVOKED'):
                runner.qualify_target('e9')
            pin.assert_not_called()

    def post_fixture(self,phase,leak=False):
        self.protect(edge='e9',ip=fixture.TARGET)
        scope=ExecutionScope('UID_ATTACH','e9',fixture.SOURCE,fixture.TARGET,'nvl0555',1636)
        ticket=fixture.ExecutionTicket(11,11,'d'*32,NOW+60,_scope_digest(scope),'a'*64)
        op,_=self.callbacks.acquire(fixture.SOURCE,fixture.TARGET)
        self.callbacks.journal(op,status='RUNNING',finished=False,require_running=True,
            detail={'kind':'K2_P3A','phase':INTENT_PHASE,'action':scope.action,'edge_id':scope.edge_id,
                'scope_digest':_scope_digest(scope),'nonce_hash':sha256(ticket.nonce.encode()).hexdigest()})
        with self.db() as db:
            db.execute('UPDATE edge_egress_uid_runtime SET last_operation_id=?,state=?',
                (op,'ROUTED_UNVERIFIED' if phase=='UID_ROUTE' else 'PROTECTED'))
        runner=self.make();runner.client=Mock(return_value=fixture.TARGET)
        manifest=SimpleNamespace(request=SimpleNamespace(username=scope.username,uid=scope.uid,
            priority=11636,spec=SimpleNamespace(edge_id=scope.edge_id,
                edge_public_ipv4=scope.target_host,route_table=20008)),dns_port=41636)
        class Capture:
            def __init__(self,argv,**kw):
                Path(argv[argv.index('-w')+1]).write_bytes(b'fixture-capture')
                self.stderr=io.StringIO('tcpdump: listening on eth0\n');self.returncode=None
            def send_signal(self,s):self.returncode=0
            def communicate(self,**kw):return '', '0 packets dropped by kernel\n'
            def poll(self):return self.returncode
        def command(argv,**kw):
            if argv[:3]==['ip','-j','-4']:return '[{"dev":"eth0"}]'
            if argv[0]=='runuser':return json.dumps({c:True for c in ('dns_udp','dns_tcp','nss','ipv6')})
            if argv[:2]==['tcpdump','-nn']:return '203.0.113.1 > 1.1.1.1: packet' if leak else ''
            raise AssertionError(argv)
        patches=(patch.object(observer,'checked',side_effect=command),
            patch.object(observer,'_root_bytes',return_value=b'hosts: files dns\n'),
            patch('edge_egress_v1_admission.load_roster',return_value={'nvl0555':object()}),
            patch('edge_egress_v1_admission.checked_guard',return_value=manifest),
            patch('edge_egress_uid_runtime_kernel.LocalLinuxProtectedRuntimeKernel',
                return_value=SimpleNamespace(assert_dns_ipv6=lambda r:None,public_ipv4=lambda r:fixture.TARGET)),
            patch.object(observer.subprocess,'Popen',Capture),
            patch('select.select',side_effect=lambda r,w,e,t:(r,[],[])),
            patch.object(observer,'root_fresh_source_evidence',return_value=lambda n:SimpleNamespace(edge_id='s8',edge_ipv4=fixture.SOURCE)),
            patch.object(runner,'_neighbours',return_value=()))
        for p in patches:p.start();self.addCleanup(p.stop)
        return runner,scope,ticket

    def test_uid_stage_runs_before_external_ssh_and_binds_nonce(self):
        runner,scope,ticket=self.post_fixture('UID_ROUTE')
        proof=runner.post(scope,ticket,phase='UID_ROUTE')
        self.assertEqual(proof.nonce_hash,sha256(ticket.nonce.encode()).hexdigest())
        runner.client.assert_not_called()

    def test_post_attach_requires_real_external_client_result(self):
        runner,scope,ticket=self.post_fixture('POST_ATTACH')
        proof=runner.post(scope,ticket,phase='POST_ATTACH')
        runner.client.assert_called_once_with(scope,ticket)
        self.assertEqual(proof.observed_public_ipv4,fixture.TARGET)

    def test_packet_leak_cannot_produce_a_success_envelope(self):
        runner,scope,ticket=self.post_fixture('UID_ROUTE',leak=True)
        with self.assertRaisesRegex(ValueError,'PACKET_LEAK'):
            runner.post(scope,ticket,phase='UID_ROUTE')

    def test_wrong_runtime_phase_fails_before_any_packet_or_ssh_command(self):
        runner,scope,ticket=self.post_fixture('UID_ROUTE')
        with self.assertRaisesRegex(ValueError,'RUNTIME_DRIFT'):
            runner.post(scope,ticket,phase='POST_ATTACH')
        runner.client.assert_not_called()

    def test_probe_programs_compile_and_do_not_pass_password_as_argv(self):
        compile(observer._UID_DNS_PROBE,'uid-probe','exec')
        compile('REQUEST={}\n'+observer._REMOTE_CLIENT,'external-client','exec')
        self.assertIn("NVL_PROBE_PASSWORD",observer._REMOTE_CLIENT)
        tree=ast.parse(observer._REMOTE_CLIENT)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)
               and isinstance(n.func,ast.Attribute) and n.func.attr=='Popen']
        self.assertEqual(len(calls),1)
        self.assertFalse(any(isinstance(n,ast.Subscript) and isinstance(n.slice,ast.Constant)
            and n.slice.value=='password' for n in ast.walk(calls[0].args[0])))

    def test_same_ingress_probe_uses_public_relay_roundtrip_instead_of_local_edge_dnat(self):
        request=dict(username='nvl0555',password='fixture-secret-only',source_ipv4=fixture.TARGET,
            port=2252,core_host_key='ssh-ed25519 fixture',challenge='d'*64,
            scope_digest='b'*64,operation_id=7,mode='POST_ATTACH',target_ipv4=fixture.TARGET)
        response=json.dumps({k:v for k,v in request.items() if k in ('challenge','scope_digest','operation_id')}
                            |{'observed_ipv4':fixture.TARGET})
        client=observer.PinnedEdgeClientProbe(self.db)
        with patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=SimpleNamespace(edge_ipv4=fixture.TARGET)),\
             patch.object(observer.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=response)) as run,\
             patch('edge_egress_v1_live_driver.RemotePinnedEdge._ssh') as ssh:
            self.assertEqual(client._run('e9',request),fixture.TARGET)
            self.assertEqual(run.call_args.args[0],['python3','-'])
            self.assertIn('fixture-secret-only',run.call_args.kwargs['input'])
            ssh.assert_not_called()
        self.assertEqual(request,{})

    def test_client_report_cannot_reuse_another_challenge_or_scope(self):
        req=dict(challenge='a'*64,scope_digest='b'*64,operation_id=2,
                 mode='POST_ATTACH',target_ipv4=fixture.TARGET)
        for change in ({'challenge':'c'*64},{'operation_id':1},{'observed_ipv4':'209.200.246.198'}):
            raw=json.dumps({k:req[k] for k in ('challenge','scope_digest','operation_id')}
                           |{'observed_ipv4':fixture.TARGET}|change)
            with self.assertRaises(ValueError):observer.PinnedEdgeClientProbe._result(req,raw)


class AuthenticatedSourceRefreshTests(fixture.CoreFixture):
    def setUp(self):
        super().setUp()
        from edge_egress_v1_ingress import IngressPeer
        from edge_egress_k2_m2_ingress_journal import encode_records
        self.raw=encode_records({})
        self.peer=IngressPeer('s8',fixture.SOURCE,'10.77.0.8',base64.b64encode(bytes(range(32))).decode())
        with self.db() as db:db.execute('UPDATE ssh_accounts SET host=? WHERE username=?',(fixture.SOURCE,'nvl0555'))
        self.client=observer.PinnedEdgeClientProbe(self.db)
        self.client._request=Mock(return_value={'username':'nvl0555'})
        self.client._run=Mock(return_value='209.200.246.198')
        def cas(before,after):
            self.assertEqual(before,self.raw);self.raw=after
        settings=(
            patch.object(observer.os,'geteuid',return_value=0),
            patch('edge_egress_k2_m2_ingress_journal.serialized_root_journal',side_effect=nullcontext),
            patch('edge_egress_k2_m2_ingress_journal.create_root_journal_if_absent',side_effect=lambda:self.raw),
            patch('edge_egress_k2_m2_ingress_journal.compare_and_swap_root_journal',side_effect=cas),
            patch('edge_egress_v1_ingress.load_registry',return_value=(self.peer,)),
            patch.object(observer,'checked',return_value=self.peer.wg_public_key+' 10.77.0.8/32\n'),
            patch('pwd.getpwnam',side_effect=lambda n:SimpleNamespace(pw_uid=self.names[n])),
            patch('time.time',return_value=self.now),
        )
        for p in settings:p.start();self.addCleanup(p.stop)

    def test_offline_source_is_written_only_after_real_authenticated_probe(self):
        from edge_egress_k2_m2_ingress_journal import _validated
        proof=self.client.refresh_source('nvl0555','e9')
        self.assertEqual(proof.edge_ipv4,fixture.SOURCE)
        self.assertEqual(_validated(self.raw)['nvl0555'].wg_public_key,self.peer.wg_public_key)
        self.client._run.assert_called_once()

    def test_historical_host_with_failed_authentication_cannot_become_source_evidence(self):
        before=self.raw
        self.client._run.side_effect=observer.CoreObservationHold('CLIENT_MEASUREMENT_FAILED')
        with self.assertRaises(ValueError):self.client.refresh_source('nvl0555','e9')
        self.assertEqual(self.raw,before)

    def test_wireguard_key_loss_after_authenticated_probe_cannot_publish_source(self):
        before=self.raw
        with patch.object(observer,'checked',side_effect=[self.peer.wg_public_key+' 10.77.0.8/32\n','']):
            with self.assertRaisesRegex(ValueError,'OWNERSHIP_CHANGED'):
                self.client.refresh_source('nvl0555','e9')
        self.assertEqual(self.raw,before)

    def test_unregistered_connection_hint_cannot_trigger_a_customer_login(self):
        with self.db() as db:db.execute("UPDATE ssh_accounts SET host='216.126.229.12' WHERE username='nvl0555'")
        with self.assertRaisesRegex(ValueError,'RECONNECT_TO_KNOWN_EDGE'):
            self.client.refresh_source('nvl0555','e9')
        self.client._run.assert_not_called()


NOW=fixture.NOW
if __name__=='__main__':unittest.main()
