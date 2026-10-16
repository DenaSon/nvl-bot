"""Automatic legacy ingress discovery uses authenticated Core evidence.

The real SQLite/source/journal/registry flow is exercised with synthetic
WireGuard, SSH and journald I/O. These are not live server acceptance tests.
"""
from contextlib import nullcontext
from dataclasses import replace
import base64
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import edge_egress_k2_core_observer as observer
import edge_egress_v1_onboarding as onboarding
from edge_egress_v1_ingress import IngressPeer, render_registry, parse_registry
from edge_egress_k2_m2_ingress_journal import encode_records, _validated
from tests.test_edge_egress_k2_core_operations import CoreFixture, SOURCE


class LegacyDiscoveryTests(CoreFixture):
    def setUp(self):
        super().setUp()
        self.peer=IngressPeer('e8',SOURCE,'10.77.0.8',base64.b64encode(bytes(range(32))).decode())
        self.target=IngressPeer('e12','144.172.84.112','10.77.0.12',
                               base64.b64encode(b't'*32).decode())
        self.peers=(self.target,)
        self.raw=encode_records({})
        self.boot='f'*32
        self.client=observer.PinnedEdgeClientProbe(self.db)
        self.client._request=Mock(return_value={'username':'nvl0555'})
        self.client._run=Mock(return_value='209.200.246.198')
        self.accept_rhost=self.peer.ingress_ipv4
        self.accepted_uid='0'
        self.accepted_exe='/usr/sbin/sshd'
        self.after_auth=0
        with self.db() as db:
            db.execute('ALTER TABLE host_pool ADD COLUMN service_port INTEGER')
            db.execute('UPDATE host_pool SET service_port=2252')
            db.execute('UPDATE ssh_accounts SET host=? WHERE username=?',(SOURCE,'nvl0555'))
            db.execute("DELETE FROM edge_egress_allocations WHERE edge_id='s8'")
        def cas(before,after):
            self.assertEqual(before,self.raw)
            self.raw=after
        def publish(peer,*,guard,allow_existing):
            guard()
            self.assertTrue(allow_existing)
            self.assertEqual(peer,self.peer)
            self.assertEqual(self.client._run.call_count,1)
            self.peers=self.peers+(peer,)
            guard()
        self.publish=Mock(side_effect=publish)
        patches=(
            patch.object(observer.os,'geteuid',return_value=0),
            patch('pwd.getpwnam',side_effect=lambda n:SimpleNamespace(pw_uid=self.names[n])),
            patch('time.time',return_value=self.now),
            patch.object(observer,'checked',side_effect=self.command),
            patch('edge_egress_v1_ingress.load_registry',side_effect=lambda:self.peers),
            patch('edge_egress_k2_m2_ingress_journal.serialized_root_journal',side_effect=nullcontext),
            patch('edge_egress_k2_m2_ingress_journal.create_root_journal_if_absent',side_effect=lambda:self.raw),
            patch('edge_egress_k2_m2_ingress_journal.compare_and_swap_root_journal',side_effect=cas),
            patch.object(onboarding,'_publish_registry',self.publish),
        )
        for item in patches:
            item.start();self.addCleanup(item.stop)

    def command(self,args,**kwargs):
        if args==['wg','show','wg0','endpoints']:
            return self.peer.wg_public_key+' '+SOURCE+':51820\n'
        if args==['wg','show','wg0','allowed-ips']:
            return self.peer.wg_public_key+' 10.77.0.8/32\n'
        if args[0]=='journalctl':
            if '--after-cursor' not in args:
                return json.dumps({'__CURSOR':'s=fixture;i=abc','_BOOT_ID':self.boot})
            self.after_auth+=1
            return json.dumps({'MESSAGE':'Accepted password for nvl0555 from '+self.accept_rhost+
                ' port 45321 ssh2','_UID':self.accepted_uid,'_BOOT_ID':self.boot,
                '_EXE':self.accepted_exe,'_PID':'456'})
        raise AssertionError(args)

    def test_old_edge_is_registered_by_the_original_review_without_manual_files(self):
        proof=self.client.refresh_source('nvl0555','e12')
        self.assertEqual(proof.edge_id,'e8')
        self.assertEqual(proof.edge_ipv4,SOURCE)
        self.assertEqual(self.peers,(self.target,self.peer))
        self.assertEqual(_validated(self.raw)['nvl0555'].ingress_ipv4,'10.77.0.8')
        self.assertEqual(self.publish.call_count,1)
        self.assertGreater(self.after_auth,0)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT * FROM edge_egress_uid_runtime').fetchall(),[])
            self.assertEqual(db.execute('SELECT * FROM failover_operations').fetchall(),[])
            self.assertEqual(db.execute('SELECT state FROM edge_egress_readiness').fetchall(),[('READY',)])
            self.assertEqual(db.execute('SELECT host FROM ssh_accounts WHERE username=?',
                                       ('nvl0555',)).fetchone(),(SOURCE,))

    def test_failed_authentication_cannot_publish_candidate_or_source(self):
        self.client._run.side_effect=observer.CoreObservationHold('CLIENT_MEASUREMENT_FAILED')
        before=self.raw
        with self.assertRaises(ValueError):self.client.refresh_source('nvl0555','e12')
        self.assertEqual(self.raw,before)
        self.publish.assert_not_called()

    def test_existing_allocated_source_identity_is_preserved_without_creating_an_alias(self):
        self.peer=replace(self.peer,edge_id='s8')
        with self.db() as db:
            db.execute("INSERT INTO edge_egress_allocations VALUES('s8',?,'STAGED',20008)",(SOURCE,))
        proof=self.client.refresh_source('nvl0555','e12')
        self.assertEqual(proof.edge_id,'s8')
        self.assertNotIn('e8',tuple(p.edge_id for p in self.peers))

    def test_duplicate_allocations_for_one_source_are_not_silently_adopted(self):
        with self.db() as db:
            db.execute("INSERT INTO edge_egress_allocations VALUES('s8',?,'STAGED',20008)",(SOURCE,))
            db.execute("INSERT INTO edge_egress_allocations VALUES('x8',?,'STAGED',20018)",(SOURCE,))
        with self.assertRaisesRegex(ValueError,'IDENTITY_CONFLICT'):
            self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()

    def test_real_core_peer_must_equal_the_candidate_not_the_historical_host(self):
        self.accept_rhost='10.77.0.12'
        with self.assertRaisesRegex(ValueError,'INGRESS_AMBIGUOUS'):
            self.client.refresh_source('nvl0555','e12')
        self.publish.assert_not_called()

    def test_unprivileged_or_wrong_executable_journal_records_cannot_attest_ingress(self):
        for uid,exe in (('1636','/usr/sbin/sshd'),('0','/usr/bin/logger')):
            self.accepted_uid,self.accepted_exe=uid,exe
            with self.subTest(uid=uid),self.assertRaisesRegex(ValueError,'INGRESS_AMBIGUOUS'):
                self.client.refresh_source('nvl0555','e12')
            self.publish.assert_not_called()

    def test_inactive_or_unpooled_hint_cannot_trigger_customer_login(self):
        with self.db() as db:db.execute('UPDATE host_pool SET active=0')
        with self.assertRaisesRegex(ValueError,'KNOWN_EDGE'):
            self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()

    def test_nonroot_process_cannot_discover_or_register_a_source(self):
        with patch.object(observer.os,'geteuid',return_value=1001):
            with self.assertRaisesRegex(ValueError,'ROOT_UID_REQUIRED'):
                self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()
        self.publish.assert_not_called()

    def test_wrong_live_wireguard_endpoint_cannot_trigger_login(self):
        original=self.command
        def wrong(args,**kw):
            return '' if args==['wg','show','wg0','endpoints'] else original(args,**kw)
        with patch.object(observer,'checked',side_effect=wrong):
            with self.assertRaisesRegex(ValueError,'PEER_UNVERIFIED'):
                self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()

    def test_key_or_endpoint_drift_after_authentication_prevents_registration(self):
        def drift(*args):
            self.peer=replace(self.peer,wg_public_key=base64.b64encode(b'x'*32).decode())
            return '209.200.246.198'
        self.client._run.side_effect=drift
        with self.assertRaisesRegex(ValueError,'OWNERSHIP_CHANGED|PEER_CHANGED'):
            self.client.refresh_source('nvl0555','e12')
        self.publish.assert_not_called()

    def test_missing_core_acceptance_holds_without_registering_anything(self):
        original=self.command
        def absent(args,**kw):
            return '' if '--after-cursor' in args else original(args,**kw)
        with patch.object(observer,'checked',side_effect=absent),\
             patch.object(observer.time,'monotonic',side_effect=[0,3]):
            with self.assertRaisesRegex(ValueError,'NOT_OBSERVED'):
                self.client.refresh_source('nvl0555','e12')
        self.publish.assert_not_called()

    def test_missing_journal_or_stale_stage_identity_cannot_authorize_login(self):
        original=self.command
        def unavailable(args,**kw):
            if args[0]=='journalctl':raise observer.CoreObservationHold('AUTOMATIC_MEASUREMENT_FAILED')
            return original(args,**kw)
        with patch.object(observer,'checked',side_effect=unavailable):
            with self.assertRaisesRegex(ValueError,'SSH_JOURNAL_REQUIRED'):
                self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'e8.json').write_text('fixture')
            with patch('edge_egress_k2_p1_worker.PIN_ROOT',root),\
                 patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=SimpleNamespace(
                     edge_ipv4='216.126.229.12',ingress_ipv4='10.77.0.8')):
                with self.assertRaisesRegex(ValueError,'IDENTITY_CONFLICT'):
                    self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()

    def test_reused_ingress_id_or_allocation_is_never_overwritten(self):
        self.peers+=(replace(self.peer,edge_ipv4='216.126.229.12'),)
        with self.assertRaisesRegex(ValueError,'IDENTITY_CONFLICT'):
            self.client.refresh_source('nvl0555','e12')
        self.client._run.assert_not_called()
        self.peers=(self.target,)
        with self.db() as db:
            db.execute("INSERT INTO edge_egress_allocations VALUES('e8','216.126.229.12','STAGED',20008)")
        with self.assertRaisesRegex(ValueError,'IDENTITY_CONFLICT'):
            self.client.refresh_source('nvl0555','e12')

    def test_duplicate_acceptance_or_new_boot_is_not_source_evidence(self):
        original=self.command
        for change in ('duplicate','boot'):
            def changed(args,**kw):
                raw=original(args,**kw)
                if '--after-cursor' not in args:return raw
                if change=='duplicate':return raw+'\n'+raw
                entry=json.loads(raw);entry['_BOOT_ID']='a'*32
                return json.dumps(entry)
            with patch.object(observer,'checked',side_effect=changed):
                with self.subTest(change=change),self.assertRaisesRegex(ValueError,'INGRESS_AMBIGUOUS'):
                    self.client.refresh_source('nvl0555','e12')
        self.publish.assert_not_called()


class RegistryAppendTests(unittest.TestCase):
    def test_guarded_append_preserves_peers_and_stops_before_replace_on_drift(self):
        first=IngressPeer('e12','144.172.84.112','10.77.0.12',base64.b64encode(b't'*32).decode())
        peer=IngressPeer('e8',SOURCE,'10.77.0.8',base64.b64encode(b's'*32).decode())
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'registry.json';path.write_text(render_registry([first]))
            def read():return parse_registry(path.read_bytes())
            with patch.object(onboarding,'REGISTRY',path),patch.object(onboarding,'_make_dir'),\
                 patch.object(onboarding,'load_registry',side_effect=read),\
                 patch.object(onboarding.os,'fstat',side_effect=lambda fd:SimpleNamespace(st_uid=0,st_mode=0o100600)):
                before=path.read_bytes()
                guard=Mock(side_effect=[None,None,ValueError('drift')])
                with self.assertRaisesRegex(ValueError,'drift'):
                    onboarding._publish_registry(peer,guard=guard,allow_existing=True)
                self.assertEqual(path.read_bytes(),before)
                onboarding._publish_registry(peer,guard=Mock(),allow_existing=True)
                self.assertEqual(read(),(first,peer))
                after=path.read_bytes()
                onboarding._publish_registry(peer,guard=Mock(),allow_existing=True)
                self.assertEqual(path.read_bytes(),after)
                with self.assertRaisesRegex(ValueError,'GUARD_REQUIRED'):
                    onboarding._publish_registry(peer,allow_existing=True)


if __name__=='__main__':unittest.main()
