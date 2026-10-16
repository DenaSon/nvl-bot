"""Bounded trial authority with real private profile bytes and SQLite.

Only OS/SSH measurements are simulated. These are not VPS acceptance results.
"""
from contextlib import ExitStack
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

import edge_egress_k2_runtime_release as release
import edge_egress_k2_core_observer as observer
from ops import k2_lab_trial as setup
from tests import test_edge_egress_k2_runtime_release as profiles


class LabTrialAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.files=profiles.RootReleaseProfileTests()
        self.files.setUp();self.addCleanup(self.files.doCleanups)
        self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close)
        self.db.executescript('''
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE ssh_accounts(username TEXT,service_type TEXT);
CREATE TABLE edge_egress_uid_runtime(username TEXT,uid INT,edge_id TEXT,edge_ipv4 TEXT);
CREATE TABLE edge_egress_uid_bindings(username TEXT,uid INT,edge_id TEXT,edge_ipv4 TEXT);
''')
        self.db.executemany('INSERT INTO settings VALUES(?,?)',(
            ('brand','NVL-LAB'),('core_wg_public_ip',release.LAB_CORE),
            ('edge_egress_protected_mode','0'),('auto_failover_mode','0'),
            ('phase6h_auto_failover_enabled','0')))
        self.db.executemany('INSERT INTO ssh_accounts VALUES(?,?)',
                            [(n,'ssh') for n in release.LAB_USERS])
        self.db.commit()
        self.files.body.update(version=3,operations_enabled=True,batch_enabled=True,
            lab_trial={'purpose':'ISOLATED_LAB_TRIAL','release_sha':'b'*40,
                'core_ipv4':release.LAB_CORE,'edge_id':'e2','edge_ipv4':release.LAB_EDGE,
                'machine_sha256':sha256(b'fixture-machine\n').hexdigest(),
                'rescue_sha256':'e'*64,'rescue_observed_at':1000})
        self.files.write()

    def authority(self):
        stack=ExitStack()
        stack.enter_context(self.files.owned())
        read=release._root_bytes
        stack.enter_context(patch.object(release,'_root_bytes',side_effect=lambda path,*a,**kw:
            b'fixture-machine\n' if path==Path('/etc/machine-id') else read(path,*a,**kw)))
        stack.enter_context(patch.object(release,'lab_rescue_digest',return_value='e'*64))
        stack.enter_context(patch.object(release.pwd,'getpwnam',side_effect=lambda n:
            SimpleNamespace(pw_uid=release.LAB_USERS[n])))
        stack.enter_context(patch.object(release.subprocess,'run',return_value=SimpleNamespace(
            returncode=0,stdout=json.dumps([{'addr_info':[{'family':'inet','local':release.LAB_CORE}]}]))))
        return stack

    def validate(self,**kwargs):
        return release.validate_lab_trial(lambda:self.db,release_sha='b'*40,
            digest=sha256(self.files.profile.read_bytes()).hexdigest(),**kwargs)

    def test_trial_allows_exact_lab_population_without_field_report_or_ready(self):
        with self.authority():
            p=self.validate(usernames=('nvltest1','nvltest2','nvltest3'))
            self.assertTrue(p.enabled and p.operations_enabled and p.batch_enabled)
            self.assertEqual(p.field_acceptance_sha256,'')
            self.assertFalse((self.files.root/'field-acceptance.json').exists())
            for table in ('edge_egress_uid_runtime','edge_egress_uid_bindings'):
                self.assertEqual(self.db.execute('SELECT * FROM '+table).fetchall(),[])

    def test_production_or_unknown_edge_and_customer_are_rejected(self):
        with self.authority():
            for change in ({'core_ipv4':'209.200.246.198'}, {'edge_id':'e12'},
                           {'usernames':('nvl0555',)}, {'usernames':('nvltest1','root')}):
                with self.subTest(change=change),self.assertRaisesRegex(ValueError,'AUTHORITY_CHANGED'):
                    self.validate(**change)

    def test_local_production_address_cannot_be_released_even_with_lab_database(self):
        with self.authority(),patch.object(release.subprocess,'run',return_value=SimpleNamespace(
            returncode=0,stdout='[{"addr_info":[{"family":"inet","local":"209.200.246.198"}]}]')):
            with self.assertRaisesRegex(ValueError,'WRONG_HOST'):self.validate()

    def test_new_customer_reused_uid_and_foreign_binding_revoke_live_trial(self):
        with self.authority():
            self.db.execute("INSERT INTO ssh_accounts VALUES('customer','ssh')")
            with self.assertRaisesRegex(ValueError,'FOREIGN_CUSTOMER'):self.validate()
            self.db.execute("DELETE FROM ssh_accounts WHERE username='customer'")
            with patch.object(release.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=9999)):
                with self.assertRaisesRegex(ValueError,'OS_UID_CHANGED'):self.validate()
            self.db.execute("INSERT INTO edge_egress_uid_runtime VALUES('customer',9999,'e2',?)",
                            (release.LAB_EDGE,))
            with self.assertRaisesRegex(ValueError,'FOREIGN_PROTECTED'):self.validate()

    def test_own_pending_or_protected_row_keeps_trial_scoped(self):
        for table in ('edge_egress_uid_runtime','edge_egress_uid_bindings'):
            self.db.execute('INSERT INTO '+table+' VALUES(?,?,?,?)',
                            ('nvltest1',1636,'e2',release.LAB_EDGE))
        with self.authority():
            self.validate(usernames=('nvltest1',))
            self.db.execute("UPDATE edge_egress_uid_bindings SET edge_id='e3'")
            with self.assertRaisesRegex(ValueError,'FOREIGN_PROTECTED'):self.validate()

    def test_machine_recovery_profile_and_global_mode_drift_revoke_grant(self):
        with self.authority():
            for patcher in (
                patch.object(release,'lab_rescue_digest',return_value='f'*64),
                patch.object(release,'load_core_profile',return_value=replace(
                    release.load_core_profile(),lab_trial_sha256='f'*64)),
                patch('time.time',return_value=999),
            ):
                with patcher,self.assertRaisesRegex(ValueError,'AUTHORITY_CHANGED'):self.validate()
            self.db.execute("UPDATE settings SET value='1' WHERE key='auto_failover_mode'")
            with self.assertRaisesRegex(ValueError,'DATABASE_IDENTITY_CHANGED'):self.validate()

    def test_trial_schema_is_explicit_and_cannot_mix_a_field_acceptance_grant(self):
        for change in ({'field_acceptance_sha256':'a'*64}, {'operations_enabled':False},
                       {'single_enabled':False}, {'batch_enabled':1}):
            original=dict(self.files.body)
            self.files.body.update(change);self.files.write()
            with self.authority(),self.assertRaises(release.CoreReleaseHold):
                release.load_core_profile()
            self.files.body=original
        self.files.write()
        self.files.body['lab_trial']['core_ipv4']='209.200.246.198';self.files.write()
        with self.authority(),self.assertRaises(release.CoreReleaseHold):release.load_core_profile()

    def test_native_lab_qualification_never_reads_or_mints_field_acceptance(self):
        with self.authority():
            runner=observer.CorePhysicalObservations(db_conn=lambda:self.db,
                host=SimpleNamespace(now=lambda:2000),qualification_sha256=sha256(
                    self.files.profile.read_bytes()).hexdigest(),release_sha='b'*40,lab_trial=True)
            with patch.object(observer,'_root_bytes') as field:
                runner._qualification(release.LAB_CORE)
                runner._trial_scope('e2',('nvltest1',))
                field.assert_not_called()
            with self.assertRaises(ValueError):runner._trial_scope('e2',('nvl0555',))
            with patch.object(release,'load_core_profile',return_value=release.CoreReleaseProfile(False,'')),\
                 patch('edge_egress_k2_p1_worker.load_stage_pin') as pin:
                with self.assertRaisesRegex(ValueError,'REVOKED'):runner.qualify_target('e2')
                pin.assert_not_called()

    def test_trial_prechecks_do_not_claim_unperformed_boot_or_wg_loss(self):
        proof=observer.CorePreAttachEvidence('a'*64,1000,1030,'e2',release.LAB_EDGE,
                                            observer.LAB_PRE_CHECKS,(),phase='PRE_ATTACH')
        proof.verify_pre_attach()
        self.assertFalse({'f4_accepted','release_qualified','wg_loss_fenced','boot_guard'} & proof.checks)
        with self.assertRaises(ValueError):
            replace(proof,checks=frozenset(('lab_trial_authorized',))).verify_pre_attach()

    def pam_receipt(self,status='SUCCEEDED',phase='EGRESS_P3_VERIFIED',probe=False):
        from edge_egress_f3_readiness import install_readiness_schema
        from edge_egress_p3_executor import ExecutionScope,_scope_digest
        install_readiness_schema(self.db)
        self.db.executescript('''CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,
            status TEXT,source_host TEXT,target_host TEXT,detail_json TEXT);''')
        self.db.execute('INSERT INTO edge_egress_readiness(edge_id,edge_ipv4,state,last_operation_id) '
                        "VALUES('e2',?,'STAGED',1)",(release.LAB_EDGE,))
        scope=ExecutionScope('UID_ENROLL_SOURCE','e2',release.LAB_EDGE,release.LAB_EDGE,'nvltest1',1636)
        detail={'kind':'K2_P3A','single_uid':True,'action':scope.action,'username':'nvltest1',
                'uid':1636,'edge_id':'e2','scope_digest':_scope_digest(scope),'nonce_hash':'c'*64,
                'phase':phase,'probe_only':probe}
        self.db.execute('INSERT INTO failover_operations VALUES(7,?,?,?,?)',
                        (status,release.LAB_EDGE,release.LAB_EDGE,json.dumps(detail)))
        self.db.commit()
        return SimpleNamespace(username='nvltest1',uid=1636,edge_id='e2',edge_ipv4=release.LAB_EDGE,
                               state='PROTECTED',last_operation_id=7),detail

    def test_separate_pam_admits_exact_completed_trial_receipt_without_fake_ready(self):
        row,detail=self.pam_receipt()
        with self.authority(),patch.object(release,'pam_cross_edge_released',return_value=True):
            self.assertTrue(release.lab_trial_pam_target(self.db,row))
            self.assertEqual(self.db.execute('SELECT state FROM edge_egress_readiness').fetchone(),('STAGED',))
            for key,value in (('scope_digest','f'*64),('uid',1637),('phase','EGRESS_P3_RECOVERY_REQUIRED'),
                              ('action','UID_ATTACH'),('kind','other')):
                changed={**detail,key:value}
                self.db.execute('UPDATE failover_operations SET detail_json=?',(json.dumps(changed),))
                self.assertFalse(release.lab_trial_pam_target(self.db,row))
            self.db.execute('UPDATE failover_operations SET detail_json=?',(json.dumps(detail),))
            self.db.execute("UPDATE edge_egress_readiness SET state='REVOKED'")
            self.assertFalse(release.lab_trial_pam_target(self.db,row))

    def test_pam_trial_probe_requires_protected_commit_and_original_6g_probe_phase(self):
        from edge_egress_p3_executor import INTENT_PHASE,RECOVERY_PHASE
        row,detail=self.pam_receipt('RUNNING',INTENT_PHASE,True)
        with self.authority(),patch.object(release,'pam_cross_edge_released',return_value=True):
            self.assertTrue(release.lab_trial_pam_target(self.db,row))
            row.state='ROUTED_UNVERIFIED'
            self.assertFalse(release.lab_trial_pam_target(self.db,row))
            row.state='PROTECTED'
            for d in ({**detail,'probe_only':False},{**detail,'phase':RECOVERY_PHASE}):
                self.db.execute('UPDATE failover_operations SET detail_json=?',(json.dumps(d),))
                self.assertFalse(release.lab_trial_pam_target(self.db,row))

    def test_missing_profile_or_normal_production_profile_never_enables_trial_pam(self):
        row,_=self.pam_receipt()
        for p in (release.CoreReleaseProfile(False,''),release.CoreReleaseProfile(True,'a'*64,
                                                                                True,True,'b'*64)):
            with patch.object(release,'load_core_profile',return_value=p),\
                 patch.object(release,'pam_cross_edge_released') as verify:
                self.assertFalse(release.lab_trial_pam_target(self.db,row))
                verify.assert_not_called()


class LabTrialPublicationTests(unittest.TestCase):
    def test_wrong_host_refuses_before_database_or_service_changes(self):
        with patch.object(setup.os,'geteuid',return_value=0),\
             patch.object(setup,'local_ipv4s',return_value={'209.200.246.198'}),\
             patch.object(setup.sqlite3,'connect') as db,patch.object(setup.publisher,'unit') as unit:
            with self.assertRaisesRegex(RuntimeError,'WRONG_LAB_HOST'):setup.preflight_trial()
            db.assert_not_called();unit.assert_not_called()

    def test_publisher_reuses_exact_original_delta_and_rollback_implementation(self):
        names=('STAGE','SHA','PACKAGE_SHA','OLD_RELEASE_SHA','OLD_BOT_SHA','EXPECTED_CHANGED')
        with patch.multiple(setup.publisher,**{n:getattr(setup.publisher,n) for n in names}),\
             patch.object(setup,'preflight_trial') as pre,patch.object(setup.publisher,'deploy') as deploy:
            setup.publish(Path('/root/nvl-lab-trial-ABCDEFGH'),'a'*40,'b'*64)
            pre.assert_called_once();deploy.assert_called_once_with()
            self.assertEqual(setup.publisher.EXPECTED_CHANGED,setup.DELTA)
            self.assertEqual(setup.publisher.OLD_RELEASE_SHA,setup.OLD_RELEASE)

    def test_expired_or_mismatched_independent_recovery_receipt_cannot_enable(self):
        release_body={'git_sha':'a'*40,'files':{'edge_egress_v1_admission.py':'b'*64}}
        with patch.object(release,'lab_rescue_digest',return_value='c'*64),\
             patch.object(release,'_root_bytes',return_value=b'fixture-machine'),\
             patch('time.time',return_value=2000):
            for proof in ({'rescue_sha256':'c'*64,'rescue_observed_at':1000},
                          {'rescue_sha256':'d'*64,'rescue_observed_at':1999},
                          {'rescue_sha256':'c'*64,'rescue_observed_at':2001}):
                with self.assertRaisesRegex(RuntimeError,'RESCUE_PROOF_REQUIRED'):
                    setup.trial_profile(release_body,proof)
            profile=setup.trial_profile(release_body,{'rescue_sha256':'c'*64,'rescue_observed_at':1999})
            self.assertNotIn('field_acceptance_sha256',profile)
            self.assertEqual(profile['version'],3)
