"""Collector -> original Single receipt -> separate PAM policy, real SQLite.

Private profile/report files are real. Kernel/ingress observations and the
field report are synthetic fixtures, never physical VPS acceptance.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import edge_egress_k2_runtime_release as release
import edge_egress_uid_admission as admission
from edge_egress_k2_core_observer import CorePhysicalObservations
from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_f4_release import ACCEPTANCE_PROBES
from edge_egress_p3_executor import INTENT_PHASE,RECOVERY_PHASE
from edge_egress_uid_runtime_store import read_binding
from tests import test_edge_egress_k2_core_probe_admission as original
from tests import test_edge_egress_k2_runtime_release as files

CORE='209.200.246.198'


class CoreNativePAMQualificationTests(unittest.TestCase):
    def setUp(self):
        self.actual_pam_release=release.pam_cross_edge_released
        self.fx=original.CoreProbeAdmissionTests()
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.files=files.RootReleaseProfileTests()
        self.files.setUp();self.addCleanup(self.files.doCleanups)
        self.db=self.fx.db
        self.fx.add_user()
        self.fx.intent(probe_only=True)
        install_readiness_schema(self.db)
        self.db.execute('INSERT INTO edge_egress_readiness(edge_id,edge_ipv4,state,last_operation_id) '
                        "VALUES('e9',?,'STAGED',1)",(original.TARGET,))
        self.db.executescript('''CREATE TABLE edge_egress_allocations(
            edge_id TEXT,edge_public_ipv4 TEXT,core_public_ipv4 TEXT,tunnel_network TEXT,
            veth_network TEXT,route_table INT,edge_listen_port INT,edge_uplink TEXT,status TEXT);''')
        self.db.execute('INSERT INTO edge_egress_allocations VALUES(?,?,?,?,?,?,?,?,?)',
            ('e9',original.TARGET,CORE,'10.79.9.0/30','10.80.9.0/30',20009,52009,'eth0','STAGED'))
        self.db.commit()
        self.evidence=dict(version=1,edge_id='e9',username='nvl0555',uid=1636,
            core_ipv4=CORE,edge_ipv4=original.TARGET,observed_edge_ipv4=original.TARGET,
            environment='controlled-core',observed_at=original.NOW-90000,
            probe_results={name:True for name in ACCEPTANCE_PROBES},
            run_id='synthetic-field-fixture-only')
        self.field=self.files.root/'field-acceptance.json'
        self.manifest=self.files.root/'release.json'
        self.manifest.write_text(json.dumps({'git_sha':'b'*40}));self.manifest.chmod(0o600)
        self.files.body.update(version=2,operations_enabled=True,batch_enabled=False)
        self.write_field()

    def write_field(self,release_sha='b'*40):
        raw=json.dumps({'release_sha':release_sha,'evidence':self.evidence}).encode()
        self.field.write_bytes(raw);self.field.chmod(0o600)
        self.files.body['field_acceptance_sha256']=sha256(raw).hexdigest()
        self.files.write()

    def owned(self):
        stack=ExitStack()
        stack.enter_context(self.files.owned())
        stack.enter_context(patch.object(release,'pam_cross_edge_released',self.actual_pam_release))
        stack.enter_context(patch('time.time',return_value=original.NOW))
        return stack

    def allow(self):
        return release.core_runtime_pam_target(self.db,read_binding(self.db,'nvl0555'))

    def test_native_collector_and_fresh_pam_context_use_same_real_report_and_receipt(self):
        with self.owned(),patch('edge_egress_k2_core_observer.QUALIFICATION',self.field):
            profile=release.load_core_profile()
            collector=CorePhysicalObservations(db_conn=lambda:self.db,
                host=SimpleNamespace(now=lambda:original.NOW),release_sha='b'*40,
                qualification_sha256=profile.field_acceptance_sha256)
            collector._qualification(CORE)
            self.assertTrue(self.allow())
            # The old Lab compatibility entry never grants a normal release.
            self.assertFalse(release.lab_trial_pam_target(self.db,read_binding(self.db,'nvl0555')))
            self.db.execute("UPDATE failover_operations SET status='SUCCEEDED',detail_json=?",
                (json.dumps({**json.loads(self.db.execute('SELECT detail_json FROM failover_operations').fetchone()[0]),
                             'phase':'EGRESS_P3_VERIFIED'}),))
            self.assertTrue(self.allow())
            self.assertEqual(self.db.execute('SELECT state FROM edge_egress_readiness').fetchone(),('STAGED',))

    def test_full_local_admission_still_requires_actual_kernel_dns_and_ingress(self):
        from edge_egress_v1_admission import Member,check_account
        from edge_egress_uid_boot import BootGuardManifest
        from edge_egress_uid_policy import UIDPolicyRequest
        from ops.edge_egress_provision import EgressSpec
        spec=EgressSpec('e9',original.TARGET,CORE,'10.79.9.0/30','10.80.9.0/30','eth0',52009,20009)
        row=read_binding(self.db,'nvl0555')
        manifest=BootGuardManifest(UIDPolicyRequest(spec,row.username,row.uid,row.priority),
                                  'PROTECTED_BOOT_GUARD',row.dns_port,True,True)
        roster={row.username:Member(row.username,row.uid,'a'*64)}
        routes=('default via 10.80.9.2 dev vnh-e9 src 10.80.9.1 metric 100\n'
                'blackhole default metric 4096\n'
                '10.77.0.0/24 dev wg0 scope link src 10.77.0.1\n')
        def run(argv,**kw):
            return SimpleNamespace(returncode=0,stdout=routes if argv[0]=='ip' else '')
        def decide(ingress=True):
            return check_account(self.db,row.username,row.uid,roster,
                guard_loader=lambda _:manifest,guard_probe=admission.probe_local_guards,
                ingress_probe=lambda _:ingress)
        with self.owned(),patch.object(admission,'BootGuardApplier') as guard,\
             patch.object(admission.subprocess,'run',side_effect=run),\
             patch('edge_egress_uid_boot.uid_deny_present',return_value=False):
            self.assertTrue(decide())
            guard.return_value.verify.assert_called()
            self.assertFalse(decide(False))
            with patch('edge_egress_uid_boot.uid_deny_present',return_value=True):
                self.assertFalse(decide())
            with patch.object(admission.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='')):
                self.assertFalse(decide())

    def test_missing_tampered_wrong_release_wrong_core_and_false_report_all_deny(self):
        with self.owned():
            self.field.unlink()
            self.assertFalse(self.allow())
            self.write_field()
            self.field.write_bytes(self.field.read_bytes()+b' ')
            self.assertFalse(self.allow())
            self.write_field(release_sha='c'*40)
            self.assertFalse(self.allow())
            self.write_field()
            self.db.execute("UPDATE edge_egress_allocations SET core_public_ipv4='144.172.84.127'")
            self.assertFalse(self.allow())
            self.db.execute('UPDATE edge_egress_allocations SET core_public_ipv4=?',(CORE,))
            self.evidence['probe_results']['boot_deny_before_ssh']=False
            self.write_field()
            self.assertFalse(self.allow())

    def test_disabled_profile_or_different_installed_pam_cannot_open_a_staged_uid(self):
        with self.owned():
            self.files.body['operations_enabled']=False;self.files.write()
            self.assertFalse(self.allow())
            self.files.body['operations_enabled']=True;self.files.write()
            self.files.module.write_bytes(b'# different installed module\n')
            self.assertFalse(self.allow())

    def test_original_running_probe_phase_is_required_and_recovery_never_admits(self):
        with self.owned():
            self.fx.intent()
            self.assertFalse(self.allow())
            self.fx.intent(probe_only=True)
            self.assertTrue(self.allow())
            self.fx.intent(phase=RECOVERY_PHASE,probe_only=True)
            self.assertFalse(self.allow())
            self.fx.intent(probe_only=True)
            self.db.execute("UPDATE edge_egress_uid_runtime SET state='ROUTED_UNVERIFIED'")
            self.assertFalse(self.allow())

    def test_nonce_scope_account_operation_and_readiness_drift_deny(self):
        with self.owned():
            for change in ({'nonce_hash':'invalid'},{'scope_digest':'f'*64},
                           {'uid':1644},{'username':'other'},{'edge_id':'s8'},{'single_uid':False}):
                self.fx.intent(probe_only=True,**change)
                self.assertFalse(self.allow(),change)
            self.fx.intent(probe_only=True)
            self.db.execute('UPDATE edge_egress_uid_runtime SET last_operation_id=42')
            self.assertFalse(self.allow())
            self.db.execute('UPDATE edge_egress_uid_runtime SET last_operation_id=1')
            self.db.execute("UPDATE edge_egress_readiness SET state='REVOKED'")
            self.assertFalse(self.allow())
