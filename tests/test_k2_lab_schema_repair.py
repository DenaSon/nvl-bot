"""Real SQLite repair atomicity; transport observations are explicit test I/O."""
import base64
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from edge_egress_k2_p1_worker import StagePin, RECOVERY
from ops.edge_egress_provision import EgressSpec
from ops import k2_lab_schema_repair as repair


class LabSchemaRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = patch.object(repair, 'CONFIG', Path(self.temp.name)/'profile')
        self.config.start()
        self.addCleanup(self.config.stop)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,is_default INT);
CREATE TABLE ssh_accounts(username TEXT,password TEXT,host TEXT);
CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,source_host TEXT,
target_host TEXT,status TEXT,detail_json TEXT,updated_at TEXT,finished_at TEXT);
INSERT INTO settings VALUES('brand','NVL-LAB');
INSERT INTO settings VALUES('core_wg_public_ip','144.172.84.127');
INSERT INTO settings VALUES('edge_egress_protected_mode','0');
INSERT INTO settings VALUES('dns_current_ip','unchanged');
INSERT INTO host_pool VALUES('144.172.84.127',1,0);
INSERT INTO ssh_accounts VALUES('nvltest1','test-password','144.172.84.112');
''')
        self.pin = StagePin('e2', repair.EDGE_IP, repair.LAB_IP, '10.77.0.2',
            'a'*64, 'b'*64, 'public-test-ssh-key', 22,
            core_wg_pub=base64.b64encode(b'a'*32).decode(),
            edge_wg_pub=base64.b64encode(b'b'*32).decode())
        self.spec = EgressSpec('e2', repair.EDGE_IP, repair.LAB_IP,
                               '10.79.2.0/30', '10.80.2.0/30', 'eth0', 52002, 20002)
        self.intent = {'kind': 'K2_P1', 'phase': RECOVERY, 'edge_id': 'e2',
            'core_sha': self.pin.core_sha, 'edge_sha': self.pin.edge_sha,
            'customers_moved': 0, 'manual_recovery': True,
            'source_mode': 'INITIAL_CORE', 'source_pool': [[repair.LAB_IP, 1, 0]]}
        self.db.execute('INSERT INTO failover_operations VALUES(1,?,?,?,?,?,NULL)',
            (repair.LAB_IP, repair.EDGE_IP, 'RUNNING', json.dumps(self.intent), 'before'))
        self.db.commit()
        self.prove = lambda pin: (self.spec, pin.edge_wg_pub, repair.EDGE_IP)
        self.recheck = lambda *args: None

    def run_repair(self):
        return repair.reconcile(lambda: self.db, self.pin,
                                prove=self.prove, recheck=self.recheck)

    def assert_held(self):
        row = self.db.execute('SELECT status,detail_json FROM failover_operations WHERE id=1').fetchone()
        self.assertEqual((row[0], json.loads(row[1])), ('RUNNING', self.intent))
        names = {row[0] for row in self.db.execute('SELECT name FROM sqlite_master')}
        self.assertFalse(repair.TABLES & names)

    def test_real_schema_allocation_and_readiness_settle_only_original_operation(self):
        tables = ('settings', 'ssh_accounts', 'host_pool')
        before = {name: self.db.execute('SELECT * FROM '+name).fetchall() for name in tables}
        result = self.run_repair()
        self.assertEqual(result['operation_id'], 1)
        self.assertEqual(result['customers_moved'], 0)
        self.assertFalse(result['customer_ready'])
        self.assertEqual(self.db.execute('SELECT edge_id,status FROM edge_egress_allocations').fetchall(),
                         [('e2', 'STAGED')])
        self.assertEqual(self.db.execute('SELECT edge_id,state,last_operation_id FROM edge_egress_readiness').fetchall(),
                         [('e2', 'STAGED', 1)])
        self.assertEqual(self.db.execute('SELECT * FROM edge_egress_uid_runtime').fetchall(), [])
        self.assertEqual(self.db.execute('SELECT * FROM edge_egress_uid_bindings').fetchall(), [])
        status, raw, finished = self.db.execute(
            'SELECT status,detail_json,finished_at FROM failover_operations').fetchone()
        self.assertEqual(status, 'SUCCEEDED')
        self.assertTrue(finished)
        self.assertEqual(json.loads(raw)['recovered_from'], RECOVERY)
        self.assertNotIn('manual_recovery', json.loads(raw))
        for name in tables:
            self.assertEqual(before[name], self.db.execute('SELECT * FROM '+name).fetchall())

    def test_pin_drift_rolls_back_ddl_f3_and_original_journal_together(self):
        def drift(*args):
            raise RuntimeError('STAGE_PIN_CHANGED')
        self.recheck = drift
        with self.assertRaisesRegex(RuntimeError, 'STAGE_PIN_CHANGED'):
            self.run_repair()
        self.assert_held()

    def test_cas_failure_rolls_back_schema_and_metadata(self):
        self.db.executescript('''CREATE TRIGGER reject_settle BEFORE UPDATE ON failover_operations
            BEGIN SELECT RAISE(IGNORE); END;''')
        with self.assertRaisesRegex(RuntimeError, 'ORIGINAL_6G_CAS_LOST'):
            self.run_repair()
        self.assert_held()

    def test_unproven_or_core_ip_never_creates_metadata(self):
        self.prove = lambda pin: (self.spec, pin.edge_wg_pub, repair.LAB_IP)
        with self.assertRaisesRegex(RuntimeError, 'FRESH_TRANSPORT_PROOF_REQUIRED'):
            self.run_repair()
        self.assert_held()

    def test_recovery_identity_and_zero_customer_scope_are_required(self):
        for key, value in (('phase', 'EGRESS_P1_TRANSPORT_INTENT'), ('core_sha', 'c'*64),
                           ('customers_moved', 1), ('manual_recovery', False),
                           ('source_mode', 'ACTIVE_RELAY')):
            with self.subTest(key=key):
                changed = {**self.intent, key: value}
                self.db.execute('UPDATE failover_operations SET detail_json=? WHERE id=1',
                                (json.dumps(changed),))
                self.db.commit()
                with self.assertRaisesRegex(RuntimeError, 'EXACT_RECOVERY_INTENT_REQUIRED'):
                    self.run_repair()
        self.db.execute('UPDATE failover_operations SET detail_json=? WHERE id=1',
                        (json.dumps(self.intent),))
        self.db.commit()
        self.assert_held()

    def test_competing_running_operation_preserves_both_rows(self):
        self.db.execute("INSERT INTO failover_operations VALUES(2,'other','target','RUNNING','{}','now',NULL)")
        self.db.commit()
        with self.assertRaisesRegex(ValueError, 'ANOTHER_6G_OPERATION_RUNNING'):
            self.run_repair()
        self.assert_held()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM failover_operations').fetchone()[0], 2)

    def test_pool_drift_holds_without_creating_tables(self):
        self.db.execute('UPDATE host_pool SET is_default=1')
        self.db.commit()
        with self.assertRaisesRegex(ValueError, 'INITIAL_CORE_BASELINE_CHANGED'):
            self.run_repair()
        self.assert_held()

    def test_existing_partial_schema_is_not_overwritten(self):
        self.db.execute('CREATE TABLE edge_egress_uid_bindings(username TEXT)')
        self.db.commit()
        with self.assertRaisesRegex(RuntimeError, 'ORIGINAL_MISSING_SCHEMAS'):
            self.run_repair()
        self.assertEqual(self.db.execute('PRAGMA table_info(edge_egress_uid_bindings)').fetchone()[1], 'username')
        self.assertIsNone(self.db.execute("SELECT name FROM sqlite_master WHERE name='edge_egress_allocations'").fetchone())

    def test_enabled_customer_profile_refuses_metadata_repair(self):
        repair.CONFIG.mkdir()
        (repair.CONFIG/'core-runtime.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'CUSTOMER_PROFILE_CHANGED'):
            self.run_repair()
        self.assert_held()

    def test_replay_cannot_create_another_operation_or_reset_success(self):
        self.run_repair()
        with self.assertRaisesRegex(ValueError, 'SHARED_6G_LEASE_NOT_CURRENT'):
            self.run_repair()
        self.assertEqual(self.db.execute('SELECT id,status FROM failover_operations').fetchall(), [(1, 'SUCCEEDED')])

    def test_wrong_target_is_refused_before_proof_or_database_access(self):
        self.pin = replace(self.pin, core_ipv4='209.200.246.198')
        self.prove = lambda _: self.fail('Must not probe on a wrong repair target')
        with self.assertRaisesRegex(RuntimeError, 'WRONG_REPAIR_TARGET'):
            self.run_repair()
        self.assert_held()

    def test_wrong_host_preflight_never_reads_source_or_database(self):
        with patch.object(repair.os, 'geteuid', return_value=0), \
             patch.object(repair.subprocess, 'run', return_value=type('Result', (), {
                 'stdout': '[{"addr_info":[{"local":"209.200.246.198"}]}]'})()), \
             patch.object(repair, 'checked') as read, \
             patch.object(repair, 'profiles_off') as profiles:
            with self.assertRaisesRegex(RuntimeError, 'WRONG_LAB_HOST'):
                repair.preflight()
        read.assert_not_called()
        profiles.assert_not_called()
