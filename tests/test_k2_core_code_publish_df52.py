"""Disposable filesystem/service simulations for the pinned code publisher."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest

from ops.k2_release_bundle import build


@unittest.skipUnless(os.geteuid() == 0, 'Runs in the extracted root/umask-077 CI step')
class CoreCodePublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        project = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            'publisher_under_test', project/getattr(self, 'publisher_file',
                'ops/k2_core_code_publish_df52.py'))
        self.pub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.pub)
        p = self.pub
        p.ROOT = base/'root'; p.ROOT.mkdir()
        p.CONFIG = base/'etc/nvl-egress/k2-m4'
        p.STAGE = base/'stage'; p.STAGE.mkdir()
        repo = base/'repo'; repo.mkdir()
        (repo/'ops').mkdir()
        (repo/'ops/__init__.py').write_bytes(b'')
        (repo/'ops/k2_release_bundle.py').write_bytes(
            (project/'ops/k2_release_bundle.py').read_bytes())
        (repo/'bot_final_v49-2.py').write_bytes(b'# reviewed new bot\n')
        (repo/'edge_egress_k2_core_runtime.py').write_bytes(b'# reviewed runtime\n')
        (repo/'edge_egress_k2_m4_root_worker.py').write_text(
            'PINNED_SOURCE_FILES=frozenset(("bot_final_v49-2.py",'
            '"edge_egress_k2_core_runtime.py", "edge_egress_k2_m4_root_worker.py"))\n')
        for args in (('init','-q'), ('config','user.name','tests'),
                     ('config','user.email','tests@example.invalid'), ('add','.'),
                     ('commit','-qm','disposable source')):
            subprocess.run(['git','-C',str(repo),*args],check=True,stdout=subprocess.DEVNULL)
        p.SHA = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        archive = base/'source.tar'
        _, p.PACKAGE_SHA = build(repo,p.SHA,archive)
        source = p.STAGE/'source'; source.mkdir()
        with tarfile.open(archive) as bundle:
            bundle.extractall(source,filter='data')
        (p.STAGE/'STAGING_OK').write_text(p.SHA+'\n')
        self.bot = p.ROOT/'bot_final_v49-2.py'
        self.bot.write_bytes(b'# original bot\n'); self.bot.chmod(0o664)
        p.OLD_BOT_SHA = hashlib.sha256(self.bot.read_bytes()).hexdigest()
        self.custom = p.ROOT/'02_recreate_ssh_users.py'
        self.custom.write_bytes(b'# locally maintained helper\n')
        with sqlite3.connect(p.ROOT/'master_bot.db') as db:
            db.execute('CREATE TABLE failover_operations (status TEXT)')
        self.state = {'active':True, 'stop':0, 'start':0}
        self.race = False
        def unit(action):
            self.state['active'] = action == 'start'
            self.state[action] += 1
            if self.race and action == 'stop' and self.state['stop'] == 1:
                with sqlite3.connect(p.ROOT/'master_bot.db') as db:
                    db.execute("INSERT INTO failover_operations VALUES ('RUNNING')")
        p.unit = unit
        p.prop = lambda name: ('active' if name == 'ActiveState' and self.state['active']
                               else ('17' if self.state['active'] else '0'))
        p.identity = lambda: None
        # /tmp is deliberately rejected by the production ancestor guard;
        # service simulations operate only inside this disposable fixture.
        p.parents = lambda path,create=False: path.parent.mkdir(parents=True,exist_ok=True) if create else None
        p.stable = lambda: '17' if self.state['active'] else self.fail('bot not restarted')

    def assert_original(self):
        p = self.pub
        self.assertTrue(self.state['active'])
        self.assertEqual(self.bot.read_bytes(),b'# original bot\n')
        self.assertEqual(self.bot.stat().st_mode & 0o777,0o664)
        self.assertEqual(self.custom.read_bytes(),b'# locally maintained helper\n')
        self.assertFalse((p.CONFIG/'release.json').exists())
        self.assertFalse((p.ROOT/'edge_egress_k2_core_runtime.py').exists())

    def test_publish_then_manual_code_rollback_preserves_new_database_activity(self):
        p = self.pub
        p.deploy()
        self.assertEqual(self.bot.read_bytes(),b'# reviewed new bot\n')
        self.assertTrue((p.STAGE/'DEPLOYED').is_file())
        with sqlite3.connect(p.ROOT/'master_bot.db') as db:
            db.execute('CREATE TABLE newer_activity (value TEXT)')
            db.execute("INSERT INTO newer_activity VALUES ('keep')")
        p.restore(json.loads((p.STAGE/'deployment-plan.json').read_bytes()))
        self.assert_original()
        with sqlite3.connect(p.ROOT/'master_bot.db') as db:
            self.assertEqual(db.execute('SELECT value FROM newer_activity').fetchall(),[('keep',)])

    def test_partial_write_failure_restores_old_modes_and_removes_only_added_code(self):
        p = self.pub
        original = p.replace
        calls = 0
        def replace(*args,**kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError('simulated write failure')
            return original(*args,**kwargs)
        p.replace = replace
        with self.assertRaisesRegex(OSError,'simulated'):
            p.deploy()
        self.assert_original()

    def test_new_service_failure_restarts_original_code(self):
        p = self.pub
        calls = 0
        def stable():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError('simulated startup failure')
            return '17'
        p.stable = stable
        with self.assertRaisesRegex(RuntimeError,'simulated startup'):
            p.deploy()
        self.assert_original()

    def test_racing_operation_preserves_original_running_journal_and_service(self):
        self.race = True
        p = self.pub
        with self.assertRaisesRegex(RuntimeError,'RUNNING_OR_RECOVERY'):
            p.deploy()
        self.assert_original()
        with sqlite3.connect(p.ROOT/'master_bot.db') as db:
            self.assertEqual(db.execute('SELECT status FROM failover_operations').fetchall(),[('RUNNING',)])

    def test_enabled_profile_blocks_before_stopping_bot(self):
        p = self.pub
        p.CONFIG.mkdir(parents=True,exist_ok=True)
        (p.CONFIG/'core-runtime.json').write_text('{"enabled":true}')
        with self.assertRaisesRegex(RuntimeError,'RUNTIME_PROFILE_CHANGED'):
            p.deploy()
        self.assertEqual(self.state['stop'],0)
        self.assertEqual(self.bot.read_bytes(),b'# original bot\n')


if __name__ == '__main__':
    unittest.main()
