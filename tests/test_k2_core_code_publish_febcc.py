"""Existing sealed release upgrade and code rollback on disposable paths."""
import hashlib
import json
from pathlib import Path
import unittest

from tests import test_k2_core_code_publish_df52 as base


class CoreCodeUpgradeTests(base.CoreCodePublishTests):
    publisher_file='ops/k2_core_code_publish_febcc.py'

    def setUp(self):
        super().setUp()
        p=self.pub
        source=p.STAGE/'source'
        worker='edge_egress_k2_m4_root_worker.py'
        old_files={
            'bot_final_v49-2.py':b'# original bot\n',
            'edge_egress_k2_core_runtime.py':b'# old runtime\n',
            worker:(source/worker).read_bytes(),
        }
        self.old_files={}
        for name,data in old_files.items():
            path=p.ROOT/name
            if not path.exists():path.write_bytes(data);path.chmod(0o600)
            self.old_files[name]=(data,path.stat().st_mode & 0o777)
        prior={'git_sha':'d'*40,'files':{n:hashlib.sha256(raw).hexdigest()
                                      for n,raw in old_files.items()}}
        self.old_release=json.dumps(prior,sort_keys=True).encode()+b'\n'
        p.CONFIG.mkdir(parents=True)
        (p.CONFIG/'release.json').write_bytes(self.old_release)
        (p.CONFIG/'release.json').chmod(0o600)
        p.OLD_RELEASE_SHA=hashlib.sha256(self.old_release).hexdigest()
        p.EXPECTED_CHANGED=frozenset(('bot_final_v49-2.py','edge_egress_k2_core_runtime.py'))

    def assert_original(self):
        self.assertTrue(self.state['active'])
        for name,(data,mode) in self.old_files.items():
            path=self.pub.ROOT/name
            self.assertEqual(path.read_bytes(),data)
            self.assertEqual(path.stat().st_mode & 0o777,mode)
        self.assertEqual((self.pub.CONFIG/'release.json').read_bytes(),self.old_release)
        self.assertEqual(self.custom.read_bytes(),b'# locally maintained helper\n')

    def test_other_installed_release_is_rejected_before_service_stop(self):
        p=self.pub
        (p.CONFIG/'release.json').write_bytes(b'{"unknown":true}\n')
        with self.assertRaisesRegex(RuntimeError,'INSTALLED_RELEASE_CHANGED'):
            p.deploy()
        self.assertEqual(self.state['stop'],0)

    def test_modified_critical_module_is_rejected_before_service_stop(self):
        p=self.pub
        (p.ROOT/'edge_egress_k2_core_runtime.py').write_bytes(b'# local edit\n')
        with self.assertRaisesRegex(RuntimeError,'INSTALLED_SOURCE_CHANGED'):
            p.deploy()
        self.assertEqual(self.state['stop'],0)

    def test_unreviewed_code_delta_is_rejected_before_service_stop(self):
        p=self.pub;p.EXPECTED_CHANGED=frozenset(('bot_final_v49-2.py',))
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_CODE_DELTA'):
            p.deploy()
        self.assertEqual(self.state['stop'],0)


if __name__=='__main__':unittest.main()
