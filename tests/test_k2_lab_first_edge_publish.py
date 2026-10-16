"""Lab publisher identity and delegation; no live service or SSH calls."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import k2_lab_first_edge_publish as lab


class LabFirstEdgePublishTests(unittest.TestCase):
    def test_wrong_host_is_rejected_before_database_or_service_access(self):
        with patch.object(lab.os, 'geteuid', return_value=0), \
             patch.object(lab, 'local_ipv4s', return_value={'209.200.246.198'}), \
             patch.object(lab.sqlite3, 'connect') as connect, \
             patch.object(lab.publisher, 'off') as off:
            with self.assertRaisesRegex(RuntimeError, 'WRONG_LAB_HOST'):
                lab.preflight()
        connect.assert_not_called()
        off.assert_not_called()

    def test_lab_database_identity_is_read_only_and_required(self):
        for ip in (lab.LAB_IP, '209.200.246.198'):
            with self.subTest(ip=ip), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'bot.db'
                with sqlite3.connect(path) as db:
                    db.execute('CREATE TABLE settings(key TEXT,value TEXT)')
                    db.executemany('INSERT INTO settings VALUES(?,?)',
                                   [('brand', 'NVL-LAB'), ('core_wg_public_ip', ip)])
                original = lab.sqlite3.connect
                connections = []
                def connect(database, **kwargs):
                    self.assertTrue(database.endswith('?mode=ro'))
                    db = original(path.as_uri()+'?mode=ro', **kwargs)
                    connections.append(db)
                    return db
                before = path.read_bytes()
                with patch.object(lab.os, 'geteuid', return_value=0), \
                     patch.object(lab, 'local_ipv4s', return_value={lab.LAB_IP}), \
                     patch.object(lab.sqlite3, 'connect', side_effect=connect), \
                     patch.object(lab.publisher, 'off') as off:
                    if ip == lab.LAB_IP:
                        lab.preflight()
                        off.assert_called_once_with()
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'LAB_IDENTITY_CHANGED'):
                            lab.preflight()
                        off.assert_not_called()
                for db in connections:
                    db.close()
                self.assertEqual(before, path.read_bytes())

    def test_dispatch_uses_existing_delta_publisher_and_saved_plan_rollback(self):
        stage = Path('/root/nvl-lab-first-edge-disposable-test')
        commit, package = 'a'*40, 'b'*64
        fields = ('STAGE', 'SHA', 'PACKAGE_SHA', 'OLD_RELEASE_SHA', 'OLD_BOT_SHA',
                  'EXPECTED_CHANGED')
        for rollback in (False, True):
            with self.subTest(rollback=rollback), \
                 patch.multiple(lab.publisher, **{key: getattr(lab.publisher, key) for key in fields}), \
                 patch.object(lab, 'preflight'), \
                 patch.object(lab.publisher, 'parents'), \
                 patch.object(lab.publisher, 'deploy') as deploy, \
                 patch.object(lab.publisher, 'restore') as restore, \
                 patch.object(lab, '__file__', str(stage/'source/ops/k2_lab_first_edge_publish.py')), \
                 patch.object(Path, 'is_symlink', return_value=False), \
                 patch.object(Path, 'resolve', autospec=True, side_effect=lambda path: path), \
                 patch.object(Path, 'read_bytes', return_value=(
                     '{"git_sha":"'+commit+'","files":[]}').encode()), \
                 patch.object(lab.os, 'umask'), \
                 patch('sys.argv', ['publish', '--stage', str(stage), '--commit', commit,
                                    '--package-sha256', package]+(['--rollback'] if rollback else [])):
                lab.main()
                self.assertEqual(lab.publisher.EXPECTED_CHANGED,
                                 frozenset(('edge_egress_k2_p1_worker.py',)))
                self.assertEqual(lab.publisher.SHA, commit)
                self.assertEqual(lab.publisher.PACKAGE_SHA, package)
                if rollback:
                    restore.assert_called_once_with({'git_sha': commit, 'files': []})
                    deploy.assert_not_called()
                else:
                    deploy.assert_called_once_with()
                    restore.assert_not_called()
