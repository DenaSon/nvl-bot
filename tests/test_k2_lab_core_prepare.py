"""Fresh Core CLI boundaries with real private payload files, no live servers."""
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from ops import k2_lab_core_copy as lab
from ops import k2_lab_core_prepare as prepare


class FreshCoreCliTests(unittest.TestCase):
    def configuration(self, ip='8.8.4.4'):
        config = {'app':'a'*40, 'destination':ip,
                  'source_sha256':'b'*64, 'package_sha256':'c'*64}
        return {'app':config['app'], 'destination':ip, 'configuration':config}

    def global_patch(self):
        names = ('APP', 'LAB_IP', 'EDGE_IP', 'SOURCE_SHA', 'PACKAGE_SHA', 'FRESH_CONFIGURATION')
        return patch.multiple(lab, **{name:getattr(lab, name) for name in names})

    def test_only_fresh_public_destination_and_never_current_core(self):
        self.assertEqual(prepare.destination_ipv4(' 8.8.4.4 ', {'1.1.1.1'}), '8.8.4.4')
        for value in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '224.0.0.1',
                      '::1', '8.8.4.4; reboot', '209.200.246.198', '1.1.1.1'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                prepare.destination_ipv4(value, {'1.1.1.1'})

    def test_config_uses_new_core_and_keeps_accounts_core_local_without_old_edge(self):
        with tempfile.TemporaryDirectory() as folder, self.global_patch():
            folder = Path(folder)
            (folder/'metadata.json').write_text(json.dumps(self.configuration()))
            info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=1000)
            with patch.object(Path, 'lstat', return_value=info):
                lab.configure_fresh_install(folder)
            self.assertEqual((lab.APP, lab.LAB_IP, lab.EDGE_IP), ('a'*40, '8.8.4.4', '8.8.4.4'))
            self.assertEqual((lab.SOURCE_SHA, lab.PACKAGE_SHA), ('b'*64, 'c'*64))
            self.assertTrue(lab.FRESH_CONFIGURATION)

    def test_private_metadata_and_production_destination_enforced_before_install(self):
        with tempfile.TemporaryDirectory() as folder, self.global_patch():
            folder = Path(folder)
            for mode, ip in ((0o644, '8.8.4.4'), (0o600, '209.200.246.198'),
                             (0o600, '127.0.0.1')):
                (folder/'metadata.json').write_text(json.dumps(self.configuration(ip)))
                info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0, st_size=1000)
                with self.subTest(mode=mode, ip=ip), patch.object(Path, 'lstat', return_value=info), \
                     self.assertRaises(RuntimeError):
                    lab.configure_fresh_install(folder)

    def test_failed_dynamic_preflight_never_enters_service_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stage = root/'nvl-lab-import-test'
            stage.mkdir()
            with patch('sys.argv', ['setup', '--fresh-install', str(stage)]), \
                 patch.object(lab, 'ROOT', root), patch.object(lab, 'configure_fresh_install'), \
                 patch.object(lab, 'preflight_lab', side_effect=RuntimeError('WRONG_LAB_HOST')), \
                 patch.object(lab, 'install_lab') as install, patch.object(lab, 'run') as run, \
                 patch.object(lab.subprocess, 'run') as processes:
                with self.assertRaisesRegex(RuntimeError, 'WRONG_LAB_HOST'):
                    lab.main()
            install.assert_not_called()
            run.assert_not_called()
            processes.assert_not_called()

    def test_swap_is_persistent_once_and_skipped_with_existing_memory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            mem, swap, fstab = root/'mem', root/'swap', root/'fstab'
            mem.write_text('MemTotal: 458000 kB\nSwapTotal: 0 kB\n')
            fstab.write_text('# existing mounts\n')
            with patch.object(lab.shutil, 'disk_usage', return_value=SimpleNamespace(free=4*1024**3)), \
                 patch.object(lab, 'run') as run:
                lab.prepare_lab_swap(meminfo=mem, swap=swap, fstab=fstab)
                self.assertEqual(swap.stat().st_mode & 0o777, 0o600)
                self.assertIn('\n'+str(swap)+' none swap sw 0 0\n', fstab.read_text())
                self.assertEqual([c.args[0][0] for c in run.call_args_list],
                                 ['dd', 'mkswap', 'swapon'])
                run.reset_mock()
                mem.write_text('MemTotal: 458000 kB\nSwapTotal: 1048576 kB\n')
                lab.prepare_lab_swap(meminfo=mem, swap=swap, fstab=fstab)
                run.assert_not_called()

    def test_swap_refuses_existing_path_and_small_disk_before_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            mem, swap, fstab = root/'mem', root/'swap', root/'fstab'
            mem.write_text('MemTotal: 458000 kB\nSwapTotal: 0 kB\n')
            fstab.write_text('# mounts\n')
            with patch.object(lab.shutil, 'disk_usage', return_value=SimpleNamespace(free=1024)), \
                 patch.object(lab, 'run') as run, self.assertRaisesRegex(RuntimeError, 'DISK_SPACE'):
                lab.prepare_lab_swap(meminfo=mem, swap=swap, fstab=fstab)
            self.assertFalse(swap.exists())
            run.assert_not_called()
            swap.write_text('keep')
            with patch.object(lab, 'run') as run, self.assertRaisesRegex(RuntimeError, 'ALREADY_PRESENT'):
                lab.prepare_lab_swap(meminfo=mem, swap=swap, fstab=fstab)
            self.assertEqual(swap.read_text(), 'keep')
            run.assert_not_called()

    def test_payload_exports_only_packages_source_and_new_test_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'source.tar').write_bytes(b'committed source')
            commands = []
            def archive(args):
                commands.append(args)
                (folder/'packages.tar.gz').write_bytes(b'installed packages')
            with patch.object(lab, 'run', side_effect=archive):
                password, metadata = prepare.payload(folder, 'a'*40, '8.8.4.4',
                    '987654321:'+('t'*30), {'id':987654321}, 'b'*64, 'c'*64)
            self.assertEqual(set(metadata['files']),
                             {'source.tar', 'packages.tar.gz', 'lab.env', 'setup.py'})
            self.assertEqual(metadata['configuration'], self.configuration()['configuration'])
            self.assertIn('MASTER_PASS='+password+'\n', (folder/'lab.env').read_text())
            self.assertEqual((folder/'lab.env').stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(commands), 1)
            self.assertEqual(commands[0][-1], 'site-packages')
            self.assertNotIn(password, repr(commands))
            for name in metadata['files']:
                self.assertEqual(lab.digest(folder/name), metadata['files'][name])

    def test_ssh_restart_reconnects_without_relaunching_install(self):
        original, replacement = Mock(), Mock()
        original.get_transport.return_value.is_active.return_value = True
        replacement.get_transport.return_value.is_active.return_value = True
        reconnect = Mock(return_value=replacement)
        result = {'status':'LAB_CORE_INSTALLED', 'runtime':'OFF', 'edge_connected':False}
        with patch.object(prepare, 'remote', side_effect=[EOFError(), json.dumps(result).encode()]) as remote, \
             patch.object(prepare.time, 'monotonic', return_value=100), \
             patch.object(prepare.time, 'sleep'):
            client, observed = prepare.wait_for_install(reconnect, original, '/root/nvl-lab-import-test')
        self.assertIs(client, replacement)
        self.assertEqual(observed, result)
        reconnect.assert_called_once_with()
        original.close.assert_called_once_with()
        self.assertTrue(all('result.json' in c.args[1] and 'nohup' not in c.args[1]
                            for c in remote.call_args_list))

    def test_cli_reads_destination_from_terminal_under_heredoc(self):
        with patch('builtins.open') as opened:
            handle = opened.return_value.__enter__.return_value
            handle.readline.return_value = '8.8.4.4\n'
            self.assertEqual(prepare.tty_line('IP: '), '8.8.4.4')
            opened.assert_called_once_with('/dev/tty', 'r+')
