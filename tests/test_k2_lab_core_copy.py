"""One-shot lab setup boundaries, without any real SSH/systemd/network actions."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from ops import k2_lab_core_copy as lab


class IsolatedLabCopyTests(unittest.TestCase):
    def test_rotated_production_token_is_still_the_same_forbidden_bot(self):
        old='123456789:'+('a'*30)
        for new in (old,'123456789:'+('b'*30)):
            with self.subTest(token=new[-1]):
                with self.assertRaisesRegex(RuntimeError,'PRODUCTION_BOT_TOKEN_FORBIDDEN'):
                    lab.check_test_token(new,old)
        lab.check_test_token('987654321:'+('b'*30),old)

    def test_bad_token_is_rejected_before_any_api_request(self):
        with self.assertRaisesRegex(RuntimeError,'INVALID_TEST_BOT_TOKEN'):
            lab.check_test_token('paste failed','123456789:'+('a'*30))

    def test_admin_ports_are_preserved_and_customer_port_added_once(self):
        self.assertEqual(lab.ssh_ports('port 22\nport 2222\nport 2252\nusepam yes'),
                         [22,2222,2252])
        with self.assertRaisesRegex(RuntimeError,'LAB_ADMIN_SSH_PORT_REQUIRES_REVIEW'):
            lab.ssh_ports('port 2222\nusepam yes')

    def archive(self,path,entries):
        with tarfile.open(path,'w:gz') as tar:
            for name,kind in entries:
                item=tarfile.TarInfo(name)
                if kind=='file':
                    item.size=2;tar.addfile(item,io.BytesIO(b'ok'))
                elif kind=='symlink':
                    item.type=tarfile.SYMTYPE;item.linkname='/etc/shadow';tar.addfile(item)
                elif kind=='hardlink':
                    item.type=tarfile.LNKTYPE;item.linkname='/etc/shadow';tar.addfile(item)

    def test_archive_rejects_links_traversal_and_duplicates_before_any_extraction(self):
        for entry in (('../escape','file'),('/etc/escape','file'),
                      ('site-packages/link','symlink'),('site-packages/link','hardlink'),
                      ('site-packages/ok','file'),('other/ok','file')):
            with self.subTest(entry=entry),tempfile.TemporaryDirectory() as root:
                root=Path(root);out=root/'out';out.mkdir()
                self.archive(root/'p.tar.gz',[('site-packages/ok','file'),entry])
                with self.assertRaises(RuntimeError):
                    lab.safe_extract(root/'p.tar.gz',out,prefix='site-packages')
                self.assertEqual(list(out.iterdir()),[])

    def test_regular_package_archive_is_extracted_privately(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);out=root/'out';out.mkdir()
            self.archive(root/'p.tar.gz',[('site-packages/pkg/example.py','file')])
            lab.safe_extract(root/'p.tar.gz',out,prefix='site-packages')
            p=out/'site-packages/pkg/example.py'
            self.assertEqual(p.read_bytes(),b'ok')
            self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_install_on_wrong_host_never_stops_any_bot_in_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);stage=root/'nvl-lab-import-test';stage.mkdir()
            with patch('sys.argv',['copy','--install',str(stage)]), \
                 patch.object(lab,'ROOT',root), \
                 patch.object(lab,'preflight_lab',side_effect=RuntimeError('WRONG_LAB_HOST')), \
                 patch.object(lab,'install_lab') as install, \
                 patch.object(lab.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'WRONG_LAB_HOST'):
                    lab.main()
                self.assertEqual(json.loads((stage/'result.json').read_text())['status'],
                                 'LAB_PREFLIGHT_FAILED')
        install.assert_not_called();run.assert_not_called()

    def test_export_cannot_be_run_on_destination(self):
        with patch.object(lab.os,'geteuid',return_value=0), \
             patch.object(lab,'local_ipv4s',return_value={lab.LAB_IP}), \
             patch.object(lab.subprocess,'run') as run, \
             patch.object(lab.getpass,'getpass') as secret:
            with self.assertRaisesRegex(RuntimeError,'RUN_ON_ORIGINAL_CORE'):
                lab.copy_from_core(22)
        run.assert_not_called();secret.assert_not_called()

    def test_wrong_release_payload_fails_before_package_or_service_changes(self):
        with tempfile.TemporaryDirectory() as root:
            stage=Path(root)
            (stage/'metadata.json').write_text(json.dumps({'app':'0'*40,'destination':lab.LAB_IP}))
            with patch.object(lab,'preflight_lab'),patch.object(lab,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'LAB_PAYLOAD_IDENTITY_CHANGED'):
                    lab.install_lab(stage)
            run.assert_not_called()


if __name__=='__main__':
    unittest.main()
