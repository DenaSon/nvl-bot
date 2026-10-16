"""Immutable source packaging; no live deployment or network I/O."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from ops.k2_release_bundle import build,verify


class SourceBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.repo=self.base/'repo';self.repo.mkdir()
        self.git('init','-q');self.git('config','user.name','tests');self.git('config','user.email','tests@example.invalid')
        (self.repo/'bot_final_v49-2.py').write_text('print("reviewed")\n')
        (self.repo/'edge_egress_k2_m4_root_worker.py').write_text(
            'PINNED_SOURCE_FILES=frozenset(("bot_final_v49-2.py","edge_egress_k2_m4_root_worker.py"))\n')
        (self.repo/'.env').write_text('TEST_SECRET=excluded\n')
        (self.repo/'.env.example').write_text('EXAMPLE=fixture\n')
        (self.repo/'.env.production').write_text('TEST_SECRET=also-excluded\n')
        examples=self.repo/'ops'/'examples';examples.mkdir(parents=True)
        (examples/'edge_egress_fra1.json').write_text('{"edge_id":"fra1"}\n')
        (examples/'edge_egress_stg1.json').write_text('{"edge_id":"stg1"}\n')
        (examples/'private.json').write_text('{"TEST_SECRET":"excluded"}\n')
        (self.repo/'master_bot.db').write_bytes(b'excluded fake db')
        self.git('add','.');self.git('commit','-qm','source fixture')
        self.commit=self.git('rev-parse','HEAD').decode().strip()

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.DEVNULL)

    def unpack(self,path):
        stage=self.base/'stage';stage.mkdir()
        with tarfile.open(path) as archive:archive.extractall(stage,filter='data')
        return stage

    def test_reproducible_pinned_objects_exclude_dirty_code_secrets_and_database(self):
        (self.repo/'bot_final_v49-2.py').write_text('dirty code must not ship')
        out=self.base/'first.tar';digest,manifest=build(self.repo,self.commit,out)
        second=self.base/'second.tar'
        self.assertEqual(build(self.repo,self.commit,second),(digest,manifest))
        stage=self.unpack(out)
        self.assertEqual(verify(stage,self.commit,manifest),6)
        self.assertEqual((stage/'bot_final_v49-2.py').read_text(),'print("reviewed")\n')
        self.assertFalse((stage/'.env').exists());self.assertFalse((stage/'master_bot.db').exists())
        self.assertEqual((stage/'.env.example').read_text(),'EXAMPLE=fixture\n')
        for edge in ('fra1','stg1'):
            self.assertEqual(json.loads((stage/'ops'/'examples'/f'edge_egress_{edge}.json').read_text()),
                             {'edge_id':edge})
        self.assertFalse((stage/'.env.production').exists())
        self.assertFalse((stage/'ops'/'examples'/'private.json').exists())
        release=json.loads((stage/'release.json').read_bytes())
        self.assertEqual(release['git_sha'],self.commit)
        self.assertEqual(sha256(out.read_bytes()).hexdigest(),digest)
        with self.assertRaises(FileExistsError):build(self.repo,self.commit,out)

    def test_tamper_wrong_commit_and_extra_import_file_fail_closed(self):
        out=self.base/'bundle.tar';_,manifest=build(self.repo,self.commit,out);stage=self.unpack(out)
        with self.assertRaises(ValueError):verify(stage,'f'*40,manifest)
        extra=stage/'json.py';extra.write_text('# shadow import')
        with self.assertRaisesRegex(ValueError,'UNEXPECTED'):verify(stage,self.commit,manifest)
        extra.unlink()
        target=stage/'bot_final_v49-2.py';target.write_text('changed')
        with self.assertRaisesRegex(ValueError,'CONTENT_MISMATCH'):verify(stage,self.commit,manifest)

    def test_symlink_sources_and_symlink_stage_cannot_pass(self):
        (self.repo/'unsafe.py').symlink_to('bot_final_v49-2.py')
        self.git('add','unsafe.py');self.git('commit','-qm','bad link')
        head=self.git('rev-parse','HEAD').decode().strip()
        with self.assertRaisesRegex(ValueError,'SYMLINK'):build(self.repo,head,self.base/'bad.tar')
        out=self.base/'good.tar';_,manifest=build(self.repo,self.commit,out);stage=self.unpack(out)
        target=stage/'bot_final_v49-2.py';target.unlink();target.symlink_to(self.repo/'bot_final_v49-2.py')
        with self.assertRaisesRegex(ValueError,'SYMLINK'):verify(stage,self.commit,manifest)

    def test_branch_names_and_short_hashes_are_not_release_pins(self):
        for ref in ('HEAD','master',self.commit[:12],'-h'):
            with self.assertRaises(ValueError):build(self.repo,ref,self.base/'bad.tar')


if __name__=='__main__':unittest.main()
