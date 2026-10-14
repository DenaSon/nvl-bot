"""Reviewable root-only Python tree: hash pins, closure and no overwrite."""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops.k2_p3_module_stage import (
    REQUIRED,ModuleStageHold,validate_module_bundle,stage_module_bundle,
    create_public_root_module,
)


class ModuleStageTests(unittest.TestCase):
    def setUp(self):
        self.blobs={name:b'from __future__ import annotations\n'
                    for name in REQUIRED}
        self.blobs["edge_egress_v1_admission.py"]=(
            b"import edge_egress_uid_boot\n"
            b"from ops.edge_egress_provision import EgressSpec\n"
        )
        self.hashes={p:sha256(b).hexdigest() for p,b in self.blobs.items()}

    def test_reviewed_complete_modules_have_stable_digest(self):
        a=validate_module_bundle(self.blobs,self.hashes)
        self.assertEqual(a,validate_module_bundle(dict(reversed(list(self.blobs.items()))),
                                                  self.hashes))
        self.assertEqual(len(a),64)

    def test_missing_dependency_rejected_before_host_mutation(self):
        new=dict(self.blobs)
        new["edge_egress_v1_admission.py"]=b"import edge_egress_missing_dynamic\n"
        dig={p:sha256(b).hexdigest() for p,b in new.items()}
        with self.assertRaisesRegex(ModuleStageHold,"MISSING_LOCAL_PYTHON_IMPORT"):
            validate_module_bundle(new,dig)

    def test_refuse_secret_or_bot_module_paths(self):
        for bad in ("bot_final_v49-2.py",".env","ops/secrets.py",
                    "../app.py","edge_egress_uid_boot.py/../../pw"):
            src=dict(self.blobs);src[bad]=b"print('hi')\n"
            dig={p:sha256(b).hexdigest() for p,b in src.items()}
            with self.subTest(bad=bad),self.assertRaises(ModuleStageHold):
                validate_module_bundle(src,dig)

    def test_hash_drift_or_syntax_error_denied(self):
        dig=dict(self.hashes)
        dig["edge_egress_uid_boot.py"]="0"*64
        with self.assertRaises(ModuleStageHold):
            validate_module_bundle(self.blobs,dig)
        src=dict(self.blobs);src["edge_egress_uid_boot.py"]=b"def !invalid"
        dig={p:sha256(b).hexdigest() for p,b in src.items()}
        with self.assertRaisesRegex(ModuleStageHold,"INVALID_REVIEWED_PYTHON_SOURCE"):
            validate_module_bundle(src,dig)

    def test_live_stager_is_default_off_and_cannot_accept_bad_pin(self):
        with self.assertRaisesRegex(ModuleStageHold,"EXPLICIT_REVIEWED_ROOT"):
            stage_module_bundle(blobs=self.blobs,reviewed_sha256=self.hashes,
                                approved_bundle_digest="0"*64)
        with self.assertRaisesRegex(ModuleStageHold,"REVIEWED_MODULE_BUNDLE_DRIFT"):
            stage_module_bundle(blobs=self.blobs,reviewed_sha256=self.hashes,
                approved_bundle_digest="0"*64,release_enabled=True,
                geteuid=lambda:0,port=lambda path,data:None)

    def test_stage_owned_tree_only_after_full_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/"nvl-egress"
            actions=[]
            approved=validate_module_bundle(self.blobs,self.hashes)
            with patch("ops.k2_p3_module_stage.TARGET",target):
                with patch("ops.k2_p3_module_stage._owned_dir"):
                    result=stage_module_bundle(
                        blobs=self.blobs,reviewed_sha256=self.hashes,
                        approved_bundle_digest=approved,
                        port=lambda p,data:actions.append((p,data)),
                        release_enabled=True,geteuid=lambda:0,
                    )
            self.assertEqual(result,approved)
            self.assertEqual(len(actions),len(self.blobs))
            self.assertTrue(all(p.is_relative_to(target) for p,_ in actions))
            self.assertNotIn("bot_final_v49-2.py",[p.name for p,_ in actions])

    def test_staging_existing_module_does_not_overwrite_or_write_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/"nvl-egress"
            target.mkdir()
            (target/"ops").mkdir()
            (target/"edge_egress_uid_boot.py").write_text("keep")
            actions=[]
            with patch("ops.k2_p3_module_stage.TARGET",target):
                with patch("ops.k2_p3_module_stage._owned_dir"):
                    with self.assertRaisesRegex(ModuleStageHold,"EXISTING_MODULE"):
                        stage_module_bundle(
                            blobs=self.blobs,reviewed_sha256=self.hashes,
                            approved_bundle_digest=validate_module_bundle(
                                self.blobs,self.hashes),
                            port=lambda p,data:actions.append((p,data)),
                            release_enabled=True,geteuid=lambda:0,
                        )
            self.assertEqual(actions,[])
            self.assertEqual((target/"edge_egress_uid_boot.py").read_text(),"keep")


if __name__=="__main__":
    unittest.main()
