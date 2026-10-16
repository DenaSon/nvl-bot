"""Root-only K2 canary UID plan stage: real O_EXCL/0600, disposable path.

Filesystem owner checks use injected fixtures, because CI runs nonroot.
The stage function defaults OFF and requires actual owner-checked directory
on a real host. No PAM/WG action.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ops.k2_m4_plan_stage as stage
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests, TARGET,
)
from tests.test_edge_egress_uid_runtime_store import req


class RootSingleUIDPlanStagingTests(unittest.TestCase):
    def setUp(self):
        fx=K2M1InventoryTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx=fx
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.inventory=fx.preview()
        spec=replace(req().spec,edge_id="e9",edge_public_ipv4=TARGET)
        self.manifest=BootGuardManifest(
            UIDPolicyRequest(spec,"nvl0555",1636),
            "PROTECTED_BOOT_GUARD",11053,True,True,
        )
        self.filename=self.root/"nvl0555.json"

    def _paths(self, released=True):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(patch.object(
            stage,"K2_INITIAL_UID_PLAN_STAGE_ENABLED",released,
        ))
        stack.enter_context(patch.object(stage,"ROOT_PLAN_DIR",self.root))
        stack.enter_context(patch.object(stage,"_verify_root_directory"))
        stack.enter_context(patch.object(
            stage,"_read_checked",side_effect=lambda p,**kw:p.read_bytes(),
        ))
        return stack

    def _stage(self, **kw):
        return stage.stage_single_uid_plan(
            inventory=kw.get("inventory",self.inventory),
            manifest=kw.get("manifest",self.manifest),
            root_dir=self.root,
            geteuid=kw.get("geteuid",lambda:0),
            release_enabled=kw.get("release_enabled",True),
        )

    def test_default_off_even_root_no_plan_created(self):
        with self._paths(released=False):
            with self.assertRaisesRegex(stage.UIDPlanStageHold,"NOT_RELEASED"):
                self._stage()
        self.assertFalse(self.filename.exists())

    def test_one_private_valid_plan_not_deleted_or_rewritten(self):
        with self._paths():
            digest=self._stage()
            raw=self.filename.read_bytes()
            self.assertEqual(sha256(raw).hexdigest(),digest)
            self.assertEqual(self.filename.stat().st_mode & 0o777,0o600)
            self.assertEqual(BootGuardManifest.parse(json.loads(raw)),
                             self.manifest)
            with self.assertRaisesRegex(stage.UIDPlanStageHold,"ALREADY_EXISTS"):
                self._stage()
            self.assertEqual(self.filename.read_bytes(),raw)
        self.assertFalse(any(p.name!="nvl0555.json"
                             for p in self.root.iterdir()))

    def test_wrong_target_scope_is_held_without_writes(self):
        wrong=replace(self.manifest,request=UIDPolicyRequest(
            replace(self.manifest.request.spec,edge_id="other"),
            "nvl0555",1636,
        ))
        with self._paths():
            with self.assertRaisesRegex(stage.UIDPlanStageHold,"SCOPE_CHANGED"):
                self._stage(manifest=wrong)
        self.assertFalse(self.filename.exists())

    def test_f4_missing_or_stale_m1_blocks_initial_file(self):
        self.fx.c.execute(
            "UPDATE edge_egress_readiness SET state='STAGED' WHERE edge_id='e9'"
        )
        changed=self.fx.preview()
        with self._paths():
            with self.assertRaisesRegex(
                stage.UIDPlanStageHold,"SOURCE_TARGET_NOT_ATTESTED"
            ):
                self._stage(inventory=changed)
        self.assertFalse(self.filename.exists())

    def test_nonroot_and_unapproved_staging_never_writes(self):
        with self._paths():
            for other in ({"geteuid":lambda:1001},
                          {"release_enabled":False}):
                with self.subTest(other=other):
                    with self.assertRaisesRegex(
                        stage.UIDPlanStageHold,"NOT_RELEASED"
                    ):
                        self._stage(**other)
        self.assertFalse(self.filename.exists())

    def test_symlink_plan_cannot_replace_external_file(self):
        external=self.root/"external.data"
        external.write_bytes(b"KEEP_UNRELATED")
        self.filename.symlink_to(external)
        with self._paths():
            with self.assertRaisesRegex(stage.UIDPlanStageHold,"ALREADY_EXISTS"):
                self._stage()
        self.assertEqual(external.read_bytes(),b"KEEP_UNRELATED")


if __name__=="__main__":
    unittest.main()
