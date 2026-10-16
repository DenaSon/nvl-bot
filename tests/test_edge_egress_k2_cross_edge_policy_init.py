"""K2 root V2 policy provisioning: single O_EXCL create, never overwrite.

Uses a disposable directory. Root checks are injected; no /etc host changes.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import edge_egress_k2_uid_ingress_egress as policy


class InitialRootCrossPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"uid-ingress-egress.json"

    def setup_flags(self, *, released=True):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(patch.object(
            policy,"ROOT_BINDINGS",self.path
        ))
        stack.enter_context(patch.object(
            policy,"K2_ROOT_POLICY_INIT_ENABLED",released
        ))
        stack.enter_context(patch.object(policy,"_trusted_directory"))
        stack.enter_context(patch.object(
            policy,"_trusted_bytes",
            side_effect=lambda path,maximum:path.read_bytes()
        ))
        return stack

    def test_default_denies_without_creating_file(self):
        with self.setup_flags(released=False):
            with self.assertRaisesRegex(policy.IngressEgressHold,"NOT_RELEASED"):
                policy.initialize_empty_root_policy(
                    geteuid=lambda:0,release_enabled=True
                )
        self.assertFalse(self.path.exists())

    def test_root_explicit_release_creates_private_empty_policy_once(self):
        with self.setup_flags():
            policy.initialize_empty_root_policy(
                geteuid=lambda:0,release_enabled=True
            )
            self.assertEqual(policy.parse_uid_ingress_egress_bindings(
                self.path.read_bytes()
            ),{})
            self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
            before=self.path.read_bytes()
            with self.assertRaisesRegex(policy.IngressEgressHold,"ALREADY_EXISTS"):
                policy.initialize_empty_root_policy(
                    geteuid=lambda:0,release_enabled=True
                )
            self.assertEqual(self.path.read_bytes(),before)

    def test_nonroot_or_unapproved_release_cannot_touch_file(self):
        with self.setup_flags():
            for uid,release in ((1000,True),(0,False)):
                with self.subTest(uid=uid,release=release):
                    with self.assertRaisesRegex(policy.IngressEgressHold,"NOT_RELEASED"):
                        policy.initialize_empty_root_policy(
                            geteuid=lambda:uid,release_enabled=release
                        )
        self.assertFalse(self.path.exists())

    def test_symlink_never_replaced(self):
        protected=Path(self.temp.name)/"other.json"
        protected.write_bytes(b"KEEP")
        self.path.symlink_to(protected)
        with self.setup_flags():
            with self.assertRaisesRegex(policy.IngressEgressHold,"ALREADY_EXISTS"):
                policy.initialize_empty_root_policy(
                    geteuid=lambda:0,release_enabled=True
                )
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(protected.read_bytes(),b"KEEP")


if __name__=="__main__":
    unittest.main()
