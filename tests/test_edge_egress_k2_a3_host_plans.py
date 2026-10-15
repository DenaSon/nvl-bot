"""A3.1 root-only M2 read-only planning (synthetic files and SQLite only)."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import edge_egress_k2_a3_host_plans as a
from edge_egress_p3_executor import ExecutionScope,ExecutionTicket,_scope_digest
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,TARGET,
)


class RootM2ReadOnlyPlanTests(unittest.TestCase):
    def setUp(self):
        fx=K2M1InventoryTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx=fx
        self.scope=ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,
            username="nvl0555",uid=1636,
        )
        self.ticket=ExecutionTicket(
            11,-222,"a"*32,NOW+100,
            _scope_digest(self.scope),"b"*64,
        )
        self.src=a.RootOwnedM2PlanSource(
            db_conn=fx.db,os_uid=lambda name:fx.uids[name],
            geteuid=lambda:0,
        )
        self.manifest=b'{"reviewed":"only-in-tests"}'
        self.pam=b"auth required pam_unix.so\n"
        self.module=b"module source pinned by OS root"
        self.guard=b'{"old":"manifest"}'
        self.proposed=SimpleNamespace(
            shared_edge=True,ingress_return=True,dns_port=11053,
            request=SimpleNamespace(
                username="nvl0555",uid=1636,
                spec=SimpleNamespace(edge_id="e9",edge_public_ipv4=TARGET),
            ),
        )
        self.mockers=[]

    def mock_sources(self,*,roster_exists=False,roster_bytes=b"roster",prior_name="nvl0557",observed_guards=None):
        names=(
            (a.PAM,self.pam),
            (a.MODULE,self.module),
            (a.ROSTER,roster_bytes),
        )
        def read(path,**kw):
            if path==a.ROOT_PLAN_DIR/("nvl0555.json"):
                return self.manifest
            if path==a.GUARD_DIR/(prior_name+".json"):
                return self.guard
            for key,value in names:
                if path==key:
                    return value
            raise AssertionError("unreviewed-root-path:"+str(path))
        guard_names=(
            (prior_name+".json",) if roster_exists else ()
        ) if observed_guards is None else observed_guards
        guard_paths=tuple(a.GUARD_DIR/name for name in guard_names)
        patches=(
            patch.object(a,"_verify_root_directory"),
            patch.object(a,"_read_checked",side_effect=read),
            patch.object(a.BootGuardManifest,"parse",return_value=self.proposed),
            patch.object(a.Path,"is_symlink",return_value=False),
            patch.object(a.Path,"exists",return_value=roster_exists),
            patch.object(a.Path,"iterdir",side_effect=lambda:iter(guard_paths)),
            patch.object(a,"A3_ROOT_OWNED_PLAN_SOURCE_ENABLED",True),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_default_off_and_invalid_nonroot_scope(self):
        self.assertFalse(a.A3_ROOT_OWNED_PLAN_SOURCE_ENABLED)
        with self.assertRaisesRegex(a.A3PlanHold,"EXACT_ROOT_SCOPE"):
            self.src(self.scope,self.ticket)
        cross=ExecutionScope(
            "UID_ATTACH","e9","172.86.111.69",TARGET,
            username="nvl0555",uid=1636,
        )
        with patch.object(a,"A3_ROOT_OWNED_PLAN_SOURCE_ENABLED",True):
            with self.assertRaisesRegex(a.A3PlanHold,"EXACT_ROOT_SCOPE"):
                self.src(cross,self.ticket)
            other=a.RootOwnedM2PlanSource(
                db_conn=self.fx.db,os_uid=self.src.os_uid,geteuid=lambda:1000,
            )
            with self.assertRaisesRegex(a.A3PlanHold,"EXACT_ROOT_SCOPE"):
                other(self.scope,self.ticket)

    def test_first_uid_requires_empty_actual_protected_db_and_no_roster(self):
        self.mock_sources()
        plan_token=object()
        with patch.object(a,"plan_guard_install",return_value=plan_token) as planner:
            result=self.src(self.scope,self.ticket)
        self.assertIs(result.plan,plan_token)
        self.assertEqual(result.kind,"FIRST_UID")
        self.assertEqual(result.scope,self.scope)
        self.assertEqual(result.manifest_sha256,sha256(self.manifest).hexdigest())
        self.assertEqual(result.original_pam_sha256,sha256(self.pam).hexdigest())
        args=planner.call_args.kwargs
        self.assertEqual(args["expected_pam_sha256"],sha256(self.pam).hexdigest())
        self.assertEqual(args["existing_guard_bytes"],{})

    def test_prior_runtime_row_blocks_first_uid_even_with_missing_roster(self):
        self.mock_sources()
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_runtime VALUES"
            "('nvl0557',1644,'e9',?,'PROTECTED')",(TARGET,),
        )
        with patch.object(a,"plan_guard_install") as planner:
            with self.assertRaisesRegex(a.A3PlanHold,"PREVIOUS_PROTECTED"):
                self.src(self.scope,self.ticket)
            planner.assert_not_called()

    def test_next_uid_requires_byte_exact_preexisting_roster(self):
        from types import SimpleNamespace
        prior=SimpleNamespace(
            uid=1644,guard_sha256=sha256(self.guard).hexdigest(),
        )
        roster={ "nvl0557":prior }
        self.mock_sources(roster_exists=True,roster_bytes=b"canonical")
        with patch.object(a,"load_roster",return_value=roster),\
             patch.object(a,"render_roster",return_value="canonical"),\
             patch.object(a,"plan_next_uid",return_value="NEXT_PLAN") as planner:
            result=self.src(self.scope,self.ticket)
        self.assertEqual(result.kind,"NEXT_UID")
        self.assertEqual(result.plan,"NEXT_PLAN")
        self.assertEqual(planner.call_args.kwargs["installed_manifests"],
                         {"nvl0557":self.guard})

    def test_next_uid_holds_on_orphaned_prior_guard_file(self):
        prior=SimpleNamespace(uid=1644,guard_sha256=sha256(self.guard).hexdigest())
        self.mock_sources(
            roster_exists=True,roster_bytes=b"canonical",
            observed_guards=("nvl0557.json","orphan.json"),
        )
        with patch.object(a,"load_roster",return_value={"nvl0557":prior}),\\
             patch.object(a,"render_roster",return_value="canonical"),\\
             patch.object(a,"plan_next_uid") as planner:
            with self.assertRaisesRegex(a.A3PlanHold,"ORPHANED_OR_MISSING_GUARD"):
                self.src(self.scope,self.ticket)
            planner.assert_not_called()

    def test_next_uid_holds_on_missing_prior_guard_in_inventory(self):
        prior=SimpleNamespace(uid=1644,guard_sha256=sha256(self.guard).hexdigest())
        self.mock_sources(
            roster_exists=True,roster_bytes=b"canonical",
            observed_guards=(),
        )
        with patch.object(a,"load_roster",return_value={"nvl0557":prior}),\\
             patch.object(a,"render_roster",return_value="canonical"),\\
             patch.object(a,"plan_next_uid") as planner:
            with self.assertRaisesRegex(a.A3PlanHold,"ORPHANED_OR_MISSING_GUARD"):
                self.src(self.scope,self.ticket)
            planner.assert_not_called()

    def test_roster_changed_never_calls_next_uid_planner(self):
        old=SimpleNamespace(uid=1644,guard_sha256=sha256(self.guard).hexdigest())
        self.mock_sources(roster_exists=True,roster_bytes=b"tampered")
        with patch.object(a,"load_roster",return_value={"nvl0557":old}),\
             patch.object(a,"render_roster",return_value="expected"),\
             patch.object(a,"plan_next_uid") as planner:
            with self.assertRaisesRegex(a.A3PlanHold,"CAS_PREVIEW"):
                self.src(self.scope,self.ticket)
            planner.assert_not_called()


if __name__=="__main__":
    unittest.main()
