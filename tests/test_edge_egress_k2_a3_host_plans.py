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
        with patch.object(a,"load_roster",return_value={"nvl0557":prior}),\
             patch.object(a,"render_roster",return_value="canonical"),\
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
        with patch.object(a,"load_roster",return_value={"nvl0557":prior}),\
             patch.object(a,"render_roster",return_value="canonical"),\
             patch.object(a,"plan_next_uid") as planner:
            with self.assertRaisesRegex(a.A3PlanHold,"ORPHANED_OR_MISSING_GUARD"):
                self.src(self.scope,self.ticket)
            planner.assert_not_called()

    def test_next_uid_rejects_candidate_in_protected_db_without_roster(self):
        prior=SimpleNamespace(uid=1644,guard_sha256=sha256(self.guard).hexdigest())
        self.mock_sources(roster_exists=True,roster_bytes=b"canonical")
        with patch.object(a,"load_roster",return_value={"nvl0557":prior}),\
             patch.object(a,"render_roster",return_value="canonical"),\
             patch.object(a,"plan_next_uid") as planner:
            for table in ("edge_egress_uid_runtime","edge_egress_uid_bindings"):
                with self.subTest(table=table):
                    status_column="state" if table.endswith("runtime") else "status"
                    self.fx.c.execute(
                        "INSERT INTO "+table+" (username,uid,edge_id,edge_ipv4,"
                        +status_column+") VALUES (?,?,?,?,?)",
                        ("nvl0555",1636,"e9",TARGET,"PROTECTED"),
                    )
                    with self.assertRaisesRegex(
                        a.A3PlanHold,"CANDIDATE_RUNTIME_ALREADY_BOUND"
                    ):
                        self.src(self.scope,self.ticket)
                    self.fx.c.execute("DELETE FROM "+table)
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



class RootOwnedSnapshotWiringTests(unittest.TestCase):
    """Source wiring, not an independent physical witness or server release."""

    def setUp(self):
        from dataclasses import replace
        from edge_egress_k2_migration_inventory import LiveIngressWitness
        from edge_egress_uid_policy import UIDPolicyRequest
        from ops.k2_p3_uid_worker import IndependentSafety
        from tests.test_edge_egress_uid_runtime_store import req as sample_req

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
        self.uid=lambda name:fx.uids[name]
        self.root=lambda:0
        self.pam=b"synthetic root-only pam bytes\n"
        self.manifest_raw=b'{"synthetic":"not-a-real-host-manifest"}'
        self.request=UIDPolicyRequest(
            replace(sample_req().spec,edge_id="e9",edge_public_ipv4=TARGET),
            "nvl0555",1636,
        )
        self.manifest=SimpleNamespace(
            request=self.request,dns_port=11053,
        )
        self.safety=IndependentSafety(
            db_conn=fx.db,target_edge_id="e9",source_ipv4=TARGET,
            ingress_rhost="10.77.0.3",ssh_local_addr="10.77.0.1",
            ssh_local_port=2252,reviewed_module_sha256="a"*64,
            packet_witness=lambda req:True,
            neighbour_witness=lambda req:True,
        )
        self.gates=a.RootHostSafetyGates(
            safety=self.safety,independent_rescue_ok=lambda:True,
            independent_f4_ok=lambda scope:True,
            mixed_legacy_pam_ok=lambda:True,
            account_idle_ok=lambda name,uid:True,
            sshd_effective_probe=lambda:"UsePAM yes",
            guard_frozen_ok=lambda manifest:True,
            dns_ipv6_ok=lambda manifest:True,
        )
        self.review=lambda selection:fx.preview(
            selection.usernames,
            ingress_witness=lambda name:LiveIngressWitness(
                name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE",
            ),
        )
        self.calls=[]
        self.plan_src=a.RootOwnedM2PlanSource(
            db_conn=fx.db,os_uid=self.uid,geteuid=self.root,
        )
        self.adapter=a.RootOwnedUIDSnapshotSource(
            plan_source=self.plan_src,
            inventory_provider=self.review,
            gates_provider=lambda scope,member:(
                self.calls.append("gates") or self.gates
            ),
            db_conn=fx.db,os_uid=self.uid,geteuid=self.root,
        )
        self.plan=self.first_plan()

    def first_plan(self):
        from ops.k2_p3_guard_installer import GuardInstallPlan
        return GuardInstallPlan(
            "nvl0555",1636,self.manifest_raw,
            sha256(self.manifest_raw).hexdigest(),
            b"roster", "guard unit","dns unit",
            "nvl-egress-guard-nvl0555.service",
            "nvl-egress-dns-nvl0555.service",
            sha256(self.pam).hexdigest(),b"new pam","a"*64,
        )

    def next_plan(self):
        from ops.k2_m2_guard_append import MultiUIDAppendPlan
        return MultiUIDAppendPlan(
            "nvl0555",1636,"e9",TARGET,self.manifest_raw,
            b"old roster",b"new roster",
            "nvl-egress-guard-nvl0555.service","guard unit",
            "nvl-egress-dns-nvl0555.service","dns unit",
            sha256(self.pam).hexdigest(),"a"*64,
        )

    def root_plan(self,kind,plan,pam_hash=None):
        return a.ReviewedRootM2Plan(
            self.scope,self.ticket,kind,plan,
            sha256(self.manifest_raw).hexdigest(),
            pam_hash or sha256(self.pam).hexdigest(),"a"*64,
        )

    def call_bound(self,kind="FIRST_UID",plan=None,pam_hash=None,pam_bytes=None):
        item=self.root_plan(kind,plan if plan is not None else self.plan,pam_hash)
        with patch.object(a,"A3_ROOT_SNAPSHOT_BINDING_ENABLED",True),\
             patch.object(a.RootOwnedM2PlanSource,"__call__",return_value=item),\
             patch.object(a,"_read_checked",return_value=(self.pam if pam_bytes is None else pam_bytes)),\
             patch.object(a.BootGuardManifest,"parse",return_value=self.manifest):
            return self.adapter(self.scope,self.ticket)

    def test_default_off_and_cross_edge_hold_without_probe_or_plan(self):
        self.assertFalse(a.A3_ROOT_SNAPSHOT_BINDING_ENABLED)
        with self.assertRaisesRegex(a.A3PlanHold,"RELEASE_REQUIRED"):
            self.adapter(self.scope,self.ticket)
        with patch.object(a,"A3_ROOT_SNAPSHOT_BINDING_ENABLED",True):
            bad=ExecutionScope(
                "UID_ATTACH","e9","172.86.111.69",TARGET,
                username="nvl0555",uid=1636,
            )
            with self.assertRaisesRegex(a.A3PlanHold,"RELEASE_REQUIRED"):
                self.adapter(bad,self.ticket)
        self.assertEqual(self.calls,[])

    def test_first_uid_builds_deferred_bootstrap_without_host_writes(self):
        from edge_egress_k2_m4_bootstrap import GuardBootstrap
        from edge_egress_k2_a_host_factory import ReviewedUIDHostSnapshot
        from ops.k2_p3_guard_installer import RootFilePort
        snapshot=self.call_bound()
        self.assertIsInstance(snapshot,ReviewedUIDHostSnapshot)
        self.assertIsInstance(snapshot.bootstrap,GuardBootstrap)
        self.assertEqual(snapshot.bootstrap.kind,"FIRST_UID")
        self.assertIsInstance(snapshot.bootstrap.kwargs["port"],RootFilePort)
        self.assertIs(snapshot.bootstrap.kwargs["db_conn"],self.fx.db)
        self.assertEqual(snapshot.bootstrap.kwargs["current_pam"],self.pam)
        self.assertIs(snapshot.request,self.request)
        self.assertEqual(self.calls,["gates"])

    def test_next_uid_uses_existing_cas_port_and_no_auto_resume(self):
        from ops.k2_m2_guard_append import CASRootRosterPort
        snapshot=self.call_bound("NEXT_UID",self.next_plan())
        self.assertEqual(snapshot.bootstrap.kind,"NEXT_UID")
        self.assertIsInstance(snapshot.bootstrap.kwargs["port"],CASRootRosterPort)
        self.assertIs(snapshot.bootstrap.kwargs["resume_partial"],False)
        self.assertNotIn("current_pam",snapshot.bootstrap.kwargs)

    def test_root_pam_drift_denied_before_gates_or_bootstrap(self):
        with self.assertRaisesRegex(a.A3PlanHold,"PAM_CHANGED"):
            self.call_bound(pam_bytes=b"unexpected PAM drift on disk")
        self.assertEqual(self.calls,[])

    def test_m2_plan_pam_and_module_digest_drift_rejected(self):
        from dataclasses import replace
        wrong_first=replace(self.plan,module_sha256="0"*64)
        with self.assertRaisesRegex(a.A3PlanHold,"ROOT_PLAN_DIGEST_DRIFT"):
            self.call_bound(plan=wrong_first)
        wrong_next=replace(self.next_plan(),pam_digest="0"*64)
        with self.assertRaisesRegex(a.A3PlanHold,"ROOT_PLAN_DIGEST_DRIFT"):
            self.call_bound("NEXT_UID",wrong_next)
        self.assertEqual(self.calls,[])

    def test_unbound_external_safety_rejected(self):
        from dataclasses import replace
        self.gates=replace(self.gates,safety=None)
        with self.assertRaisesRegex(a.A3PlanHold,"PHYSICAL_WITNESS"):
            self.call_bound()

    def test_factory_receives_real_typed_snapshot_and_defers_sixg(self):
        import edge_egress_k2_a_host_factory as factory
        from edge_egress_k2_m4_bootstrap import DeferredOriginal6GHostPort
        host=factory.ReviewedM2P3HostFactory(
            db_conn=self.fx.db,read_root_snapshot=self.adapter,
            os_uid=self.uid,geteuid=self.root,release_enabled=True,
        )
        item=self.root_plan("FIRST_UID",self.plan)
        with patch.object(factory,"M4A_REAL_HOST_FACTORY_ENABLED",True),\
             patch.object(a,"A3_ROOT_SNAPSHOT_BINDING_ENABLED",True),\
             patch.object(a.RootOwnedM2PlanSource,"__call__",return_value=item),\
             patch.object(a,"_read_checked",return_value=self.pam),\
             patch.object(a.BootGuardManifest,"parse",return_value=self.manifest):
            port=host(self.scope,self.ticket,self.review)
        self.assertIsInstance(port,DeferredOriginal6GHostPort)
        self.assertFalse(port._started)
        self.assertEqual(self.calls,["gates"])



if __name__=="__main__":
    unittest.main()
