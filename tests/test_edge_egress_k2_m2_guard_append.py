"""M2: additive first→Nth UID guard staging and fail-closed roster CAS.

All host mutations and 6G/F4 witnesses are FAKE. Not a physical PAM or
Core cutover acceptance test.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_v1_admission import (
    GUARD_DIR, PAM_LINE, ROSTER, Member, render_roster,
)
from ops.k2_p3_guard_installer import PAM, UNITS
from ops.k2_m2_guard_append import (
    M2_APPEND_ENABLED, MultiUIDHold, plan_next_uid, apply_next_uid,
)
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests

MODULE="a"*64


def encode(manifest):
    req=manifest.request
    return json.dumps({
        "mode":manifest.mode,"username":req.username,"uid":req.uid,
        "priority":req.priority,"spec":asdict(req.spec),
        "dns_port":manifest.dns_port,"ingress_return":True,
        "shared_edge":True,
    },sort_keys=True,separators=(",",":")).encode()


class FakePort:
    def __init__(self, host):
        self.host=host
        self.actions=[]
        self.block_at=None

    def create(self, path, data):
        self.actions.append(("create",str(path)))
        if self.block_at=="create" and len(self.actions)==2:
            raise MultiUIDHold("SYNTHETIC_CRASH")
        self.host[str(path)]=data

    def command(self, *args):
        self.actions.append(("command",tuple(args)))
        if self.block_at=="systemd":
            raise MultiUIDHold("SYNTHETIC_SYSTEMD_FAILURE")

    def replace_roster_exact(self, before, after):
        self.actions.append(("roster_cas",))
        if self.host[str(ROSTER)] != before:
            raise MultiUIDHold("ROSTER_CAS_CHANGED")
        self.host[str(ROSTER)]=after


class M2MultiUIDTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        existing=self.fx.manifest
        self.existing=encode(existing)
        req=replace(existing.request, username="nvl0555", uid=1636, priority=1799)
        self.new=encode(replace(existing,request=req,dns_port=10554))
        self.pam=("auth required pam_unix.so\n"+PAM_LINE+
                  "\naccount required pam_unix.so\n").encode()
        self.guards={"nvl0557":self.existing}
        self.roster=render_roster(self.guards).encode()
        self.host={
            str(PAM):self.pam,
            str(ROSTER):self.roster,
            str(GUARD_DIR/"nvl0557.json"):self.existing,
        }
        self.lookup=lambda n:{"nvl0557":1644,"nvl0555":1636}[n]
        self.plan=self.make_plan()
        self.scope=ExecutionScope(
            "UID_ENROLL_SOURCE","src1",self.plan.edge_ipv4,
            self.plan.edge_ipv4,username="nvl0555",uid=1636)
        self.ticket=ExecutionTicket(
            15,15,"a"*32,99999999999,_scope_digest(self.scope),"b"*64)
        self.port=FakePort(self.host)
        self.checks=[]

    def make_plan(self,**updates):
        kwargs=dict(
            username="nvl0555",manifest_bytes=self.new,
            current_roster=self.roster,
            installed_manifests=self.guards,pam_bytes=self.pam,
            module_digest=MODULE,os_uid=self.lookup)
        kwargs.update(updates)
        return plan_next_uid(**kwargs)

    def apply(self,**updates):
        args=dict(plan=self.plan,db_conn=lambda:None,
                  scope=self.scope,ticket=self.ticket,
                  os_uid=self.lookup,port=self.port,
                  rescue_ok=lambda:True,idle_ok=lambda name,uid:True,
                  independent_f4_ok=lambda scope:True,
                  legacy_pam_ok=lambda:True,
                  sshd_effective=lambda:"usepam yes\n",
                  guard_verify=lambda m:self.checks.append("FROZEN"),
                  release_enabled=True,geteuid=lambda:0)
        args.update(updates)
        return apply_next_uid(**args)

    def mocks(self):
        """Never touch /etc or run systemctl; 6G lease and root bytes faked."""
        return [
            patch("ops.k2_m2_guard_append.M2_APPEND_ENABLED",True),
            patch("ops.k2_m2_guard_append._owned"),
            patch("ops.k2_m2_guard_append._safe_read",
                  side_effect=lambda path,**kw:self.host[str(path)]),
            patch("ops.k2_m2_guard_append.verify_installed_gate_digest",
                  return_value=True),
            patch("ops.k2_m2_guard_append.load_roster",side_effect=lambda:{
                n:Member(n,1644,sha256(raw).hexdigest())
                for n,raw in self.guards.items()
            }),
            patch("ops.k2_m2_guard_append.inspect_pam",return_value=True),
            patch("ops.k2_m2_guard_append.assert_guarded_6g_intent",
                  side_effect=lambda db,scope,ticket:self.checks.append("6G")),
        ]

    def run_with_mocks(self,**kwargs):
        active=self.mocks()
        for p in active:p.start()
        try:return self.apply(**kwargs)
        finally:
            for p in reversed(active):p.stop()

    def test_plan_appends_second_uid_without_changing_first(self):
        self.assertFalse(M2_APPEND_ENABLED)
        self.assertEqual(self.plan.uid,1636)
        self.assertEqual(self.plan.current_roster,self.roster)
        members=json.loads(self.plan.next_roster)["protected"]
        self.assertEqual([m["username"] for m in members],
                         ["nvl0555","nvl0557"])
        self.assertEqual(next(m for m in members
                              if m["username"]=="nvl0557")["guard_sha256"],
                         sha256(self.existing).hexdigest())
        self.assertNotIn("ssh.service",self.plan.guard_unit+self.plan.dns_unit)
        self.assertEqual(len(self.plan.fingerprint),64)

    def test_first_uid_must_use_existing_bootstrap(self):
        with self.assertRaisesRegex(MultiUIDHold,"FIRST_UID_REQUIRES_BOOTSTRAP"):
            self.make_plan(installed_manifests={})

    def test_stale_or_noncanonical_roster_rejected(self):
        with self.assertRaisesRegex(MultiUIDHold,"ROSTER_AND_MANIFESTS"):
            self.make_plan(current_roster=self.roster+b" ")
        with self.assertRaisesRegex(MultiUIDHold,"ROSTER_AND_MANIFESTS"):
            self.make_plan(installed_manifests={"nvl0557":self.new})

    def test_existing_uid_or_username_collision_rejected(self):
        with self.assertRaisesRegex(MultiUIDHold,"MEMBER_ALREADY_EXISTS"):
            self.make_plan(username="nvl0557",manifest_bytes=self.existing)
        new=json.loads(self.new)
        new["uid"]=1644
        with self.assertRaises(ValueError):
            self.make_plan(manifest_bytes=json.dumps(new).encode())

    def test_priority_and_dns_listener_must_be_unique(self):
        new=json.loads(self.new)
        new["priority"]=self.fx.request.priority
        with self.assertRaisesRegex(MultiUIDHold,"PRIORITY_OR_DNS_PORT"):
            self.make_plan(manifest_bytes=json.dumps(new).encode())
        new=json.loads(self.new)
        new["dns_port"]=self.fx.manifest.dns_port
        with self.assertRaisesRegex(MultiUIDHold,"PRIORITY_OR_DNS_PORT"):
            self.make_plan(manifest_bytes=json.dumps(new).encode())

    def test_pam_hook_or_os_identity_required(self):
        with self.assertRaisesRegex(MultiUIDHold,"EXISTING_PAM_HOOK_REQUIRED"):
            self.make_plan(pam_bytes=b"account required pam_unix.so\n")
        with self.assertRaisesRegex(MultiUIDHold,"NEW_UID_IDENTITY"):
            self.make_plan(os_uid=lambda _:1788)

    def test_default_not_released_has_zero_side_effects(self):
        with self.assertRaisesRegex(MultiUIDHold,"ROOT_RELEASE"):
            self.apply()
        self.assertEqual(self.port.actions,[])
        self.assertEqual(self.host[str(ROSTER)],self.roster)

    def test_existing_pam_must_never_be_rewritten(self):
        self.run_with_mocks()
        actions=self.port.actions
        self.assertEqual([x[0] for x in actions],
                         ["create","create","create","command","command",
                          "command","roster_cas"])
        self.assertEqual(self.host[str(PAM)],self.pam)
        self.assertEqual(self.host[str(ROSTER)],self.plan.next_roster)
        self.assertLess(self.checks.index("FROZEN"),
                        len(self.checks)-1)
        self.assertEqual(self.checks[-1],"6G")

    def test_hard_stop_if_rescue_f4_or_mixed_legacy_not_proven(self):
        for kw in (
            {"rescue_ok":lambda:False},
            {"idle_ok":lambda name,uid:False},
            {"independent_f4_ok":lambda scope:False},
            {"legacy_pam_ok":lambda:False},
            {"geteuid":lambda:1000},
            {"os_uid":lambda n:9999},
        ):
            with self.subTest(kw=kw),self.assertRaises(ValueError):
                self.run_with_mocks(**kw)
            self.assertEqual(self.port.actions,[])
            self.assertEqual(self.host[str(ROSTER)],self.roster)

    def test_stale_roster_blocks_before_any_write(self):
        self.host[str(ROSTER)]=b"{}"
        with self.assertRaisesRegex(MultiUIDHold,"ROSTER_CHANGED"):
            self.run_with_mocks()
        self.assertEqual(self.port.actions,[])

    def test_forged_or_drifted_plan_blocks_before_any_write(self):
        self.plan=replace(self.plan,next_roster=b'{"version":1,"protected":[]}')
        with self.assertRaisesRegex(MultiUIDHold,"PLAN_CHANGED_OR_FORGED"):
            self.run_with_mocks()
        self.assertEqual(self.port.actions,[])

    def test_existing_guard_drift_fails_before_any_write(self):
        self.host[str(GUARD_DIR/"nvl0557.json")]=self.new
        with self.assertRaisesRegex(MultiUIDHold,"EXISTING_GUARD_DRIFT"):
            self.run_with_mocks()
        self.assertEqual(self.port.actions,[])

    def test_loss_of_6g_lease_midstage_leaves_roster_unmodified(self):
        patches=self.mocks()
        for p in patches:p.start()
        try:
            counter=[0]
            def lease(*args):
                counter[0]+=1
                if counter[0]==3:
                    raise MultiUIDHold("LEASE_LOST")
            with patch("ops.k2_m2_guard_append.assert_guarded_6g_intent",
                       side_effect=lease):
                with self.assertRaisesRegex(MultiUIDHold,"LEASE_LOST"):
                    self.apply()
            self.assertEqual(self.host[str(ROSTER)],self.roster)
            self.assertFalse(any(x[0]=="roster_cas" for x in self.port.actions))
        finally:
            for p in reversed(patches):p.stop()

    def test_partial_stage_never_overwrites_existing_artifacts(self):
        path=str(GUARD_DIR/"nvl0555.json")
        self.host[path]=self.new
        with patch("ops.k2_m2_guard_append.Path.exists",
                   side_effect=lambda path: str(path) in self.host):
            # This test is about the existing file, not a fake filesystem.
            with self.assertRaises(ValueError):
                self.run_with_mocks()

    def test_systemd_failure_keeps_new_uid_out_of_roster(self):
        self.port.block_at="systemd"
        with self.assertRaisesRegex(MultiUIDHold,"SYNTHETIC_SYSTEMD_FAILURE"):
            self.run_with_mocks()
        self.assertEqual(self.host[str(ROSTER)],self.roster)
        self.assertFalse(any(x[0]=="roster_cas" for x in self.port.actions))

    def test_source_target_scope_mismatch_blocks(self):
        other=ExecutionScope(
            "UID_ENROLL_SOURCE","src1",self.scope.source_host,
            self.scope.target_host,username="nvl0557",uid=1644)
        with self.assertRaisesRegex(MultiUIDHold,"SCOPE_OR_EDGE_MISMATCH"):
            self.run_with_mocks(scope=other)
        self.assertEqual(self.port.actions,[])


if __name__=="__main__":
    unittest.main()
