"""K2 P3 installer tests: real manifest + fail-closed fake root host."""
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from ops.k2_p3_guard_installer import (
    GuardInstallHold, plan_guard_install, apply_guard_install,
    _pam_append_before_first_account,
)
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests


class FakePort:
    def __init__(self):
        self.actions=[]
    def create(self,p,data):
        self.actions.append(("create",str(p),len(data)))
    def command(self,*args):
        self.actions.append(("cmd",tuple(args)))
    def replace_exact(self,p,before,after):
        self.actions.append(("pam",str(p)))
        self.pam_after=after


class GuardInstallerTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        m=self.fx.manifest
        req=m.request
        raw=json.dumps({
            "mode":m.mode,"username":req.username,"uid":req.uid,
            "priority":req.priority,"spec":asdict(req.spec),
            "dns_port":m.dns_port,"ingress_return":True,"shared_edge":True,
        },sort_keys=True,separators=(",",":")).encode()
        self.raw=raw
        self.pam=b"auth required pam_unix.so\naccount required pam_unix.so\n"
        self.module="a"*64

    def plan(self,**changes):
        opts=dict(username="nvl0557",manifest_bytes=self.raw,
            pam_before=self.pam,module_sha256=self.module,
            existing_guard_bytes={},os_uid=self.fx.lookup,
            expected_pam_sha256=sha256(self.pam).hexdigest())
        opts.update(changes)
        return plan_guard_install(**opts)

    def test_pure_plan_contains_pinned_guard_roster_and_isolated_units(self):
        p=self.plan()
        self.assertTrue(p.guard_unit_name.startswith("nvl-egress-guard-"))
        self.assertIn("PROTECTED_BOOT_GUARD",p.manifest_bytes.decode())
        self.assertIn('"nvl0557"',p.roster_bytes.decode())
        self.assertIn("ExecStart=",p.guard_unit)
        self.assertNotIn("ssh.service",p.guard_unit+p.dns_unit)
        self.assertTrue(p.fingerprint)
        lines=p.pam_after.decode().splitlines()
        self.assertLess(lines.index("account requisite pam_exec.so quiet /usr/bin/python3 /opt/nvl-egress/edge_egress_v1_admission.py"),
                        lines.index("account required pam_unix.so"))

    def test_reject_os_identity_or_existing_uid_ownership(self):
        with self.assertRaises(GuardInstallHold):
            self.plan(os_uid=lambda _:1655)
        with self.assertRaises(GuardInstallHold):
            self.plan(existing_guard_bytes={"nvl0557":self.raw})
        with self.assertRaises(GuardInstallHold):
            self.plan(expected_pam_sha256="f"*64)

    def test_pam_duplicate_guard_and_unreviewed_account_exec_refused(self):
        from edge_egress_v1_admission import PAM_LINE
        for raw in (self.pam+PAM_LINE.encode()+b"\n",
                    b"account required pam_exec.so /tmp/script\n",
                    b"account requisite pam_exec.so /tmp/script\n"):
            with self.subTest(raw=raw),self.assertRaises(GuardInstallHold):
                _pam_append_before_first_account(raw)

    def test_disabled_no_probes_no_artifacts(self):
        p=self.plan()
        port=FakePort()
        with self.assertRaises(GuardInstallHold):
            apply_guard_install(
                plan=p,current_pam=self.pam,existing_guards={},
                os_uid=self.fx.lookup,port=port,reviewed_module_sha=self.module)
        self.assertEqual(port.actions,[])

    def test_missing_rescue_or_active_ssh_uid_denied(self):
        p=self.plan()
        port=FakePort()
        base=dict(plan=p,current_pam=self.pam,existing_guards={},
                  os_uid=self.fx.lookup,port=port,release_enabled=True,
                  reviewed_module_sha=self.module,geteuid=lambda:0,
                  sshd_effective_probe=lambda:"usepam yes\\n")
        with self.assertRaisesRegex(GuardInstallHold,"INDEPENDENT_RESCUE"):
            apply_guard_install(**base,
                independent_console_ok=lambda:False,
                account_idle_ok=lambda n,u:True)
        with self.assertRaisesRegex(GuardInstallHold,"LIVE_UID_NOT_IDLE"):
            apply_guard_install(**base,
                independent_console_ok=lambda:True,
                account_idle_ok=lambda n,u:False)
        self.assertEqual(port.actions,[])

    def test_success_orders_deny_before_pam_last(self):
        plan=self.plan()
        port=FakePort()
        fake_pam=[self.pam]
        class Guard:
            def verify(self,man,require_frozen=False):
                self.__class__.calls.append(require_frozen)
            calls=[]
        with patch("ops.k2_p3_guard_installer.verify_installed_gate_digest",
                   return_value=True), \
             patch("ops.k2_p3_guard_installer._safe_read",
                   side_effect=lambda p,**kw:fake_pam[0] if p==Path("/etc/pam.d/sshd") else b""), \
             patch("ops.k2_p3_guard_installer._owned"), \
             patch("edge_egress_uid_boot.BootGuardApplier",Guard):
            # The fake port records exact PAM CAS but does not touch the host.
            original=port.replace_exact
            def cas(path,before,after):
                original(path,before,after)
                fake_pam[0]=after
            port.replace_exact=cas
            apply_guard_install(
                plan=plan,current_pam=self.pam,existing_guards={},
                os_uid=self.fx.lookup,port=port,release_enabled=True,
                independent_console_ok=lambda:True,
                account_idle_ok=lambda n,u:True,
                reviewed_module_sha=self.module,geteuid=lambda:0,
                sshd_effective_probe=lambda:"usepam yes\\n")
        ops=[x[0] for x in port.actions]
        self.assertEqual(ops[:5],["create"]*5)
        self.assertEqual(ops[-1],"pam")
        self.assertEqual(Guard.calls,[True])
        self.assertTrue(any("enable" in x[1] and plan.guard_unit_name in x[1]
                            for x in port.actions if x[0]=="cmd"))

    def test_guard_failure_never_installs_pam_or_deprotects(self):
        plan=self.plan()
        port=FakePort()
        class BrokenGuard:
            def verify(self,*args,**kw):
                raise ValueError("UNVERIFIED_GUARD")
        with patch("ops.k2_p3_guard_installer.verify_installed_gate_digest",
                   return_value=True),\
             patch("ops.k2_p3_guard_installer._safe_read",return_value=self.pam),\
             patch("ops.k2_p3_guard_installer._owned"),\
             patch("edge_egress_uid_boot.BootGuardApplier",BrokenGuard):
            with self.assertRaises(ValueError):
                apply_guard_install(
                    plan=plan,current_pam=self.pam,existing_guards={},
                    os_uid=self.fx.lookup,port=port,release_enabled=True,
                    independent_console_ok=lambda:True,
                    account_idle_ok=lambda n,u:True,
                    reviewed_module_sha=self.module,geteuid=lambda:0,
                    sshd_effective_probe=lambda:"usepam yes\\n")
        self.assertNotIn("pam",[x[0] for x in port.actions])
        self.assertTrue(any(x[0]=="create" for x in port.actions))


if __name__=="__main__":
    unittest.main()
