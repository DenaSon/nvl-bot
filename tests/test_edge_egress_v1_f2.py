"""Small F2 regressions: identity, deny-first, SSH reply route, no host writes."""
import hashlib
import json
import sqlite3
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_boot import BootGuardApplier, BootGuardManifest
from edge_egress_uid_route_state import inspect_owned_routes, ProtectedRouteError
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_v1_admission import (
    AdmissionHold, Member, check_account, inspect_pam, render_pam_review,
    render_roster, render_v1_guard_unit, PAM_LINE, main,
)
from tests.test_edge_egress_uid_boot import FakeKernel, manifest as base_manifest


INGRESS = "10.77.0.0/24 dev wg0 scope link src 10.77.0.1\n"
BH = "blackhole default metric 4096\n"
EDGE = "default via 10.78.101.2 dev vnh-fra1 src 10.78.101.1 metric 100\n"
KW = dict(next_hop="10.78.101.2", device="vnh-fra1", source="10.78.101.1")


def protected_fixture():
    source = base_manifest()
    return replace(source, ingress_return=True, shared_edge=True)


def guard_bytes():
    m = protected_fixture()
    raw = dict(mode=m.mode, username=m.request.username, uid=m.request.uid,
               priority=m.request.priority, dns_port=m.dns_port,
               ingress_return=True, shared_edge=True, spec=m.request.spec.__dict__)
    return json.dumps(raw).encode()


class FakeIngressKernel(FakeKernel):
    def __init__(self):
        super().__init__()
        self.ingress_return = False

    def __call__(self, *args):
        if args[:5] == ("ip", "-4", "route", "replace", "10.77.0.0/24"):
            self.log.append(args)
            self.ingress_return = True
            return SimpleNamespace(returncode=0, stdout="")
        if args == ("ip", "-4", "route", "show", "table", "1780"):
            base = super().__call__(*args)
            return SimpleNamespace(returncode=0, stdout=base.stdout +
                                   (INGRESS if self.ingress_return else ""))
        return super().__call__(*args)


class F2Tests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(":memory:")
        self.c.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT);
            INSERT INTO failover_operations VALUES(42,'SUCCEEDED');
        """)
        install_runtime_schema(self.c)
        install_protected_mapping_schema(self.c)
        self.guard = protected_fixture()
        self.member = Member("nvl0557", 1644, hashlib.sha256(guard_bytes()).hexdigest())
        self.members = {"nvl0557": self.member}

    def tearDown(self):
        self.c.close()

    def protected_row(self, state="PROTECTED"):
        self.c.execute("""
            INSERT INTO edge_egress_uid_runtime
            (username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,state,last_operation_id)
            VALUES('nvl0557',1644,'fra1','216.126.229.12',1780,1780,10553,?,42)
        """, (state,))
        self.c.execute("""
            INSERT INTO edge_egress_uid_bindings
            (username,uid,edge_id,edge_ipv4,status)
            VALUES('nvl0557',1644,'fra1','216.126.229.12','PROTECTED')
        """)

    def decide(self, name="nvl0557", uid=1644, verify=True):
        return check_account(self.c, name, uid, self.members,
                             guard_loader=lambda _: self.guard,
                             guard_probe=lambda conn, row: verify,
                             ingress_probe=lambda row: True)

    def test_only_exact_ingress_return_is_safe(self):
        with self.assertRaises(ProtectedRouteError):
            inspect_owned_routes(EDGE + BH + INGRESS, **KW)
        self.assertTrue(inspect_owned_routes(
            EDGE + BH + INGRESS, allow_ingress_return=True, **KW
        ).edge_attached)
        for bad in (
            "10.77.0.0/24 dev eth0 scope link src 10.77.0.1\n",
            "10.77.0.0/24 dev wg0 scope link src 209.200.246.198\n",
            "10.77.0.0/24 via 10.77.0.8 dev wg0\n",
            INGRESS + INGRESS,
        ):
            with self.subTest(bad=bad), self.assertRaises(ProtectedRouteError):
                inspect_owned_routes(EDGE + BH + bad,
                                     allow_ingress_return=True, **KW)

    def test_boot_installs_reply_route_before_uid_and_freezes_edge(self):
        kernel = FakeIngressKernel()
        kernel.edge_attached = True
        kernel.blackhole = True
        kernel.priority = True
        guard = BootGuardApplier(run=kernel, get_uid=lambda _: 1644,
                                 geteuid=lambda: 0,
                                 read_nss=lambda: "hosts: files dns\n")
        guard.apply(replace(self.guard, shared_edge=False))
        self.assertTrue(kernel.ingress_return)
        self.assertFalse(kernel.edge_attached)
        self.assertTrue(kernel.blackhole)
        self.assertTrue(kernel.priority)
        self.assertTrue(any(x[:5] == ("ip", "-4", "route", "replace",
                                       "10.77.0.0/24") for x in kernel.log))
        self.assertTrue(any(x[:5] == ("ip", "-4", "route", "del",
                                       "default") for x in kernel.log))

    def test_protected_legacy_and_deleted_db_record(self):
        self.assertFalse(self.decide())  # roster says protected, DB says legacy
        self.assertTrue(self.decide(name="nvl_other", uid=1650))
        self.assertFalse(self.decide(name="renamed", uid=1644))
        self.protected_row()
        self.assertTrue(self.decide())
        self.assertFalse(self.decide(uid=1645))
        self.assertFalse(self.decide(verify=False))
        self.c.execute("DELETE FROM edge_egress_uid_runtime")
        self.c.execute("DELETE FROM edge_egress_uid_bindings")
        self.assertFalse(self.decide())  # cannot silently downgrade to legacy

    def test_pending_and_shared_lock_block(self):
        self.protected_row(state="BLOCKED")
        self.assertFalse(self.decide())
        self.c.execute("UPDATE edge_egress_uid_runtime SET state='PROTECTED'")
        self.c.execute("UPDATE failover_operations SET status='RUNNING'")
        self.assertFalse(self.decide())

    def test_roster_render_requires_explicit_guard_and_single_uid_per_edge(self):
        raw = guard_bytes()
        out = json.loads(render_roster({"nvl0557": raw}))
        self.assertEqual(out["protected"][0]["guard_sha256"],
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual(out["protected"][0]["uid"], 1644)
        stripped = json.loads(raw)
        del stripped["ingress_return"]
        with self.assertRaisesRegex(AdmissionHold, "INVALID_MANIFEST_INPUT"):
            render_roster({"nvl0557": json.dumps(stripped).encode()})
        changed = dict(stripped, ingress_return=True, uid=1645, username="nvl0558")
        shared = json.loads(render_roster({
            "nvl0557": raw, "nvl0558": json.dumps(changed).encode()
        }))
        self.assertEqual(len(shared["protected"]), 2)
        changed["uid"] = 1644
        with self.assertRaisesRegex(AdmissionHold, "INVALID_OR_SHARED"):
            render_roster({"nvl0557": raw, "nvl0558": json.dumps(changed).encode()})

    def test_units_and_pam_are_offline_review_only(self):
        unit = render_v1_guard_unit(self.guard)
        self.assertIn("After=local-fs.target wg-quick@wg0.service", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("--enforce", unit)
        self.assertNotIn("ssh.service", unit)
        self.assertNotIn("ExecStop=", unit)
        self.assertIn(PAM_LINE, render_pam_review())
        self.assertTrue(inspect_pam(PAM_LINE + "\n@include common-account\n",
                                    "usepam yes\n"))
        self.assertFalse(inspect_pam("@include common-account\n" + PAM_LINE,
                                     "usepam yes\n"))
        self.assertFalse(inspect_pam(PAM_LINE, "usepam no\n"))

    def test_root_bypass_and_missing_roster_deny_every_other_user(self):
        with patch("edge_egress_v1_admission.os.geteuid", return_value=0), \
             patch.dict("os.environ", {"PAM_TYPE": "account", "PAM_USER": "root"}), \
             patch("edge_egress_v1_admission.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=0)), \
             patch("edge_egress_v1_admission.load_roster",
                   side_effect=AssertionError("root cannot require roster")):
            self.assertEqual(main(), 0)
        with patch("edge_egress_v1_admission.os.geteuid", return_value=0), \
             patch.dict("os.environ", {"PAM_TYPE": "account", "PAM_USER": "nvl0557"}), \
             patch("edge_egress_v1_admission.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)), \
             patch("edge_egress_v1_admission.load_roster",
                   side_effect=AdmissionHold("ROSTER_MISSING")):
            self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
