"""R1 real two-host LAB ingress, current 6G gating and deny-only PAM tests.

Every network, PAM and SQLite operation is mocked. No customer READY proof.
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch
import json

from edge_egress_r1_lab_topology import TwoHostCoreIngress
from edge_egress_r1_lab_pam import decide_lab_pam, PAM_ACCOUNT_LINE
from edge_egress_r1_lab_launcher import (
    R1Lab6GShadow, R1LabUnsafe, CurrentBridge6GLease,
)
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime import attach_protected
from tests.test_edge_egress_r1_lab_launcher import spec, host


def req():
    return UIDPolicyRequest(spec(), "nvlr1test", 1555, 1780)


class TwoHostTopologyTests(TestCase):
    def marker(self):
        m = MagicMock()
        m.is_symlink.return_value = False
        m.is_file.return_value = True
        m.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100600)
        m.read_bytes.return_value = b"test-lab-marker"
        return m

    def test_actual_machine_and_locked_account_allows_lab_source(self):
        import hashlib
        marker = self.marker()
        attestation = TwoHostCoreIngress(
            marker=marker,
            marker_sha256=hashlib.sha256(b"test-lab-marker").hexdigest(),
            machine_id="a" * 32,
        )
        with patch("edge_egress_r1_lab_topology._LAB_MARKER_SHA256", attestation.marker_sha256), patch(
            "edge_egress_r1_lab_topology._LAB_MACHINE_ID", attestation.machine_id
        ), patch("edge_egress_r1_lab_topology.os.geteuid", return_value=0), patch(
            "edge_egress_r1_lab_topology.Path.read_text", return_value="a" * 32
        ), patch(
            "edge_egress_r1_lab_topology.pwd.getpwnam",
            return_value=SimpleNamespace(pw_uid=1555, pw_shell="/usr/sbin/nologin"),
        ), patch(
            "edge_egress_r1_lab_topology.subprocess.run",
            return_value=SimpleNamespace(stdout=json.dumps([{
                "addr_info": [{"local": "107.189.16.36"}]
            }])),
        ):
            self.assertTrue(attestation.for_request(req(), spec().core_public_ipv4))
            self.assertFalse(attestation.for_request(req(), spec().edge_public_ipv4))
            marker.read_bytes.return_value = b"tampered"
            self.assertFalse(attestation.for_request(req(), spec().core_public_ipv4))

    def test_non_root_or_foreign_identity_cannot_be_lab_ingress(self):
        with patch("edge_egress_r1_lab_topology.os.geteuid", return_value=1000):
            self.assertFalse(TwoHostCoreIngress().for_request(
                req(), spec().core_public_ipv4))
        foreign = UIDPolicyRequest(spec(), "somecustomer", 1556, 1780)
        with patch("edge_egress_r1_lab_topology.os.geteuid", return_value=0):
            self.assertFalse(TwoHostCoreIngress().for_request(
                foreign, spec().core_public_ipv4))


class FakeInspectSSH:
    def __init__(self, edge="TRANSPORT_VERIFIED", core="TRANSPORT_VERIFIED"):
        self.states = {"edge": edge, "core": core}
        self.events = []

    def run(self, target, action, wanted):
        self.events.append((target.role, action))
        if action == "inspect":
            return {"ok": True, "role": target.role,
                    "state": self.states[target.role]}
        if action == "probe":
            return {"ok": True, "role": target.role,
                    "state": "OFFLINE_VERIFIED"}
        return {"ok": True, "role": target.role,
                "state": "TRANSPORT_VERIFIED"}


class RunningTransportTests(TestCase):
    def make(self, ssh, enabled=True):
        return R1Lab6GShadow(
            spec(), SimpleNamespace(for_request=lambda r: True),
            lambda r: True, host("edge"), host("core"), ssh,
            explicitly_enabled=True, disposable_vps=True,
            accept_verified_running_transport=enabled,
        )

    def test_both_verified_are_inspected_without_restart(self):
        ssh = FakeInspectSSH()
        asyncio.run(self.make(ssh).start(req()))
        self.assertEqual(ssh.events, [
            ("edge", "inspect"), ("core", "inspect")
        ])

    def test_partial_or_asymmetric_state_is_hold_never_repaired(self):
        ssh = FakeInspectSSH(core="OFFLINE")
        with self.assertRaisesRegex(R1LabUnsafe, "UNCERTAIN_HOLD"):
            asyncio.run(self.make(ssh).start(req()))
        self.assertEqual(ssh.events, [
            ("edge", "inspect"), ("core", "inspect")
        ])

    def test_two_offline_still_require_both_exact_probes_before_start(self):
        ssh = FakeInspectSSH(edge="OFFLINE", core="OFFLINE")
        asyncio.run(self.make(ssh).start(req()))
        self.assertEqual(ssh.events, [
            ("edge", "inspect"), ("core", "inspect"),
            ("edge", "probe"), ("core", "probe"),
            ("edge", "start"), ("core", "start")
        ])

    def test_default_does_not_adopt_existing(self):
        ssh = FakeInspectSSH()
        # This test enforces the backward-compatible default branch:
        # no inspect/adoption unless explicitly requested.
        asyncio.run(self.make(ssh, enabled=False).start(req()))
        self.assertNotIn(("edge", "inspect"), ssh.events)


class LeaseSourceTests(TestCase):
    def test_core_source_requires_attestor_and_same_live_journal(self):
        bridge = SimpleNamespace(
            operation_id=5, source=spec().core_public_ipv4,
            target=spec().edge_public_ipv4, db_conn=lambda: None,
        )
        with patch(
            "edge_egress_r1_lab_launcher.Existing6GR1LeaseProbe.active",
            return_value=True,
        ) as live, patch.object(
            TwoHostCoreIngress, "for_request", return_value=True
        ) as identity:
            self.assertFalse(CurrentBridge6GLease(bridge).for_request(req()))
            self.assertFalse(CurrentBridge6GLease(
                bridge, lambda r, source: True
            ).for_request(req()))
            self.assertTrue(CurrentBridge6GLease(
                bridge, TwoHostCoreIngress()
            ).for_request(req()))
            identity.assert_called_once()
            live.assert_called_once()

    def test_f2_core_ingress_refused_without_attestation(self):
        class Busy:
            async def acquire_6g(self, source, target):
                return None, 0
        port = Busy()
        original = asyncio.run(attach_protected(
            port, req(), source=spec().core_public_ipv4,
            dns_port=10553, authorized=True,
        ))
        self.assertEqual(original.reason, "INVALID_SOURCE_EDGE")
        with patch.object(TwoHostCoreIngress, "for_request",
                          return_value=True):
            allowed = asyncio.run(attach_protected(
                port, req(), source=spec().core_public_ipv4,
                dns_port=10553, authorized=True,
                lab_core_ingress_attestor=TwoHostCoreIngress(),
            ))
        self.assertEqual(allowed.reason, "SHARED_6G_BUSY")
        denied = asyncio.run(attach_protected(
            port, req(), source=spec().core_public_ipv4,
            dns_port=10553, authorized=True,
            lab_core_ingress_attestor=lambda r, source: True,
        ))
        self.assertEqual(denied.reason, "INVALID_SOURCE_EDGE")


class LabPamTests(TestCase):
    def lookup(self, username):
        if username == "root":
            return SimpleNamespace(pw_uid=0)
        if username == "nvlr1test":
            return SimpleNamespace(pw_uid=1555)
        if username == "alias":
            return SimpleNamespace(pw_uid=1555)
        return SimpleNamespace(pw_uid=2001)

    def test_preserves_root_and_unrelated_pam_accounts(self):
        self.assertTrue(decide_lab_pam(
            username="root", pam_type="account", geteuid=0,
            lookup=self.lookup))
        self.assertTrue(decide_lab_pam(
            username="normaladmin", pam_type="account", geteuid=0,
            lookup=self.lookup))
        self.assertFalse(decide_lab_pam(
            username="alias", pam_type="account", geteuid=0,
            lookup=self.lookup))
        self.assertFalse(decide_lab_pam(
            username="root", pam_type="auth", geteuid=0,
            lookup=self.lookup))

    def test_pilot_denied_when_db_absent_and_no_pam_changes(self):
        self.assertFalse(decide_lab_pam(
            username="nvlr1test", pam_type="account", geteuid=0,
            lookup=self.lookup, db=Path("/nonexistent/path/r1.db")))
        self.assertIn("account requisite pam_exec.so", PAM_ACCOUNT_LINE)

    def test_pilot_requires_existing_admission_protected_guard_evidence(self):
        obj = SimpleNamespace(
            request=SimpleNamespace(username="nvlr1test", uid=1555),
            mode="PROTECTED_BOOT_GUARD",
        )
        db = MagicMock()
        db.is_file.return_value = True
        db.is_symlink.return_value = False
        db.absolute.return_value.as_uri.return_value = "file:///tmp/r1.db"
        with patch(
            "edge_egress_r1_lab_pam.read_root_only_manifest",
            return_value=obj,
        ), patch(
            "edge_egress_r1_lab_pam.sqlite3.connect",
        ), patch(
            "edge_egress_r1_lab_pam.decide_account",
            return_value=SimpleNamespace(
                permitted=True, reason="GUARDED_EDGE_ROUTE",
            ),
        ):
            self.assertTrue(decide_lab_pam(
                username="nvlr1test", pam_type="account", geteuid=0,
                lookup=self.lookup, db=db))
        with patch(
            "edge_egress_r1_lab_pam.read_root_only_manifest",
            return_value=obj,
        ), patch(
            "edge_egress_r1_lab_pam.sqlite3.connect",
        ), patch(
            "edge_egress_r1_lab_pam.decide_account",
            return_value=SimpleNamespace(
                permitted=True, reason="NO_PROTECTED_INTENT",
            ),
        ):
            self.assertFalse(decide_lab_pam(
                username="nvlr1test", pam_type="account", geteuid=0,
                lookup=self.lookup, db=db))


if __name__ == "__main__":
    import unittest
    unittest.main()
