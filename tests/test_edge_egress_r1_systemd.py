"""R1 persistent transport boundary tests: fake commands, no host mutation."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from edge_egress_r1_reconcile import (
    R1RecoveryInputs, assess_r1_recovery,
)
from edge_egress_r1_systemd import (
    R1BootContract, R1ServiceUnsafe, assert_disposable_identity,
    read_contract, render_unit, start_disposable_transport,
)
from edge_egress_r1_transport import R1Observation
from ops.edge_egress_provision import EgressSpec


def spec():
    return EgressSpec(
        edge_id="fra1", edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.110.0/30", veth_network="10.78.111.0/30",
        edge_uplink="eth0", edge_listen_port=51842, route_table=1790
    )


def contract(role="core"):
    return R1BootContract(
        spec(), role, {x: "a" * 64 for x in (
            "manifest.json", "wg.conf", "up.sh", "down.sh")},
        "f" * 32, hashlib.sha256(b"disposable-marker").hexdigest()
    )


def observation(role="core", *, valid=True):
    return R1Observation(
        role, valid, role == "core", role == "core", True, False,
        False, role == "edge", False, (), valid,
    )


class R1SystemdTests(unittest.TestCase):
    def test_render_offline_service_no_global_ssh_or_autocleanup(self):
        text = render_unit(contract(), "a" * 64)
        self.assertIn("After=network-online.target", text)
        self.assertIn("Type=oneshot", text)
        self.assertIn("RemainAfterExit=yes", text)
        self.assertIn("Restart=no", text)
        self.assertIn("WantedBy=multi-user.target", text)
        self.assertIn("r1-fra1-core.json", text)
        self.assertIn("start --manifest", text)
        self.assertNotIn("ExecStop=", text)
        self.assertNotIn("ssh.service", text.split("[Install]")[0])
        self.assertNotIn("BindsTo=", text)
        self.assertNotIn("wg0", text)
        self.assertNotIn("edge_egress_protected_mode", text)

    def test_reject_unpinned_unit_digest(self):
        with self.assertRaisesRegex(R1ServiceUnsafe, "UNREVIEWED_UNIT_INPUT"):
            render_unit(contract(), "not-sha")
        with self.assertRaisesRegex(R1ServiceUnsafe, "UNREVIEWED_UNIT_INPUT"):
            render_unit(contract(), "a" * 64, Path("/tmp/evil.py"))

    def test_direct_dataclass_forgery_cannot_change_boot_mode_or_role(self):
        for changed in (replace(contract(), mode="PRODUCTION"),
                        replace(contract(), role="edge\nExecStart=evil")):
            with self.assertRaisesRegex(R1ServiceUnsafe, "ROLE_OR_MODE"):
                render_unit(changed, "a" * 64)
            with self.assertRaisesRegex(R1ServiceUnsafe, "ROLE_OR_MODE"):
                start_disposable_transport(changed)

    def test_contract_schema_strict_and_no_customer_mode(self):
        data = dict(spec=asdict(spec()), role="core",
                    stage_sha256=contract().stage_sha256,
                    machine_id="f" * 32,
                    disposable_marker_sha256=contract().disposable_marker_sha256,
                    mode="DISPOSABLE_ONLY")
        self.assertEqual(R1BootContract.parse(data), contract())
        data["mode"] = "PRODUCTION"
        with self.assertRaisesRegex(R1ServiceUnsafe, "INVALID_BOOT_CONTRACT"):
            R1BootContract.parse(data)
        data["mode"] = "DISPOSABLE_ONLY"
        data["other"] = "disabled"
        with self.assertRaisesRegex(R1ServiceUnsafe, "FIELDS"):
            R1BootContract.parse(data)

    def test_manifest_path_sha_verification_and_tamper(self):
        c = contract()
        data = dict(spec=asdict(c.spec), role=c.role,
                    stage_sha256=c.stage_sha256, machine_id=c.machine_id,
                    disposable_marker_sha256=c.disposable_marker_sha256,
                    mode=c.mode)
        raw = json.dumps(data).encode("utf-8")
        sha = hashlib.sha256(raw).hexdigest()
        with TemporaryDirectory() as d, patch(
            "edge_egress_r1_systemd.MANIFEST_ROOT", Path(d)
        ), patch(
            "edge_egress_r1_systemd._read_checked", return_value=raw
        ):
            self.assertEqual(
                read_contract(Path(d) / c.filename(), sha), c)
            with self.assertRaisesRegex(R1ServiceUnsafe, "SHA_CHANGED"):
                read_contract(Path(d) / c.filename(), "0" * 64)
            with self.assertRaisesRegex(R1ServiceUnsafe, "PATH_MISMATCH"):
                read_contract(Path(d) / "foreign.json", sha)

    def test_disposable_host_identity_required(self):
        c = contract()
        with TemporaryDirectory() as d:
            machine_id = Path(d) / "machine-id"
            marker = Path(d) / "marker"
            machine_id.write_text(c.machine_id + "\n")
            with patch("edge_egress_r1_systemd._read_checked",
                       return_value=b"disposable-marker"):
                assert_disposable_identity(
                    c, marker=marker, machine_id=machine_id)
                machine_id.write_text("1" * 32)
                with self.assertRaisesRegex(R1ServiceUnsafe,
                                            "DISPOSABLE_HOST_ID_MISMATCH"):
                    assert_disposable_identity(
                        c, marker=marker, machine_id=machine_id)
            with patch("edge_egress_r1_systemd._read_checked",
                       return_value=b"wrong-marker"):
                with self.assertRaisesRegex(R1ServiceUnsafe, "MARKER_MISMATCH"):
                    assert_disposable_identity(
                        c, marker=marker, machine_id=machine_id)

    def _start(self, *, c=None, stage_owned=True, preflight=True,
               after=None, exit_code=0):
        c = c or contract()
        events = []
        fake = SimpleNamespace(returncode=exit_code)
        def owned(*args):
            events.append("pin")
            return stage_owned
        def run(script):
            events.append("start")
            return fake
        def check(*args):
            events.append("precheck")
            return {"ok":preflight, "issues": [] if preflight else ["COLLISION"]}
        def observed():
            events.append("inspect")
            return after or observation(c.role)
        def action():
            with patch("edge_egress_r1_systemd.os.geteuid", return_value=0), \
                 patch("edge_egress_r1_systemd.assert_disposable_identity"), \
                 patch("edge_egress_r1_systemd._stage_owned", side_effect=owned):
                return start_disposable_transport(
                    c, executor=run, precheck=check, observe=observed)
        return action, events

    def test_start_happy_path_requires_pin_precheck_and_proof(self):
        action, events = self._start()
        self.assertEqual(action(), "TRANSPORT_ONLY_NOT_CUSTOMER_READY")
        self.assertEqual(events, ["pin","precheck","pin","start","inspect"])

    def test_stage_mismatch_never_calls_executor(self):
        action, events = self._start(stage_owned=False)
        with self.assertRaisesRegex(R1ServiceUnsafe, "STAGE_SHA"):
            action()
        self.assertEqual(events, ["pin"])

    def test_foreign_resources_halt_before_executor(self):
        action, events = self._start(preflight=False)
        with self.assertRaisesRegex(R1ServiceUnsafe, "RESOURCE_COLLISION"):
            action()
        self.assertEqual(events, ["pin","precheck"])

    def test_failed_start_remains_hold_no_down_or_cleanup(self):
        action, events = self._start(exit_code=1)
        with self.assertRaisesRegex(R1ServiceUnsafe, "UNCERTAIN_HOLD"):
            action()
        self.assertEqual(events, ["pin","precheck","pin","start"])

    def test_post_start_no_identity_is_hold(self):
        action, events = self._start(after=observation(valid=False))
        with self.assertRaisesRegex(R1ServiceUnsafe, "IDENTITY_UNCERTAIN_HOLD"):
            action()
        self.assertEqual(events, ["pin","precheck","pin","start","inspect"])

    def test_never_start_without_root(self):
        action, events = self._start()
        with patch("edge_egress_r1_systemd.os.geteuid", return_value=1000):
            with self.assertRaisesRegex(R1ServiceUnsafe, "ROOT_REQUIRED"):
                start_disposable_transport(contract())
        self.assertEqual(events, [])


def recovery(**changes):
    base = R1RecoveryInputs(
        R1Observation("core", True, True, True, True, True,
                      True, False, False, (), True),
        False, 0, False, False, False
    )
    return R1RecoveryInputs(**dict(
        transport=changes.get("transport", base.transport),
        shared_6g_running=changes.get("shared_6g_running", base.shared_6g_running),
        protected_binding_count=changes.get("protected_binding_count",
                                            base.protected_binding_count),
        protected_uid_guards_attested=changes.get(
            "protected_uid_guards_attested", base.protected_uid_guards_attested),
        protected_ssh_gate_attested=changes.get(
            "protected_ssh_gate_attested", base.protected_ssh_gate_attested),
        outstanding_recovery_marker=changes.get("outstanding_recovery_marker",
                                                base.outstanding_recovery_marker),
    ))


class R1ReconcileTests(unittest.TestCase):
    def test_running_is_transport_only_and_never_auto_reattaches_uid(self):
        result = assess_r1_recovery(recovery())
        self.assertEqual(result.state, "TRANSPORT_ONLY")
        self.assertFalse(result.customer_ready)
        self.assertFalse(result.network_mutation_allowed)
        self.assertFalse(result.uid_attach_allowed)

    def test_unknown_missing_db_schema_or_journal_holds(self):
        result = assess_r1_recovery(recovery(protected_binding_count=None))
        self.assertEqual(result.reason, "JOURNAL_OR_UID_GUARD_EVIDENCE_UNKNOWN")

    def test_open_6g_lease_blocks_automatic_recovery(self):
        self.assertEqual(assess_r1_recovery(recovery(
            shared_6g_running=True)).reason,
            "SHARED_6G_RECOVERY_LEASE_ACTIVE")

    def test_marker_retains_operator_hold(self):
        self.assertEqual(assess_r1_recovery(recovery(
            outstanding_recovery_marker=True)).state, "HOLD")

    def test_existing_protected_uid_without_pam_attestation_holds(self):
        self.assertEqual(assess_r1_recovery(recovery(
            protected_binding_count=1,
            protected_uid_guards_attested=True,
            protected_ssh_gate_attested=False)).reason,
            "PROTECTED_UID_ADMISSION_NOT_ATTESTED")

    def test_existing_protected_uid_even_with_guard_requires_f2_witness(self):
        result = assess_r1_recovery(recovery(
            protected_binding_count=1,
            protected_uid_guards_attested=True,
            protected_ssh_gate_attested=True))
        self.assertEqual(result.reason, "PROTECTED_UID_NEEDS_INDEPENDENT_F2_RECONCILE")

    def test_unowned_live_stg1_comes_back_hold_not_adopted(self):
        t = R1Observation("core", True, True, True, False, False, False,
                          False, False)
        self.assertEqual(assess_r1_recovery(
            recovery(transport=t)).state,"HOLD")


if __name__ == "__main__":
    unittest.main()
