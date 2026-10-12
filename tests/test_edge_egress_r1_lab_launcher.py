"""Disposable R1 SSH launcher/host agent tests. All host effects mocked."""
import asyncio
import base64
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_launcher import (
    LabHost, LabSSHExecutor, R1Lab6GShadow, R1LabUnsafe,
)
from edge_egress_r1_lab_agent import LabAgentUnsafe, _request, execute, main
from edge_egress_r1_transport import R1Observation
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def spec():
    return EgressSpec(
        edge_id="lab1", core_public_ipv4="107.189.16.36",
        edge_public_ipv4="216.126.229.12", tunnel_network="10.78.120.0/30",
        veth_network="10.78.121.0/30", edge_uplink="eth0",
        edge_listen_port=51852, route_table=1791, mode="relay",
    )


def host(role):
    return LabHost(
        role=role,
        public_ipv4=spec().core_public_ipv4 if role == "core"
                    else spec().edge_public_ipv4,
        machine_id="1" * 32, marker_sha256="2" * 64,
        stage_sha256={name: "3" * 64 for name in (
            "manifest.json", "wg.conf", "up.sh", "down.sh")},
    )


def payload(role="core"):
    return host(role).payload(spec())


class FakeSSH:
    def __init__(self):
        self.events = []
        self.error_at = None

    def run(self, target, action, requested_spec):
        self.events.append((target.role, action))
        if (target.role, action) == self.error_at:
            raise R1LabUnsafe("REMOTE_UNCERTAIN")
        return {"ok": True, "role": target.role,
                "state": "OFFLINE_VERIFIED" if action == "probe"
                         else "TRANSPORT_VERIFIED"}


class FakeLease:
    def __init__(self):
        self.calls = 0
        self.fail_at = None

    def for_request(self, req):
        self.calls += 1
        return self.calls != self.fail_at


class R1Lab6GTests(unittest.TestCase):
    def setUp(self):
        self.req = UIDPolicyRequest(spec(), "labuser", 1555, 1791)
        self.ssh = FakeSSH()
        self.lease = FakeLease()
        self.guard = True
        self.port = R1Lab6GShadow(
            spec(), self.lease, lambda req: self.guard,
            host("edge"), host("core"), self.ssh,
            explicitly_enabled=True, disposable_vps=True,
        )

    def test_success_sequence_edge_first_core_second(self):
        asyncio.run(self.port.start(self.req))
        self.assertEqual(self.ssh.events, [
            ("edge", "probe"), ("core", "probe"),
            ("edge", "start"), ("core", "start"),
        ])
        self.assertEqual(self.lease.calls, 4)

    def test_denied_without_explicit_disposable_opt_in(self):
        self.port.disposable_vps = False
        with self.assertRaisesRegex(R1LabUnsafe, "DEFAULT_OFF"):
            asyncio.run(self.port.start(self.req))
        self.assertEqual(self.ssh.events, [])

    def test_guard_and_lease_denied_before_any_host_call(self):
        self.guard = False
        with self.assertRaisesRegex(R1LabUnsafe, "GUARD_NOT_ATTESTED"):
            asyncio.run(self.port.start(self.req))
        self.assertEqual(self.ssh.events, [])
        self.guard = True
        self.lease.fail_at = 1
        with self.assertRaisesRegex(R1LabUnsafe, "LEASE_REQUIRED"):
            asyncio.run(self.port.start(self.req))
        self.assertEqual(self.ssh.events, [])

    def test_lease_lost_after_edge_no_core_start_and_no_cleanup(self):
        # Admission, preflight, post-Edge recheck.
        self.lease.fail_at = 3
        with self.assertRaisesRegex(R1LabUnsafe, "UNCERTAIN_HOLD"):
            asyncio.run(self.port.start(self.req))
        self.assertEqual(self.ssh.events[-1], ("edge", "start"))
        self.assertNotIn(("core", "start"), self.ssh.events)
        self.assertTrue(all(action != "stop" for _, action in self.ssh.events))

    def test_edge_launch_failure_no_core_mutation(self):
        self.ssh.error_at = ("edge", "start")
        with self.assertRaisesRegex(R1LabUnsafe, "UNCERTAIN_HOLD"):
            asyncio.run(self.port.start(self.req))
        self.assertNotIn(("core", "start"), self.ssh.events)

    def test_changed_request_fails_before_ssh(self):
        altered = UIDPolicyRequest(EgressSpec(
            **{**asdict(spec()), "edge_listen_port": 51854}),
            "labuser", 1555, 1791)
        with self.assertRaisesRegex(R1LabUnsafe, "SPEC_CHANGED"):
            asyncio.run(self.port.start(altered))
        self.assertEqual(self.ssh.events, [])

    def test_lease_source_target_must_be_from_existing_f2(self):
        # F2 lease adapter uses request.spec.edge_public_ipv4 for target
        # and refuses source=Core or source=target Edge.
        from edge_egress_r1_shared6g import Existing6GR1LeaseProbe
        candidate = Existing6GR1LeaseProbe(
            lambda: None, 1, spec().core_public_ipv4, spec().edge_public_ipv4)
        self.assertFalse(candidate.for_request(self.req))


class R1LabSSHTests(unittest.TestCase):
    def test_ssh_strict_host_pin_and_fixed_agent(self):
        runner = LabSSHExecutor(
            Path("/root/id_r1"), Path("/root/known_hosts_r1"))
        with patch.object(runner, "_check_local_files"), patch(
            "edge_egress_r1_lab_launcher.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=json.dumps({
                "ok": True, "role": "edge",
                "state": "OFFLINE_VERIFIED"}))
        ) as call:
            self.assertEqual(runner.run(host("edge"), "probe", spec())["role"],
                             "edge")
        argv = call.call_args.args[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("UserKnownHostsFile=/root/known_hosts_r1", argv)
        self.assertEqual(argv[-3], "/root/nvl-egress-lab1-source/edge_egress_r1_lab_agent.py")
        self.assertEqual(argv[-2], "probe")
        self.assertEqual(argv[-1], payload("edge"))
        self.assertNotIn("StrictHostKeyChecking=no", argv)

    def test_ssh_output_does_not_authorize_without_exact_verified_response(self):
        runner = LabSSHExecutor(Path("/root/k"), Path("/root/h"))
        with patch.object(runner, "_check_local_files"), patch(
            "edge_egress_r1_lab_launcher.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout='{"ok":true,"role":"core","state":"OFFLINE_VERIFIED"}')
        ):
            with self.assertRaisesRegex(R1LabUnsafe, "VERIFICATION_FAILED"):
                runner.run(host("edge"), "probe", spec())
        with self.assertRaisesRegex(R1LabUnsafe, "NOT_ALLOWED"):
            runner.run(host("edge"), "stop", spec())


class R1LabAgentTests(unittest.TestCase):
    def test_strict_request(self):
        self.assertEqual(_request(payload("edge")).role, "edge")
        bad = base64.b64encode(b'{"action":"start"}').decode()
        with self.assertRaisesRegex(LabAgentUnsafe, "REQUEST_FIELDS"):
            _request(bad)

    def test_probe_read_only_stage_guarded(self):
        with patch("edge_egress_r1_lab_agent._assert_local_host"), patch(
            "edge_egress_r1_lab_agent._no_previous_resources"
        ), patch("edge_egress_r1_lab_agent.subprocess.run") as invoked:
            result = execute("probe", payload("edge"))
        self.assertEqual(result["state"], "OFFLINE_VERIFIED")
        invoked.assert_not_called()

    def test_agent_denies_direct_local_start(self):
        with patch("edge_egress_r1_lab_agent._assert_local_host"), patch(
            "edge_egress_r1_lab_agent._no_previous_resources"
        ), patch.dict("os.environ", {"SSH_CONNECTION": ""}):
            with self.assertRaisesRegex(LabAgentUnsafe, "SSH_COORDINATOR_REQUIRED"):
                execute("start", payload("edge"))

    def test_agent_checks_post_start_identity_and_never_auto_tears_down(self):
        healthy = R1Observation("edge", True, False, False, True,
                                False, False, True, False, (), True)
        with patch("edge_egress_r1_lab_agent._assert_local_host"), patch(
            "edge_egress_r1_lab_agent._no_previous_resources"
        ), patch("edge_egress_r1_lab_agent._stage_owned", return_value=True), patch(
            "edge_egress_r1_lab_agent.inspect_linux", return_value=healthy
        ), patch("edge_egress_r1_lab_agent.subprocess.run",
                 return_value=SimpleNamespace(returncode=0)) as call, patch.dict(
            "os.environ", {"SSH_CONNECTION": "1 2 3 4"}):
            self.assertEqual(execute("start", payload("edge"))["state"],
                             "TRANSPORT_VERIFIED")
            self.assertEqual(call.call_count, 1)
            self.assertTrue(call.call_args.args[0][-1].endswith("/up.sh"))

    def test_agent_false_success_when_observation_bad_is_refused(self):
        bad = R1Observation("core", True, True, True, True, False,
                            False, False, False, (), False)
        with patch("edge_egress_r1_lab_agent._assert_local_host"), patch(
            "edge_egress_r1_lab_agent._no_previous_resources"
        ), patch("edge_egress_r1_lab_agent._stage_owned", return_value=True), patch(
            "edge_egress_r1_lab_agent.inspect_linux", return_value=bad
        ), patch("edge_egress_r1_lab_agent.subprocess.run",
                 return_value=SimpleNamespace(returncode=0)), patch.dict(
            "os.environ", {"SSH_CONNECTION": "1 2 3 4"}):
            with self.assertRaisesRegex(LabAgentUnsafe, "UNCERTAIN_HOLD"):
                execute("start", payload("core"))


if __name__ == "__main__":
    unittest.main()
