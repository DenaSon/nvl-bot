"""D1-C2B3/C2C: transport identity, remote stream and shadow rollback."""
import asyncio
import base64
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from edge_egress_ssh_transport import (
    EgressSSHError, EgressSSHIdentity, PinnedEgressHostPort,
    _remote_source, _invoke_ssh, activate_and_prove_lab_shadow,
    stop_lab_shadow,
)
from ops.edge_egress_provision import EgressSpec


def spec():
    return EgressSpec.from_json(dict(
        edge_id="fra1", edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198", tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30", edge_uplink="eth0",
        edge_listen_port=51832, route_table=1780, mode="relay"))


def identity(role="core", pin="SHA256:" + "A" * 43):
    return EgressSSHIdentity(role, "192.0.2.5",
                             "209.200.246.198" if role == "core" else "216.126.229.12",
                             pin, "/tmp/lab_key")


class TransportTests(unittest.TestCase):
    def test_reject_absent_or_invalid_pin_before_any_network(self):
        with self.assertRaisesRegex(EgressSSHError, "PINNED_FINGERPRINT_REQUIRED"):
            _invoke_ssh(identity(pin=""), "preflight", {})
        with self.assertRaisesRegex(EgressSSHError, "PINNED_FINGERPRINT_REQUIRED"):
            PinnedEgressHostPort(identity(pin="not-a-sha"))

    def test_no_arbitrary_action(self):
        with self.assertRaisesRegex(EgressSSHError, "ACTION_NOT_ALLOWLISTED"):
            _invoke_ssh(identity(), "rm -rf /", {})

    def test_spec_address_binding_before_ssh(self):
        port = PinnedEgressHostPort(identity())
        with self.assertRaisesRegex(EgressSSHError, "SPEC_HOST_IDENTITY_MISMATCH"):
            asyncio.run(PinnedEgressHostPort(identity(role="edge")).read_only_preflight(
                EgressSpec.from_json({**vars(spec()), "edge_public_ipv4": "217.182.1.1"})))
        self.assertIsNone(port._spec)

    def test_stage_and_private_key_never_cross_worker_boundary(self):
        calls = []
        def fake(_id, action, payload):
            calls.append((action, payload))
            if action == "preflight":
                return {"ok": True, "issues": []}
            if action == "key":
                return {"public_key": base64.b64encode(bytes(range(32))).decode()}
            return {"state": "STAGED"}
        p = PinnedEgressHostPort(identity())
        with patch("edge_egress_ssh_transport._invoke_ssh", fake):
            self.assertEqual(asyncio.run(p.read_only_preflight(spec())), (True, ()))
            public = asyncio.run(p.ensure_local_keypair("fra1"))
            asyncio.run(p.stage_config_only(spec(), peer_public_key=public))
            asyncio.run(p.discard_staged_config_only("fra1"))
        self.assertEqual([a for a, _ in calls], ["preflight", "key", "stage", "discard"])
        self.assertNotIn("private_key", json.dumps(calls))
        self.assertEqual(calls[-1][1]["token"], calls[-2][1]["token"])
        self.assertNotIn("lab_activation", json.dumps(calls))

    def test_lab_commands_default_disabled(self):
        p = PinnedEgressHostPort(identity())
        with self.assertRaisesRegex(EgressSSHError, "LAB_ACTIVATION_DISABLED"):
            asyncio.run(p.start_shadow(spec()))

    def test_inline_agent_bundle_parses_and_does_not_require_installed_agent(self):
        code = _remote_source()
        compile(code, "<stream>", "exec")
        payload = base64.b64encode(b'{}').decode()
        proc = subprocess.run([sys.executable, "-", "arbitrary", payload],
                              input=code, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["error"], "ACTION_NOT_ALLOWLISTED")


class FakeShadow:
    def __init__(self, name, events, *, output="216.126.229.12", fail=None):
        self.name, self.events, self.output, self.fail = name, events, output, fail

    async def inspect_shadow(self, spec):
        self.events.append(self.name + ":inspect")
        return {"state": "STAGED"}

    async def start_shadow(self, spec):
        self.events.append(self.name + ":start")
        if self.fail == "start":
            raise RuntimeError("fake failure")

    async def stop_shadow(self, spec):
        self.events.append(self.name + ":stop")
        if self.fail == "stop":
            raise RuntimeError("fake cleanup failure")

    async def observe_public_egress(self, spec):
        self.events.append(self.name + ":proof")
        return self.output


class LabProofTests(unittest.TestCase):
    def test_starts_edge_before_core_and_proves_public_edge_ip(self):
        events = []
        core, edge = FakeShadow("core", events), FakeShadow("edge", events)
        result = asyncio.run(activate_and_prove_lab_shadow(spec(), core=core, edge=edge))
        self.assertTrue(result.proven)
        self.assertEqual(result.observed_ip, spec().edge_public_ipv4)
        self.assertEqual(events, ["edge:inspect", "core:inspect",
                                  "edge:start", "core:start", "core:proof"])
        asyncio.run(stop_lab_shadow(spec(), core=core, edge=edge))
        self.assertEqual(events[-2:], ["core:stop", "edge:stop"])

    def test_wrong_public_ip_stops_core_then_edge(self):
        events = []
        core = FakeShadow("core", events, output="209.200.246.198")
        edge = FakeShadow("edge", events)
        result = asyncio.run(activate_and_prove_lab_shadow(spec(), core=core, edge=edge))
        self.assertFalse(result.proven)
        self.assertIn("MISMATCH", result.reason)
        self.assertFalse(result.cleanup_uncertain)
        self.assertEqual(events[-2:], ["core:stop", "edge:stop"])

    def test_partial_core_start_triggers_both_cleanup_attempts(self):
        events = []
        core = FakeShadow("core", events, fail="start")
        edge = FakeShadow("edge", events, fail="stop")
        result = asyncio.run(activate_and_prove_lab_shadow(spec(), core=core, edge=edge))
        self.assertFalse(result.proven)
        self.assertTrue(result.cleanup_uncertain)
        self.assertEqual(events[-2:], ["core:stop", "edge:stop"])


if __name__ == "__main__":
    unittest.main()
