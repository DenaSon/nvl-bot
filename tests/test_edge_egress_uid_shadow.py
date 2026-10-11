"""D1-C3B: pinned shadow ordering and partial-start cleanup."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_lifecycle import UIDCanaryUnsafe
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_shadow import PinnedUIDCanaryShadow
from ops.edge_egress_provision import EgressSpec


def req():
    spec = EgressSpec.from_json({
        "edge_id":"fra1","edge_public_ipv4":"216.126.229.12",
        "core_public_ipv4":"209.200.246.198",
        "tunnel_network":"10.78.100.0/30",
        "veth_network":"10.78.101.0/30","edge_uplink":"eth0",
        "edge_listen_port":51832,"route_table":1780,"mode":"relay"})
    return UIDPolicyRequest(spec, "nvl0557", 1644)


class Edge:
    def __init__(self, events, fail=None):
        self.identity = SimpleNamespace(role="edge",
                                        expected_public_ip="216.126.229.12")
        self.lab_activation = True
        self.events, self.fail = events, fail

    async def read_only_preflight(self, spec):
        self.events.append("edge:preflight")
        return True, ()

    async def inspect_shadow(self, spec):
        self.events.append("edge:inspect")
        return {"state": "STAGED"}

    async def start_shadow(self, spec):
        self.events.append("edge:start")
        if self.fail == "start":
            raise RuntimeError("synthetic")

    async def stop_shadow(self, spec):
        self.events.append("edge:stop")


class ShadowTests(unittest.TestCase):
    def execute(self, events, failing=None):
        def call(action, payload):
            events.append("core:" + action)
            if action == failing:
                raise RuntimeError("synthetic")
            if action == "preflight":
                return {"ok": True, "issues": []}
            if action == "inspect":
                return {"state": "STAGED"}
            return {"state": "DONE"}
        return call

    def test_preflight_then_edge_first_start_and_core_first_stop(self):
        events = []
        r = req()
        adapter = PinnedUIDCanaryShadow(r.spec, Edge(events))
        with patch("edge_egress_uid_shadow.local_execute",
                   side_effect=self.execute(events)):
            asyncio.run(adapter.preflight(r))
            asyncio.run(adapter.start(r))
            asyncio.run(adapter.stop(r))
        self.assertEqual(events, [
            "core:preflight", "edge:preflight", "core:inspect",
            "edge:inspect", "edge:start", "core:start",
            "core:stop", "edge:stop",
        ])

    def test_partial_core_start_always_attempts_both_stops(self):
        events = []
        r = req()
        adapter = PinnedUIDCanaryShadow(r.spec, Edge(events))
        with patch("edge_egress_uid_shadow.local_execute",
                   side_effect=self.execute(events, failing="start")):
            with self.assertRaisesRegex(UIDCanaryUnsafe, "SHADOW_START_FAILED"):
                asyncio.run(adapter.start(r))
        self.assertEqual(events, [
            "edge:start", "core:start", "core:stop", "edge:stop",
        ])

    def test_disabled_shadow_activation_refuses(self):
        r = req()
        edge = Edge([])
        edge.lab_activation = False
        a = PinnedUIDCanaryShadow(r.spec, edge)
        with self.assertRaisesRegex(UIDCanaryUnsafe, "DISABLED"):
            asyncio.run(a.start(r))


if __name__ == "__main__":
    unittest.main()
