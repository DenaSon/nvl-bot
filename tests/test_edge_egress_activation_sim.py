"""D1-B3: simulated Edge/Core lifecycle and rollback using fake network commands.

IMPORTANT: these tests run staged scripts with fake networking commands in an
unprivileged temporary PATH. There is NO genuine WireGuard handshake, kernel
route, network namespace, or VPS involved.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ops.edge_egress_provision import EgressSpec, stage_files


KEY_A = base64.b64encode(bytes(range(32))).decode("ascii")
KEY_B = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")
FAKE_COMMAND = Path(__file__).resolve().parent / "support" / "fake_egress_command.py"


def spec(edge_id="fra1", tunnel="10.78.100.0/30", veth="10.78.101.0/30",
         port=51832):
    return EgressSpec.from_json({
        "edge_id": edge_id,
        "edge_public_ipv4": "172.86.94.174",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": tunnel,
        "veth_network": veth,
        "edge_uplink": "eth0",
        "edge_listen_port": port,
        "route_table": 1780,
        "mode": "relay",
    })


class SimulatedHost:
    def __init__(self, base, role, cfg, fail_contains=None, busy=False):
        self.path = Path(base)
        self.role = role
        self.spec = cfg
        self.stage = self.path / f"{role}-{cfg.edge_id}"
        stage_files(cfg, role, self.stage, KEY_A, KEY_B)
        self.fake_bin = self.path / f"{role}-bin"
        self.fake_bin.mkdir()
        script = self.fake_bin / "_dispatcher"
        shutil.copy2(FAKE_COMMAND, script)
        script.chmod(0o700)
        for command in ("ip", "wg", "iptables", "sysctl", "ss"):
            (self.fake_bin / command).symlink_to(script)

        self.state_path = self.path / f"{role}-state.json"
        self.baseline = {
            "links": {"wg0": "root", "eth0": "root"},
            "namespaces": [],
            "rules": ["BASELINE:wg0"],
            "nest_rules": [],
            "calls": [],
            "port_busy": busy,
        }
        self.state_path.write_text(json.dumps(self.baseline))
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.fake_bin) + os.pathsep + os.environ["PATH"]
        self.env["NVL_FAKE_STATE"] = str(self.state_path)
        if fail_contains:
            self.env["NVL_FAKE_FAIL_CONTAINS"] = fail_contains

        # Explicit paths to real privileged binaries are forbidden in the test.
        for script_name in ("up.sh", "down.sh"):
            text = (self.stage / script_name).read_text()
            for absolute in ("/sbin/ip", "/usr/sbin/ip", "/sbin/iptables",
                             "/usr/sbin/iptables", "/usr/bin/wg", "/usr/bin/ip"):
                if absolute in text:
                    raise AssertionError(f"unsafe unmocked external binary: {absolute}")
            subprocess.run(["bash", "-n", str(self.stage / script_name)], check=True)

    def run(self, phase: str):
        return subprocess.run(
            ["bash", str(self.stage / (phase + ".sh"))],
            capture_output=True, text=True, timeout=12, env=self.env, check=False
        )

    @property
    def state(self):
        return json.loads(self.state_path.read_text())

    def assert_restored(self, testcase):
        st = self.state
        testcase.assertEqual(st["links"], self.baseline["links"])
        testcase.assertEqual(st["namespaces"], [])
        testcase.assertEqual(st["rules"], ["BASELINE:wg0"])
        testcase.assertEqual(st["nest_rules"], [])


class ShadowLifecycleTests(unittest.TestCase):
    def test_edge_up_down_preserves_base_rules_and_wg0(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "edge", spec())
            result = host.run("up")
            self.assertEqual(result.returncode, 0, result.stderr)
            state = host.state
            self.assertIn("wg-nvl-fra1", state["links"])
            self.assertEqual(len(state["rules"]), 5)
            for rule in state["rules"][1:]:
                self.assertIn("nvl-egress-fra1", rule)
            self.assertFalse(any("wg0" in call and "del" in call for call in state["calls"]))
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)

    def test_core_up_down_is_namespace_scoped_with_correct_veth_nat_source(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "core", spec())
            result = host.run("up")
            self.assertEqual(result.returncode, 0, result.stderr)
            state = host.state
            self.assertIn("nvl-egress-fra1", state["namespaces"])
            self.assertEqual(state["links"]["wg-nvl-fra1"], "nvl-egress-fra1")
            self.assertEqual(state["links"]["vnh-fra1"], "root")
            self.assertEqual(state["links"]["vnn-fra1"], "nvl-egress-fra1")
            self.assertIn(
                "ip netns exec nvl-egress-fra1 iptables -w -t nat -A POSTROUTING -s 10.78.101.1/32 -o wg-nvl-fra1 -j MASQUERADE",
                state["calls"],
            )
            self.assertFalse(any("ip rule " in x for x in state["calls"]))
            self.assertFalse(any(x.startswith("ip route add") for x in state["calls"]))
            self.assertFalse(any(x.startswith("iptables ") for x in state["calls"]))
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)

    def test_edge_fault_injection_removes_partial_firewall_rules(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "edge", spec(),
                                 fail_contains="iptables -w -A FORWARD -i eth0")
            result = host.run("up")
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertTrue(host.state.get("failed_once"))
            host.assert_restored(self)
            self.assertEqual(host.run("up").returncode, 0)
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)

    def test_core_fault_injection_deletes_namespace_and_veth(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "core", spec(),
                                 fail_contains="ip netns exec nvl-egress-fra1 iptables -w -t nat -A POSTROUTING")
            result = host.run("up")
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertTrue(host.state.get("failed_once"))
            host.assert_restored(self)
            self.assertEqual(host.run("up").returncode, 0)
            self.assertEqual(host.run("down").returncode, 0)
            host.assert_restored(self)

    def test_edge_port_collision_aborts_without_modification(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "edge", spec(), busy=True)
            result = host.run("up")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("UDP port occupied", result.stderr)
            host.assert_restored(self)

    def test_preexisting_interface_collision_is_fail_safe(self):
        with tempfile.TemporaryDirectory() as td:
            host = SimulatedHost(td, "core", spec())
            baseline = host.state
            baseline["links"]["wg-nvl-fra1"] = "root"
            host.state_path.write_text(json.dumps(baseline))
            result = host.run("up")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interface collision", result.stderr)
            self.assertEqual(host.state["links"]["wg-nvl-fra1"], "root")
            self.assertEqual(host.state["namespaces"], [])

    def test_script_restart_cycle_is_repeatable(self):
        with tempfile.TemporaryDirectory() as td:
            hosts = [SimulatedHost(td, "edge", spec()),
                     SimulatedHost(td, "core", spec())]
            for _ in range(2):
                for host in hosts:
                    r = host.run("up")
                    self.assertEqual(r.returncode, 0, r.stderr)
                for host in reversed(hosts):
                    self.assertEqual(host.run("down").returncode, 0)
                    host.assert_restored(self)

    def test_distinct_edges_generate_distinct_resource_names(self):
        s1 = spec()
        s2 = spec("lon1", "10.78.102.0/30", "10.78.103.0/30", 51833)
        self.assertNotEqual(s1.iface, s2.iface)
        self.assertNotEqual(s1.namespace, s2.namespace)
        self.assertNotEqual(s1.veth_root, s2.veth_root)
        self.assertFalse(s1.tunnel.overlaps(s2.tunnel))
        self.assertFalse(s1.veth.overlaps(s2.veth))


if __name__ == "__main__":
    unittest.main()
