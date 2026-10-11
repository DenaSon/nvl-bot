"""D1-B2 regression: pure/staged provisioner must not mutate running NVL."""
from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ops.edge_egress_provision import (
    EgressSpec,
    ProvisionError,
    edge_down_script,
    edge_up_script,
    core_up_script,
    core_down_script,
    load_spec,
    main,
    plan,
    preflight,
    stage_files,
    validated_key,
)


VALID_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
PEER_KEY = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")


def sample(**changes):
    data = dict(
        edge_id="fra1",
        edge_public_ipv4="172.86.94.174",
        core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30",
        edge_uplink="eth0",
        edge_listen_port=51832,
        route_table=1780,
    )
    data.update(changes)
    return EgressSpec.from_json(data)


class ProvisionValidationTests(unittest.TestCase):
    def test_valid_plan_refuses_to_install_user_routes(self):
        spec = sample()
        p = plan(spec, "core")
        self.assertEqual(p["mode"], "STAGE_ONLY_NO_NETWORK_MUTATION")
        self.assertFalse(p["user_routes_changed"])
        self.assertFalse(p["wg0_changed"])
        self.assertEqual(p["namespace"], "nvl-egress-fra1")
        self.assertEqual(spec.edge_tunnel_ip, "10.78.100.1")
        self.assertEqual(spec.core_tunnel_ip, "10.78.100.2")

    def test_rejects_illegal_interface_ids_and_injection(self):
        for edge_id in ("", "FRANKFURT", "invalid;rm", "toolong99", "../a", "1edge"):
            with self.subTest(edge_id=edge_id), self.assertRaises(ProvisionError):
                sample(edge_id=edge_id)

    def test_rejects_device_shell_injection(self):
        for dev in ("eth0 -j ACCEPT", "eth0;reboot", "", "$(id)", "1234"):
            with self.subTest(dev=dev), self.assertRaises(ProvisionError):
                sample(edge_uplink=dev)

    def test_rejects_poc_ingress_and_mutually_overlapping_subnets(self):
        pairs = (
            dict(tunnel_network="10.77.0.0/30"),
            dict(tunnel_network="10.78.99.0/30"),
            dict(veth_network="10.78.98.0/30"),
            dict(tunnel_network="10.78.101.0/30"),
            dict(tunnel_network="10.78.100.1/30"),
            dict(veth_network="10.78.100.0/30"),
        )
        for case in pairs:
            with self.subTest(case=case), self.assertRaises(ProvisionError):
                sample(**case)

    def test_rejects_non_public_peer_addresses(self):
        for name in ("edge_public_ipv4", "core_public_ipv4"):
            with self.subTest(name=name), self.assertRaises(ProvisionError):
                sample(**{name: "10.0.0.4"})
        with self.assertRaises(ProvisionError):
            sample(core_public_ipv4="172.86.94.174")

    def test_rejects_wrong_mode_bad_ports_and_unknown_keys(self):
        for fields in ({"mode": "datapath"}, {"edge_listen_port": 22},
                       {"route_table": 77}, {"edge_listen_port": True},
                       {"bogus_flag": True}):
            with self.subTest(fields=fields), self.assertRaises(ProvisionError):
                sample(**fields)

    def test_wireguard_key_validation(self):
        self.assertEqual(validated_key(VALID_KEY, "test"), VALID_KEY)
        for key in ("foo", "A" * 44, VALID_KEY[:-1], "x\\ny", ""):
            with self.subTest(key=key), self.assertRaises(ProvisionError):
                validated_key(key, "test")


class StagedArtifactTests(unittest.TestCase):
    def test_core_staging_is_atomic_restricted_and_non_deploying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "core-fra1"
            spec = sample()
            stage_files(spec, "core", dst, VALID_KEY, PEER_KEY)
            self.assertEqual(set(p.name for p in dst.iterdir()), {
                "wg.conf", "up.sh", "down.sh", "nvl-egress-fra1.service", "manifest.json"
            })
            for p in dst.iterdir():
                self.assertEqual(p.stat().st_mode & 0o077, 0)
            wg = (dst / "wg.conf").read_text()
            self.assertIn("AllowedIPs = 0.0.0.0/0", wg)
            self.assertIn("Endpoint = 172.86.94.174:51832", wg)
            self.assertNotIn("wg0", (dst / "up.sh").read_text())
            up = (dst / "up.sh").read_text()
            self.assertIn("ip netns add", up)
            self.assertIn('wg setconf "$IFACE" "$WGCONF"', up)
            self.assertIn('ip netns exec "$NS" ip route add default', up)
            self.assertNotIn("ip rule add", up)
            self.assertNotIn("systemctl ", up)
            self.assertNotIn("iptables -F", up)
            manifest = json.loads((dst / "manifest.json").read_text())
            self.assertFalse(manifest["user_routes_installed"])
            self.assertNotIn(VALID_KEY, (dst / "manifest.json").read_text())
            with self.assertRaises(ProvisionError):
                stage_files(spec, "core", dst, VALID_KEY, PEER_KEY)

    def test_edge_staging_has_only_scoped_nat(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / "edge-fra1"
            stage_files(sample(), "edge", dst, VALID_KEY, PEER_KEY)
            wg = (dst / "wg.conf").read_text()
            self.assertIn("ListenPort = 51832", wg)
            self.assertIn("AllowedIPs = 10.78.100.2/32", wg)
            self.assertNotIn("AllowedIPs = 0.0.0.0/0", wg)
            up = (dst / "up.sh").read_text()
            self.assertIn('POSTROUTING -s "$CORE_WG/32" -o "$UPLINK"', up)
            self.assertIn('INPUT -i "$UPLINK" -p udp --dport "$PORT"', up)
            self.assertNotIn("iptables -t nat -F", up)
            self.assertNotIn("netfilter-persistent", up)
            self.assertNotIn("wg0", up)
            self.assertNotIn("systemctl ", up)

    def test_symlink_or_world_writable_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "public"
            public.mkdir()
            public.chmod(0o777)
            with self.assertRaises(ProvisionError):
                stage_files(sample(), "edge", public / "staged", VALID_KEY, PEER_KEY)
            link = root / "link"
            link.symlink_to(root)
            with self.assertRaises(ProvisionError):
                stage_files(sample(), "edge", link / "staged", VALID_KEY, PEER_KEY)

    def test_stage_does_not_change_existing_files_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "existing"
            dst.mkdir()
            (dst / "untouched").write_text("sentinel")
            with self.assertRaises(ProvisionError):
                stage_files(sample(), "core", dst, VALID_KEY, PEER_KEY)
            self.assertEqual((dst / "untouched").read_text(), "sentinel")

    def test_stage_cli_requires_local_owner_only_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec_file = root / "spec.json"
            spec_file.write_text(json.dumps(sample().__dict__))
            key_file = root / "private.key"
            key_file.write_text(VALID_KEY + "\n")
            key_file.chmod(0o644)
            args = ["stage", "--role", "core", "--spec", str(spec_file),
                    "--stage-dir", str(root / "staged"),
                    "--private-key-file", str(key_file),
                    "--peer-public-key", PEER_KEY]
            self.assertEqual(main(args), 2)
            self.assertFalse((root / "staged").exists())
            key_file.chmod(0o600)
            self.assertEqual(main(args), 0)
            self.assertTrue((root / "staged" / "wg.conf").exists())


class ReadonlyPreflightTests(unittest.TestCase):
    @patch("ops.edge_egress_provision._run_read_only")
    @patch("ops.edge_egress_provision.subprocess.run")
    @patch("ops.edge_egress_provision.shutil.which", return_value="/usr/sbin/mock")
    def test_fresh_core_no_custom_table_is_safe(self, which, run, read):
        run.return_value.returncode = 1
        def fake(*args):
            if args[:3] == ("ip", "netns", "list"):
                return ""
            return json.dumps([
                {"dst": "default", "dev": "eth0", "table": "main"},
                {"dst": "10.77.0.0/24", "dev": "wg0", "table": "main"}
            ])
        read.side_effect = fake
        result = preflight(sample(), "core")
        self.assertEqual(result, {"ok": True, "issues": [], "role": "core"})

    @patch("ops.edge_egress_provision._run_read_only")
    @patch("ops.edge_egress_provision.subprocess.run")
    @patch("ops.edge_egress_provision.shutil.which", return_value="/usr/sbin/mock")
    def test_core_route_collision_blocks(self, which, run, read):
        run.return_value.returncode = 1
        read.side_effect = lambda *a: "" if a[:3] == ("ip", "netns", "list") else json.dumps([
            {"dst": "10.78.100.0/30", "dev": "wg-other", "table": "main"}
        ])
        self.assertIn("ROUTE_SUBNET_COLLISION:10.78.100.0/30",
                      preflight(sample(), "core")["issues"])

    @patch("ops.edge_egress_provision._run_read_only")
    @patch("ops.edge_egress_provision.subprocess.run")
    @patch("ops.edge_egress_provision.shutil.which", return_value="/usr/sbin/mock")
    def test_edge_port_collision_blocks(self, which, run, read):
        run.return_value.returncode = 1
        def fake(*args):
            if args[0] == "sysctl":
                return "1\n"
            if args[0] == "ss":
                return "UNCONN 0 0 0.0.0.0:51832 0.0.0.0:*\n"
            return "1.1.1.1 via 10.0.0.1 dev eth0 src 172.86.94.174"
        read.side_effect = fake
        self.assertIn("UDP_PORT_BUSY", preflight(sample(), "edge")["issues"])


if __name__ == "__main__":
    unittest.main()
