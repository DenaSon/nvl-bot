"""Focused, fast P1-F tests: no WireGuard/network/systemd mutation."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops import edge_egress_v1_transport as p
from ops.edge_egress_provision import EgressSpec


PEER = base64.b64encode(bytes(range(32))).decode()


def fixture(stage: Path, role="core"):
    spec = EgressSpec.from_json(dict(
        edge_id="mia1", core_public_ipv4="209.200.246.198",
        edge_public_ipv4="144.172.84.76",
        tunnel_network="10.78.130.0/30",
        veth_network="10.78.131.0/30", edge_uplink="eth0",
        edge_listen_port=51843, route_table=1781, mode="relay",
    ))
    stage.mkdir()
    (stage / "manifest.json").write_text(json.dumps(
        dict(config=spec.__dict__, role=role, stage_only=True)))
    (stage / "wg.conf").write_text("[Peer]\nPublicKey = " + PEER + "\n")
    (stage / "up.sh").write_text("#!/bin/bash\ntrue\n")
    (stage / "down.sh").write_text("#!/bin/bash\ntrue\n")
    return spec


def read_user_stage(path: Path, directory=False) -> bytes:
    return b"" if directory else path.read_bytes()


class PersistenceTests(unittest.TestCase):
    def test_pinned_stage_and_no_ssh_coupling(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, "_file", read_user_stage):
            stage = Path(tmp) / "stage"
            fixture(stage)
            digest = p.stage_hash(stage)
            spec, peer = p.pinned(stage, "core", digest)
            self.assertEqual(spec.edge_id, "mia1")
            self.assertEqual(peer, PEER)
            unit = p.render_unit(stage, "core", digest)
            self.assertIn("ops.edge_egress_v1_transport ensure", unit)
            self.assertIn(digest, unit)
            self.assertNotIn("ExecStop=", unit)
            self.assertNotIn("ssh.service", unit)
            self.assertNotIn("wg-quick@wg0", unit)
            self.assertNotIn("ip rule", unit)

    def test_tamper_and_wrong_role_hold(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, "_file", read_user_stage):
            stage = Path(tmp) / "stage"
            fixture(stage)
            digest = p.stage_hash(stage)
            with self.assertRaisesRegex(p.EgressHold, "STAGE_ROLE_MISMATCH"):
                p.pinned(stage, "edge", digest)
            (stage / "up.sh").write_text("unexpected change\n")
            with self.assertRaisesRegex(p.EgressHold, "STAGE_HASH_CHANGED"):
                p.pinned(stage, "core", digest)

    def test_stage_rejects_bad_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            fixture(stage)
            stage.chmod(0o755)  # Explicitly unsafe even for root with umask 077.
            with self.assertRaisesRegex(p.EgressHold, "STAGE_PERMISSIONS"):
                p.stage_hash(stage)
            link = Path(tmp) / "linked"
            link.symlink_to(stage)
            with self.assertRaisesRegex(p.EgressHold, "STAGE_SYMLINK"):
                p.stage_hash(link)

    def test_absent_core_and_partial_core(self):
        spec = EgressSpec.from_json(dict(
            edge_id="mia1", core_public_ipv4="209.200.246.198",
            edge_public_ipv4="144.172.84.76",
            tunnel_network="10.78.130.0/30",
            veth_network="10.78.131.0/30", edge_uplink="eth0",
            edge_listen_port=51843, route_table=1781,
        ))
        from subprocess import CompletedProcess
        with patch.object(p, "_read", return_value=""), patch.object(p, "_run",
                 return_value=CompletedProcess([], 1, "", "")):
            self.assertEqual(p.observe(spec, "core", PEER), "ABSENT")
        with patch.object(p, "_read", return_value="nvl-egress-mia1 (id: 1)"), patch.object(
            p, "_run", return_value=CompletedProcess([], 1, "", "")
        ):
            with self.assertRaisesRegex(p.EgressHold, "PARTIAL_CORE"):
                p.observe(spec, "core", PEER)
        with patch.object(p, "_run", side_effect=[
            CompletedProcess([], 1, "", ""), CompletedProcess([], 0, "", "")
        ]):
            with self.assertRaisesRegex(p.EgressHold, "PARTIAL_EDGE_NAT"):
                p.observe(spec, "edge", PEER)

    def test_existing_healthy_transport_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, "_file", read_user_stage):
            stage = Path(tmp) / "stage"
            fixture(stage)
            digest = p.stage_hash(stage)
            with patch.object(p.os, "geteuid", return_value=0), patch.object(
                p, "observe", return_value="UP"
            ), patch.object(p.subprocess, "run") as runner:
                self.assertEqual(p.ensure(stage, "core", digest), "EXACT_TRANSPORT_ALREADY_UP")
                runner.assert_not_called()

    def test_failure_never_calls_down_script(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, "_file", read_user_stage):
            stage = Path(tmp) / "stage"
            fixture(stage)
            digest = p.stage_hash(stage)
            with patch.object(p.os, "geteuid", return_value=0), patch.object(
                p, "observe", side_effect=p.EgressHold("PARTIAL_CORE_TRANSPORT")
            ), patch.object(p.subprocess, "run") as runner:
                with self.assertRaisesRegex(p.EgressHold, "PARTIAL_CORE"):
                    p.ensure(stage, "core", digest)
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
