"""R1 ownership/bridge regression tests; mocks only, never modify host networking."""
import asyncio
from dataclasses import asdict
import hashlib
import json
from unittest.mock import patch
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from edge_egress_r1_transport import (
    GuardedR1ShadowPort, R1Observation, R1Unsafe, _root_owned, _stage_owned,
    decide, inspect_linux,
)
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def spec():
    return EgressSpec(
        edge_id="stg1", edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.110.0/30", veth_network="10.78.111.0/30",
        edge_uplink="eth0", edge_listen_port=51842, route_table=1790
    )


def snapshot(**changes):
    base = R1Observation("core", False, False, False,
                         True, True, False, False, False)
    return replace(base, **changes)


class R1DecisionTests(unittest.TestCase):
    def test_existing_unmanaged_shadow_never_adopted(self):
        s = snapshot(interface_present=True, namespace_present=True,
                     veth_present=True, stage_owned=False)
        self.assertEqual(decide(s).reason, "UNMANAGED_EXISTING_SHADOW")
        self.assertFalse(decide(s).activation_authorized)

    def test_stage_offline_not_ready(self):
        result = decide(snapshot())
        self.assertEqual(result.state, "STAGED_OFFLINE")
        self.assertFalse(result.customer_ready)
        self.assertFalse(result.activation_authorized)

    def test_active_unit_missing_link_is_hold(self):
        self.assertEqual(decide(snapshot(unit_active=True)).state, "HOLD")

    def test_partial_core_never_managed(self):
        s = snapshot(interface_present=True, veth_present=True,
                     unit_active=True, identity_proven=True)
        self.assertEqual(decide(s).reason, "PARTIAL_TRANSPORT_RESOURCES")

    def test_live_peer_needs_cryptographic_identity_evidence(self):
        s = snapshot(interface_present=True, namespace_present=True,
                     veth_present=True, unit_active=True)
        self.assertEqual(decide(s).reason, "WIREGUARD_OR_ROUTE_IDENTITY_UNVERIFIED")
        self.assertEqual(decide(replace(s, identity_proven=True)).state,
                         "MANAGED_RUNNING")
        self.assertFalse(decide(replace(s, identity_proven=True)).customer_ready)

    def test_broad_nat_precedence_blocks_edge_even_if_active(self):
        edge = R1Observation("edge", True, False, False,
                             True, True, True, True, True,
                             identity_proven=True)
        self.assertEqual(decide(edge).reason, "LEGACY_NAT_PRECEDENCE_UNREVIEWED")

    def test_foreign_nat_without_interface_blocks_reuse(self):
        edge = R1Observation("edge", False, False, False,
                             True, True, False, True, False)
        self.assertEqual(decide(edge).reason, "STRAY_TAGGED_NAT_WITHOUT_INTERFACE")

    def test_probe_errors_block_without_exception_text(self):
        s = snapshot(probe_errors=("NAT_INVENTORY_FAILED",))
        self.assertEqual(decide(s).reason, "INCOMPLETE_READ_ONLY_EVIDENCE")

    def test_stage_ownership_requires_reviewed_hashes_and_tamper_refusal(self):
        with TemporaryDirectory() as d:
            root = Path(d) / "stage-root"
            st = root / "stg1-core"
            st.mkdir(parents=True)
            data = {"config": asdict(spec()), "role": "core",
                    "stage_only": True, "user_routes_installed": False,
                    "owner_token": "a" * 32}
            contents = {
                "manifest.json": json.dumps(data),
                "wg.conf": "[Peer]\\nPublicKey = TEST\\n",
                "up.sh": "# reviewed script\\n",
                "down.sh": "# reviewed cleanup script\\n",
            }
            for name, value in contents.items():
                (st / name).write_text(value)
            hashes = {name: hashlib.sha256(value.encode()).hexdigest()
                      for name, value in contents.items()}
            with patch("edge_egress_r1_transport._root_owned", return_value=True):
                self.assertFalse(_stage_owned(spec(), "core", root))
                self.assertTrue(_stage_owned(spec(), "core", root, hashes))
                (st / "up.sh").write_text("modified")
                self.assertFalse(_stage_owned(spec(), "core", root, hashes))

    def test_symlink_never_root_owned(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "data"
            link = Path(d) / "link"
            p.write_text("file")
            link.symlink_to(p)
            self.assertFalse(_root_owned(link))


class R1InspectTests(unittest.TestCase):
    def test_read_only_core_existing_namespace_rejected_as_unmanaged(self):
        calls = []
        def run(*args):
            calls.append(args)
            if args == ("ip", "netns", "list"):
                return SimpleNamespace(returncode=0,
                                       stdout="nvl-egress-stg1 (id: 0)\n")
            if args == ("ip", "link", "show", "dev", "wg-nvl-stg1"):
                return SimpleNamespace(returncode=1, stdout="",
                                       stderr='Device "wg-nvl-stg1" does not exist.')
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with TemporaryDirectory() as d:
            obs = inspect_linux(spec(), "core", run=run,
                                stage_root=Path(d)/"no-stage",
                                unit_root=Path(d)/"no-unit")
        self.assertTrue(obs.interface_present)
        self.assertTrue(obs.namespace_present)
        self.assertTrue(obs.veth_present)
        self.assertEqual(decide(obs).reason, "UNMANAGED_EXISTING_SHADOW")
        self.assertTrue(all(c[0] in {"ip", "systemctl"} for c in calls))
        self.assertTrue(all("delete" not in c and "flush" not in c
                            and "add" not in c for c in calls))

    def test_staged_peer_parser_accepts_real_wireguard_key_line(self):
        with TemporaryDirectory() as d:
            stage = Path(d) / "stg1-core"
            stage.mkdir()
            (stage / "wg.conf").write_text(
                "[Interface]\nPrivateKey = OMITTED\n"
                "[Peer]\nPublicKey = REVIEWED_PUBLIC_PEER\n"
                "AllowedIPs = 0.0.0.0/0\n")
            def run(*args):
                if args == ("ip", "link", "show", "dev", "wg-nvl-stg1"):
                    return SimpleNamespace(returncode=1, stdout="",
                        stderr='Device "wg-nvl-stg1" does not exist.')
                if args == ("ip", "netns", "list"):
                    return SimpleNamespace(returncode=0,
                        stdout="nvl-egress-stg1 (id: 0)\n", stderr="")
                if args[-4:] == ("wg", "show", "wg-nvl-stg1", "peers"):
                    value = "REVIEWED_PUBLIC_PEER\n"
                elif args[-4:] == ("wg", "show", "wg-nvl-stg1", "allowed-ips"):
                    value = "REVIEWED_PUBLIC_PEER\t0.0.0.0/0\n"
                elif args[-3:] == ("route", "show", "default"):
                    value = "default dev wg-nvl-stg1 scope link\n"
                elif args[-1:] == ("wg-nvl-stg1",):
                    value = "42: wg-nvl-stg1 inet 10.78.110.2/30\n"
                elif args[-1:] == ("vnh-stg1",):
                    value = "17: vnh-stg1 inet 10.78.111.1/30\n"
                elif args[-1:] == ("vnn-stg1",):
                    value = "17: vnn-stg1 inet 10.78.111.2/30\n"
                else:
                    value = ""
                return SimpleNamespace(returncode=0, stdout=value, stderr="")
            with patch("edge_egress_r1_transport._stage_owned", return_value=True):
                obs = inspect_linux(spec(), "core", run=run,
                    stage_root=Path(d), unit_root=Path(d))
            self.assertTrue(obs.identity_proven)
            self.assertEqual(obs.probe_errors, ())

    def test_permission_failure_is_not_interpreted_as_absent_interface(self):
        def run(*args):
            if args[:3] == ("ip", "link", "show"):
                return SimpleNamespace(returncode=2, stdout="",
                                       stderr="Operation not permitted")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with TemporaryDirectory() as d:
            obs = inspect_linux(spec(), "edge", run=run,
                                stage_root=Path(d)/"no-stage",
                                unit_root=Path(d)/"no-unit")
        self.assertIn("EDGE_INTERFACE_PROBE_FAILED", obs.probe_errors)
        self.assertEqual(decide(obs).reason, "INCOMPLETE_READ_ONLY_EVIDENCE")

    def test_iptables_early_broad_nat_detected_without_mutations(self):
        commands = []
        def run(*args):
            commands.append(args)
            if args[:3] == ("iptables", "-t", "nat"):
                return SimpleNamespace(returncode=0, stdout=(
                    "-A POSTROUTING -j MASQUERADE\n"
                    "-A POSTROUTING -s 10.78.110.2/32 -o eth0 "
                    "-m comment --comment nvl-egress-stg1 -j MASQUERADE\n"
                ))
            if args == ("iptables", "-S", "FORWARD"):
                return SimpleNamespace(returncode=0, stdout="")
            if args == ("sysctl", "-n", "net.ipv4.ip_forward"):
                return SimpleNamespace(returncode=0, stdout="1\n")
            return SimpleNamespace(returncode=0, stdout="")
        with TemporaryDirectory() as d:
            obs = inspect_linux(spec(), "edge", run=run,
                                stage_root=Path(d)/"no-stage",
                                unit_root=Path(d)/"no-unit")
        self.assertTrue(obs.nat_shadowed)
        self.assertTrue(obs.nat_tagged)
        self.assertTrue(all(c[0] in {"ip", "iptables", "sysctl"} for c in commands))


class R1GuardedPortTests(unittest.TestCase):
    def setUp(self):
        self.req = UIDPolicyRequest(spec(), "nvl0557", 1644, 1790)
        self.calls = []
        self.state = snapshot()
        self.lease = True
        self.guard = True

    def port(self, *, enabled=True, disposable=True):
        async def edge(req):
            self.calls.append("edge")
        async def core(req):
            self.calls.append("core")
            self.state = snapshot(interface_present=True,
                                  namespace_present=True, veth_present=True,
                                  unit_active=True, identity_proven=True)
        return GuardedR1ShadowPort(
            spec(), lambda: self.state,
            lambda _: self.lease, lambda _: self.guard,
            edge, core, explicitly_enabled=enabled, disposable_vps=disposable,
        )

    def test_disabled_by_default_and_no_live_effect(self):
        p = self.port(enabled=False)
        with self.assertRaisesRegex(R1Unsafe, "DISABLED"):
            asyncio.run(p.start(self.req))
        self.assertEqual(self.calls, [])

    def test_requires_disposable_vps(self):
        with self.assertRaisesRegex(R1Unsafe, "DISABLED"):
            asyncio.run(self.port(disposable=False).start(self.req))
        self.assertEqual(self.calls, [])

    def test_requires_existing_6g_and_uid_guard(self):
        self.lease = False
        with self.assertRaisesRegex(R1Unsafe, "LEASE_REQUIRED"):
            asyncio.run(self.port().start(self.req))
        self.lease = True
        self.guard = False
        with self.assertRaisesRegex(R1Unsafe, "GUARD_NOT_ATTESTED"):
            asyncio.run(self.port().start(self.req))
        self.assertEqual(self.calls, [])

    def test_unmanaged_shadow_not_started_or_destroyed(self):
        self.state = snapshot(interface_present=True, namespace_present=True,
                              veth_present=True, stage_owned=False)
        with self.assertRaisesRegex(R1Unsafe, "EXISTING_TRANSPORT_NOT_OWNED"):
            asyncio.run(self.port().start(self.req))
        self.assertEqual(self.calls, [])

    def test_explicit_owned_start_requires_post_start_identity(self):
        asyncio.run(self.port().start(self.req))
        self.assertEqual(self.calls, ["edge", "core"])
        self.assertEqual(decide(self.state).state, "MANAGED_RUNNING")

    def test_lease_loss_between_remote_and_local_is_hold(self):
        async def edge(req):
            self.calls.append("edge")
            self.lease = False
        p = self.port()
        p.start_edge = edge
        with self.assertRaisesRegex(R1Unsafe, "UNCERTAIN_HOLD"):
            asyncio.run(p.start(self.req))
        self.assertEqual(self.calls, ["edge"])
        self.assertEqual(self.state, snapshot())

    def test_post_start_missing_identity_is_hold_no_blind_cleanup(self):
        async def core(req):
            self.calls.append("core")
        p = self.port()
        p.start_core = core
        with self.assertRaisesRegex(R1Unsafe, "UNCERTAIN_HOLD"):
            asyncio.run(p.start(self.req))
        self.assertEqual(self.calls, ["edge", "core"])

    def test_already_managed_is_noop_but_still_requires_lease_guard(self):
        self.state = snapshot(interface_present=True, namespace_present=True,
                              veth_present=True, unit_active=True,
                              identity_proven=True)
        asyncio.run(self.port().start(self.req))
        self.assertEqual(self.calls, [])
        self.lease = False
        with self.assertRaisesRegex(R1Unsafe, "LEASE_REQUIRED"):
            asyncio.run(self.port().start(self.req))


if __name__ == "__main__":
    unittest.main()
