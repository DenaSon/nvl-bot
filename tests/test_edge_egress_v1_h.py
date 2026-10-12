"""H: small offline SSH ingress pinning tests; never executes ssh/wg/network."""
import base64
import json
import sqlite3
import unittest
from dataclasses import replace
from unittest.mock import patch

from edge_egress_uid_runtime_store import RuntimeBinding
from edge_egress_v1_ingress import (
    IngressHold, IngressPeer, parse_registry, render_registry,
    verify_ingress, probe_ingress,
)
from edge_egress_v1_admission import Member, check_account
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from tests.test_edge_egress_v1_f2 import protected_fixture

KEY1 = base64.b64encode(b"a" * 32).decode()
KEY2 = base64.b64encode(b"b" * 32).decode()
MIAMI = IngressPeer("mia1", "144.172.84.76", "10.77.0.8", KEY1)
OTHER = IngressPeer("fra1", "216.126.229.12", "10.77.0.6", KEY2)
ALLOWED = KEY1 + "\t10.77.0.8/32\n" + KEY2 + "\t10.77.0.6/32\n"
ROW = RuntimeBinding("nvl0557", 1644, "mia1", "144.172.84.76",
                     1781, 1781, 10553, "PROTECTED", 3, 42)


class HTests(unittest.TestCase):
    def test_actual_miami_ssh_peer_matches_pinned_edge(self):
        peers = parse_registry(render_registry([MIAMI, OTHER]).encode())
        self.assertTrue(verify_ingress(ROW, "10.77.0.8", peers, ALLOWED))
        # Comma-separated wg allowed IP networks are supported.
        expanded = KEY1 + "\t10.77.0.8/32, fd00::8/128\n" + (
            KEY2 + "\t10.77.0.6/32\n"
        )
        self.assertTrue(verify_ingress(ROW, "10.77.0.8", peers, expanded))

    def test_active_relay_switch_cannot_repin_an_existing_uid(self):
        peers = (MIAMI, OTHER)
        # Simulated 6H default changes: it is NOT consulted.
        self.assertFalse(verify_ingress(ROW, "10.77.0.6", peers, ALLOWED))
        self.assertTrue(verify_ingress(ROW, "10.77.0.8", peers, ALLOWED))

    def test_unknown_public_or_missing_peer_fails_closed(self):
        peers = (MIAMI, OTHER)
        for observed in ("", "144.172.84.76", "203.0.113.10",
                         "10.77.0.99", "10.77.0.1",
                         "::ffff:10.77.0.8", "10.77.0.8/32",
                         "10.77.0.08"):
            with self.subTest(observed=observed):
                self.assertFalse(verify_ingress(ROW, observed, peers, ALLOWED))
        self.assertFalse(verify_ingress(ROW, "10.77.0.8", peers, ""))

    def test_wrong_public_key_overlapping_peer_and_broad_prefix_denied(self):
        peers = (MIAMI, OTHER)
        self.assertFalse(verify_ingress(ROW, "10.77.0.8", peers,
                                       KEY2 + "\t10.77.0.8/32\n"))
        self.assertFalse(verify_ingress(
            ROW, "10.77.0.8", peers,
            ALLOWED + KEY2 + "\t10.77.0.0/24\n",
        ))
        self.assertFalse(verify_ingress(
            ROW, "10.77.0.8", peers,
            KEY1 + "\t10.77.0.8/32\n" + KEY2 + "\t0.0.0.0/0\n",
        ))

    def test_registry_refuses_ambiguous_or_forged_allocation(self):
        cases = (
            [MIAMI, MIAMI],
            [MIAMI, replace(OTHER, ingress_ipv4="10.77.0.8")],
            [MIAMI, replace(OTHER, edge_ipv4="144.172.84.76")],
            [MIAMI, replace(OTHER, wg_public_key=KEY1)],
            [replace(MIAMI, ingress_ipv4="10.77.0.1")],
            [replace(MIAMI, ingress_ipv4="203.0.113.2")],
            [replace(MIAMI, wg_public_key="x")],
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(IngressHold):
                render_registry(case)
        self.assertRaises(IngressHold, parse_registry, b'{"version":2,"peers":[]}')
        self.assertRaises(IngressHold, parse_registry,
                          b'{"version":1,"peers":[],"extra":1}')

    def test_integration_fails_closed_when_no_ingress_probe(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT);
            INSERT INTO failover_operations VALUES(42,'SUCCEEDED');
        """)
        install_runtime_schema(db)
        install_protected_mapping_schema(db)
        db.execute("""
            INSERT INTO edge_egress_uid_runtime
             (username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,
              state,last_operation_id)
             VALUES('nvl0557',1644,'mia1','144.172.84.76',1781,1781,
                    10553,'PROTECTED',42)
        """)
        db.execute("""
            INSERT INTO edge_egress_uid_bindings
             (username,uid,edge_id,edge_ipv4,status)
             VALUES('nvl0557',1644,'mia1','144.172.84.76','PROTECTED')
        """)
        guard = protected_fixture()
        guard = replace(guard, request=replace(
            guard.request, spec=replace(
                guard.request.spec, edge_id="mia1",
                edge_public_ipv4="144.172.84.76", route_table=1781),
            priority=1781))
        member = Member("nvl0557", 1644, "a" * 64)
        props = dict(guard_loader=lambda _: guard,
                     guard_probe=lambda conn, row: True)
        self.assertFalse(check_account(db, "nvl0557", 1644,
                                       {"nvl0557": member}, **props))
        self.assertFalse(check_account(
            db, "nvl0557", 1644, {"nvl0557": member},
            ingress_probe=lambda _: False, **props
        ))
        self.assertTrue(check_account(
            db, "nvl0557", 1644, {"nvl0557": member},
            ingress_probe=lambda row: verify_ingress(
                row, "10.77.0.8", (MIAMI, OTHER), ALLOWED,
            ), **props
        ))
        self.assertFalse(check_account(
            db, "nvl0557", 1644, {"nvl0557": member},
            ingress_probe=lambda row: verify_ingress(
                row, "10.77.0.6", (MIAMI, OTHER), ALLOWED,
            ), **props
        ))

    def test_failed_or_missing_wireguard_inventory_does_not_allow(self):
        with patch("edge_egress_v1_ingress.load_registry",
                   return_value=(MIAMI, OTHER)), patch(
                       "edge_egress_v1_ingress.subprocess.run",
                       side_effect=OSError("wg unavailable")
                   ):
            self.assertFalse(probe_ingress(ROW, "10.77.0.8"))


if __name__ == "__main__":
    unittest.main()
