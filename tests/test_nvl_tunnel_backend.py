"""Read-only AWG/WG backend registry tests. Never touch real network/SQLite."""
import sqlite3
import subprocess
import time
import unittest

from nvl_tunnel_backend import (
    SCHEMA, TunnelHold, lookup_binding, verified_shared_edge_sources,
    is_shared_ingress_source, probe_binding,
)

CORE_KEY = "MjJZ0TMjrkwJEZhsHYjH1del3JtIcSA/5Q8xv+5KlnQ="
EDGE_KEY = "Isv5UL+ufARwGoYfhj5P+K7vp53OmArFWjpB+F4mYCw="
HOST = "149.104.110.138"


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")

    def tearDown(self):
        self.db.close()

    def add(self, **updates):
        row = dict(host=HOST, backend="amneziawg", interface="awg0",
                   core_tunnel_ip="10.203.77.1",
                   edge_tunnel_ip="10.203.77.2",
                   peer_public_key=EDGE_KEY, state="VERIFIED",
                   verified_at=1794642576)
        row.update(updates)
        self.db.execute(
            "INSERT INTO edge_tunnel_bindings VALUES (?,?,?,?,?,?,?,?)",
            tuple(row.values()),
        )

    def test_no_schema_no_write_and_legacy_fallback(self):
        self.assertIsNone(lookup_binding(self.db, HOST))
        self.assertEqual(verified_shared_edge_sources(self.db), frozenset())
        self.assertFalse(self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='edge_tunnel_bindings'"
        ).fetchone())

    def test_verified_awg_registered_and_exact_shared_ip(self):
        self.db.executescript(SCHEMA)
        self.add()
        binding = lookup_binding(self.db, HOST)
        self.assertEqual((binding.backend, binding.interface, binding.edge_tunnel_ip),
                         ("amneziawg", "awg0", "10.203.77.2"))
        ips = verified_shared_edge_sources(self.db)
        self.assertTrue(is_shared_ingress_source("10.203.77.2", ips))
        self.assertFalse(is_shared_ingress_source("10.203.77.3", ips))
        self.assertTrue(is_shared_ingress_source("10.77.0.175", ips))
        self.assertFalse(is_shared_ingress_source("198.51.100.10", ips))

    def test_unverified_and_invalid_do_not_silently_fallback(self):
        self.db.executescript(SCHEMA)
        self.add(state="HOLD")
        with self.assertRaisesRegex(TunnelHold, "NOT_VERIFIED"):
            lookup_binding(self.db, HOST)
        self.db.execute("UPDATE edge_tunnel_bindings SET state='VERIFIED', "
                        "interface='wg0'")
        with self.assertRaisesRegex(TunnelHold, "BACKEND_INTERFACE"):
            lookup_binding(self.db, HOST)

    def test_duplicate_tunnel_address_rejected_by_unique_index(self):
        self.db.executescript(SCHEMA)
        self.add()
        with self.assertRaises(sqlite3.IntegrityError):
            self.add(host="149.104.110.139")

    def test_no_private_keys_or_obfuscation_secrets_in_schema(self):
        for secret_field in ("private_key", "header_protection_key", "password"):
            self.assertNotIn(secret_field, SCHEMA.lower())


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(SCHEMA)
        self.db.execute(
            "INSERT INTO edge_tunnel_bindings VALUES (?,?,?,?,?,?,?,?)",
            (HOST, "amneziawg", "awg0", "10.203.77.1", "10.203.77.2",
             EDGE_KEY, "VERIFIED", 1794642576),
        )
        self.binding = lookup_binding(self.db, HOST)
        self.commands = []

    def tearDown(self):
        self.db.close()

    def runner(self, cmd, **kwargs):
        self.commands.append(cmd)
        assert kwargs["timeout"] <= 5
        if cmd[:3] == ["awg", "show", "awg0"]:
            if cmd[3] == "allowed-ips":
                return subprocess.CompletedProcess(cmd, 0,
                    EDGE_KEY + " 10.203.77.2/32\n", "")
            if cmd[3] == "latest-handshakes":
                return subprocess.CompletedProcess(cmd, 0,
                    EDGE_KEY + " 1794642576\n", "")
        if cmd[0] == "ping":
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError("Unexpected command: " + str(cmd))

    def test_awg_probe_uses_only_registered_interface(self):
        report = probe_binding(self.binding, runner=self.runner,
                               clock=lambda: 1794642580)
        self.assertTrue(report["wg_peer_ok"])
        self.assertTrue(report["core_path_ok"])
        self.assertEqual(report["tunnel_backend"], "amneziawg")
        self.assertIn(["awg", "show", "awg0", "latest-handshakes"], self.commands)
        self.assertIn(["ping", "-I", "awg0", "-c", "1", "-W", "3",
                       "10.203.77.2"], self.commands)
        self.assertTrue(all(cmd[0] in ("awg", "ping") for cmd in self.commands))

    def test_wrong_peer_or_overlapping_allowed_ips_fails_closed(self):
        def wrong(cmd, **kwargs):
            if cmd[-1] == "allowed-ips":
                return subprocess.CompletedProcess(cmd, 0,
                    CORE_KEY + " 10.203.77.0/24\n", "")
            raise AssertionError("Must not ping a wrong peer")
        result = probe_binding(self.binding, runner=wrong)
        self.assertIsNone(result["wg_peer_ok"])
        self.assertIsNone(result["core_path_ok"])
        self.assertEqual(result["wg_reason"], "TUNNEL_PEER_OWNERSHIP_AMBIGUOUS")

    def test_no_peer_rejects_without_ping(self):
        result = probe_binding(self.binding, runner=lambda cmd, **kw:
            subprocess.CompletedProcess(cmd, 0, "", ""))
        self.assertFalse(result["wg_peer_ok"])
        self.assertFalse(result["core_path_ok"])
        self.assertEqual(result["wg_reason"], "TUNNEL_PEER_MISSING")

    def test_path_can_prove_health_when_handshake_is_old(self):
        result = probe_binding(self.binding, runner=self.runner,
                               clock=lambda: 1794645000)
        self.assertTrue(result["wg_peer_ok"])
        self.assertTrue(result["core_path_ok"])
        self.assertEqual(result["wg_reason"], "TUNNEL_PATH_PROVEN")

    def test_command_failure_never_raises_or_mutates(self):
        def fail(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 3)
        report = probe_binding(self.binding, runner=fail)
        self.assertIsNone(report["wg_peer_ok"])
        self.assertIsNone(report["core_path_ok"])
        self.assertEqual(len(self.db.execute(
            "SELECT * FROM edge_tunnel_bindings").fetchall()), 1)


if __name__ == "__main__":
    unittest.main()
