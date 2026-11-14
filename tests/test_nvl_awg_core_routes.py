"""No-network regression for AWG /32 Linux return routes and boot replay."""
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from nvl_awg_core_routes import (
    AWGRouteHold, ensure_core_route, verify_core_route,
    reconcile_registered_routes,
)

CORE = "10.203.77.1"
EDGE = "10.203.77.4"
KEY = "B" * 43 + "="


class FakeKernel:
    def __init__(self):
        self.route = ""
        self.wrong_lookup = False
        self.calls = []

    def __call__(self, args, **_kwargs):
        self.calls.append(tuple(args))
        if args == ["ip", "-4", "route", "show", "table", "main",
                    "exact", EDGE + "/32"]:
            result = self.route
        elif args == ["ip", "-4", "route", "get", EDGE, "from", CORE]:
            result = (f"{EDGE} from {CORE} via 172.31.1.1 dev eth0\n"
                      if self.wrong_lookup or not self.route
                      else f"{EDGE} from {CORE} dev awg0 uid 0\n")
        elif args == ["ip", "-4", "route", "add", EDGE + "/32",
                      "dev", "awg0", "src", CORE]:
            if self.route:
                raise AssertionError("must never replace a route")
            self.route = f"{EDGE} dev awg0 scope link src {CORE}"
            result = ""
        elif args == ["ip", "-4", "route", "del", EDGE + "/32",
                      "dev", "awg0"]:
            self.route = ""
            result = ""
        elif args == ["awg", "show", "awg0", "allowed-ips"]:
            result = KEY + "\t" + EDGE + "/32\n"
        else:
            raise AssertionError("unexpected command: " + repr(args))
        return subprocess.CompletedProcess(args, 0, result, "")


class AWGCoreRouteTests(unittest.TestCase):
    def test_missing_route_is_created_and_second_run_is_idempotent(self):
        kernel = FakeKernel()
        with self.assertRaisesRegex(AWGRouteHold, "AWG_CORE_ROUTE_MISSING"):
            verify_core_route(EDGE, CORE, runner=kernel)
        self.assertTrue(ensure_core_route(EDGE, CORE, runner=kernel))
        self.assertTrue(verify_core_route(EDGE, CORE, runner=kernel))
        self.assertFalse(ensure_core_route(EDGE, CORE, runner=kernel))
        self.assertEqual(sum(c[3] == "add" for c in kernel.calls
                             if len(c) > 3 and c[:3] == ("ip", "-4", "route")), 1)

    def test_foreign_route_is_not_overwritten(self):
        kernel = FakeKernel()
        kernel.route = f"{EDGE} via 172.31.1.1 dev eth0"
        with self.assertRaisesRegex(AWGRouteHold, "AWG_CORE_ROUTE_CONFLICT"):
            ensure_core_route(EDGE, CORE, runner=kernel)
        self.assertFalse(any("add" in call for call in kernel.calls))

    def test_wrong_policy_route_rolls_back_only_new_32(self):
        kernel = FakeKernel()
        kernel.wrong_lookup = True
        with self.assertRaisesRegex(AWGRouteHold, "AWG_CORE_ROUTE_POSTCHECK_FAILED"):
            ensure_core_route(EDGE, CORE, runner=kernel)
        self.assertEqual(kernel.route, "")
        self.assertTrue(any("del" in call for call in kernel.calls))

    def test_unverified_peer_blocks_boot_without_any_route_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "db.sqlite"
            self._db(file, public_key="C" * 43 + "=")
            kernel = FakeKernel()
            with self.assertRaisesRegex(AWGRouteHold, "AWG_CORE_ROUTE_PEER_UNVERIFIED"):
                reconcile_registered_routes(
                    db_path=file, runner=kernel, root_check=lambda: 0,
                    lock_path=str(Path(tmp) / "lock"))
            self.assertFalse(any("add" in call for call in kernel.calls))

    def test_boot_replays_only_verified_peer_and_no_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "db.sqlite"
            self._db(file, public_key=KEY)
            kernel = FakeKernel()
            count = reconcile_registered_routes(
                db_path=file, runner=kernel, root_check=lambda: 0,
                lock_path=str(Path(tmp) / "lock"))
            self.assertEqual(count, 1)
            self.assertTrue(verify_core_route(EDGE, CORE, runner=kernel))
            self.assertFalse(any(c[0] == "systemctl" for c in kernel.calls))

    @staticmethod
    def _db(file, *, public_key):
        with sqlite3.connect(file) as db:
            db.executescript("""
                CREATE TABLE edge_tunnel_bindings (
                  host TEXT,backend TEXT,interface TEXT,core_tunnel_ip TEXT,
                  edge_tunnel_ip TEXT,peer_public_key TEXT,state TEXT,
                  verified_at INTEGER
                );
            """)
            db.execute(
                "INSERT INTO edge_tunnel_bindings VALUES "
                "('8.8.4.4','amneziawg','awg0',?,?,?,'VERIFIED',1)",
                (CORE, EDGE, public_key),
            )


if __name__ == "__main__":
    unittest.main()
