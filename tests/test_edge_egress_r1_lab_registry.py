"""Rootless R1 LAB registry tests, no live WireGuard or SSH mutations."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_registry import (
    register_verified_stage, verified_live_stage, Lab6GUnsafe,
)
from edge_egress_r1_lab_6g_bootstrap import JOURNAL_SCHEMA, compile_pinned_bot_callbacks
from edge_egress_inventory import SCHEMA as ALLOCATION_SCHEMA
from edge_egress_f3_readiness import READINESS_SCHEMA
from edge_egress_uid_runtime_store import RUNTIME_SCHEMA
from edge_egress_protected_mapping import MAPPING_SCHEMA
from ops.edge_egress_provision import EgressSpec


def spec():
    return EgressSpec(
        edge_id="lab1", core_public_ipv4="107.189.16.36",
        edge_public_ipv4="216.126.229.12", tunnel_network="10.78.120.0/30",
        veth_network="10.78.121.0/30", edge_uplink="eth0",
        edge_listen_port=51852, route_table=1791,
    )

# These are valid WireGuard-shaped public keys; test never uses private keys.
KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


def reviewed_bot_callbacks(_source, connector):
    # Same immutable original bot source, but CI checkout is non-root-owned.
    return compile_pinned_bot_callbacks(BOT.read_bytes(), connector)


class LabRegistryTests(unittest.TestCase):
    def connector(self, db):
        @contextmanager
        def connect():
            conn = sqlite3.connect(db)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        return connect

    def create_empty(self, db):
        with sqlite3.connect(db) as conn:
            for s in (
                JOURNAL_SCHEMA, ALLOCATION_SCHEMA,
                READINESS_SCHEMA, RUNTIME_SCHEMA, MAPPING_SCHEMA,
            ):
                conn.executescript(s)

    def test_register_exact_staged_allocation_under_real_bot_6g(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "r1lab.sqlite3"
            self.create_empty(db)
            with patch(
                "edge_egress_r1_lab_registry.verified_live_stage",
                return_value=(spec(), KEY_A, KEY_B),
            ), patch(
                "edge_egress_r1_lab_registry.make_lab_db_conn",
                return_value=self.connector(db),
            ), patch(
                "edge_egress_r1_lab_registry.verified_bot_callbacks",
                side_effect=reviewed_bot_callbacks,
            ):
                register_verified_stage()
            with sqlite3.connect(db) as c:
                self.assertEqual(c.execute(
                    "SELECT status FROM failover_operations"
                ).fetchone(), ("SUCCEEDED",))
                self.assertEqual(c.execute(
                    "SELECT status FROM edge_egress_allocations"
                ).fetchone(), ("STAGED",))
                self.assertEqual(c.execute(
                    "SELECT state FROM edge_egress_readiness"
                ).fetchone(), ("STAGED",))
                self.assertEqual(c.execute(
                    "SELECT COUNT(*) FROM edge_egress_uid_runtime"
                ).fetchone()[0], 0)
                self.assertEqual(c.execute(
                    "SELECT COUNT(*) FROM edge_egress_uid_bindings"
                ).fetchone()[0], 0)
                self.assertEqual(set(c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()).issuperset({
                    ("edge_egress_allocations",),
                    ("edge_egress_readiness",),
                }), True)

    def test_duplicate_registry_refuses_before_acquiring_second_lease(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "r1lab.sqlite3"
            self.create_empty(db)
            with sqlite3.connect(db) as c:
                c.execute("INSERT INTO failover_operations "
                          "(mode,source_host,target_host,status,started_at,updated_at) "
                          "VALUES ('MANUAL','107.189.16.36','216.126.229.12',"
                          "'SUCCEEDED','2026-10-12','2026-10-12')")
            with patch(
                "edge_egress_r1_lab_registry.verified_live_stage",
                return_value=(spec(), KEY_A, KEY_B),
            ), patch(
                "edge_egress_r1_lab_registry.make_lab_db_conn",
                return_value=self.connector(db),
            ), patch(
                "edge_egress_r1_lab_registry.verified_bot_callbacks"
            ) as callback:
                with self.assertRaisesRegex(Lab6GUnsafe, "NOT_EMPTY"):
                    register_verified_stage()
                callback.assert_called_once()
            with sqlite3.connect(db) as c:
                self.assertEqual(c.execute(
                    "SELECT COUNT(*) FROM failover_operations"
                ).fetchone()[0], 1)

    def test_registration_failure_never_marks_6g_succeeded(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "r1lab.sqlite3"
            self.create_empty(db)
            with patch(
                "edge_egress_r1_lab_registry.verified_live_stage",
                return_value=(spec(), KEY_A, KEY_B),
            ), patch(
                "edge_egress_r1_lab_registry.make_lab_db_conn",
                return_value=self.connector(db),
            ), patch(
                "edge_egress_r1_lab_registry.verified_bot_callbacks",
                side_effect=reviewed_bot_callbacks,
            ), patch(
                "edge_egress_r1_lab_registry.reserve_allocation",
                side_effect=RuntimeError("fault"),
            ):
                with self.assertRaisesRegex(Lab6GUnsafe, "UNCERTAIN_HOLD"):
                    register_verified_stage()
            with sqlite3.connect(db) as c:
                self.assertEqual(c.execute(
                    "SELECT status FROM failover_operations"
                ).fetchone(), ("RUNNING",))
                self.assertEqual(c.execute(
                    "SELECT COUNT(*) FROM edge_egress_allocations"
                ).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
