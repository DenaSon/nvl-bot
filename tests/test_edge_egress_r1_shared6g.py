"""Proof that the R1 lease predicate queries ONLY the original 6G journal."""
import sqlite3
import unittest

from edge_egress_r1_shared6g import Existing6GR1LeaseProbe
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


class R1Shared6GTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.execute("""CREATE TABLE failover_operations (
            id INTEGER PRIMARY KEY, status TEXT,
            source_host TEXT, target_host TEXT
        )""")
        self.conn.execute(
            "INSERT INTO failover_operations VALUES (42, 'RUNNING', ?, ?)",
            ("172.86.94.174", "216.126.229.12"),
        )
        self.conn.commit()
        self.lease = Existing6GR1LeaseProbe(
            lambda: self.conn, 42, "172.86.94.174", "216.126.229.12"
        )
        self.req = UIDPolicyRequest(
            EgressSpec(
                edge_id="fra1",
                core_public_ipv4="209.200.246.198",
                edge_public_ipv4="216.126.229.12",
                tunnel_network="10.78.110.0/30",
                veth_network="10.78.111.0/30",
                edge_uplink="eth0", edge_listen_port=51842,
                route_table=1790,
            ),
            "nvl0557", 1644, priority=1790
        )

    def test_only_unique_running_matching_original_lease_accepts(self):
        self.assertTrue(self.lease.active())
        self.assertTrue(self.lease.for_request(self.req))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM failover_operations").fetchone(), (1,))

    def test_finished_stale_lease_rejected_without_new_lock(self):
        self.conn.execute("UPDATE failover_operations SET status='SUCCEEDED'")
        self.conn.commit()
        self.assertFalse(self.lease.active())

    def test_second_concurrent_6g_operation_fails_closed(self):
        self.conn.execute(
            "INSERT INTO failover_operations VALUES (43, 'RUNNING', ?, ?)",
            ("172.86.94.174", "216.126.229.12"),
        )
        self.conn.commit()
        self.assertFalse(self.lease.active())

    def test_wrong_source_target_op_or_disconnected_db_rejected(self):
        self.assertFalse(Existing6GR1LeaseProbe(
            lambda: self.conn, 43, "172.86.94.174", "216.126.229.12").active())
        self.assertFalse(Existing6GR1LeaseProbe(
            lambda: self.conn, 42, "172.86.94.174", "209.200.246.198").active())
        self.assertFalse(Existing6GR1LeaseProbe(
            lambda: self.conn, 42, "204.11.2.212", "216.126.229.12").active())
        self.assertFalse(Existing6GR1LeaseProbe(
            lambda: None, 42, "172.86.94.174", "216.126.229.12").active())

    def test_invalid_lease_id_never_accepted(self):
        for value in (0, -1, True, "42"):
            with self.assertRaisesRegex(ValueError, "IDENTITY"):
                Existing6GR1LeaseProbe(lambda: self.conn, value,
                                       "172.86.94.174", "216.126.229.12")

    def test_wrong_target_in_policy_request_denied(self):
        from dataclasses import replace
        bad = replace(self.req, spec=replace(
            self.req.spec, edge_public_ipv4="216.126.229.13"))
        self.assertFalse(self.lease.for_request(bad))

    def test_missing_schema_denied_not_migrated(self):
        self.conn.execute("DROP TABLE failover_operations")
        self.conn.commit()
        self.assertFalse(self.lease.active())


if __name__ == "__main__":
    unittest.main()
