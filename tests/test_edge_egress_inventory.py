"""D1-C2B isolated SQLite tests of immutable Edge allocation reservations."""
import base64
import sqlite3
import unittest
from dataclasses import replace

from edge_egress_inventory import (
    AllocationConflict, ensure_schema, reserve_allocation, mark_stage_only,
)
from ops.edge_egress_provision import EgressSpec

def key(n):
    return base64.b64encode(bytes((x+n)%256 for x in range(32))).decode("ascii")

def spec(edge_id="fra1", ip="172.86.94.174", tunnel="10.78.100.0/30",
         veth="10.78.101.0/30", table=1780):
    return EgressSpec.from_json({
        "edge_id":edge_id, "edge_public_ipv4":ip,
        "core_public_ipv4":"209.200.246.198",
        "tunnel_network":tunnel, "veth_network":veth,
        "edge_uplink":"eth0", "edge_listen_port":51832,
        "route_table":table, "mode":"relay"
    })

class EgressInventoryTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        ensure_schema(self.db)

    def tearDown(self):
        self.db.close()

    def reserve(self, spec_obj=None, core=None, edge=None):
        return reserve_allocation(self.db, spec_obj or spec(),
                                  core_public_key=core or key(1),
                                  edge_public_key=edge or key(2))

    def first(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.reserve()

    def other(self, **changes):
        fields = dict(edge_id="lon1",ip="216.126.229.12",
                      tunnel="10.78.102.0/30",veth="10.78.103.0/30",table=1781)
        fields.update(changes)
        return spec(**fields)

    def test_add_allocation_only_inside_transaction(self):
        with self.assertRaisesRegex(AllocationConflict,"SHARED_TRANSACTION_REQUIRED"):
            self.reserve()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM edge_egress_allocations").fetchone()[0], 0)
        result=self.first()
        self.assertEqual(result.status,"RESERVED")
        self.assertTrue(result.created)
        self.db.commit()

    def test_allocation_has_only_public_keys_and_no_customer_mutations(self):
        self.first()
        self.db.commit()
        record=self.db.execute(
            "SELECT core_public_key,edge_public_key,status FROM edge_egress_allocations"
        ).fetchone()
        self.assertEqual(record,(key(1),key(2),"RESERVED"))
        cols=[c[1] for c in self.db.execute("PRAGMA table_info(edge_egress_allocations)")]
        for forbidden in ("private_key","user","uid","password","token"):
            self.assertNotIn(forbidden,cols)
        self.assertEqual(len(self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ssh_accounts'").fetchall()),0)

    def test_same_reservation_idempotent_including_after_commit(self):
        self.first(); self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        again=self.reserve()
        self.assertFalse(again.created)
        self.assertEqual(again.status,"RESERVED")
        self.db.commit()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM edge_egress_allocations").fetchone()[0],1)

    def test_new_edge_requires_fresh_identity_and_unique_resources(self):
        self.first(); self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        second=self.reserve(self.other(),core=key(3),edge=key(4))
        self.assertEqual(second.edge_id,"lon1")
        self.db.commit()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM edge_egress_allocations").fetchone()[0],2)

    def test_replacement_cannot_reuse_id_with_different_ip(self):
        self.first();self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(AllocationConflict,"EDGE_ID_IMMUTABLE_RESERVATION"):
            self.reserve(spec(edge_id="fra1",ip="216.126.229.12"))
        self.db.rollback()

    def test_retired_edge_identity_cannot_be_reused(self):
        self.first(); self.db.commit()
        self.db.execute(
            "UPDATE edge_egress_allocations SET status='RETIRED' WHERE edge_id='fra1'"
        )
        self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(AllocationConflict, "RETIRED_EDGE_ID_MUST_NOT_BE_REUSED"):
            self.reserve()
        self.db.rollback()

    def test_subnet_collision_even_across_tunnel_and_veth(self):
        self.first();self.db.commit()
        for changed in (
            {"tunnel":"10.78.101.0/30"},
            {"veth":"10.78.100.0/30"},
            {"tunnel":"10.78.100.0/30"},
            {"veth":"10.78.101.0/30"},
        ):
            with self.subTest(changed=changed):
                candidate=self.other(**changed)
                self.db.execute("BEGIN IMMEDIATE")
                with self.assertRaisesRegex(AllocationConflict,"NETWORK_SUBNET_COLLISION"):
                    self.reserve(candidate,core=key(3),edge=key(4))
                self.db.rollback()

    def test_route_table_and_ip_collision(self):
        self.first(); self.db.commit()
        for changed in ({"table":1780},{"ip":"172.86.94.174"}):
            with self.subTest(changed=changed):
                self.db.execute("BEGIN IMMEDIATE")
                with self.assertRaises(AllocationConflict):
                    self.reserve(self.other(**changed),core=key(3),edge=key(4))
                self.db.rollback()

    def test_wireguard_key_reuse_rejected_for_new_edge(self):
        self.first();self.db.commit()
        for core,edge in ((key(1),key(4)),(key(3),key(2)),(key(2),key(3)),(key(3),key(1))):
            with self.subTest(core=core,edge=edge):
                self.db.execute("BEGIN IMMEDIATE")
                with self.assertRaisesRegex(AllocationConflict,"WIREGUARD_PUBLIC_KEY_REUSE"):
                    self.reserve(self.other(),core=core,edge=edge)
                self.db.rollback()

    def test_equal_core_and_edge_public_keys_refused(self):
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(AllocationConflict,"REUSED_WG_PUBLIC_KEY"):
            self.reserve(core=key(1),edge=key(1))
        self.db.rollback()

    def test_rollback_restores_empty_state_without_touching_other_tables(self):
        self.first()
        self.db.rollback()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM edge_egress_allocations").fetchone()[0],0)

    def test_stage_marker_is_not_live_or_verified(self):
        self.first();self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        mark_stage_only(self.db,"fra1")
        self.db.commit()
        self.assertEqual(self.db.execute(
            "SELECT status FROM edge_egress_allocations WHERE edge_id='fra1'"
        ).fetchone()[0],"STAGED")
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(AllocationConflict,"STALE_OR_UNKNOWN_EDGE_RESERVATION"):
            mark_stage_only(self.db,"fra1",expected_status="RESERVED")
        self.db.rollback()

if __name__=="__main__":
    unittest.main()
