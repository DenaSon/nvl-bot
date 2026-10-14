"""K2 M1: real SQLite SELECT-only single/batch inventory acceptance tests.

F4 READY and independent ingress witnesses here are synthetic fixtures.
These tests do NOT attest any real Core, packet, PAM or customer migration.
"""
from __future__ import annotations

from dataclasses import replace
import sqlite3
import unittest

from edge_egress_k2_migration_inventory import (
    M1_EXECUTION_ENABLED, LiveIngressWitness, MigrationInventoryHold,
    preview_migration, select_migration,
)

TARGET="45.61.163.75"
SOURCE="172.86.111.69"
OTHER="104.194.144.195"
NOW=1792010100


class K2M1InventoryTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(":memory:")
        self.addCleanup(self.c.close)
        self.c.executescript("""
        CREATE TABLE ssh_accounts(
          username TEXT,host TEXT,service_type TEXT,status TEXT);
        INSERT INTO ssh_accounts VALUES
          ('nvl0555','104.194.144.195','ssh','🟢 فعال'),
          ('nvl0557','104.194.144.195','ssh','🟢 فعال'),
          ('pool_user','172.86.111.69','ssh','🟢 فعال'),
          ('inactive','104.194.144.195','ssh','🔴 غیرفعال'),
          ('other_service','104.194.144.195','v2ray','🟢 فعال');
        CREATE TABLE host_pool(host TEXT,active INTEGER,is_default INTEGER);
        INSERT INTO host_pool VALUES ('172.86.111.69',1,1);
        CREATE TABLE edge_egress_allocations(
          edge_id TEXT,edge_public_ipv4 TEXT,status TEXT,route_table INTEGER);
        INSERT INTO edge_egress_allocations VALUES
          ('e9','45.61.163.75','STAGED',20009),
          ('s8','172.86.111.69','STAGED',20008);
        CREATE TABLE edge_egress_readiness(
          edge_id TEXT,edge_ipv4 TEXT,state TEXT,observed_ipv4 TEXT,
          witness TEXT,probed_at INTEGER,expires_at INTEGER,
          generation INTEGER,last_operation_id INTEGER);
        INSERT INTO edge_egress_readiness VALUES
          ('e9','45.61.163.75','READY','45.61.163.75',
           'F4_PRODUCTION_ACCEPTANCE',1792010090,1792010500,2,7);
        CREATE TABLE edge_egress_uid_runtime(
          username TEXT,uid INTEGER,edge_id TEXT,edge_ipv4 TEXT,state TEXT);
        CREATE TABLE edge_egress_uid_bindings(
          username TEXT,uid INTEGER,edge_id TEXT,edge_ipv4 TEXT,status TEXT);
        CREATE TABLE failover_operations(
          id INTEGER,status TEXT);
        """)
        self.uids={"nvl0555":1636,"nvl0557":1644,"pool_user":1666}
        self.witness=lambda n:LiveIngressWitness(
            n,"s8",SOURCE,NOW-2,"INDEPENDENT_LIVE")
        self.db=lambda:self.c

    def preview(self, names=("nvl0555",), mode="SINGLE", **opts):
        args=dict(db_conn=self.db,
                  selection=select_migration(mode,names,"e9"),
                  os_uid=lambda n:self.uids[n],
                  ingress_witness=self.witness,
                  session_count=lambda name,uid:0,
                  now=NOW)
        args.update(opts)
        return preview_migration(**args)

    def selected(self,p):
        return [x for x in p.accounts if x.selected]

    def test_single_and_batch_use_same_account_evidence(self):
        single=self.preview()
        batch=self.preview(("nvl0555","pool_user"),"BATCH")
        self.assertFalse(M1_EXECUTION_ENABLED)
        self.assertFalse(single.can_execute)
        self.assertFalse(batch.can_execute)
        self.assertTrue(single.inventory_clear)
        self.assertTrue(batch.inventory_clear)
        self.assertEqual(single.active_total,3)
        self.assertEqual(batch.selected_total,2)
        # Unselected users remain explicitly unproven, never implicitly
        # considered safe just because their historical host is in host_pool.
        self.assertEqual(single.needs_review_count,2)
        self.assertEqual(batch.needs_review_count,1)
        self.assertEqual(self.selected(single)[0],
                         next(x for x in batch.accounts if x.username=="nvl0555"))
        self.assertEqual(dict(batch.host_counts),
                         {"UNPOOLED_HISTORICAL_METADATA":2,
                          "ACTIVE_POOL_METADATA":1})

    def test_unpooled_historical_host_is_not_trusted_source(self):
        snap=self.preview()
        u=self.selected(snap)[0]
        self.assertEqual(u.historical_host,OTHER)
        self.assertEqual(u.host_class,"UNPOOLED_HISTORICAL_METADATA")
        self.assertEqual(u.source_ipv4,SOURCE)
        self.assertTrue(u.source_proven)
        self.assertNotEqual(u.historical_host,u.source_ipv4)

    def test_missing_trusted_ingress_cannot_fall_back_to_host(self):
        snap=self.preview(ingress_witness=None)
        u=self.selected(snap)[0]
        self.assertFalse(u.source_proven)
        self.assertEqual(u.source_ipv4,"")
        self.assertIn("SOURCE_INGRESS_NOT_ATTESTED",u.issues)
        self.assertFalse(snap.inventory_clear)

    def test_wrong_user_or_stale_source_witness_cannot_pass(self):
        variants=[
            LiveIngressWitness("other","s8",SOURCE,NOW-2,"INDEPENDENT_LIVE"),
            LiveIngressWitness("nvl0555","s8",SOURCE,NOW-301,"INDEPENDENT_LIVE"),
            LiveIngressWitness("nvl0555","s8",SOURCE,NOW+1,"INDEPENDENT_LIVE"),
            LiveIngressWitness("nvl0555","s8",SOURCE,NOW-2,"OPERATOR_TEXT"),
            LiveIngressWitness("nvl0555","s8",TARGET,NOW-2,"INDEPENDENT_LIVE"),
        ]
        for item in variants:
            with self.subTest(item=item):
                snap=self.preview(ingress_witness=lambda _n,v=item:v)
                self.assertIn("SOURCE_WITNESS_INVALID_OR_STALE",
                              self.selected(snap)[0].issues)
                self.assertFalse(snap.inventory_clear)

    def test_same_target_ingress_allows_legacy_protected_enrollment(self):
        snap=self.preview(ingress_witness=lambda name:LiveIngressWitness(
            name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE"))
        self.assertNotIn("TARGET_ALREADY_CURRENT_INGRESS",
                         self.selected(snap)[0].issues)
        self.assertTrue(snap.inventory_clear)
        self.assertFalse(snap.can_execute)

    def test_user_already_protected_on_target_is_hold(self):
        self.c.execute(
            "INSERT INTO edge_egress_uid_runtime VALUES"
            "('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        self.c.execute(
            "INSERT INTO edge_egress_uid_bindings VALUES"
            "('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        snap=self.preview(ingress_witness=lambda name:LiveIngressWitness(
            name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE"))
        self.assertIn("TARGET_ALREADY_PROTECTED",self.selected(snap)[0].issues)
        self.assertFalse(snap.inventory_clear)

    def test_missing_and_active_sessions_fail_closed(self):
        self.assertIn("SESSION_STATE_NOT_ATTESTED",
                      self.selected(self.preview(session_count=None))[0].issues)
        self.assertIn("ACTIVE_SESSIONS_PRESENT",
                      self.selected(self.preview(session_count=lambda n,u:1))[0].issues)
        self.assertFalse(self.preview(session_count=lambda n,u:True).inventory_clear)

    def test_f4_staged_or_expired_does_not_authorize_inventory(self):
        self.c.execute("UPDATE edge_egress_readiness SET state='STAGED' "
                       "WHERE edge_id='e9'")
        self.assertIn("TARGET_F4_NOT_ACCEPTED",self.preview().global_issues)
        self.c.execute("UPDATE edge_egress_readiness SET state='READY',"
                       "expires_at=? WHERE edge_id='e9'",(NOW-1,))
        self.assertIn("TARGET_F4_NOT_ACCEPTED",self.preview().global_issues)

    def test_bad_target_f3_or_duplicate_edge_ip_holds(self):
        self.c.execute("UPDATE edge_egress_allocations SET status='HOLD' "
                       "WHERE edge_id='e9'")
        self.assertIn("TARGET_F3_NOT_STAGED",self.preview().global_issues)
        self.c.execute("UPDATE edge_egress_allocations SET status='STAGED' "
                       "WHERE edge_id='e9'")
        self.c.execute("INSERT INTO edge_egress_allocations VALUES"
                       "('duplicate',?,'STAGED',20010)",(TARGET,))
        self.assertIn("TARGET_EGRESS_IDENTITY_COLLISION",
                      self.preview().global_issues)

    def test_shared_6g_operation_blocks_both_modes(self):
        self.c.execute("INSERT INTO failover_operations VALUES(123,'RUNNING')")
        for mode,names in (("SINGLE",("nvl0555",)),
                           ("BATCH",("nvl0555","nvl0557"))):
            self.assertIn("SHARED_6G_BUSY",
                          self.preview(names,mode).global_issues)

    def test_partial_runtime_and_mismatched_binding_are_identified(self):
        self.c.execute(
            "INSERT INTO edge_egress_uid_runtime VALUES"
            "('nvl0555',1636,'s8',?,'PROTECTED')",(SOURCE,))
        u=self.selected(self.preview())[0]
        self.assertIn("PARTIAL_PROTECTED_IDENTITY",u.issues)
        self.c.execute(
            "INSERT INTO edge_egress_uid_bindings VALUES"
            "('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        self.assertIn("PROTECTED_IDENTITY_CONFLICT",
                      self.selected(self.preview())[0].issues)

    def test_uid_collision_blocks_all_candidates(self):
        self.uids["nvl0557"]=1636
        for names,mode in ((("nvl0555",),"SINGLE"),
                           (("nvl0555","nvl0557"),"BATCH")):
            p=self.preview(names,mode)
            self.assertIn("UNSAFE_ACCOUNT_OWNERSHIP",p.global_issues)
            self.assertFalse(p.inventory_clear)

    def test_orphan_protected_identity_blocks_preflight(self):
        self.c.execute("INSERT INTO edge_egress_uid_runtime VALUES"
                       "('orphan',1650,'s8',?,'PROTECTED')",(SOURCE,))
        self.assertIn("ORPHAN_PROTECTED_IDENTITY",self.preview().global_issues)

    def test_unknown_selected_account_fails_without_mutating(self):
        statements=[]
        self.c.set_trace_callback(statements.append)
        p=self.preview(("does_not_exist",))
        self.c.set_trace_callback(None)
        self.assertIn("SELECTED_ACCOUNT_NOT_ACTIVE",p.global_issues)
        self.assertFalse(any(sql.lstrip().upper().startswith(
            ("UPDATE","INSERT","DELETE","REPLACE","ALTER",
             "DROP","CREATE","BEGIN IMMEDIATE")) for sql in statements))

    def test_selected_list_not_affect_nonselected_neighbors(self):
        self.c.execute("UPDATE ssh_accounts SET host='198.51.100.50' "
                       "WHERE username='nvl0557'")
        p=self.preview()
        neighbor=next(x for x in p.accounts if x.username=="nvl0557")
        self.assertFalse(neighbor.selected)
        self.assertFalse(neighbor.source_proven)
        self.assertTrue(neighbor.needs_review)
        self.assertIn("SOURCE_INGRESS_NOT_ATTESTED",neighbor.issues)
        self.assertEqual(neighbor.host_class,
                         "UNRESOLVED_HISTORICAL_METADATA")
        self.assertTrue(p.inventory_clear)

    def test_duplicate_accounts_not_silently_dropped(self):
        self.c.execute("INSERT INTO ssh_accounts VALUES"
                       "('nvl0555',?,'ssh','🟢 فعال')",(OTHER,))
        p=self.preview()
        self.assertEqual(p.active_total,4)
        self.assertIn("UNSAFE_ACCOUNT_OWNERSHIP",p.global_issues)

    def test_invalid_selection_fails_before_any_db_access(self):
        invalid=[
            ("SINGLE",("nvl0555","nvl0557"),"e9"),
            ("BATCH",[],"e9"),
            ("BATCH",("nvl0555","nvl0555"),"e9"),
            ("SINGLE",("../../../",),"e9"),
            ("BATCH",("nvl0555",),"../e9"),
            ("ALL",("nvl0555",),"e9"),
        ]
        for mode,names,eid in invalid:
            with self.subTest(mode=mode,names=names,eid=eid):
                with self.assertRaises(MigrationInventoryHold):
                    select_migration(mode,names,eid)
        with self.assertRaisesRegex(MigrationInventoryHold,
                                    "SINGLE_REQUIRES_ONE_USERNAME"):
            preview_migration(self.db,replace(
                select_migration("SINGLE",("nvl0555",),"e9"),
                usernames=("nvl0555","nvl0557")),
                os_uid=lambda n:self.uids[n],now=NOW)

    def test_missing_migration_schema_fails_closed(self):
        self.c.execute("DROP TABLE edge_egress_uid_bindings")
        with self.assertRaisesRegex(MigrationInventoryHold,
                                    "M1_CONTROL_SCHEMA_UNAVAILABLE"):
            self.preview()

    def test_snapshot_digest_changes_on_ownership_or_f4_drift(self):
        a=self.preview()
        b=self.preview()
        self.assertEqual(a.fingerprint,b.fingerprint)
        self.c.execute("UPDATE ssh_accounts SET host=? WHERE username='nvl0555'",
                       (SOURCE,))
        c=self.preview()
        self.assertNotEqual(c.fingerprint,a.fingerprint)
        self.c.execute("UPDATE edge_egress_readiness SET state='STAGED' "
                       "WHERE edge_id='e9'")
        d=self.preview()
        self.assertNotEqual(d.fingerprint,c.fingerprint)

    def test_425_account_inventory_is_lossless_and_scoped(self):
        self.c.execute("DELETE FROM ssh_accounts")
        hosts=([SOURCE]+["146.190.3.22"]*5+[OTHER]*405+
               ["172.86.107.57"]*3+["144.172.84.76"]*3+
               ["172.86.127.145"]*2+["172.86.108.21"]*2+
               ["146.190.3.21","146.190.3.23","146.190.3.24",
                "146.190.3.25"])
        self.assertEqual(len(hosts),425)
        self.c.executemany("INSERT INTO ssh_accounts VALUES"
                           "(?,?,'ssh','🟢 فعال')",
                           [(f"user{i:04d}",host) for i,host in enumerate(hosts)])
        uids={f"user{i:04d}":2000+i for i in range(len(hosts))}
        p=preview_migration(self.db,select_migration(
            "SINGLE",("user0000",),"e9"),os_uid=lambda n:uids[n],
            ingress_witness=self.witness,session_count=lambda n,u:0,now=NOW)
        self.assertEqual(p.active_total,425)
        self.assertEqual(sum(n for _,n in p.host_counts),425)
        self.assertEqual(p.selected_total,1)
        self.assertEqual(len(p.accounts),425)
        self.assertFalse(any(x.selected for x in p.accounts[1:]))
        # This is artificial input inspired by operator statistics, NOT a
        # replay of /root/master_bot.db or a real 425-account attestation.


if __name__ == "__main__":
    unittest.main()
