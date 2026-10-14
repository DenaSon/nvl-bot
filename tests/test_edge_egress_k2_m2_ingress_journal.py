"""M2 ingress journal: PAM-only proof, 300-second expiry and immutable roster."""
from __future__ import annotations
import base64
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from edge_egress_k2_m2_ingress_journal import (
    DurableIngressHold, IngressRecord, add_authenticated_observation,
    encode_records, verified_recent_observation, create_root_journal_if_absent,
    compare_and_swap_root_journal,
)
from edge_egress_v1_ingress import IngressPeer
from edge_egress_k2_migration_inventory import preview_migration, select_migration
from tests.test_edge_egress_k2_migration_inventory import K2M1InventoryTests
NOW=1792010100
KEY=base64.b64encode(bytes(range(32))).decode()
KEY2=base64.b64encode(bytes(range(1,33))).decode()
P=IngressPeer("e9","45.61.163.75","10.77.0.9",KEY)
W=KEY+"\t10.77.0.9/32\n"

class M2IngressJournalTests(unittest.TestCase):
    def setUp(self):
        self.raw=encode_records({})
        self.kw=dict(
            username="nvl0555",uid=1636,pam_env={
                "PAM_SERVICE":"sshd","PAM_TYPE":"account",
                "PAM_USER":"nvl0555","PAM_RHOST":"10.77.0.9",
            },peers=(P,),allowed_ips=W,now=NOW,
            geteuid=lambda:0,resolve_uid=lambda name:1636,
        )
    def observed(self,**changes):
        args=dict(self.kw);args.update(changes)
        return add_authenticated_observation(self.raw,**args)
    def verified(self,data,**changes):
        opts=dict(username="nvl0555",uid=1636,peers=(P,),
                  allowed_ips=W,now=NOW+60,resolve_uid=lambda _:1636)
        opts.update(changes)
        return verified_recent_observation(data,**opts)

    def test_root_pam_observation_round_trip(self):
        data=self.observed()
        v=self.verified(data)
        self.assertEqual((v.username,v.edge_id,v.edge_ipv4,v.observed_at),
                         ("nvl0555","e9","45.61.163.75",NOW))
        self.assertNotIn(b"104.194.144.195",data)
        self.assertEqual(data,self.observed())

    def test_credentialless_nonpam_input_denied(self):
        for change in (
            {"geteuid":lambda:1000},
            {"pam_env":dict(self.kw["pam_env"],PAM_TYPE="session")},
            {"pam_env":dict(self.kw["pam_env"],PAM_USER="nvl0557")},
            {"pam_env":dict(self.kw["pam_env"],PAM_RHOST="10.77.0.8")},
            {"resolve_uid":lambda _:1644},
            {"allowed_ips":KEY2+"\t10.77.0.9/32\n"},
        ):
            with self.subTest(change=change),self.assertRaises(DurableIngressHold):
                self.observed(**change)

    def test_freshness_boundary_and_time_rewind(self):
        data=self.observed()
        self.assertEqual(self.verified(data,now=NOW+300).edge_id,"e9")
        for time in (NOW-1,NOW+301):
            with self.subTest(time=time),self.assertRaises(DurableIngressHold):
                self.verified(data,now=time)
        self.raw=data
        with self.assertRaises(DurableIngressHold):
            self.observed(now=NOW-1)

    def test_root_owned_record_never_proves_drifted_wireguard(self):
        data=self.observed()
        for changes in (
            {"peers":(replace(P,edge_ipv4="45.61.163.76"),)},
            {"peers":()},
            {"allowed_ips":KEY2+"\t10.77.0.9/32\n"},
            {"allowed_ips":W+KEY2+"\t10.77.0.0/24\n"},
            {"resolve_uid":lambda _:1637},
            {"uid":1637},
        ):
            with self.subTest(changes=changes),self.assertRaises((DurableIngressHold,ValueError)):
                self.verified(data,**changes)

    def test_multi_record_cannot_silently_drop_old_user(self):
        before=self.observed()
        self.raw=before
        args=dict(self.kw,username="nvl0557",uid=1644,
                  resolve_uid=lambda _:1644,
                  pam_env=dict(self.kw["pam_env"],PAM_USER="nvl0557"),
                  now=NOW+5)
        after=add_authenticated_observation(self.raw,**args)
        self.assertEqual(len(json.loads(after)["records"]),2)
        self.assertEqual(self.verified(after).username,"nvl0555")
        self.assertEqual(self.verified(after,username="nvl0557",uid=1644,
                          resolve_uid=lambda _:1644).username,"nvl0557")

    def test_duplicate_malformed_or_missing_journal_fails_closed(self):
        with self.assertRaises(DurableIngressHold):
            verified_recent_observation(b"{}",username="nvl0555",uid=1636,
                peers=(P,),allowed_ips=W,now=NOW,resolve_uid=lambda _:1636)
        duplicate=json.loads(self.observed())
        duplicate["records"].append(duplicate["records"][0])
        with self.assertRaises(DurableIngressHold):
            verified_recent_observation(json.dumps(duplicate).encode(),
                username="nvl0555",uid=1636,peers=(P,),allowed_ips=W,
                now=NOW,resolve_uid=lambda _:1636)

    def test_can_feed_m1_readonly_inventory_not_live_lease(self):
        fx=K2M1InventoryTests()
        fx.setUp()
        try:
            fx.c.execute("UPDATE edge_egress_allocations "
                         "SET edge_id='e9' WHERE edge_id='s8'")
            # M1 expects unique pinned target, so use another known source
            # Edge instead of using the same target allocation twice.
            fx.c.execute("UPDATE edge_egress_allocations "
                         "SET edge_id='s8' WHERE edge_id='e9' AND edge_public_ipv4 != '45.61.163.75'")
            data=self.observed()
            p=preview_migration(fx.db,select_migration(
                "SINGLE",("nvl0555",),"e9"),os_uid=lambda n:fx.uids[n],
                ingress_witness=lambda _:self.verified(data,now=NOW+1),
                session_count=lambda n,u:0,now=NOW+1)
            self.assertFalse(p.can_execute)
        finally:
            fx.doCleanups()

    def test_nonroot_cannot_create_or_write_journal(self):
        with self.assertRaises(DurableIngressHold):
            create_root_journal_if_absent(geteuid=lambda:1000)
        with self.assertRaises(DurableIngressHold):
            compare_and_swap_root_journal(self.observed(),self.observed(),
                                          geteuid=lambda:1000)

if __name__=="__main__":
    unittest.main()
