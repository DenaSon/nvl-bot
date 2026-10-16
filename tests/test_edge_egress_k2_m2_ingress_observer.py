"""M2 read-only SSH PAM→pinned wg0 ingress evidence regressions."""
from __future__ import annotations

import base64
from dataclasses import replace
from unittest.mock import patch
import unittest

from edge_egress_k2_m2_ingress_observer import (
    PAMIngressHold, observe_pam_ingress, observe_current_pam_ingress,
)
from edge_egress_v1_ingress import IngressPeer

NOW=1792010100
SRC="10.77.0.9"
EDGE="45.61.163.75"
KEY=base64.b64encode(bytes(range(32))).decode()
FOREIGN=base64.b64encode(bytes(range(1,33))).decode()


class M2IngressWitnessTests(unittest.TestCase):
    def setUp(self):
        self.env={"PAM_SERVICE":"sshd","PAM_TYPE":"account",
                  "PAM_USER":"nvl0555","PAM_RHOST":SRC}
        self.peers=(IngressPeer("e9",EDGE,SRC,KEY),)
        self.allowed=KEY+"\t"+SRC+"/32\n"
        self.kw=dict(username="nvl0555",uid=1636,pam_env=self.env,
                     peers=self.peers,allowed_ips=self.allowed,now=NOW,
                     geteuid=lambda:0,resolve_uid=lambda n:1636)

    def observe(self,**opts):
        kw=dict(self.kw);kw.update(opts)
        return observe_pam_ingress(**kw)

    def test_exact_pam_user_peer_and_wg_key_resolve_edge(self):
        found=self.observe()
        self.assertEqual((found.username,found.edge_id,found.edge_ipv4),
                         ("nvl0555","e9",EDGE))
        self.assertEqual(found.observed_at,NOW)
        self.assertEqual(found.proof_kind,"INDEPENDENT_LIVE")

    def test_no_root_or_wrong_pam_phase_is_denied(self):
        for change in (
            {"geteuid":lambda:1000},
            {"pam_env":dict(self.env,PAM_TYPE="session")},
            {"pam_env":dict(self.env,PAM_SERVICE="login")},
            {"pam_env":dict(self.env,PAM_USER="nvl0557")},
        ):
            with self.subTest(change=change),self.assertRaises(PAMIngressHold):
                self.observe(**change)

    def test_unknown_or_external_peer_not_a_proof(self):
        for addr in ("209.200.246.198","10.77.0.7","garbage","10.77.0.1"):
            with self.subTest(addr=addr),self.assertRaises(PAMIngressHold):
                self.observe(pam_env=dict(self.env,PAM_RHOST=addr))

    def test_ambiguous_registry_rejected(self):
        with self.assertRaises(PAMIngressHold):
            self.observe(peers=self.peers+self.peers)

    def test_missing_key_or_foreign_overlapping_allowedips_rejected(self):
        for raw in (
            FOREIGN+"\t"+SRC+"/32\n",
            self.allowed+FOREIGN+"\t10.77.0.0/24\n",
            self.allowed+KEY+"\t10.77.0.9/32\n",
        ):
            with self.subTest(raw=raw),self.assertRaises(PAMIngressHold):
                self.observe(allowed_ips=raw)

    def test_os_uid_changed_rejected(self):
        with self.assertRaises(PAMIngressHold):
            self.observe(resolve_uid=lambda n:2000)

    def test_nonroot_concrete_probe_never_invokes_wireguard(self):
        calls=[]
        def fake_run(*args,**kwargs):
            calls.append(args)
            raise AssertionError("should not execute")
        with self.assertRaises(PAMIngressHold):
            observe_current_pam_ingress(geteuid=lambda:1000,run=fake_run)
        self.assertEqual(calls,[])

    def test_pam_source_is_not_db_host_or_dns(self):
        # Only the exact SSH PAM/WG peer can produce a witness.
        self.assertEqual(self.observe().edge_ipv4,EDGE)
        with self.assertRaises(PAMIngressHold):
            self.observe(pam_env=dict(self.env,PAM_RHOST="104.194.144.195"))


if __name__=="__main__":
    unittest.main()
