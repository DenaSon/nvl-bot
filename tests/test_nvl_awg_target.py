"""No-network AWG-03 target/standby admission regression tests."""
import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from nvl_awg_target import (
    Target, verify_awg_target, target_backend, core_limiter_canary_ready,
)
from nvl_tunnel_backend import SCHEMA, TunnelHold
from nvl_awg_nat_evidence import verify_awg_nat

CORE_KEY = "A"*43 + "="
EDGE_KEY = "B"*43 + "="
HOST = "8.8.4.4"
CORE_PUBLIC = "8.8.8.8"
CORE_TUNNEL = "10.231.55.1"
EDGE_TUNNEL = "10.231.55.3"


def nat_rules():
    return "\n".join(
        f"-A {chain} {args}" for p in (2252,2088)
        for chain,args in (
            ("PREROUTING", f"-i eth1 -p tcp --dport {p} "
                            f"-j DNAT --to-destination {CORE_TUNNEL}:{p}"),
            ("POSTROUTING",f"-d {CORE_TUNNEL}/32 -o awg0 -p tcp "
                           f"--dport {p} -j SNAT --to-source {EDGE_TUNNEL}")
        )
    )


def forward_rules():
    return "\n".join(
        f"-A FORWARD {args}" for p in (2252,2088)
        for args in (
            f"-d {CORE_TUNNEL}/32 -i eth1 -o awg0 -p tcp "
            f"--dport {p} -j ACCEPT",
            f"-s {CORE_TUNNEL}/32 -i awg0 -o eth1 -p tcp "
            f"--sport {p} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        )
    )


class FakeSSH:
    def close(self):
        pass


class AWGTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbfile = str(Path(self.temp.name)/"state.db")
        self.db_factory = lambda: sqlite3.connect(self.dbfile)
        with self.db_factory() as db:
            db.executescript(SCHEMA)
            db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE manual_edge_operations(
              ip TEXT, admin_port INTEGER, pin_type TEXT, pin_base64 TEXT,
              tunnel_backend TEXT, status TEXT
            );
            CREATE TABLE host_pool(
              host TEXT PRIMARY KEY, service_port INTEGER,
              admin_ssh_port INTEGER
            );
            """)
            db.execute("INSERT INTO settings VALUES (?,?)",
                       ("core_wg_public_ip", CORE_PUBLIC))
            db.execute(
                "INSERT INTO edge_tunnel_bindings "
                "VALUES (?,?,?,?,?,?,?,?)",
                (HOST,"amneziawg","awg0",CORE_TUNNEL,EDGE_TUNNEL,
                 EDGE_KEY,"VERIFIED",int(time.time())),
            )
            db.execute(
                "INSERT INTO manual_edge_operations VALUES (?,?,?,?,?,?)",
                (HOST,22,"ssh-ed25519","PINNED","amneziawg","EDGE_READY"),
            )
            db.execute("INSERT INTO host_pool VALUES (?,?,?)",
                       (HOST,2252,22))
        self.target = Target(
            HOST,2252,2088,22,"ssh-ed25519","PINNED",
        )
        self.remote_calls = []
        self.commands = []

    def runner(self, cmd, **kwargs):
        self.commands.append(cmd)
        if cmd == ["awg","show","awg0","allowed-ips"]:
            data=EDGE_KEY+" "+EDGE_TUNNEL+"/32\n"
        elif cmd == ["awg","show","awg0","latest-handshakes"]:
            data=EDGE_KEY+" "+str(int(time.time()))+"\n"
        elif cmd == ["awg","show","awg0","public-key"]:
            data=CORE_KEY+"\n"
        elif cmd[0]=="ping":
            data=""
        else:
            raise AssertionError("unexpected local command "+repr(cmd))
        return subprocess.CompletedProcess(cmd,0,data,"")

    def remote(self, ssh, cmd, timeout=8):
        self.remote_calls.append(cmd)
        if cmd=="awg show awg0 peers":
            return CORE_KEY
        if cmd=="awg show awg0 allowed-ips":
            return CORE_KEY+" "+CORE_TUNNEL+"/32"
        if cmd.startswith("ip -4 -o addr show"):
            return "10: awg0 inet "+EDGE_TUNNEL+"/32 scope global"
        if cmd.startswith("ip -4 route get"):
            return "eth1"
        if cmd=="iptables -t nat -S":
            return nat_rules()
        if cmd=="iptables -S FORWARD":
            return forward_rules()
        if cmd=="cat /etc/iptables/rules.v4":
            return nat_rules()+"\n"+forward_rules()
        return {
            "sysctl -n net.ipv4.ip_forward":"1",
            "systemctl is-active awg-quick@awg0":"active",
            "systemctl is-enabled awg-quick@awg0":"enabled",
            "systemctl is-enabled netfilter-persistent":"enabled",
        }[cmd]

    def verify(self):
        with patch("nvl_awg_target._remote", side_effect=self.remote):
            return verify_awg_target(
                self.db_factory,self.target,
                runner=self.runner,
                ssh_connect=lambda *a:FakeSSH(),
            )

    def test_verified_target_has_pinned_wan_and_both_nat_ports(self):
        self.assertTrue(self.verify())
        self.assertTrue(any(CORE_PUBLIC in cmd
                            for cmd in self.remote_calls if "route get" in cmd))
        self.assertFalse(any("10.203.77." in str(cmd)
                             for cmd in self.remote_calls))

    def test_invalid_edge_peer_blocks_before_nat(self):
        with patch("nvl_awg_target._remote", side_effect=lambda ssh,cmd,timeout=8:
                   "WRONG" if cmd=="awg show awg0 peers"
                   else self.remote(ssh,cmd,timeout)):
            result=verify_awg_target(
                self.db_factory,self.target,
                runner=self.runner, ssh_connect=lambda *a: FakeSSH(),
            )
        self.assertFalse(result)

    def test_failed_saved_nat_fails_closed(self):
        def broken(ssh,cmd,timeout=8):
            if cmd=="cat /etc/iptables/rules.v4":
                return nat_rules()
            return self.remote(ssh,cmd,timeout)
        with patch("nvl_awg_target._remote", side_effect=broken):
            self.assertFalse(verify_awg_target(
                self.db_factory,self.target,
                runner=self.runner,ssh_connect=lambda *a: FakeSSH(),
            ))

    def test_unregistered_or_held_binding_never_becomes_legacy(self):
        with self.db_factory() as db:
            self.assertEqual(target_backend(db,HOST),"amneziawg")
            db.execute("UPDATE edge_tunnel_bindings SET state='HOLD'")
        with self.db_factory() as db:
            with self.assertRaises(TunnelHold):
                target_backend(db,HOST)
        self.assertFalse(self.verify())
        with self.db_factory() as db:
            db.execute("DELETE FROM edge_tunnel_bindings")
        with self.db_factory() as db:
            self.assertEqual(target_backend(db,HOST),"wireguard")

    def test_limiter_gate_rejects_missing_file(self):
        self.assertFalse(core_limiter_canary_ready(
            EDGE_TUNNEL,marker_path=str(Path(self.temp.name)/"no-marker")))


if __name__=="__main__":
    unittest.main()
