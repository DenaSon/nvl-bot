"""D1-D2A: Core staging preflight must never mutate production."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.labs.edge_egress_core_staging_preflight import evaluate_core


class FakeCore:
    def __init__(self, *, address_conflict=False, table_busy=False,
                 rule_busy=False, namespace_busy=False, iface_busy=False,
                 wg0=True):
        self.commands = []
        self.address_conflict = address_conflict
        self.table_busy = table_busy
        self.rule_busy = rule_busy
        self.namespace_busy = namespace_busy
        self.iface_busy = iface_busy
        self.wg0 = wg0

    def __call__(self, argv):
        self.commands.append(tuple(argv))
        name = " ".join(argv)
        output = ""
        if name == "ip -j link show":
            output = json.dumps([{"ifname":"wg0"},{"ifname":"eth0"}] +
                                ([{"ifname":"vnh-stg1"}] if self.iface_busy else []))
        elif name == "ip -j -4 addr show":
            ips=[{"ifname":"eth0","addr_info":[{"family":"inet",
                   "local":"209.200.246.198","prefixlen":24}]}]
            if self.address_conflict:
                ips.append({"ifname":"veth-existing","addr_info":[
                    {"family":"inet","local":"10.78.110.1","prefixlen":30}]})
            output=json.dumps(ips)
        elif name == "ip -j -4 route show table all":
            output=json.dumps([{"dst":"default","table":"main","dev":"eth0"}] +
                              ([{"dst":"default","table":1790}] if self.table_busy else []))
        elif name == "ip -4 rule show":
            output=("0: from all lookup local\n32766: from all lookup main\n" +
                    ("1790: from all uidrange 1659-1659 lookup 1790\n" if self.rule_busy else ""))
        elif name == "ip netns list":
            output="nvl-egress-stg1 (id: 1)\n" if self.namespace_busy else ""
        elif name in ("ss -H -lun","ss -H -ltn"):
            output=""
        elif name == "wg show interfaces":
            output="wg0 wg-nvl-fra1" if self.wg0 else "wg-nvl-fra1"
        elif name == "systemctl show nvlbot -p ActiveState --no-pager":
            output="ActiveState=active\n"
        elif name == "systemctl show ssh.service -p ActiveState --no-pager":
            output="ActiveState=active\n"
        else:
            raise AssertionError("UNREVIEWED_HOST_QUERY:" + name)
        return 0, output


def fake_database(path):
    return {"available": True, "settings_table": True,
            "operations_table": True, "protected_mode":"0",
            "running_6g_operations":0}


def absent_user(username):
    raise KeyError(username)


def run(fake, *, db_reader=fake_database, user=absent_user):
    with patch("ops.labs.edge_egress_core_staging_preflight.shutil.which",
               return_value="/usr/bin/dummy"):
        return evaluate_core(probe=fake, db_reader=db_reader,
                             username_lookup=user, db_path=Path("/root/master_bot.db"))


class CoreStagingPreflightTests(unittest.TestCase):
    def test_clean_prod_core_gives_candidate_not_activation_approval(self):
        runner=FakeCore()
        result=run(runner)
        self.assertEqual(result["verdict"],"CORE_ONLY_CANDIDATE")
        self.assertFalse(result["activation_authorized"])
        self.assertEqual(result["candidate"]["edge_id"],"stg1")
        self.assertEqual(result["candidate"]["route_table"],1790)
        self.assertEqual(result["next_gate"],
                         "STANDBY_EDGE_PREFLIGHT_AND_OPERATOR_REVIEW")
        self.assertTrue(result["observed"]["wg0_present"])

    def test_route_table_priority_network_and_namespace_collisions_block(self):
        for key in ("address_conflict","table_busy","rule_busy",
                    "namespace_busy","iface_busy"):
            with self.subTest(key=key):
                result=run(FakeCore(**{key:True}))
                self.assertEqual(result["verdict"],"BLOCKED")
                self.assertFalse(result["activation_authorized"])

    def test_core_wg0_missing_blocks_without_attempting_repair(self):
        r=run(FakeCore(wg0=False))
        self.assertEqual(r["verdict"],"BLOCKED")
        self.assertIn("PRODUCTION_WG0_BASELINE_MISSING",r["issues"])

    def test_running_shared_6g_or_enabled_protected_mode_blocks(self):
        for field,value in (("running_6g_operations",1),("protected_mode","1")):
            def database(_):
                result=fake_database(None)
                result[field]=value
                return result
            with self.subTest(field=field):
                self.assertEqual(run(FakeCore(),db_reader=database)["verdict"],
                                 "BLOCKED")

    def test_existing_staging_username_blocks(self):
        report=run(FakeCore(),user=lambda _:object())
        self.assertIn("STAGING_USERNAME_OCCUPIED",report["issues"])

    def test_probes_strictly_read_only_and_do_not_dump_credentials(self):
        fake=FakeCore()
        result=run(fake)
        commands=[" ".join(x) for x in fake.commands]
        self.assertNotIn("private_key", json.dumps(result))
        self.assertNotIn("accounts", json.dumps(result))
        self.assertEqual(len(commands),10)
        for c in commands:
            for forbidden in (" add "," del "," replace "," restart",
                              " stop"," start","iptables","wg show wg0",
                              "sqlite3 ", "systemctl enable",
                              "systemctl disable"):
                self.assertNotIn(forbidden,c)
        self.assertEqual(result["mode"],"READ_ONLY_PREFLIGHT")

    def test_command_probe_failure_denies(self):
        base=FakeCore()
        def broken(cmd):
            if cmd == ("ip","-j","-4","route","show","table","all"):
                return 1,""
            return base(cmd)
        result=run(broken)
        self.assertEqual(result["verdict"],"BLOCKED")
        self.assertIn("PROBE_FAILED:routes",result["issues"])


if __name__=="__main__":
    unittest.main()
