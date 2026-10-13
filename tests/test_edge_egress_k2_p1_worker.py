"""K2 Phase 1 activation: precise mock I/O, real SQLite journal semantics.

Does not start WireGuard, SSH, iptables, systemd, DNS, PAM or user routes.
"""
import json
import sqlite3
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_k2_p1_worker import (
    StagePin, Phase1Hold, activate_phase1, inspect_phase1, _prove_ipv4, INTENT, RECOVERY,
)
from edge_egress_handoff import is_egress_recovery_hold

EDGE = "172.86.105.68"
CORE = "209.200.246.198"
SOURCE = "144.172.84.82"


class Phase1TransportActivationTests(unittest.TestCase):
    def setUp(self):
        self.conn=sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,is_default INT);
            INSERT INTO host_pool VALUES('144.172.84.82',1,1);
            CREATE TABLE failover_operations(
                id INTEGER PRIMARY KEY,source_host TEXT,target_host TEXT,
                status TEXT,detail_json TEXT);
            CREATE TABLE ssh_accounts(username TEXT,host TEXT);
            INSERT INTO ssh_accounts VALUES('nvl0001','144.172.84.82');
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('hosts','144.172.84.82');
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.82');
        """)
        self.pin=StagePin(
            "e8",EDGE,CORE,"10.77.0.8","a"*64,"b"*64,
            "dummy-key-mocked",22,
        )
        self.spec=SimpleNamespace(
            edge_id="e8",edge_public_ipv4=EDGE,core_public_ipv4=CORE,
        )
        self.events=[]
        self.next_id=0
        self.edge_running=False
        self.core_running=False

    def acquire(self,source,target):
        self.events.append("lock")
        self.next_id+=1
        self.conn.execute(
            "INSERT INTO failover_operations VALUES(?,?,?,?,?)",
            (self.next_id,source,target,"RUNNING","{}"),
        )
        self.conn.commit()
        return self.next_id,None

    def journal(self,operation_id,*,status,detail,**kwargs):
        self.events.append(detail["phase"])
        self.conn.execute(
            "UPDATE failover_operations SET status=?,detail_json=? WHERE id=?",
            (status,json.dumps(detail),operation_id),
        )
        self.conn.commit()

    def remote(self,pin,action):
        self.events.append("edge:"+action)
        if action == "inspect":
            return "UP" if self.edge_running else "ABSENT"
        self.edge_running=True
        return "TRANSPORT_STARTED"

    def core(self,*args):
        self.events.append("core:ensure")
        self.core_running=True
        return "TRANSPORT_STARTED"

    def prove(self,spec):
        self.events.append("ip:prove")
        return EDGE

    def start(self,**kwargs):
        with patch(
            "edge_egress_k2_p1_worker._check_stage",
            return_value=(self.spec,"wg-peer",Path("/root/nvl-egress-v1/core-e8")),
        ),patch("edge_egress_k2_p1_worker.observe",
                side_effect=lambda *args: "UP" if self.core_running else "ABSENT"):
            return activate_phase1(
                "e8",db_conn=lambda:self.conn,
                acquire=self.acquire,journal=self.journal,
                load_pin=lambda _:self.pin,
                remote_transport=self.remote,core_ensure=self.core,
                ipv4_proof=self.prove,**kwargs,
            )

    def test_only_dedicated_transport_started_and_observed_edge_ipv4(self):
        result=self.start()
        self.assertEqual(result["observed_ipv4"],EDGE)
        self.assertFalse(result["customer_ready"])
        self.assertLess(self.events.index("edge:ensure"),self.events.index("core:ensure"))
        self.assertLess(self.events.index("core:ensure"),self.events.index("ip:prove"))
        self.assertEqual(self.events[-1],"EGRESS_P1_TRANSPORT_PROVEN")
        self.assertEqual(self.conn.execute(
            "SELECT host FROM ssh_accounts").fetchone()[0],SOURCE)
        self.assertEqual(self.conn.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        ).fetchone()[0],SOURCE)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM host_pool").fetchone()[0],1)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM failover_operations").fetchone()[0],"SUCCEEDED")

    def test_failed_ipv4_proof_keeps_shared_6g_hold_not_core_fallback(self):
        def bad_proof(_spec):
            self.events.append("failed-ip-proof")
            raise Phase1Hold("EDGE_IP_MISMATCH")
        self.prove=bad_proof
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        status,detail=self.conn.execute(
            "SELECT status,detail_json FROM failover_operations").fetchone()
        self.assertEqual(status,"RUNNING")
        self.assertEqual(json.loads(detail)["phase"],RECOVERY)
        self.assertTrue(is_egress_recovery_hold(detail))
        self.assertFalse(any("down" in x for x in self.events))

    def test_competing_lock_blocks_before_any_host_change(self):
        self.conn.execute(
            "INSERT INTO failover_operations VALUES(7,?,?,?,?)",
            (SOURCE,EDGE,"RUNNING",json.dumps({"phase":INTENT})),
        )
        self.conn.commit()
        def busy(_src,_target):
            return None,7
        with patch(
            "edge_egress_k2_p1_worker._check_stage",
            return_value=(self.spec,"wg-peer",Path("/root/nvl-egress-v1/core-e8")),
        ),patch("edge_egress_k2_p1_worker.observe",return_value="ABSENT"):
            with self.assertRaisesRegex(Phase1Hold,"BUSY"):
                activate_phase1(
                    "e8",db_conn=lambda:self.conn,acquire=busy,
                    journal=self.journal,load_pin=lambda _:self.pin,
                    remote_transport=self.remote,core_ensure=self.core,
                )
        self.assertNotIn("edge:ensure",self.events)
        self.assertNotIn("core:ensure",self.events)

    def test_candidate_present_in_live_customer_pool_refused(self):
        self.conn.execute(
            "INSERT INTO host_pool VALUES(?,1,0)",(EDGE,))
        self.conn.commit()
        with self.assertRaisesRegex(Phase1Hold,"UNSAFE_ACTIVE_RELAY"):
            self.start()
        self.assertEqual(self.events,[])

    def test_readonly_inspection_does_not_modify_database(self):
        trace=[]
        self.conn.set_trace_callback(trace.append)
        with patch(
            "edge_egress_k2_p1_worker._check_stage",
            return_value=(self.spec,"wg-peer",Path("/root/nvl-egress-v1/core-e8")),
        ),patch("edge_egress_k2_p1_worker.observe",return_value="ABSENT"):
            summary=inspect_phase1(
                "e8",db_conn=lambda:self.conn,
                load_pin=lambda _:self.pin,remote_transport=self.remote,
            )
        self.assertFalse(summary["customer_ready"])
        self.assertEqual(summary["edge"],"ABSENT")
        self.assertFalse(any(x.lstrip().upper().startswith(
            ("INSERT ","UPDATE ","DELETE ","REPLACE ","CREATE ")
        ) for x in trace))

    def test_public_ipv4_proof_requires_exact_edge_and_no_dns_lookup(self):
        spec = SimpleNamespace(namespace="nvleg8", edge_public_ipv4=EDGE)
        calls=[]
        def response(cmd,**kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout="fl=example\nip="+EDGE+"\n")
        self.assertEqual(_prove_ipv4(spec,run=response,sleep=lambda n:None), EDGE)
        self.assertIn("--resolve", calls[0])
        self.assertIn("one.one.one.one:443:1.1.1.1", calls[0])
        self.assertEqual(calls[0][0:4], ["ip","netns","exec","nvleg8"])
        def wrong(cmd,**kw):
            return SimpleNamespace(returncode=0,stdout="ip="+CORE+"\n")
        with self.assertRaisesRegex(Phase1Hold,"IP_NOT_PROVEN"):
            _prove_ipv4(spec,run=wrong,sleep=lambda n:None)


    def test_wrong_injected_public_proof_must_not_signal_success(self):
        self.prove=lambda _spec: CORE
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        status,detail=self.conn.execute(
            "SELECT status,detail_json FROM failover_operations").fetchone()
        self.assertEqual(status,"RUNNING")
        self.assertEqual(json.loads(detail)["phase"],RECOVERY)
        self.assertNotIn("EGRESS_P1_TRANSPORT_PROVEN",self.events)

    def test_ownership_change_after_remote_activation_holds_before_core(self):
        original=self.remote
        def changed(pin,action):
            value=original(pin,action)
            if action == "ensure":
                self.conn.execute(
                    "UPDATE host_pool SET is_default=0 WHERE host=?", (SOURCE,))
                self.conn.commit()
            return value
        self.remote=changed
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        self.assertNotIn("core:ensure",self.events)
        detail=self.conn.execute(
            "SELECT detail_json FROM failover_operations").fetchone()[0]
        self.assertEqual(json.loads(detail)["phase"],RECOVERY)

    def test_core_start_that_does_not_report_success_holds(self):
        self.core=lambda *args: "ABSENT"
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        self.assertNotIn("ip:prove",self.events)

    def test_post_start_remote_verification_requires_actual_up(self):
        original=self.remote
        def no_up(pin,action):
            result=original(pin,action)
            return "ABSENT" if action=="inspect" else result
        self.remote=no_up
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        self.assertNotIn("ip:prove",self.events)

    def test_recovery_marker_does_not_authorize_continuing_activation(self):
        original=self.remote
        def tamper_intent(pin,action):
            result=original(pin,action)
            if action == "ensure":
                row=self.conn.execute(
                    "SELECT id,detail_json FROM failover_operations").fetchone()
                data=json.loads(row[1])
                data["phase"]=RECOVERY
                self.conn.execute(
                    "UPDATE failover_operations SET detail_json=? WHERE id=?",
                    (json.dumps(data),row[0]),
                )
                self.conn.commit()
            return result
        self.remote=tamper_intent
        with self.assertRaisesRegex(Phase1Hold,"HELD_FOR_REVIEW"):
            self.start()
        self.assertNotIn("core:ensure",self.events)

    def test_source_wizard_pins_both_stages_no_fake_ready(self):
        txt=Path("edge_egress_v1_onboarding.py").read_text(encoding="utf-8")
        self.assertIn("edge_digest = _remote_stage_digest(ssh, remote_dir)",txt)
        self.assertIn("core_sha=stage_hash(core_stage)",txt)
        self.assertIn("publish_stage_pin(StagePin(",txt)
        self.assertLess(txt.index("publish_stage_pin(StagePin("),
                        txt.index("_publish_registry(peer)\n    return dict("))
        self.assertNotIn("customer_ready=True",txt)

    def test_bot_requires_admin_confirmation_and_opt_in_no_users(self):
        src=Path("bot_final_v49-2.py").read_text(encoding="utf-8")
        for marker in (
            "hpeg_p1_open_", "hpeg_p1_yes_", "hpeg_p1_status_",
            "k2_p1_activation_ticket", "role != 'admin'",
            "k2_p1_transport_activation_enabled",
            "activate_phase1, edge_id, db_conn=db_conn",
        ):
            self.assertIn(marker,src)
        self.assertIn("hpeg_p1_open_",Path(
            "edge_egress_p3_telegram.py").read_text(encoding="utf-8"))
        self.assertIn("hpeg_p1_status_",Path(
            "edge_egress_p3_telegram.py").read_text(encoding="utf-8"))
        self.assertIn("اثبات IP عمومی فقط",src)
        self.assertIn("Edge هنوز F4 READY نیست",src)

    def test_pin_file_rejects_invalid_fields_before_network(self):
        for value in ("bad/ip", "10.0.0.1", "1.2.3.999"):
            pin=StagePin("e8",value,CORE,"10.77.0.8","a"*64,"b"*64,"x",22)
            with self.assertRaises(Phase1Hold):
                pin.validate()
        pin=StagePin("e8",EDGE,CORE,"10.77.0.8","xx","b"*64,"x",22)
        with self.assertRaisesRegex(Phase1Hold,"DIGEST"):
            pin.validate()


if __name__=="__main__":
    unittest.main()
