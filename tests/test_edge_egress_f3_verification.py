"""F3: pinned Core/Edge witness cannot mark a disposable lab as READY."""
import asyncio
from contextlib import contextmanager
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from edge_egress_f3_readiness import (
    Existing6GReadinessStore, install_readiness_schema, read_readiness,
)
from edge_egress_f3_verification import Existing6GEdgeVerifier, HOLD_PHASE
from edge_egress_ssh_transport import PinnedEgressHostPort
from ops.edge_egress_provision import EgressSpec

SOURCE="172.86.94.174"
EDGE="216.126.229.12"
CORE="209.200.246.198"


def spec():
    return EgressSpec(
        edge_id="fra1",edge_public_ipv4=EDGE,core_public_ipv4=CORE,
        tunnel_network="10.78.100.0/30",veth_network="10.78.101.0/30",
        edge_uplink="eth0",route_table=1780,edge_listen_port=51832,
    )


def fake_host(role, observed=EDGE, *, stop_failure=False):
    # No SSH/network access: inject an instance with a deliberately fixed
    # role/IP and limited async protocol methods.
    port=object.__new__(PinnedEgressHostPort)
    port.identity=SimpleNamespace(
        role=role, expected_public_ip=CORE if role=="core" else EDGE,
    )
    port.lab_activation=True
    calls=[]
    async def inspect(_): calls.append("inspect");return {"state":"STAGED"}
    async def start(_): calls.append("start")
    async def stop(_):
        calls.append("stop")
        if stop_failure:
            raise RuntimeError("injected peer cleanup error")
    async def observe(_): calls.append("probe");return observed
    port.inspect_shadow=inspect
    port.start_shadow=start
    port.stop_shadow=stop
    port.observe_public_egress=observe
    return port,calls


class F3ProofTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.temp.name)/"test.db")
        with self.conn() as c:
            c.executescript("""
              CREATE TABLE failover_operations (
                id INTEGER PRIMARY KEY,status TEXT,source_host TEXT,
                target_host TEXT,detail_json TEXT);
              INSERT INTO failover_operations VALUES(
                42,'RUNNING','172.86.94.174','216.126.229.12',NULL);
              CREATE TABLE host_pool (
                host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER);
              INSERT INTO host_pool VALUES('172.86.94.174',1,1);
              CREATE TABLE settings (key TEXT,value TEXT);
              INSERT INTO settings VALUES('dns_current_ip','172.86.94.174');
              CREATE TABLE edge_egress_allocations (
                edge_id TEXT PRIMARY KEY,edge_public_ipv4 TEXT,
                core_public_ipv4 TEXT,tunnel_network TEXT,veth_network TEXT,
                route_table INTEGER,status TEXT);
              INSERT INTO edge_egress_allocations VALUES(
                'fra1','216.126.229.12','209.200.246.198',
                '10.78.100.0/30','10.78.101.0/30',1780,'STAGED');
            """)
            install_readiness_schema(c)
        self.readiness=Existing6GReadinessStore(self.conn)
        self.readiness.mark_staged(
            42,source=SOURCE,edge_id="fra1",target=EDGE)
        self.events=[]

    @contextmanager
    def conn(self):
        c=sqlite3.connect(self.path)
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def tearDown(self): self.temp.cleanup()

    def verifier(self, observed=EDGE, *, stop_failure=False):
        core, cc=fake_host("core",observed,stop_failure=stop_failure)
        edge, ec=fake_host("edge",observed)
        def update(op, *, status, detail, finished, require_running):
            self.events.append((status,detail["phase"]))
            with self.conn() as c:
                current=c.execute(
                    "SELECT status FROM failover_operations WHERE id=?",(op,)
                ).fetchone()
                if current!=("RUNNING",):
                    raise RuntimeError("lost shared 6G lock")
                c.execute(
                    "UPDATE failover_operations SET status=? WHERE id=?",
                    (status,op),
                )
        verifier=Existing6GEdgeVerifier(
            db_conn=self.conn,
            acquire_fn=lambda source,target:(42,None),
            update_fn=update,
            readiness=self.readiness,core=core,edge=edge,
        )
        return verifier,cc,ec

    def test_lab_probe_success_stops_peers_and_never_sets_ready(self):
        verify,cc,ec=self.verifier()
        result=asyncio.run(verify.verify_lab(
            spec(),source=SOURCE,explicitly_authorized=True))
        self.assertTrue(result.ok)
        self.assertFalse(result.customer_ready)
        self.assertIn("stop",cc)
        self.assertIn("stop",ec)
        with self.conn() as c:
            self.assertEqual(read_readiness(c,"fra1").state,"VERIFIED_LAB")
            self.assertEqual(c.execute(
                "SELECT status FROM failover_operations WHERE id=42"
            ).fetchone(),("SUCCEEDED",))

    def test_wrong_observed_public_ip_never_promotes(self):
        verify,cc,ec=self.verifier(observed=CORE)
        result=asyncio.run(verify.verify_lab(
            spec(),source=SOURCE,explicitly_authorized=True))
        self.assertFalse(result.ok)
        self.assertFalse(result.customer_ready)
        self.assertIn("stop",cc)
        self.assertIn("stop",ec)
        with self.conn() as c:
            self.assertEqual(read_readiness(c,"fra1").state,"STAGED")

    def test_uncertain_peer_cleanup_holds_shared_6g(self):
        verify,cc,ec=self.verifier(stop_failure=True)
        result=asyncio.run(verify.verify_lab(
            spec(),source=SOURCE,explicitly_authorized=True))
        self.assertTrue(result.recovery_required)
        self.assertEqual(result.state,"HOLD")
        with self.conn() as c:
            self.assertEqual(read_readiness(c,"fra1").state,"HOLD")
            self.assertEqual(c.execute(
                "SELECT status FROM failover_operations WHERE id=42"
            ).fetchone(),("RUNNING",))
        self.assertIn(("RUNNING",HOLD_PHASE),self.events)

    def test_no_authorization_never_acquires_lock_or_network(self):
        verify,cc,ec=self.verifier()
        out=asyncio.run(verify.verify_lab(spec(),source=SOURCE))
        self.assertEqual(out.reason,"EXPLICIT_LAB_AUTHORIZATION_REQUIRED")
        self.assertEqual(self.events,[])
        self.assertEqual(cc,[])
        self.assertEqual(ec,[])

    def test_changed_active_ingress_denies_stage_proof(self):
        with self.conn() as c:
            c.execute("UPDATE host_pool SET is_default=0")
        verify,cc,ec=self.verifier()
        out=asyncio.run(verify.verify_lab(
            spec(),source=SOURCE,explicitly_authorized=True))
        self.assertFalse(out.ok)
        self.assertEqual(cc,[])
        self.assertEqual(ec,[])

if __name__=="__main__":
    unittest.main()
