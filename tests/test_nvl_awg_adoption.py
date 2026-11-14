"""AWG-02 tests: offline acceptance, no installs, network writes or DNS."""
import base64
from dataclasses import replace
import sqlite3
import unittest

from nvl_awg_adoption import (
    AWGExistingEdge, AWGNetworkSnapshot, AWGAdoptionHold,
    validate_snapshot, register_inactive,
)
from nvl_tunnel_backend import lookup_binding

EDGE_KEY = "Isv5UL+ufARwGoYfhj5P+K7vp53OmArFWjpB+F4mYCw="
CORE_KEY = "MjJZ0TMjrkwJEZhsHYjH1del3JtIcSA/5Q8xv+5KlnQ="
SSH_PUB = base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"A"*32).decode()


def spec():
    return AWGExistingEdge(
        host="149.104.110.138", admin_port=22, customer_port=2252,
        tls_port=2088, core_public_ip="91.107.170.239",
        core_tunnel_ip="10.203.77.1", edge_tunnel_ip="10.203.77.2",
        core_public_key=CORE_KEY, edge_public_key=EDGE_KEY,
        ssh_host_key_type="ssh-ed25519",
        ssh_host_key_base64=SSH_PUB,
    )


def snapshot():
    nat = []
    forward = []
    for port in (2252, 2088):
        nat += [
            f"-A PREROUTING -i eth1 -p tcp -m tcp --dport {port} "
            f"-j DNAT --to-destination 10.203.77.1:{port}",
            f"-A POSTROUTING -d 10.203.77.1/32 -o awg0 -p tcp "
            f"-m tcp --dport {port} -j SNAT --to-source 10.203.77.2",
        ]
        forward += [
            f"-A FORWARD -d 10.203.77.1/32 -i eth1 -o awg0 "
            f"-p tcp -m tcp --dport {port} -j ACCEPT",
            f"-A FORWARD -s 10.203.77.1/32 -i awg0 -o eth1 "
            f"-p tcp -m tcp --sport {port} -m conntrack "
            f"--ctstate RELATED,ESTABLISHED -j ACCEPT",
        ]
    return AWGNetworkSnapshot(
        core_peers=EDGE_KEY + "\n" + CORE_KEY + "\n",
        core_allowed_ips=EDGE_KEY + " 10.203.77.2/32\n" +
                         CORE_KEY + " 10.77.0.3/32",
        core_ping_ok=True,
        edge_peers=CORE_KEY + "\n",
        edge_awg_address="2: awg0 inet 10.203.77.2/32 scope global awg0",
        edge_forwarding="1",
        edge_wan="eth1",
        nat_live="\n".join(nat), nat_saved="\n".join(nat),
        forward_live="\n".join(forward),
        forward_saved="\n".join(forward),
        edge_awg_service="active", edge_awg_enabled="enabled",
        netfilter_enabled="enabled",
    )


def db_setup():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE host_pool(
            host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
            is_standby INTEGER, provider TEXT, provider_instance_id TEXT,
            added_at TEXT, ssh_port INTEGER, service_port INTEGER,
            admin_ssh_port INTEGER
        );
        CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY, host TEXT);
    """)
    db.executemany("INSERT INTO settings VALUES (?,?)", [
        ("core_wg_public_ip", "91.107.170.239"),
        ("port", "2252"), ("tls_port", "2088"),
        ("hosts", "153.75.87.190"), ("dns_current_ip", "153.75.87.190"),
        ("auto_failover_mode", "0"),
        ("phase6h_auto_failover_enabled", "0"),
        ("edge_egress_v1_onboard_enabled", "0"),
    ])
    db.execute(
        "INSERT INTO host_pool(host,active,is_default,is_standby) "
        "VALUES ('153.75.87.190',1,1,0)"
    )
    db.commit()
    return db


class ValidationTests(unittest.TestCase):
    def test_good_evidence_and_extra_core_peer(self):
        proof = validate_snapshot(spec(), snapshot(), clock=lambda: 1500)
        self.assertEqual(proof.verified_at, 1500)
        self.assertEqual(proof.spec.host, "149.104.110.138")

    def test_current_pilot_without_tls_port_is_not_accepted(self):
        value = snapshot()
        live = "\n".join(x for x in value.nat_live.splitlines()
                         if "2088" not in x)
        with self.assertRaisesRegex(AWGAdoptionHold, "NAT_OR_FORWARD"):
            validate_snapshot(spec(), replace(value, nat_live=live))

    def test_saved_rules_and_return_forward_required(self):
        value = snapshot()
        with self.assertRaisesRegex(AWGAdoptionHold, "NAT_OR_FORWARD"):
            validate_snapshot(spec(), replace(value, nat_saved=""))
        with self.assertRaisesRegex(AWGAdoptionHold, "NAT_OR_FORWARD"):
            validate_snapshot(spec(), replace(value, forward_saved=""))

    def test_other_core_peer_must_not_own_the_same_ip(self):
        value = snapshot()
        overlap = value.core_allowed_ips.replace(
            "10.77.0.3/32", "10.203.77.0/24"
        )
        with self.assertRaisesRegex(AWGAdoptionHold, "CORE_AWG_ALLOWED_IP"):
            validate_snapshot(spec(), replace(value, core_allowed_ips=overlap))

    def test_edge_peer_and_route_mismatches_rejected(self):
        value = snapshot()
        for update in (
            {"edge_peers": EDGE_KEY},
            {"core_ping_ok": False},
            {"edge_forwarding": "0"},
            {"edge_awg_enabled": "disabled"},
            {"netfilter_enabled": "disabled"},
            {"edge_wan": "awg0"},
        ):
            with self.subTest(update=update):
                with self.assertRaises(AWGAdoptionHold):
                    validate_snapshot(spec(), replace(value, **update))

    def test_repeated_or_conflicting_nat_rules_are_not_accepted(self):
        value = snapshot()
        with self.assertRaisesRegex(AWGAdoptionHold, "NAT_OR_FORWARD"):
            validate_snapshot(spec(), replace(
                value, nat_saved=value.nat_saved + "\n" +
                value.nat_saved.splitlines()[0]
            ))

    def test_admin_port_collision_rejected(self):
        with self.assertRaisesRegex(AWGAdoptionHold, "COLLISION"):
            replace(spec(), admin_port=2252)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.db = db_setup()
        self.acceptance = validate_snapshot(spec(), snapshot(), clock=lambda: 1000)

    def tearDown(self):
        self.db.close()

    def register(self, **kwargs):
        return register_inactive(
            self.db, self.acceptance,
            actor=7, chat=7, guard=lambda db: None,
            now=lambda: 1005, **kwargs,
        )

    def test_atomic_inactive_adoption_without_dns_or_customer_changes(self):
        before = dict(self.db.execute("SELECT * FROM settings"))
        op = self.register()
        self.assertEqual(before, dict(self.db.execute("SELECT * FROM settings")))
        row = self.db.execute(
            "SELECT active,is_default,is_standby,provider,service_port "
            "FROM host_pool WHERE host=?", (spec().host,),
        ).fetchone()
        self.assertEqual(row, (0, 0, 0, "manual", 2252))
        receipt = self.db.execute(
            "SELECT status,pin_type FROM manual_edge_operations "
            "WHERE id=?", (op,),
        ).fetchone()
        self.assertEqual(receipt, ("EDGE_READY", "ssh-ed25519"))
        self.assertEqual(
            lookup_binding(self.db, spec().host).backend, "amneziawg",
        )
        self.assertEqual(self.db.execute(
            "SELECT code FROM manual_edge_events WHERE op_id=?",
            (op,),
        ).fetchone()[0], "AWG_EXISTING_VERIFIED_NO_INSTALL")

    def test_duplicate_adoption_rejected_without_changing_original(self):
        op = self.register()
        with self.assertRaisesRegex(AWGAdoptionHold, "REGISTERED"):
            self.register()
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM manual_edge_operations"
        ).fetchone()[0], 1)
        self.assertEqual(self.db.execute(
            "SELECT id FROM manual_edge_operations"
        ).fetchone()[0], op)

    def test_guard_and_core_identity_failure_rollback_everything(self):
        before = set(self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall())
        with self.assertRaisesRegex(RuntimeError, "PROTECTED"):
            register_inactive(
                self.db, self.acceptance, actor=7, chat=7,
                guard=lambda db: (_ for _ in ()).throw(
                    RuntimeError("PROTECTED")
                ), now=lambda: 1005,
            )
        self.assertEqual(before, set(self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()))
        self.db.execute(
            "UPDATE settings SET value='91.107.170.240' "
            "WHERE key='core_wg_public_ip'"
        )
        self.db.commit()
        with self.assertRaisesRegex(AWGAdoptionHold, "CORE_IDENTITY"):
            self.register()
        self.assertIsNone(self.db.execute(
            "SELECT 1 FROM host_pool WHERE host=?", (spec().host,)
        ).fetchone())

    def test_stale_evidence_and_public_route_collision_stop_before_write(self):
        with self.assertRaisesRegex(AWGAdoptionHold, "EVIDENCE_EXPIRED"):
            register_inactive(
                self.db, self.acceptance, actor=7, chat=7,
                guard=lambda db: None, now=lambda: 1200,
            )
        self.db.execute(
            "UPDATE settings SET value=? WHERE key='dns_current_ip'",
            (spec().host,),
        )
        self.db.commit()
        with self.assertRaisesRegex(AWGAdoptionHold, "ALREADY_PUBLICLY_ROUTED"):
            self.register()

    def test_require_authorized_private_admin_and_shared_guard(self):
        with self.assertRaisesRegex(AWGAdoptionHold, "PRIVATE_ADMIN_REQUIRED"):
            register_inactive(
                self.db, self.acceptance, actor=7, chat=8,
                guard=lambda db: None, now=lambda: 1005,
            )
        with self.assertRaisesRegex(AWGAdoptionHold, "GUARD_REQUIRED"):
            register_inactive(
                self.db, self.acceptance, actor=7, chat=7,
                guard=None, now=lambda: 1005,
            )


if __name__ == "__main__":
    unittest.main()
