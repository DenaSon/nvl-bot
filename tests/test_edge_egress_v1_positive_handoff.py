"""J guarded positive adapter: five small DB/host-fault acceptance tests.

Uses a real in-memory SQLite schema and a strict fake for host/DNS I/O.
No production shell, network, SSH, systemd or Cloudflare access.
"""
import asyncio
from datetime import datetime, timezone
import sqlite3
import time
import unittest

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_handoff import TargetObservation
from edge_egress_policy import EgressReadiness
from edge_egress_v1_handoff_adapter import (
    Existing6GProtectedHandoffAdapter, execute_protected_switch,
    PositiveHandoffHold,
)

SOURCE, TARGET, CORE = "144.172.84.76", "144.172.84.82", "209.200.246.198"
USERS = (("nvl0557", 1644), ("nvl0558", 1645))


class Host:
    def __init__(self, *, fail=None, busy=False):
        self.events = []
        self.blocked = set()
        self.pinned = {name: SOURCE for name, _ in USERS}
        self.dns = SOURCE
        self.fail = fail
        self.sessions = busy

    def mark(self, step):
        self.events.append(step)
        if step == self.fail:
            raise RuntimeError("host evidence unavailable")

    async def ensure_target_transport(self, target):
        self.mark("transport")
        assert target == TARGET

    async def assert_target_peer(self, target):
        self.mark("peer")

    async def external_target_observation(self, target):
        self.mark("observation")
        return TargetObservation(
            EgressReadiness(
                edge_host=TARGET, public_ipv4=TARGET,
                observed_egress_ipv4=TARGET,
                ingress_service_ok=True, management_ssh_ok=True,
                ingress_wireguard_ok=True, egress_wireguard_ok=True,
                egress_nat_ok=True, fail_closed_policy_ok=True,
                ipv6_leak_protected=True, fresh=True,
            ), datetime.now(timezone.utc), "edge-e9"
        )

    async def assert_real_ingress(self, target):
        self.mark("ingress")

    async def assert_no_ssh_sessions(self, username, uid):
        self.mark("drain")
        if self.sessions:
            raise RuntimeError("active SSH sessions")

    async def freeze_uid(self, username, uid):
        self.mark("freeze")
        self.blocked.add(username)

    async def assert_uid_frozen(self, username, uid):
        if username not in self.blocked:
            raise RuntimeError("uid not frozen")

    async def repin_frozen_uid(self, username, uid, old_edge, new_edge):
        self.mark("repin")
        assert username in self.blocked and old_edge == SOURCE
        self.pinned[username] = new_edge

    async def prove_uid_ipv4(self, username, uid, target_ip):
        self.mark("ipv4")
        if self.pinned[username] != target_ip or username not in self.blocked:
            raise RuntimeError("IPv4 proof failed")

    async def switch_dns_edge_to_edge(self, source, target):
        self.mark("dns")
        assert source == SOURCE and target == TARGET
        self.dns = target

    async def assert_dns_target(self, target):
        if self.dns != target:
            raise RuntimeError("dns not at target")

    async def release_uid(self, username, uid):
        self.mark("release")
        self.blocked.remove(username)

    async def assert_uid_target(self, username, uid, target):
        self.mark("uid-target")
        if self.pinned[username] != target:
            raise RuntimeError("uid on wrong Edge")


class PositiveAdapterTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','1');
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.76');
            CREATE TABLE failover_operations(
                id INTEGER PRIMARY KEY, status TEXT, source_host TEXT,
                target_host TEXT, detail_json TEXT
            );
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
              is_default INTEGER,is_standby INTEGER,service_port INTEGER);
            INSERT INTO host_pool VALUES('144.172.84.76',1,1,0,2252);
            INSERT INTO host_pool VALUES('144.172.84.82',1,0,1,2252);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
              service_type TEXT,status TEXT);
            CREATE TABLE edge_egress_allocations(edge_id TEXT PRIMARY KEY,
              edge_public_ipv4 TEXT,core_public_ipv4 TEXT,
              route_table INTEGER,status TEXT);
            INSERT INTO edge_egress_allocations VALUES
              ('e9','144.172.84.82','209.200.246.198',20009,'STAGED');
        """)
        install_readiness_schema(self.db)
        install_runtime_schema(self.db)
        install_protected_mapping_schema(self.db)
        clock = int(time.time())
        self.db.execute(
            "INSERT INTO edge_egress_readiness"
            "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
            "expires_at,last_operation_id)"
            "VALUES('e9',?,'READY',?,'F4_PRODUCTION_ACCEPTANCE',?,?,1)",
            (TARGET, TARGET, clock - 5, clock + 300),
        )
        for i, (name, uid) in enumerate(USERS):
            self.db.execute(
                "INSERT INTO ssh_accounts VALUES(?,?,?,?)",
                (name, SOURCE, "ssh", "🟢 فعال"),
            )
            self.db.execute(
                "INSERT INTO edge_egress_uid_runtime "
                "(username,uid,edge_id,edge_ipv4,route_table,priority,"
                "dns_port,state,last_operation_id) "
                "VALUES(?,?,'e8',?,20008,?,?, 'PROTECTED',1)",
                (name, uid, SOURCE, 20010 + i, 10553 + i),
            )
            self.db.execute(
                "INSERT INTO edge_egress_uid_bindings "
                "(username,uid,edge_id,edge_ipv4,status) "
                "VALUES(?,?,'e8',?,'PROTECTED')",
                (name, uid, SOURCE),
            )
        self.events = []

    def adapter(self, host):
        def acquire(source, target):
            self.db.execute(
                "INSERT INTO failover_operations(id,status,source_host,target_host)"
                "VALUES(42,'RUNNING',?,?)", (source, target)
            )
            return 42, None

        def journal(operation_id, *, status, detail, finished, require_running):
            self.events.append((status, detail["phase"]))
            self.db.execute(
                "UPDATE failover_operations SET status=?,detail_json=? WHERE id=?",
                (status, __import__("json").dumps(detail), operation_id)
            )
        # Monkeypatch OS UID lookup only in source module under review.
        return Existing6GProtectedHandoffAdapter(
            db_conn=lambda: self.db, acquire_fn=acquire, journal_fn=journal,
            core_ip=CORE, host_actions=host
        )

    def run_it(self, host):
        from unittest.mock import patch
        from types import SimpleNamespace
        def getpwnam(name):
            return SimpleNamespace(pw_uid=dict(USERS)[name])
        with patch("edge_egress_v1_handoff_adapter.pwd.getpwnam",
                   side_effect=getpwnam):
            return asyncio.run(execute_protected_switch(
                self.adapter(host), SOURCE, TARGET
            ))

    def test_success_rebinds_both_db_tables_and_dns_without_core(self):
        host = Host()
        result = self.run_it(host)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(host.dns, TARGET)
        self.assertEqual(self.db.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        ).fetchone(), (TARGET,))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM edge_egress_uid_runtime "
            "WHERE edge_ipv4=? AND state='PROTECTED'", (TARGET,)
        ).fetchone()[0], 2)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM edge_egress_uid_bindings "
            "WHERE edge_ipv4=?", (TARGET,)
        ).fetchone()[0], 2)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM ssh_accounts WHERE host=?", (TARGET,)
        ).fetchone()[0], 2)
        self.assertEqual(self.db.execute(
            "SELECT status FROM failover_operations WHERE id=42"
        ).fetchone(), ("SUCCEEDED",))
        self.assertNotIn(CORE, host.events)
        self.assertLess(host.events.index("drain"), host.events.index("repin"))
        self.assertLess(host.events.index("repin"), host.events.index("dns"))
        self.assertFalse(host.blocked)

    def test_active_session_holds_without_repin_or_dns_change(self):
        host = Host(busy=True)
        result = self.run_it(host)
        self.assertFalse(result.ok)
        self.assertTrue(result.needs_manual_recovery)
        self.assertEqual(host.dns, SOURCE)
        self.assertNotIn("repin", host.events)
        self.assertNotIn("dns", host.events)
        self.assertEqual(self.db.execute(
            "SELECT status FROM failover_operations WHERE id=42"
        ).fetchone(), ("RUNNING",))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM edge_egress_uid_runtime WHERE state='HOLD'"
        ).fetchone()[0], 2)

    def test_dns_failure_keeps_frozen_uid_and_shared_lock(self):
        host = Host(fail="dns")
        result = self.run_it(host)
        self.assertTrue(result.needs_manual_recovery)
        self.assertEqual(host.dns, SOURCE)
        self.assertEqual(len(host.blocked), 2)
        self.assertEqual(self.db.execute(
            "SELECT status FROM failover_operations WHERE id=42"
        ).fetchone(), ("RUNNING",))
        self.assertNotIn("release", host.events)

    def test_pre_mutation_readiness_failure_never_blocks_uid(self):
        self.db.execute(
            "UPDATE edge_egress_readiness SET state='VERIFIED_LAB'"
        )
        host = Host()
        result = self.run_it(host)
        self.assertFalse(result.ok)
        self.assertFalse(result.needs_manual_recovery)
        self.assertNotIn("freeze", host.events)
        self.assertNotIn("dns", host.events)

    def test_cannot_start_without_audited_live_host_driver(self):
        a = self.adapter(None)
        with self.assertRaisesRegex(PositiveHandoffHold,
                                    "K_LIVE_HOST_ACTIONS_NOT_INSTALLED"):
            asyncio.run(execute_protected_switch(a, SOURCE, TARGET))


if __name__ == "__main__":
    unittest.main()
