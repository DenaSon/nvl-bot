"""D1-D1: SQLite protected Egress mapping CAS, no legacy account movement."""
from contextlib import contextmanager
import sqlite3
import tempfile
from pathlib import Path
import unittest

from edge_egress_handoff import AccountOwner, HandoffSnapshot
from edge_egress_inventory import ensure_schema
from edge_egress_protected_mapping import (
    Existing6GProtectedMappingPort, install_protected_mapping_schema,
    MappingUnsafe,
)


SOURCE="172.86.94.174"
TARGET="216.126.229.12"
CORE="209.200.246.198"


def snapshot():
    return HandoffSnapshot(
        source_host=SOURCE, target_host=TARGET,
        core_public_ipv4=CORE, current_dns_ipv4=SOURCE,
        active_accounts=(AccountOwner("nvl0557",1644),
                         AccountOwner("nvl0558",1645)),
        other_explicit_active_accounts=0,
        source_is_default=True, target_is_active_standby=True,
        source_service_port=2252, target_service_port=2252,
        target_egress_identity_unique=True,
    )


class SQLiteMappingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.temp.name)/"fake-core.db")

        with self.conn() as c:
            c.executescript("""
              CREATE TABLE failover_operations(
                id INTEGER PRIMARY KEY,status TEXT,
                source_host TEXT,target_host TEXT);
              INSERT INTO failover_operations VALUES
                (42,'RUNNING','172.86.94.174','216.126.229.12');
              CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
              INSERT INTO settings VALUES('edge_egress_protected_mode','1');
              INSERT INTO settings VALUES('dns_current_ip','172.86.94.174');
              CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
                is_default INTEGER,is_standby INTEGER,service_port INTEGER);
              INSERT INTO host_pool VALUES
                ('172.86.94.174',1,1,0,2252),
                ('216.126.229.12',1,0,1,2252);
              CREATE TABLE ssh_accounts(
                username TEXT PRIMARY KEY,host TEXT,service_type TEXT,status TEXT);
              INSERT INTO ssh_accounts VALUES
                ('nvl0557','172.86.94.174','ssh','🟢 فعال'),
                ('nvl0558','172.86.94.174','ssh','🟢 فعال');
            """)
            ensure_schema(c)
            # Reservation needs only enough to test reviewed staged target;
            # no WireGuard secret material is used by the mapping CAS.
            c.execute("""INSERT INTO edge_egress_allocations
                (edge_id,edge_public_ipv4,core_public_ipv4,tunnel_network,
                veth_network,route_table,edge_listen_port,edge_uplink,
                core_public_key,edge_public_key,status)
                VALUES('fra1','216.126.229.12','209.200.246.198',
                '10.78.100.0/30','10.78.101.0/30',1780,51832,'eth0',
                'not-a-key','not-a-key','STAGED')""")
            install_protected_mapping_schema(c)
            c.execute("""INSERT INTO edge_egress_uid_bindings
                (username,uid,edge_id,edge_ipv4,status)
                VALUES('nvl0557',1644,'source','172.86.94.174','PROTECTED'),
                      ('nvl0558',1645,'source','172.86.94.174','PROTECTED')""")
        self.p=Existing6GProtectedMappingPort(
            self.conn, lambda username: {"nvl0557":1644,"nvl0558":1645}[username],
        )

    def tearDown(self):
        self.temp.cleanup()

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

    def scalar(self,query):
        with self.conn() as c:
            return c.execute(query).fetchone()[0]

    def bindings(self):
        with self.conn() as c:
            return c.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status,generation "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall()

    def test_mapping_cas_changes_only_new_registry(self):
        self.assertEqual(self.p.commit_mapping_cas_only(42,snapshot()),2)
        self.assertEqual(self.bindings(),[
            ("nvl0557",1644,"fra1",TARGET,"PROTECTED",2),
            ("nvl0558",1645,"fra1",TARGET,"PROTECTED",2),
        ])
        self.assertEqual(self.scalar(
            "SELECT host FROM ssh_accounts WHERE username='nvl0557'"),SOURCE)
        self.assertEqual(self.scalar("SELECT value FROM settings WHERE key='dns_current_ip'"),SOURCE)
        self.assertEqual(self.scalar(
            "SELECT host FROM host_pool WHERE is_default=1"),SOURCE)
        self.assertEqual(self.scalar(
            "SELECT status FROM failover_operations WHERE id=42"),"RUNNING")

    def test_replay_cas_does_not_succeed_again(self):
        self.p.commit_mapping_cas_only(42,snapshot())
        first=self.bindings()
        with self.assertRaisesRegex(MappingUnsafe,"BINDING_SOURCE"):
            self.p.commit_mapping_cas_only(42,snapshot())
        self.assertEqual(self.bindings(),first)

    def test_wrong_os_uid_rejected_before_writes(self):
        prior=self.bindings()
        p=Existing6GProtectedMappingPort(self.conn,lambda username:1644)
        with self.assertRaisesRegex(MappingUnsafe,"CORE_OS_UID"):
            p.commit_mapping_cas_only(42,snapshot())
        self.assertEqual(self.bindings(),prior)

    def test_mode_off_and_lost_lock_deny_all_writes(self):
        for sql,expected in (
            ("UPDATE settings SET value='0' WHERE key='edge_egress_protected_mode'",
             "PROTECTED_MODE_NOT_CONFIRMED"),
            ("UPDATE failover_operations SET status='ABORTED_STALE' WHERE id=42",
             "SHARED_6G_LOCK_NOT_CURRENT"),
        ):
            with self.subTest(sql=sql):
                before=self.bindings()
                with self.conn() as c: c.execute(sql)
                with self.assertRaisesRegex(MappingUnsafe,expected):
                    self.p.commit_mapping_cas_only(42,snapshot())
                self.assertEqual(self.bindings(),before)
                with self.conn() as c:
                    c.execute("UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'")
                    c.execute("UPDATE failover_operations SET status='RUNNING' WHERE id=42")

    def test_changed_ssh_owner_and_missing_binding_are_rejected(self):
        cases=[
            ("UPDATE ssh_accounts SET host='216.126.229.12' WHERE username='nvl0557'",
             "SSH_INGRESS_ACCOUNT_HOST_CHANGED"),
            ("DELETE FROM edge_egress_uid_bindings WHERE username='nvl0558'",
             "INCOMPLETE_OR_FOREIGN_UID_MAPPING"),
            ("UPDATE settings SET value='209.200.246.198' WHERE key='dns_current_ip'",
             "PUBLIC_DNS_CHANGED"),
        ]
        for sql,error in cases:
            with self.subTest(error=error):
                with self.conn() as c: c.execute(sql)
                before=self.bindings()
                with self.assertRaisesRegex(MappingUnsafe,error):
                    self.p.commit_mapping_cas_only(42,snapshot())
                self.assertEqual(self.bindings(),before)
                with self.conn() as c:
                    c.execute("UPDATE ssh_accounts SET host=? WHERE username='nvl0557'",(SOURCE,))
                    c.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",(SOURCE,))
                    c.execute("""INSERT OR IGNORE INTO edge_egress_uid_bindings
                      (username,uid,edge_id,edge_ipv4,status)
                      VALUES('nvl0558',1645,'source',?,'PROTECTED')""",(SOURCE,))

    def test_sql_error_after_first_row_rolls_back_whole_mapping(self):
        before=self.bindings()
        with self.conn() as c:
            c.execute("""CREATE TRIGGER fail_second_uid_change
              BEFORE UPDATE ON edge_egress_uid_bindings
              WHEN OLD.username='nvl0558'
              BEGIN SELECT RAISE(ABORT,'synthetic commit crash'); END;""")
        with self.assertRaises(sqlite3.DatabaseError):
            self.p.commit_mapping_cas_only(42,snapshot())
        self.assertEqual(self.bindings(),before)

    def test_staged_target_required_does_not_elevate_to_ready(self):
        with self.conn() as c:
            c.execute("""UPDATE edge_egress_allocations
              SET status='RESERVED' WHERE edge_id='fra1'""")
        with self.assertRaisesRegex(MappingUnsafe,"TARGET_ALLOCATION"):
            self.p.commit_mapping_cas_only(42,snapshot())
        self.assertEqual(self.scalar(
            "SELECT status FROM edge_egress_allocations WHERE edge_id='fra1'"),
            "RESERVED")


if __name__=="__main__":
    unittest.main()
