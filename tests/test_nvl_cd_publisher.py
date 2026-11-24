"""Hermetic publisher safety tests; never control real systemd or production DB."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ops import nvl_cd_publisher as pub
from ops import nvl_cd_planner as p

A, B = "a" * 40, "b" * 40


class SafetyTests(unittest.TestCase):
    def test_existing_lease_holds_only_active_states(self):
        with sqlite3.connect(":memory:") as con:
            con.execute("CREATE TABLE failover_operations(status TEXT)")
            con.execute("CREATE TABLE manual_quick_switch_jobs(status TEXT)")
            con.execute("INSERT INTO failover_operations VALUES ('SUCCEEDED')")
            con.execute("INSERT INTO manual_quick_switch_jobs VALUES ('HOLD')")
            self.assertFalse(pub.busy(con))
            con.execute("INSERT INTO failover_operations VALUES ('RUNNING')")
            self.assertTrue(pub.busy(con))
            con.execute("DELETE FROM failover_operations")
            con.execute("INSERT INTO manual_quick_switch_jobs VALUES ('DNS_INTENT')")
            self.assertTrue(pub.busy(con))

    def test_cloudzy_purchase_and_install_defer_publication(self):
        with sqlite3.connect(":memory:") as con:
            con.execute("CREATE TABLE failover_operations(status TEXT)")
            con.execute("CREATE TABLE cloudzy_edge_operations(status TEXT)")
            for status in ("CREATING", "PROVISIONING", "HOLD_SSH", "EDGE_READY"):
                with self.subTest(status=status):
                    con.execute("DELETE FROM cloudzy_edge_operations")
                    con.execute("INSERT INTO cloudzy_edge_operations VALUES (?)", (status,))
                    self.assertEqual(pub.busy(con), status in ("CREATING", "PROVISIONING"))

    def test_missing_shared_lease_schema_holds(self):
        with sqlite3.connect(":memory:") as con, self.assertRaises(p.Hold):
            pub.busy(con)

    def test_schema_fingerprint_changes_on_ddl_not_data(self):
        with sqlite3.connect(":memory:") as con:
            con.execute("CREATE TABLE example(id INTEGER)")
            before = pub.schema(con)
            con.execute("INSERT INTO example VALUES (1)")
            self.assertEqual(pub.schema(con), before)
            con.execute("ALTER TABLE example ADD COLUMN value TEXT")
            self.assertNotEqual(pub.schema(con), before)

    def test_explicit_new_file_only_when_absent(self):
        new = {"new.py": ("100644", "blob", B)}
        for current, expected in (("ABSENT", "PLAN_READY"), (None, "HOLD"), (A, "HOLD")):
            self.assertEqual(p.build_plan({}, new, {"new.py"}, lambda _: current)["status"],
                             expected)
        self.assertEqual(p.build_plan({}, new, set(), lambda _: "ABSENT")["status"], "HOLD")


class FakeHost:
    def __init__(self, root):
        self.runtime = root / "runtime"
        self.runtime.mkdir()
        self.backups = root / "backup"
        self.backups.mkdir()
        self.db = root / "db"
        self.db.write_bytes(b"database")
        self.running = True
        self.schema_value = "old-schema"
        self.fail_health = 0
        self.schema_on_start = None
        self.stops = 0
        self.starts = 0

    def active(self):
        return self.running

    def idle(self):
        return True

    def stop(self):
        self.stops += 1
        self.running = False

    def start(self):
        self.starts += 1
        self.running = True
        if self.schema_on_start:
            self.schema_value = self.schema_on_start

    def healthy(self):
        if self.fail_health:
            self.fail_health -= 1
            raise p.Hold("BOT_HEALTH_FAILED")

    def schema(self):
        return self.schema_value

    def snapshot_db(self, path):
        path.write_bytes(b"backup")
        return pub.digest(b"backup"), self.schema()

    def live(self, name):
        path = self.runtime / name
        return pub.blob(path.read_bytes()) if path.exists() else "ABSENT"


class PublisherTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.host = FakeHost(self.root)
        self.state = self.root / "state"
        self.state.mkdir()
        self.old_raw, self.new_raw = b"x = 1\n", b"x = 2\n"
        (self.host.runtime / "bot.py").write_bytes(self.old_raw)
        self.old = {"bot.py": ("100644", "blob", pub.blob(self.old_raw))}
        self.new = {"bot.py": ("100644", "blob", pub.blob(self.new_raw))}
        # Fixtures under /tmp are not trusted production locations.
        patcher = patch.object(p, "trusted", side_effect=lambda path, **kw: path)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(p, "git", return_value=self.new_raw)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(pub.shutil, "disk_usage", return_value=type("D", (), {"free": 10**10})())
        patcher.start()
        self.addCleanup(patcher.stop)

    def publish(self, revalidate=lambda: None):
        return pub.publish(self.host, self.state, self.root, A, B,
                           ["bot.py"], self.old, self.new, revalidate)

    def test_success_advances_baseline(self):
        result = self.publish()
        self.assertEqual((result["phase"], result["deployed"]), ("COMMITTED", B))
        self.assertEqual((self.host.runtime / "bot.py").read_bytes(), self.new_raw)
        self.assertEqual(self.host.db.read_bytes(), b"database")

    def test_failed_health_restores_only_code(self):
        self.host.fail_health = 1
        result = self.publish()
        self.assertEqual((result["phase"], result["deployed"]), ("ROLLED_BACK", A))
        self.assertEqual((self.host.runtime / "bot.py").read_bytes(), self.old_raw)
        self.assertEqual(self.host.db.read_bytes(), b"database")

    def test_schema_change_never_auto_rolls_back(self):
        self.host.schema_on_start = "new-schema"
        result = self.publish()
        self.assertEqual(result["phase"], "HOLD")
        self.assertEqual((self.host.runtime / "bot.py").read_bytes(), self.new_raw)
        self.assertEqual(self.host.stops, 1)
        self.assertEqual(self.host.db.read_bytes(), b"database")

    def test_gate_failure_never_stops_bot(self):
        def reject():
            raise p.Hold("MASTER_MOVED")
        with self.assertRaises(p.Hold):
            self.publish(reject)
        self.assertEqual(self.host.stops, 0)
        self.assertEqual((self.host.runtime / "bot.py").read_bytes(), self.old_raw)

    def test_interrupted_publication_recovers_from_verified_backup(self):
        directory, _ = pub.stage(self.host, self.root, A, B, ["bot.py"], self.old, self.new)
        checkpoint = dict(deployed=A, candidate=B, phase="PUBLISHING",
                          backup=str(directory), manifest_sha256=pub.file_digest(directory / "manifest.json"))
        (self.host.runtime / "bot.py").write_bytes(self.new_raw)
        result = pub.restore(self.host, self.state, checkpoint)
        self.assertEqual(result["phase"], "ROLLED_BACK")
        self.assertEqual((self.host.runtime / "bot.py").read_bytes(), self.old_raw)

    def test_corrupt_backup_never_overwrites_runtime(self):
        directory, _ = pub.stage(self.host, self.root, A, B, ["bot.py"], self.old, self.new)
        checkpoint = dict(deployed=A, candidate=B, phase="PUBLISHING",
                          backup=str(directory), manifest_sha256=pub.file_digest(directory / "manifest.json"))
        (directory / "before" / "bot.py").write_bytes(b"corrupt")
        with self.assertRaises(p.Hold):
            pub.restore(self.host, self.state, checkpoint)
        self.assertEqual(self.host.stops, 0)

    def test_invalidate_only_changed_module_cache(self):
        cache = self.host.runtime / "__pycache__"
        cache.mkdir()
        changed = cache / "bot.cpython-312.pyc"
        unrelated = cache / "other.cpython-312.pyc"
        changed.write_bytes(b"stale")
        unrelated.write_bytes(b"keep")
        self.publish()
        self.assertFalse(changed.exists())
        self.assertTrue(unrelated.exists())

    def test_schema_change_during_backup_does_not_stop_bot(self):
        def snapshot(path):
            path.write_bytes(b"backup")
            return pub.digest(b"backup"), "different-schema"
        with patch.object(self.host, "snapshot_db", side_effect=snapshot):
            with self.assertRaises(p.Hold):
                self.publish()
        self.assertEqual(self.host.stops, 0)

    def test_recovery_never_starts_mixed_generation_on_busy_state(self):
        directory, _ = pub.stage(self.host, self.root, A, B, ["bot.py"], self.old, self.new)
        checkpoint = dict(deployed=A, candidate=B, phase="PUBLISHING",
                          backup=str(directory), manifest_sha256=pub.file_digest(directory / "manifest.json"))
        self.host.running = False
        with patch.object(self.host, "idle", return_value=False):
            with self.assertRaises(p.Hold):
                pub.restore(self.host, self.state, checkpoint)
        self.assertEqual(self.host.starts, 0)
