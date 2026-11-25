"""CICD-07A: discovery and reconciliation are read-only, fail closed."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from ops import nvl_cd_inventory as inv
from ops import nvl_cd_planner as p


def entry(raw):
    return ("100644", "blob",
            hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())


class DiscoveryTests(unittest.TestCase):
    def plan(self, old, new, live, approved=None):
        a, b = ({name: entry(raw) for name, raw in tree.items()}
                for tree in (old, new))
        objects = {entry(raw)[2]: raw for raw in list(old.values()) + list(new.values())}
        with patch.object(p, "git", side_effect=lambda repo, *args: objects[args[-1]]), \
                patch.object(inv.os.path, "lexists", return_value=False), \
                patch.object(p, "monitor_reconciled", return_value=set()):
            return p.build_release_plan(Path("/repo"), a, b, approved or {inv.ENTRY},
                                        Path("/root"), lambda n: live.get(n, "ABSENT"))

    def test_new_imported_modules_are_published_without_inventory_edit(self):
        old = {inv.ENTRY: b"pass\n"}
        new = {inv.ENTRY: b"import feature\n", "feature.py": b"import helper\n",
               "helper.py": b"pass\n"}
        plan = self.plan(old, new, {inv.ENTRY: entry(old[inv.ENTRY])[2]})
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertEqual(plan["updates"], [inv.ENTRY, "feature.py", "helper.py"])
        self.assertEqual(plan["discovered"], ["feature.py", "helper.py"])

    def test_discovered_dependency_stays_managed_and_drift_checked(self):
        old = {inv.ENTRY: b"import feature\n", "feature.py": b"x = 1\n"}
        new = dict(old, **{"feature.py": b"x = 2\n"})
        live = {name: entry(raw)[2] for name, raw in old.items()}
        self.assertEqual(self.plan(old, new, live)["updates"], ["feature.py"])
        self.assertEqual(self.plan(old, new, {})["status"], "HOLD")

    def test_unowned_scripts_and_shared_modules_remain_held(self):
        old = {inv.ENTRY: b"pass\n", inv.INDEPENDENT[0]: b"import shared\n",
               "shared.py": b"x = 1\n"}
        new = dict(old, **{inv.ENTRY: b"import shared\n", "shared.py": b"x = 2\n",
                           "unrelated.py": b"pass\n"})
        plan = self.plan(old, new, {inv.ENTRY: entry(old[inv.ENTRY])[2]})
        self.assertEqual(plan["status"], "HOLD")
        self.assertEqual(plan["manual"], ["shared.py", "unrelated.py"])

    def test_package_and_deletion_are_not_admitted(self):
        old = {inv.ENTRY: b"import feature\n", "feature.py": b"pass\n"}
        new = {inv.ENTRY: b"from pkg import item\n", "pkg/item.py": b"pass\n"}
        plan = self.plan(old, new, {name: entry(raw)[2] for name, raw in old.items()})
        self.assertEqual(plan["status"], "HOLD")
        self.assertEqual(plan["manual"], ["feature.py", "pkg/item.py"])

    def test_existing_unowned_file_is_not_overwritten(self):
        old = {inv.ENTRY: b"pass\n"}
        new = {inv.ENTRY: b"import feature\n", "feature.py": b"pass\n"}
        live = {inv.ENTRY: entry(old[inv.ENTRY])[2], "feature.py": entry(b"local")[2]}
        self.assertEqual(self.plan(old, new, live)["drift"], ["feature.py"])

    def test_retired_sync_and_offline_replay_do_not_block(self):
        plan = self.plan({inv.ENTRY: b"pass\n"},
                         {inv.ENTRY: b"pass\n", "sync_bot_to_edges.sh": b"ignored",
                          "ops/nvl_network_fast_alert_v2_replay.py": b"ignored"},
                         {inv.ENTRY: entry(b"pass\n")[2]})
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertEqual(plan["updates"], [])


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.new = {name: entry(name.encode()) for name in p.MONITOR_FILES}
        self.hashes = {path: self.new[name][2] for name, path in p.MONITOR_FILES.items()}

    def systemd(self, args, **kwargs):
        unit = args[2]
        sampler = "sampler" in unit
        return "\n".join([
            "FragmentPath=/etc/systemd/system/" + unit,
            "DropInPaths=" + (str(p.MONITOR_FILES["systemd/nvl-network-sampler.timer.d/15s.conf.example"]) if sampler else ""),
            "NeedDaemonReload=no", "ActiveState=active", "UnitFileState=enabled",
            "Unit=" + unit.replace(".timer", ".service"), "AccuracyUSec=1s",
            "RandomizedDelayUSec=0", "TimersCalendar=",
            "TimersMonotonic={ OnActiveUSec=" + ("1s" if sampler else "2s") +
            " ; next_elapse=0 } { OnUnitActiveUSec=15s ; next_elapse=0 }",
        ])

    def test_complete_manual_release_reconciles(self):
        with patch.object(p, "live_blob", side_effect=lambda parent, name: self.hashes[parent / name]), \
                patch.object(p.subprocess, "check_output", side_effect=self.systemd):
            self.assertEqual(p.monitor_reconciled({}, self.new), set(self.new))

    def test_partial_release_or_wrong_schedule_is_not_reconciled(self):
        with patch.object(p, "live_blob", return_value="ABSENT"):
            self.assertEqual(p.monitor_reconciled({}, self.new), set())
        with patch.object(p, "live_blob", side_effect=lambda parent, name: self.hashes[parent / name]), \
                patch.object(p.subprocess, "check_output",
                             side_effect=lambda *a, **kw: self.systemd(*a, **kw).replace("15s", "60s")):
            self.assertEqual(p.monitor_reconciled({}, self.new), set())


if __name__ == "__main__":
    unittest.main()
