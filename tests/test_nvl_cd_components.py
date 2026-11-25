"""Component-aware Core deployment planning tests."""
import unittest

from ops import nvl_cd_components as components


def make_tree(files):
    tree, blobs = {}, {}
    for name, raw in files.items():
        oid = components.git_blob(raw)
        tree[name] = ("100644", "blob", oid)
        blobs[oid] = raw
    return tree, lambda oid: blobs[oid]


class ComponentCatalogTests(unittest.TestCase):
    def test_network_alert_dependencies_and_timer_destinations(self):
        files = {
            "ops/nvl_network_live_alerts.py":
                b"from .nvl_network_intelligence import observation\n",
            "ops/nvl_network_intelligence.py": b"import json\n",
            "systemd/nvl-network-sampler.timer.d/90-nvl-cadence.conf.example":
                b"[Timer]\nOnUnitActiveSec=15s\n",
            "systemd/nvl-network-alerts.timer.d/90-nvl-cadence.conf.example":
                b"[Timer]\nOnUnitInactiveSec=20s\n",
        }
        tree, read = make_tree(files)
        targets = components.component_targets(tree, read)
        self.assertIn(
            ("ops/nvl_network_live_alerts.py",
             "/opt/nvl-network-alerts/nvl_network_live_alerts.py"),
            targets,
        )
        self.assertIn(
            ("ops/nvl_network_intelligence.py",
             "/opt/nvl-network-alerts/nvl_network_intelligence.py"),
            targets,
        )
        self.assertIn(
            ("systemd/nvl-network-sampler.timer.d/90-nvl-cadence.conf.example",
             "/etc/systemd/system/nvl-network-sampler.timer.d/90-nvl-cadence.conf"),
            targets,
        )
        self.assertIn(
            ("systemd/nvl-network-alerts.timer.d/90-nvl-cadence.conf.example",
             "/etc/systemd/system/nvl-network-alerts.timer.d/90-nvl-cadence.conf"),
            targets,
        )

    def test_awg_witness_closure_includes_route_dependency(self):
        files = {
            "nvl_awg_witness_refresh.py":
                b"from nvl_awg_limiter_witness import refresh\n",
            "nvl_awg_limiter_witness.py":
                b"from nvl_awg_core_routes import route_state\n",
            "nvl_awg_core_routes.py": b"import subprocess\n",
            "nvl-awg-core-routes.service": b"[Service]\n",
            "nvl-awg-witness-refresh.service": b"[Service]\n",
            "nvl-awg-witness-refresh.timer": b"[Timer]\n",
        }
        tree, read = make_tree(files)
        targets = components.component_targets(tree, read)
        route = targets[("nvl_awg_core_routes.py", "/root/nvl_awg_core_routes.py")]
        self.assertEqual(
            route["components"], ["awg-core-routes", "awg-witness-refresh"]
        )
        self.assertIn(
            ("nvl_awg_limiter_witness.py", "/root/nvl_awg_limiter_witness.py"),
            targets,
        )
        self.assertIn(
            ("nvl-awg-witness-refresh.timer",
             "/etc/systemd/system/nvl-awg-witness-refresh.timer"),
            targets,
        )

    def test_candidate_already_installed_is_reconciled_without_rewrite(self):
        old, read_old = make_tree({
            "ops/nvl_network_live_alerts.py": b"from .nvl_network_intelligence import old\n",
            "ops/nvl_network_intelligence.py": b"VALUE = 1\n",
        })
        new, read_new = make_tree({
            "ops/nvl_network_live_alerts.py": b"from .nvl_network_intelligence import new\n",
            "ops/nvl_network_intelligence.py": b"VALUE = 1\n",
        })
        live = {
            "/opt/nvl-network-alerts/nvl_network_live_alerts.py":
                new["ops/nvl_network_live_alerts.py"][2],
            "/opt/nvl-network-alerts/nvl_network_intelligence.py":
                old["ops/nvl_network_intelligence.py"][2],
        }
        plan = components.plan_updates(
            old, new, read_old, read_new, lambda path: live.get(path, components.ABSENT)
        )
        self.assertEqual(plan["updates"], [])
        self.assertEqual(plan["drift"], [])
        self.assertEqual(plan["components"], ["network-alerts"])

    def test_old_hash_plans_update_and_unknown_hash_is_drift(self):
        old, read_old = make_tree({
            "ops/nvl_network_live_alerts.py": b"from .nvl_network_intelligence import old\n",
            "ops/nvl_network_intelligence.py": b"VALUE = 1\n",
        })
        new, read_new = make_tree({
            "ops/nvl_network_live_alerts.py": b"from .nvl_network_intelligence import new\n",
            "ops/nvl_network_intelligence.py": b"VALUE = 1\n",
        })
        destination = "/opt/nvl-network-alerts/nvl_network_live_alerts.py"
        old_hash = old["ops/nvl_network_live_alerts.py"][2]
        plan = components.plan_updates(
            old, new, read_old, read_new,
            lambda path: old_hash if path == destination else (
                old["ops/nvl_network_intelligence.py"][2]
            ),
        )
        self.assertEqual(len(plan["updates"]), 1)
        self.assertEqual(plan["updates"][0]["source"], "ops/nvl_network_live_alerts.py")
        self.assertEqual(plan["updates"][0]["action"], "write")

        drift = components.plan_updates(
            old, new, read_old, read_new, lambda _path: "f" * 40
        )
        self.assertTrue(drift["drift"])
        self.assertFalse(drift["updates"])

    def test_unrelated_awg_drift_does_not_block_network_release(self):
        old, read_old = make_tree({
            "ops/nvl_network_live_alerts.py": b"VALUE = 1\n",
            "nvl_awg_core_routes.py": b"VALUE = 1\n",
        })
        new, read_new = make_tree({
            "ops/nvl_network_live_alerts.py": b"VALUE = 2\n",
            "nvl_awg_core_routes.py": b"VALUE = 1\n",
        })
        live = {
            "/opt/nvl-network-alerts/nvl_network_live_alerts.py":
                old["ops/nvl_network_live_alerts.py"][2],
            "/root/nvl_awg_core_routes.py": "f" * 40,
        }
        plan = components.plan_updates(
            old, new, read_old, read_new, lambda path: live.get(path, components.ABSENT)
        )
        self.assertEqual(plan["drift"], [])
        self.assertEqual(len(plan["updates"]), 1)
        self.assertEqual(plan["components"], ["network-alerts"])

    def test_bot_imports_are_added_without_manual_inventory_edits(self):
        files = {
            "bot_final_v49-2.py": b"import bot_runtime_module\n",
            "bot_runtime_module.py": b"from ops.runtime_helpers import run\n",
            "ops/runtime_helpers.py": b"VALUE = 1\n",
            "nvl_awg_core_routes.py": b"import subprocess\n",
            "nvl-awg-core-routes.service": b"[Service]\n",
        }
        tree, read = make_tree(files)
        paths = components.bot_runtime_paths(tree, read)
        self.assertEqual(
            paths,
            {"bot_final_v49-2.py", "bot_runtime_module.py",
             "ops/runtime_helpers.py"},
        )
        effective = components.effective_inventory(tree, tree, set(), read)
        self.assertEqual(effective, paths)
        self.assertNotIn("nvl_awg_core_routes.py", effective)

    def test_shared_awg_module_is_left_to_bot_transaction(self):
        old, read_old = make_tree({
            "bot_final_v49-2.py": b"import nvl_awg_core_routes\n",
            "nvl_awg_core_routes.py": b"VALUE = 1\n",
            "nvl-awg-core-routes.service": b"[Service]\n",
        })
        new, read_new = make_tree({
            "bot_final_v49-2.py": b"import nvl_awg_core_routes\n",
            "nvl_awg_core_routes.py": b"VALUE = 2\n",
            "nvl-awg-core-routes.service": b"[Service]\n",
        })
        bot_paths = components.bot_runtime_paths(new, read_new)
        service_path = "/etc/systemd/system/nvl-awg-core-routes.service"
        live = {service_path: old["nvl-awg-core-routes.service"][2]}
        plan = components.plan_updates(
            old, new, read_old, read_new,
            lambda path: live.get(path, old["nvl_awg_core_routes.py"][2]),
            bot_inventory=bot_paths,
        )
        self.assertEqual(plan["updates"], [])
        self.assertEqual(plan["post_components"], ["awg-core-routes"])
        self.assertEqual(plan["post_sources"], ["nvl_awg_core_routes.py"])

    def test_edge_sync_is_explicitly_excluded(self):
        for path in (
            "nvl_edge_sync.py",
            "ops/edge-sync/deploy.py",
            "edge_sync/runtime.py",
        ):
            self.assertTrue(components.is_edge_sync_path(path))
        self.assertFalse(components.is_edge_sync_path("nvl_awg_core_routes.py"))


if __name__ == "__main__":
    unittest.main()
