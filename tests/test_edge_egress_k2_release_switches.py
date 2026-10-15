"""Central default-OFF release contract for original single Cross-Edge.

These tests intentionally prevent a code-only green CI from ever implicitly
activating live SSH/PAM/6G/Telegram migration or legacy Batch.
"""
import importlib
import unittest


PROTECTED_RELEASE_SWITCHES = {
    "edge_egress_k2_m3_waves": (
        "M3_WAVE_EXECUTION_ENABLED",
        "M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED",
    ),
    "edge_egress_k2_m4_root_portal": (
        "M4_ROOT_PORTAL_ENABLED",
        "M4_CROSS_EDGE_SINGLE_ENABLED",
    ),
    "edge_egress_k2_m42_bindings": (
        "M42_LIVE_BINDINGS_ENABLED",
        "M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED",
    ),
    "edge_egress_k2_a_host_factory": (
        "M4A_REAL_HOST_FACTORY_ENABLED",
        "M4A_CROSS_EDGE_FACTORY_ENABLED",
    ),
    "edge_egress_k2_a3_host_plans": (
        "A3_ROOT_OWNED_PLAN_SOURCE_ENABLED",
        "A3_ROOT_CROSS_EDGE_PLAN_ENABLED",
        "A3_ROOT_SNAPSHOT_BINDING_ENABLED",
        "A3_ROOT_CROSS_EDGE_SNAPSHOT_ENABLED",
    ),
    "edge_egress_p3_executor": (
        "P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED",
    ),
    "edge_egress_uid_runtime_store": (
        "K2_CROSS_EDGE_RUNTIME_STORE_ENABLED",
    ),
    "edge_egress_k2_uid_ingress_egress": (
        "K2_M4_POLICY_STAGE_ENABLED",
        "K2_ROOT_POLICY_INIT_ENABLED",
    ),
    "edge_egress_k2_m4_cross_edge_port": (
        "M4_CROSS_EDGE_UID_PORT_ENABLED",
        "CROSS_EDGE_PAM_SAFETY_ENABLED",
    ),
    "edge_egress_k2_m4_bootstrap": (
        "M42_CROSS_EDGE_DEFERRED_ENABLED",
    ),
    "edge_egress_v1_admission": (
        "M4_CROSS_EDGE_PAM_RELEASED",
    ),
    "edge_egress_k2_m4_root_worker": (
        "M4_ROOT_WORKER_ENABLED",
    ),
    "ops.k2_m4_plan_stage": (
        "K2_INITIAL_UID_PLAN_STAGE_ENABLED",
    ),
    "ops.k2_m4_root_daemon": (
        "M4A_ROOT_DAEMON_RELEASED",
    ),
    "edge_egress_k2_m4_ipc": (
        "M4_UNIX_IPC_ENABLED",
        "M4_BATCH_RELEASE_ENABLED",
    ),
    "edge_egress_k2_m43_client": (
        "M43_TELEGRAM_EXECUTION_ENABLED",
        "M43_BATCH_EXECUTION_ENABLED",
    ),
}


class ReviewedReleaseSentinelTests(unittest.TestCase):
    def test_no_live_single_or_batch_release_toggles_on_by_import(self):
        for module_name, names in PROTECTED_RELEASE_SWITCHES.items():
            module=importlib.import_module(module_name)
            for name in names:
                with self.subTest(module=module_name,flag=name):
                    self.assertIs(getattr(module,name),False)

    def test_root_daemon_main_still_denies_unaccepted_host_composition(self):
        from ops.k2_m4_root_daemon import main
        self.assertEqual(main(),78)


if __name__=="__main__":
    unittest.main()
