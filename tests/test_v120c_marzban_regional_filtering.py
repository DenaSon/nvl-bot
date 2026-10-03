import pathlib
import sqlite3
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import marzban_asset_discovery as discovery
import marzban_regional_filtering as regional
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
MODULE_PATH = ROOT / "marzban_regional_filtering.py"


def asset(key, kind, ip, port, *, metadata=None, source_id="1"):
    return discovery.MarzbanAsset(
        asset_key=key,
        asset_type=kind,
        source_id=source_id,
        name=key,
        address=ip,
        port=port,
        resolved_ips=(ip,) if ip else (),
        metadata=dict(metadata or {}),
    )


def healthy(state="LOCAL_HEALTHY"):
    return {
        "healthy": state == "LOCAL_HEALTHY",
        "health_state": state,
        "checked_at": "2026-10-03T21:00:00Z",
    }


@dataclass
class Summary:
    total_nodes: int = 6
    completed_nodes: int = 6
    successful_nodes: int = 1
    failed_nodes: int = 5
    pending_nodes: int = 0
    success_ratio: float = 1 / 6
    failed_asns: tuple = ("AS1", "AS2", "AS3", "AS4", "AS5")
    failed_cities: tuple = ("Tehran", "Shiraz")


@dataclass
class Decision:
    state: str
    reason: str = "TEST"
    summary: Summary = None

    def __post_init__(self):
        if self.summary is None:
            self.summary = Summary()


@dataclass
class Probe:
    provider: str = "check-host"
    request_id: str = "req-1"
    permanent_link: str = "https://check-host.net/check-tcp/req-1"


class V120CTargetPolicyTests(unittest.TestCase):
    def test_targets_include_main_and_public_host_but_never_node_control_port(self):
        main = asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, "198.51.100.1", 2053)
        node = asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            "203.0.113.10",
            62050,
            source_id="7",
            metadata={"node_id": 7, "api_port": 62051},
        )
        public = asset(
            "MARZBAN_PUBLIC_HOST:VLESS:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.10",
            443,
        )
        targets = regional.build_probe_targets(
            [main, node, public],
            {
                main.asset_key: healthy(),
                node.asset_key: healthy(),
                public.asset_key: healthy(),
            },
        )
        endpoints = {(t.host, t.port) for t in targets}
        self.assertIn(("198.51.100.1", 2053), endpoints)
        self.assertIn(("203.0.113.10", 443), endpoints)
        self.assertNotIn(("203.0.113.10", 62050), endpoints)
        self.assertNotIn(("203.0.113.10", 62051), endpoints)

    def test_unhealthy_or_disabled_public_host_is_not_probed(self):
        bad = asset(
            "MARZBAN_PUBLIC_HOST:A:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.10",
            443,
        )
        disabled = asset(
            "MARZBAN_PUBLIC_HOST:B:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.11",
            8443,
            metadata={"is_disabled": True},
        )
        targets = regional.build_probe_targets(
            [bad, disabled],
            {
                bad.asset_key: healthy("SERVICE_DOWN"),
                disabled.asset_key: {
                    "healthy": None,
                    "health_state": "DISABLED",
                },
            },
        )
        self.assertEqual(targets, ())

    def test_duplicate_endpoint_is_one_provider_request(self):
        a = asset(
            "MARZBAN_PUBLIC_HOST:A:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.10",
            443,
        )
        b = asset(
            "MARZBAN_PUBLIC_HOST:B:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.10",
            443,
        )
        targets = regional.build_probe_targets(
            [a, b],
            {a.asset_key: healthy(), b.asset_key: healthy()},
        )
        self.assertEqual(len(targets), 1)
        self.assertEqual(
            targets[0].asset_keys,
            (a.asset_key, b.asset_key),
        )

    def test_rotation_is_bounded_and_fair(self):
        targets = tuple(
            regional.RegionalTarget(f"k{i}", f"203.0.113.{i}", 443, (f"a{i}",))
            for i in range(4)
        )
        first, cursor = regional.select_rotating_targets(targets, 0, 2)
        second, cursor2 = regional.select_rotating_targets(targets, cursor, 2)
        self.assertEqual([x.target_key for x in first], ["k0", "k1"])
        self.assertEqual([x.target_key for x in second], ["k2", "k3"])
        self.assertEqual(cursor2, 0)


class V120CEvidencePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        regional.install_schema(self.conn)
        self.target = regional.RegionalTarget(
            "203.0.113.10|443",
            "203.0.113.10",
            443,
            ("MARZBAN_PUBLIC_HOST:VLESS:0",),
        )

    def tearDown(self):
        self.conn.close()

    def test_success_persists_full_regional_summary(self):
        regional.persist_probe_success(
            self.conn,
            self.target,
            Probe(),
            Decision(REGIONAL_STATE_LIKELY),
            checked_at="2026-10-03T21:00:00Z",
        )
        rows = regional.load_endpoint_states(
            self.conn,
            [self.target],
            now=datetime(2026, 10, 3, 21, 1, tzinfo=timezone.utc),
            max_age_seconds=300,
        )
        row = rows[self.target.target_key]
        self.assertEqual(row["filter_state"], REGIONAL_STATE_LIKELY)
        self.assertEqual(row["failed_nodes"], 5)
        self.assertEqual(len(row["failed_asns"]), 5)
        self.assertTrue(row["fresh"])

    def test_provider_error_does_not_destroy_previous_good_evidence(self):
        regional.persist_probe_success(
            self.conn,
            self.target,
            Probe(),
            Decision(REGIONAL_STATE_CLEAR),
            checked_at="2026-10-03T21:00:00Z",
        )
        regional.persist_probe_attempt_error(
            self.conn,
            self.target,
            "LIMITED",
            "limit_exceeded",
            attempted_at="2026-10-03T21:01:00Z",
        )
        row = regional.load_endpoint_states(
            self.conn,
            [self.target],
            now=datetime(2026, 10, 3, 21, 2, tzinfo=timezone.utc),
            max_age_seconds=300,
        )[self.target.target_key]
        self.assertEqual(row["filter_state"], REGIONAL_STATE_CLEAR)
        self.assertEqual(row["provider_status"], "LIMITED")
        self.assertEqual(row["provider_error"], "limit_exceeded")

    def test_stale_evidence_becomes_unknown_without_deleting_history(self):
        regional.persist_probe_success(
            self.conn,
            self.target,
            Probe(),
            Decision(REGIONAL_STATE_LIKELY),
            checked_at="2026-10-03T21:00:00Z",
        )
        row = regional.load_endpoint_states(
            self.conn,
            [self.target],
            now=datetime(2026, 10, 3, 21, 20, tzinfo=timezone.utc),
            max_age_seconds=300,
        )[self.target.target_key]
        self.assertEqual(row["filter_state"], REGIONAL_STATE_UNKNOWN)
        self.assertEqual(
            row["filter_reason"],
            regional.REASON_ENDPOINT_EVIDENCE_STALE,
        )
        self.assertFalse(row["fresh"])


class V120CAssetDerivationTests(unittest.TestCase):
    def setUp(self):
        self.main = asset(
            "MARZBAN_MAIN:main",
            discovery.ASSET_MAIN,
            "198.51.100.1",
            2053,
        )
        self.node = asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            "203.0.113.10",
            62050,
            source_id="7",
        )
        self.public = asset(
            "MARZBAN_PUBLIC_HOST:VLESS:0",
            discovery.ASSET_PUBLIC_HOST,
            "203.0.113.10",
            443,
        )
        self.health = {
            self.main.asset_key: healthy(),
            self.node.asset_key: healthy(),
            self.public.asset_key: healthy(),
        }
        self.targets = regional.build_probe_targets(
            [self.main, self.node, self.public],
            self.health,
        )

    def test_node_state_is_derived_from_public_host_same_ip(self):
        endpoint_states = {
            target.target_key: {
                "filter_state": (
                    REGIONAL_STATE_LIKELY
                    if self.public.asset_key in target.asset_keys
                    else REGIONAL_STATE_CLEAR
                )
            }
            for target in self.targets
        }
        states = {
            row.asset_key: row
            for row in regional.derive_asset_states(
                [self.main, self.node, self.public],
                self.health,
                self.targets,
                endpoint_states,
                checked_at="2026-10-03T21:00:00Z",
            )
        }
        self.assertEqual(
            states[self.public.asset_key].filter_state,
            REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(
            states[self.node.asset_key].filter_state,
            REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(
            states[self.node.asset_key].filter_reason,
            regional.REASON_DERIVED_PUBLIC_HOSTS,
        )

    def test_node_without_public_host_mapping_is_unknown(self):
        states = {
            row.asset_key: row
            for row in regional.derive_asset_states(
                [self.node],
                {self.node.asset_key: healthy()},
                (),
                {},
            )
        }
        self.assertEqual(
            states[self.node.asset_key].filter_state,
            REGIONAL_STATE_UNKNOWN,
        )
        self.assertEqual(
            states[self.node.asset_key].filter_reason,
            regional.REASON_NO_PUBLIC_HOST_MAPPING,
        )

    def test_local_failure_blocks_filtering_verdict(self):
        health_map = dict(self.health)
        health_map[self.public.asset_key] = healthy("SERVICE_DOWN")
        targets = regional.build_probe_targets(
            [self.main, self.node, self.public],
            health_map,
        )
        states = {
            row.asset_key: row
            for row in regional.derive_asset_states(
                [self.main, self.node, self.public],
                health_map,
                targets,
                {},
            )
        }
        self.assertEqual(
            states[self.public.asset_key].filter_state,
            REGIONAL_STATE_UNKNOWN,
        )
        self.assertEqual(
            states[self.public.asset_key].filter_reason,
            regional.REASON_LOCAL_NOT_HEALTHY,
        )

    def test_mixed_clear_and_likely_endpoints_is_possible(self):
        multi = discovery.MarzbanAsset(
            asset_key="MARZBAN_PUBLIC_HOST:MULTI:0",
            asset_type=discovery.ASSET_PUBLIC_HOST,
            source_id="MULTI:0",
            name="multi",
            address="multi.example",
            port=443,
            resolved_ips=("203.0.113.20", "203.0.113.21"),
            metadata={},
        )
        health_map = {multi.asset_key: healthy()}
        targets = regional.build_probe_targets([multi], health_map)
        endpoint_states = {
            targets[0].target_key: {"filter_state": REGIONAL_STATE_CLEAR},
            targets[1].target_key: {"filter_state": REGIONAL_STATE_LIKELY},
        }
        state = regional.derive_asset_states(
            [multi], health_map, targets, endpoint_states
        )[0]
        self.assertEqual(state.filter_state, REGIONAL_STATE_POSSIBLE)


class V120CRuntimeStateTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        regional.install_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_limited_provider_uses_independent_exponential_backoff(self):
        now = datetime(2026, 10, 3, 21, 0, tzinfo=timezone.utc)
        first = regional.record_provider_limited(
            self.conn,
            "limit",
            now=now,
            base_seconds=300,
            max_seconds=3600,
        )
        second = regional.record_provider_limited(
            self.conn,
            "limit",
            now=now,
            base_seconds=300,
            max_seconds=3600,
        )
        self.assertEqual(first, 300)
        self.assertEqual(second, 600)
        self.assertEqual(
            regional.get_runtime(self.conn)["provider_status"],
            "LIMITED",
        )

    def test_provider_ok_resets_backoff(self):
        now = datetime(2026, 10, 3, 21, 0, tzinfo=timezone.utc)
        regional.record_provider_limited(self.conn, "limit", now=now)
        regional.record_provider_ok(self.conn, now=now + timedelta(minutes=1))
        self.assertEqual(regional.backoff_remaining_seconds(
            self.conn,
            now=now + timedelta(minutes=1),
        ), 0)
        self.assertEqual(
            regional.get_runtime(self.conn)["provider_status"],
            "OK",
        )

    def test_asset_state_since_is_stable(self):
        first = regional.AssetRegionalState(
            "MARZBAN_MAIN:main",
            discovery.ASSET_MAIN,
            REGIONAL_STATE_CLEAR,
            regional.REASON_DIRECT_ENDPOINTS,
            "2026-10-03T21:00:00Z",
            {},
        )
        second = regional.AssetRegionalState(
            first.asset_key,
            first.asset_type,
            REGIONAL_STATE_CLEAR,
            first.filter_reason,
            "2026-10-03T21:05:00Z",
            {},
        )
        regional.persist_asset_states(self.conn, [first])
        regional.persist_asset_states(self.conn, [second])
        row = regional.list_asset_states(self.conn)[first.asset_key]
        self.assertEqual(row["state_since"], "2026-10-03T21:00:00Z")


class V120CSourceSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = BOT_PATH.read_text(encoding="utf-8")
        cls.module = MODULE_PATH.read_text(encoding="utf-8")

    def test_module_never_uses_node_control_ports_as_regional_targets(self):
        self.assertIn("ASSET_MAIN", self.module)
        self.assertIn("ASSET_PUBLIC_HOST", self.module)
        target_region = self.module[
            self.module.index("def build_probe_targets"):
            self.module.index("def select_rotating_targets")
        ]
        self.assertNotIn("ASSET_NODE,", target_region)
        self.assertNotIn("62050", target_region)
        self.assertNotIn("62051", target_region)

    def test_runtime_has_clean_lifecycle_and_shared_provider_lock(self):
        init = self.bot.index("async def _post_init(app):")
        shutdown = self.bot.index("async def _post_shutdown(app):", init)
        main = self.bot.index("if __name__ == '__main__':", shutdown)
        self.assertIn("marzban_regional_task", self.bot[init:shutdown])
        self.assertIn("marzban_regional_task", self.bot[shutdown:main])
        region_start = self.bot.index("async def _marzban_regional_filter_tick")
        region_end = self.bot.index("def _db_mark_reserved_v2ray_sale", region_start)
        runtime = self.bot[region_start:region_end]
        self.assertIn("_regional_probe_lock(app)", runtime)
        self.assertIn('provider.discover_nodes, "ir"', runtime)

    def test_v120c_runtime_does_not_notify_or_failover(self):
        region_start = self.bot.index("async def _marzban_regional_filter_tick")
        region_end = self.bot.index("def _db_mark_reserved_v2ray_sale", region_start)
        runtime = self.bot[region_start:region_end]
        for forbidden in (
            "_notify_admins(",
            "_notify_filter_state_transition(",
            "_regional_provider_enter_limited(",
            "_regional_provider_enter_error(",
            "_regional_provider_mark_ok(",
            "_safe_manual_failover(",
            "_phase6h_auto_failover_tick(",
            "_cf_switch_public_domain(",
        ):
            self.assertNotIn(forbidden, runtime)

    def test_bounded_defaults(self):
        for fragment in (
            'NVL_MARZBAN_REGIONAL_INTERVAL", 300',
            'NVL_MARZBAN_REGIONAL_MAX_TARGETS", 2',
            'NVL_MARZBAN_REGIONAL_EVIDENCE_MAX_AGE", 900',
        ):
            self.assertIn(fragment, self.bot)


if __name__ == "__main__":
    unittest.main()
