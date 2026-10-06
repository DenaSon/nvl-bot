import pathlib
import sqlite3
import unittest

import marzban_asset_discovery as discovery
import marzban_local_health as local_health
import marzban_observability as obs
import marzban_regional_filtering as regional
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
MODULE_PATH = ROOT / "marzban_observability.py"


def asset(key="MARZBAN_MAIN:main", kind=discovery.ASSET_MAIN, name="Main"):
    return discovery.MarzbanAsset(
        asset_key=key,
        asset_type=kind,
        source_id="main",
        name=name,
        address="198.51.100.1",
        port=2053,
        resolved_ips=("198.51.100.1",),
        metadata={},
    )


def state(value, key="MARZBAN_MAIN:main", kind=discovery.ASSET_MAIN, stamp="2026-10-03T22:00:00Z"):
    return regional.AssetRegionalState(
        asset_key=key,
        asset_type=kind,
        filter_state=value,
        filter_reason=regional.REASON_DIRECT_ENDPOINTS,
        checked_at=stamp,
        evidence={"sample": True},
    )


class V120DTransitionPolicyTests(unittest.TestCase):
    def test_initial_clear_and_unknown_are_silent(self):
        self.assertFalse(obs.classify_transition(None, REGIONAL_STATE_CLEAR).notify)
        self.assertFalse(obs.classify_transition(None, REGIONAL_STATE_UNKNOWN).notify)

    def test_initial_possible_and_likely_alert(self):
        self.assertEqual(
            obs.classify_transition(None, REGIONAL_STATE_POSSIBLE).kind,
            obs.TRANSITION_WARNING,
        )
        self.assertEqual(
            obs.classify_transition(None, REGIONAL_STATE_LIKELY).kind,
            obs.TRANSITION_CRITICAL,
        )

    def test_same_state_never_realerts(self):
        self.assertFalse(
            obs.classify_transition(
                REGIONAL_STATE_LIKELY,
                REGIONAL_STATE_LIKELY,
            ).notify
        )

    def test_recovery_and_unknown_evidence_gap(self):
        self.assertEqual(
            obs.classify_transition(
                REGIONAL_STATE_LIKELY,
                REGIONAL_STATE_CLEAR,
            ).kind,
            obs.TRANSITION_RECOVERED,
        )
        self.assertFalse(
            obs.classify_transition(
                REGIONAL_STATE_POSSIBLE,
                REGIONAL_STATE_UNKNOWN,
            ).notify
        )


class V120DOutboxTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)
        local_health.install_schema(self.conn)
        regional.install_schema(self.conn)
        obs.install_schema(self.conn)
        self.asset = asset()

    def tearDown(self):
        self.conn.close()

    def _seed_previous(self, value):
        regional.persist_asset_states(
            self.conn,
            [state(value, stamp="2026-10-03T21:55:00Z")],
        )

    def test_transition_is_recorded_before_state_update(self):
        self._seed_previous(REGIONAL_STATE_CLEAR)
        created = obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_LIKELY)],
            {self.asset.asset_key: {"healthy": True, "health_state": "LOCAL_HEALTHY"}},
        )
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].previous_state, REGIONAL_STATE_CLEAR)
        self.assertEqual(created[0].current_state, REGIONAL_STATE_LIKELY)
        self.assertEqual(created[0].transition_kind, obs.TRANSITION_CRITICAL)

    def test_same_state_creates_no_outbox_event(self):
        self._seed_previous(REGIONAL_STATE_LIKELY)
        created = obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_LIKELY)],
            {},
        )
        self.assertEqual(created, ())

    def test_unknown_gap_does_not_create_churn_or_duplicate_likely(self):
        self._seed_previous(REGIONAL_STATE_LIKELY)
        gap = obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_UNKNOWN, stamp="2026-10-03T22:00:00Z")],
            {},
        )
        self.assertEqual(gap, ())
        regional.persist_asset_states(
            self.conn,
            [state(REGIONAL_STATE_UNKNOWN, stamp="2026-10-03T22:00:00Z")],
        )
        again = obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_LIKELY, stamp="2026-10-03T22:05:00Z")],
            {},
        )
        self.assertEqual(again, ())
        self.assertEqual(obs.pending_notifications(self.conn), ())

    def test_pending_notifications_are_marked_after_delivery(self):
        obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_POSSIBLE)],
            {},
        )
        pending = obs.pending_notifications(self.conn)
        self.assertEqual(len(pending), 1)
        obs.mark_notified(self.conn, [pending[0].event_id], notified_at="2026-10-03T22:01:00Z")
        self.assertEqual(obs.pending_notifications(self.conn), ())

    def test_alert_digest_explicitly_says_no_automatic_action(self):
        obs.record_state_transitions(
            self.conn,
            [self.asset],
            [state(REGIONAL_STATE_LIKELY)],
            {},
        )
        text = obs.render_alert_digest(obs.pending_notifications(self.conn))
        self.assertIn("LIKELY", text)
        self.assertIn("هیچ اقدام خودکاری", text)


class V120DStatusReportTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)
        local_health.install_schema(self.conn)
        regional.install_schema(self.conn)
        obs.install_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_status_report_combines_inventory_local_regional_and_history(self):
        item = asset()
        discovery.sync_inventory(
            self.conn,
            [item],
            observed_at="2026-10-03T21:50:00Z",
        )
        local_health.persist_health_snapshot(
            self.conn,
            [
                local_health.AssetHealth(
                    item.asset_key,
                    item.asset_type,
                    local_health.STATE_LOCAL_HEALTHY,
                    local_health.REASON_OK,
                    True,
                    "2026-10-03T21:59:00Z",
                    10.0,
                    {},
                )
            ],
        )
        regional.persist_asset_states(
            self.conn,
            [state(REGIONAL_STATE_CLEAR, stamp="2026-10-03T21:59:00Z")],
        )
        report = obs.render_dashboard_report(self.conn)
        self.assertIn("Marzban Monitor", report)
        self.assertIn("سالم", report)
        self.assertIn("198.51.100.1:2053", report)
        self.assertNotIn("LOCAL_HEALTHY", report)

    def test_disabled_public_hosts_are_kept_in_inventory_but_hidden_from_monitor(self):
        enabled = asset(
            key="MARZBAN_PUBLIC_HOST:LIVE:0",
            kind=discovery.ASSET_PUBLIC_HOST,
            name="Live Host",
        )
        disabled = discovery.MarzbanAsset(
            asset_key="MARZBAN_PUBLIC_HOST:OLD:0",
            asset_type=discovery.ASSET_PUBLIC_HOST,
            source_id="OLD:0",
            name="Old disabled host",
            address="old.example.test",
            port=443,
            resolved_ips=(),
            metadata={"is_disabled": True},
        )
        discovery.sync_inventory(
            self.conn,
            [enabled, disabled],
            observed_at="2026-10-03T21:50:00Z",
        )
        local_health.persist_health_snapshot(
            self.conn,
            [
                local_health.AssetHealth(
                    enabled.asset_key,
                    enabled.asset_type,
                    local_health.STATE_LOCAL_HEALTHY,
                    local_health.REASON_OK,
                    True,
                    "2026-10-03T21:59:00Z",
                    10.0,
                    {},
                ),
                local_health.AssetHealth(
                    disabled.asset_key,
                    disabled.asset_type,
                    local_health.STATE_DISABLED,
                    local_health.REASON_PUBLIC_HOST_DISABLED,
                    None,
                    "2026-10-03T21:59:00Z",
                    None,
                    {},
                ),
            ],
        )
        report = obs.render_hosts_report(self.conn)
        self.assertIn("Live Host", report)
        self.assertNotIn("Old disabled host", report)

    def test_node_without_active_public_host_is_rendered_na_not_unknown(self):
        node = discovery.MarzbanAsset(
            asset_key="MARZBAN_NODE:7",
            asset_type=discovery.ASSET_NODE,
            source_id="7",
            name="USA-1",
            address="216.126.237.205",
            port=62050,
            resolved_ips=("216.126.237.205",),
            metadata={"node_id": 7, "status": "connected", "api_port": 62051},
        )
        discovery.sync_inventory(
            self.conn,
            [node],
            observed_at="2026-10-03T21:50:00Z",
        )
        local_health.persist_health_snapshot(
            self.conn,
            [
                local_health.AssetHealth(
                    node.asset_key,
                    node.asset_type,
                    local_health.STATE_LOCAL_HEALTHY,
                    local_health.REASON_OK,
                    True,
                    "2026-10-03T21:59:00Z",
                    8.0,
                    {},
                )
            ],
        )
        regional.persist_asset_states(
            self.conn,
            [
                regional.AssetRegionalState(
                    node.asset_key,
                    node.asset_type,
                    REGIONAL_STATE_UNKNOWN,
                    regional.REASON_NO_PUBLIC_HOST_MAPPING,
                    "2026-10-03T21:59:00Z",
                    {},
                )
            ],
        )
        report = obs.render_nodes_report(self.conn)
        self.assertIn("USA-1", report)
        self.assertIn("Regional: ➖ <b>N/A</b>", report)
        self.assertNotIn("UNKNOWN", report)

    def test_report_is_bounded_for_telegram(self):
        for renderer in (
            obs.render_dashboard_report,
            obs.render_nodes_report,
            obs.render_hosts_report,
            obs.render_regional_report,
            obs.render_events_report,
        ):
            report = renderer(self.conn)
            self.assertLessEqual(len(report), 3900)


class V120DSourceSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = BOT_PATH.read_text(encoding="utf-8")
        cls.module = MODULE_PATH.read_text(encoding="utf-8")

    def test_admin_status_command_is_registered(self):
        self.assertIn('CommandHandler("marzban_monitor", cmd_marzban_monitor)', self.bot)

    def test_v120d_schema_is_installed(self):
        self.assertIn("marzban_observability.install_schema(conn)", self.bot)

    def test_alert_delivery_marks_outbox_only_after_send_success(self):
        start = self.bot.index("async def _deliver_marzban_monitor_alerts")
        end = self.bot.index("async def _marzban_regional_filter_loop", start)
        runtime = self.bot[start:end]
        self.assertIn("send_message", runtime)
        self.assertIn("mark_notified", runtime)
        self.assertIn("delivered > 0", runtime)

    def test_observability_module_has_no_operational_mutations(self):
        lower = self.module.lower()
        for forbidden in (
            "modify_node(",
            "update_host(",
            "set_node_enabled(",
            "reconnect_node(",
            "_safe_manual_failover(",
            "_phase6h_auto_failover_tick(",
            "_cf_switch_public_domain(",
            "subprocess.",
            "paramiko.",
        ):
            self.assertNotIn(forbidden, lower)

    def test_bot_version_is_v120d(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B1-2026-10-06-adopt-public-endpoint"',
            self.bot,
        )


if __name__ == "__main__":
    unittest.main()
