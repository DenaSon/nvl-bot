"""Regression tests for low-noise Marzban Telegram filtering alerts."""
from datetime import datetime, timedelta, timezone
import pathlib
import sqlite3
import unittest

import marzban_alerting as alerts
import marzban_asset_discovery as discovery
import marzban_observability as obs
import marzban_regional_filtering as regional

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = datetime(2026, 11, 12, 15, 0, tzinfo=timezone.utc)


def dt(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def asset(*, node=False):
    return discovery.MarzbanAsset(
        asset_key="MARZBAN_NODE:7" if node else "MARZBAN_PUBLIC_HOST:A:0",
        asset_type=discovery.ASSET_NODE if node else discovery.ASSET_PUBLIC_HOST,
        source_id="7" if node else "A",
        name="Amsterdam" if node else "TCP",
        address="198.51.100.10",
        port=443,
        resolved_ips=("198.51.100.10",),
        metadata={},
    )


def status(item, state: str, tick: int, evidence_tick=None):
    is_node = item.asset_type == discovery.ASSET_NODE
    evidence = (
        {"public_host_assets": [{"asset_key": "MARZBAN_PUBLIC_HOST:A:0",
                                 "filter_state": state}]}
        if is_node else
        {"endpoints": {"provider:test": {
            "fresh": True,
            "filter_state": state,
            "evidence_checked_at": dt(evidence_tick if evidence_tick is not None else tick),
        }}}
    )
    return regional.AssetRegionalState(
        asset_key=item.asset_key,
        asset_type=item.asset_type,
        filter_state=state,
        filter_reason=(regional.REASON_DERIVED_PUBLIC_HOSTS if is_node
                       else regional.REASON_DIRECT_ENDPOINTS),
        checked_at=dt(tick),
        evidence=evidence,
    )


class MarzbanAlertPolicyTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)
        regional.install_schema(self.conn)
        obs.install_schema(self.conn)
        alerts.install_schema(self.conn)
        self.item = asset()

    def tearDown(self):
        self.conn.close()

    def cycle(self, value, minute, evidence_minute=None, item=None):
        item = item or self.item
        state = status(item, value, minute, evidence_minute)
        obs.record_state_transitions(self.conn, [item], [state], {})
        alerts.observe_regional_scan(self.conn, [state])
        regional.persist_asset_states(self.conn, [state])

    def plan(self, minute=30):
        return alerts.prepare_delivery(
            self.conn, confirm_scans=3, cooldown_minutes=60,
            now=BASE + timedelta(minutes=minute),
        )

    def test_possible_requires_three_distinct_provider_evidence_revisions(self):
        self.cycle("POSSIBLE", 0)
        self.assertEqual(len(self.plan()[0]), 0)
        self.cycle("POSSIBLE", 5, evidence_minute=0)  # cached Check-Host
        self.assertEqual(len(self.plan()[0]), 0)
        self.cycle("POSSIBLE", 10)
        self.assertEqual(len(self.plan()[0]), 0)
        self.cycle("POSSIBLE", 15)
        send, suppressed = self.plan()
        self.assertEqual(len(send), 1)
        self.assertEqual(send[0].transition_kind, obs.TRANSITION_WARNING)
        self.assertEqual(suppressed, ())

    def test_unknown_gap_resets_warning_confirmation(self):
        self.cycle("POSSIBLE", 0)
        self.cycle("UNKNOWN", 5)
        self.cycle("POSSIBLE", 10)
        self.cycle("POSSIBLE", 15)
        self.assertEqual(len(self.plan()[0]), 0)

    def test_likely_critical_sends_immediately(self):
        self.cycle("LIKELY", 0)
        send, _ = self.plan()
        self.assertEqual(len(send), 1)
        self.assertEqual(send[0].transition_kind, obs.TRANSITION_CRITICAL)

    def test_unannounced_possible_recovery_is_silent(self):
        self.cycle("POSSIBLE", 0)
        self.cycle("CLEAR", 5)
        send, suppressed = self.plan()
        self.assertEqual(send, ())
        self.assertEqual({reason for _, reason in suppressed},
                         {"STALE_POSSIBLE", "UNANNOUNCED_WARNING_RECOVERY"})

    def test_recovery_after_critical_is_delivered(self):
        self.cycle("LIKELY", 0)
        send, _ = self.plan()
        obs.mark_notified(self.conn, [send[0].event_id], notified_at=dt(1))
        self.cycle("CLEAR", 5)
        send, _ = self.plan()
        self.assertEqual(len(send), 1)
        self.assertEqual(send[0].transition_kind, obs.TRANSITION_RECOVERED)

    def test_flapping_critical_cooldown_and_recovery_resets_it(self):
        self.cycle("LIKELY", 0)
        first, _ = self.plan()
        obs.mark_notified(self.conn, [first[0].event_id], notified_at=dt(1))
        self.cycle("POSSIBLE", 5)
        self.cycle("LIKELY", 10)
        send, suppressed = self.plan()
        self.assertEqual(send, ())
        self.assertIn("CRITICAL_COOLDOWN", [reason for _, reason in suppressed])
        alerts.mark_suppressed(self.conn, suppressed)
        self.cycle("CLEAR", 15)
        recovery, _ = self.plan()
        self.assertTrue(any(e.transition_kind == obs.TRANSITION_RECOVERED for e in recovery))
        obs.mark_notified(self.conn,
                          [e.event_id for e in recovery if e.transition_kind == obs.TRANSITION_RECOVERED],
                          notified_at=dt(16))
        self.cycle("LIKELY", 20)
        send, _ = self.plan()
        self.assertTrue(any(e.transition_kind == obs.TRANSITION_CRITICAL for e in send))

    def test_derived_node_is_not_a_second_telegram_alert(self):
        node = asset(node=True)
        self.cycle("POSSIBLE", 0, item=node)
        send, suppressed = self.plan()
        self.assertEqual(send, ())
        self.assertEqual(suppressed[0][1], "DERIVED_NODE_DUPLICATE")
        alerts.mark_suppressed(self.conn, suppressed)
        self.assertEqual(alerts.prepare_delivery(self.conn)[1], ())

    def test_repeated_suppressions_do_not_block_later_critical(self):
        node = asset(node=True)
        self.cycle("POSSIBLE", 0, item=node)
        _, suppressed = self.plan()
        alerts.mark_suppressed(self.conn, suppressed)
        self.cycle("LIKELY", 10, item=node)
        self.assertEqual(len(self.plan()[0]), 0)  # still derived
        self.cycle("LIKELY", 12, item=self.item)
        send, _ = self.plan()
        self.assertEqual(len(send), 1)
        self.assertEqual(send[0].asset_key, self.item.asset_key)


class MarzbanTelegramRoutingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        start = source.index("async def _deliver_marzban_monitor_alerts")
        end = source.index("async def _marzban_regional_filter_loop", start)
        cls.delivery = source[start:end]

    def test_only_group_chat_id_used_and_missing_id_fails_closed(self):
        self.assertIn('MARZBAN_ALERT_CHAT_ID', self.delivery)
        self.assertIn('chat_id=chat_id', self.delivery)
        self.assertIn('if chat_id >= 0:', self.delivery)
        self.assertNotIn('_db_get_admin_chat_ids', self.delivery)
        self.assertNotIn('_notify_admins(', self.delivery)

    def test_outbox_marked_only_after_send_success(self):
        self.assertIn('if delivered > 0:', self.delivery)
        self.assertIn('marzban_observability.mark_notified', self.delivery)
        self.assertIn('marzban_alerting.mark_suppressed', self.delivery)


if __name__ == "__main__":
    unittest.main()
