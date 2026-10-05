import pathlib
import sqlite3
import unittest

import marzban_asset_discovery as discovery
import marzban_local_health as local_health
import marzban_observability as obs
import marzban_regional_filtering as regional
from regional_filtering import REGIONAL_STATE_CLEAR, REGIONAL_STATE_LIKELY


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class V122AMonitoringPresentationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)
        local_health.install_schema(self.conn)
        regional.install_schema(self.conn)
        obs.install_schema(self.conn)

        self.node = discovery.MarzbanAsset(
            asset_key="MARZBAN_NODE:1",
            asset_type=discovery.ASSET_NODE,
            source_id="1",
            name="Pingo✅",
            address="172.86.72.203",
            port=62050,
            resolved_ips=("172.86.72.203",),
            metadata={
                "node_id": 1,
                "status": "connected",
                "api_port": 62051,
                "xray_version": "25.9.11",
            },
        )
        self.hosts = (
            self._host("Shadowsocks TCP", 1080, 10.0),
            self._host("VLESS TCP REALITY", 8443, 12.0),
            self._host("Trojan WS", 8080, 14.0),
        )
        discovery.sync_inventory(
            self.conn,
            [self.node, *self.hosts],
            observed_at="2026-10-06T00:00:00Z",
        )

        health_rows = [
            local_health.AssetHealth(
                self.node.asset_key,
                self.node.asset_type,
                local_health.STATE_LOCAL_HEALTHY,
                local_health.REASON_OK,
                True,
                "2026-10-06T00:01:00Z",
                8.0,
                {
                    "node_status": "connected",
                    "node_api": {"ok": True, "latency_ms": 9.0},
                },
            )
        ]
        for item, latency in zip(self.hosts, (10.0, 12.0, 14.0)):
            health_rows.append(
                local_health.AssetHealth(
                    item.asset_key,
                    item.asset_type,
                    local_health.STATE_LOCAL_HEALTHY,
                    local_health.REASON_OK,
                    True,
                    "2026-10-06T00:01:00Z",
                    latency,
                    {},
                )
            )
        local_health.persist_health_snapshot(self.conn, health_rows)

        regional.persist_asset_states(
            self.conn,
            [
                regional.AssetRegionalState(
                    item.asset_key,
                    item.asset_type,
                    REGIONAL_STATE_CLEAR,
                    regional.REASON_DIRECT_ENDPOINTS,
                    "2026-10-06T00:02:00Z",
                    {
                        "endpoints": {
                            f"{item.address}|{item.port}": {
                                "provider": "check-host",
                                "completed_nodes": 10,
                                "successful_nodes": 9,
                                "failed_nodes": 1,
                                "pending_nodes": 0,
                                "success_ratio": 0.9,
                                "failed_asns": ["AS123"],
                                "failed_cities": ["Tehran"],
                                "evidence_checked_at": "2026-10-06T00:02:00Z",
                            }
                        }
                    },
                )
                for item in self.hosts
            ],
        )

    def tearDown(self):
        self.conn.close()

    def _host(self, tag, port, latency):
        del latency
        return discovery.MarzbanAsset(
            asset_key=f"MARZBAN_PUBLIC_HOST:{tag}:0",
            asset_type=discovery.ASSET_PUBLIC_HOST,
            source_id=f"{tag}:0",
            name="Pingo✅ ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]",
            address="172.86.72.203",
            port=port,
            resolved_ips=("172.86.72.203",),
            metadata={
                "inbound_tag": tag,
                "is_disabled": False,
            },
        )

    def test_hosts_are_grouped_by_node_and_never_render_marzban_templates(self):
        report = obs.render_hosts_report(self.conn)

        self.assertEqual(report.count("Pingo✅"), 1)
        self.assertIn("Shadowsocks TCP", report)
        self.assertIn("VLESS Reality", report)
        self.assertIn("Trojan WS", report)
        self.assertIn("10 ms", report)
        self.assertNotIn("{USERNAME}", report)
        self.assertNotIn("{PROTOCOL}", report)
        self.assertNotIn("{TRANSPORT}", report)

    def test_dashboard_is_compact_and_uses_summary_counts(self):
        report = obs.render_dashboard_report(self.conn)

        self.assertIn("Marzban Monitor", report)
        self.assertIn("<b>1/1</b> متصل و سالم", report)
        self.assertIn("<b>3/3</b> سالم", report)
        self.assertIn("🟢 3 سالم", report)
        self.assertNotIn("{USERNAME}", report)
        self.assertNotIn("Recent transitions", report)

    def test_regional_page_surfaces_existing_evidence(self):
        report = obs.render_regional_report(self.conn)

        self.assertIn("Regional Monitoring", report)
        self.assertIn("Reachability: <b>90%</b>", report)
        self.assertIn("OK 9 · Fail 1 · Pending 0", report)
        self.assertIn("AS123", report)
        self.assertIn("Tehran", report)
        self.assertNotIn("{USERNAME}", report)

    def test_public_host_alerts_never_render_marzban_templates(self):
        host = self.hosts[1]
        created = obs.record_state_transitions(
            self.conn,
            [host],
            [
                regional.AssetRegionalState(
                    host.asset_key,
                    host.asset_type,
                    REGIONAL_STATE_LIKELY,
                    regional.REASON_DIRECT_ENDPOINTS,
                    "2026-10-06T00:03:00Z",
                    {},
                )
            ],
            {
                host.asset_key: {
                    "healthy": True,
                    "health_state": local_health.STATE_LOCAL_HEALTHY,
                }
            },
        )
        self.assertEqual(len(created), 1)
        digest = obs.render_alert_digest(created)

        self.assertIn("VLESS Reality", digest)
        self.assertNotIn("{USERNAME}", digest)
        self.assertNotIn("{PROTOCOL}", digest)
        self.assertNotIn("{TRANSPORT}", digest)


class V122ANavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_marzban_monitor_is_not_visible_on_admin_home(self):
        region = self._region("async def show_main_menu", "async def cmd_start")
        self.assertNotIn(
            "['🛡 بررسی فیلترینگ', '🛰 بررسی مرزبان']",
            region,
        )
        self.assertIn("['🛡 بررسی فیلترینگ']", region)
        self.assertIn("🧩 برنامه‌ها", region)

    def test_old_marzban_home_text_remains_compatibility_alias(self):
        region = self._region(
            "if text in main_menus and is_auth(context):",
            "elif text in ('🛠 V2Ray / Marzban'",
        )
        self.assertIn("elif text == '🛰 بررسی مرزبان'", region)
        self.assertIn("await _render_marzban_monitor_panel(update.message)", region)

    def test_programs_monitor_has_four_read_only_drilldowns(self):
        region = self._region(
            "async def _render_marzban_monitor_panel",
            "async def cmd_marzban_monitor",
        )
        for callback in (
            "apps_mzm_nodes",
            "apps_mzm_hosts",
            "apps_mzm_regional",
            "apps_mzm_events",
        ):
            self.assertIn(callback, region)
        self.assertIn("↩️ برنامه‌ها", region)
        self.assertIn("↩️ نمای کلی", region)


if __name__ == "__main__":
    unittest.main()
