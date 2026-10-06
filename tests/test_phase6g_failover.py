import pathlib
import sqlite3
import tempfile
import unittest

import promote_standby_for_filtered_edge as standby_helper
from safe_failover import (
    FailoverValidationError,
    RebuildSummary,
    is_transparent_dns_handoff_safe,
    parse_helper_summary,
    validate_complete_rebuild,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
HELPER_PATH = ROOT / "promote_standby_for_filtered_edge.py"


class Phase6GPureValidationTests(unittest.TestCase):
    def test_parse_helper_uses_final_json_line(self):
        summary = parse_helper_summary(
            "human log\n"
            '{"ok": true, "source_host": "1.1.1.1", "target_host": "2.2.2.2", '
            '"requested": 2, "rebuilt": 2, "failed": 0, '
            '"rebuilt_usernames": ["a", "b"], "failed_usernames": [], '
            '"db_committed": false}\n'
        )
        self.assertTrue(summary.ok)
        self.assertEqual(summary.rebuilt_usernames, ("a", "b"))

    def test_complete_rebuild_requires_exact_username_set(self):
        summary = RebuildSummary(
            source_host="1.1.1.1",
            target_host="2.2.2.2",
            requested=2,
            rebuilt=2,
            failed=0,
            rebuilt_usernames=("a", "b"),
            failed_usernames=(),
            db_committed=False,
            ok=True,
        )
        self.assertIs(
            validate_complete_rebuild(
                summary,
                source_host="1.1.1.1",
                target_host="2.2.2.2",
                expected_usernames=["b", "a"],
            ),
            summary,
        )

    def test_complete_rebuild_rejects_partial_or_wrong_users(self):
        summary = RebuildSummary(
            source_host="1.1.1.1",
            target_host="2.2.2.2",
            requested=2,
            rebuilt=1,
            failed=1,
            rebuilt_usernames=("a",),
            failed_usernames=("b",),
            db_committed=False,
            ok=False,
        )
        with self.assertRaises(FailoverValidationError):
            validate_complete_rebuild(
                summary,
                source_host="1.1.1.1",
                target_host="2.2.2.2",
                expected_usernames=["a", "b"],
            )

    def test_complete_rebuild_rejects_helper_db_mutation(self):
        summary = RebuildSummary(
            source_host="1.1.1.1",
            target_host="2.2.2.2",
            requested=1,
            rebuilt=1,
            failed=0,
            rebuilt_usernames=("a",),
            failed_usernames=(),
            db_committed=True,
            ok=True,
        )
        with self.assertRaises(FailoverValidationError):
            validate_complete_rebuild(
                summary,
                source_host="1.1.1.1",
                target_host="2.2.2.2",
                expected_usernames=["a"],
            )

    def test_transparent_handoff_allows_source_or_core_only(self):
        ok, reason = is_transparent_dns_handoff_safe(
            cloudflare_configured=True,
            dns_current_ip="1.1.1.1",
            source_host="1.1.1.1",
            source_service_port=443,
            target_service_port=443,
            core_fallback_ip="9.9.9.9",
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

        ok, _ = is_transparent_dns_handoff_safe(
            cloudflare_configured=True,
            dns_current_ip="9.9.9.9",
            source_host="1.1.1.1",
            source_service_port=443,
            target_service_port=443,
            core_fallback_ip="9.9.9.9",
        )
        self.assertTrue(ok)

        ok, reason = is_transparent_dns_handoff_safe(
            cloudflare_configured=True,
            dns_current_ip="8.8.8.8",
            source_host="1.1.1.1",
            source_service_port=443,
            target_service_port=443,
            core_fallback_ip="9.9.9.9",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "DNS_NOT_POINTING_TO_SOURCE_OR_CORE")

    def test_transparent_handoff_rejects_port_mismatch(self):
        ok, reason = is_transparent_dns_handoff_safe(
            cloudflare_configured=True,
            dns_current_ip="1.1.1.1",
            source_host="1.1.1.1",
            source_service_port=443,
            target_service_port=22,
            core_fallback_ip="9.9.9.9",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SERVICE_PORT_MISMATCH")


class Phase6GStandbyHelperTests(unittest.TestCase):
    def _make_db(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        conn = sqlite3.connect(tmp.name)
        conn.execute(
            "CREATE TABLE ssh_accounts ("
            "username TEXT PRIMARY KEY, password TEXT, expire_date TEXT, "
            "host TEXT, status TEXT, service_type TEXT)"
        )
        conn.executemany(
            "INSERT INTO ssh_accounts VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("src_active", "p1", "2026-12-01", "1.1.1.1", "🟢 فعال", "ssh"),
                ("src_inactive", "p2", "2026-12-01", "1.1.1.1", "🔴 غیرفعال", "ssh"),
                ("other_active", "p3", "2026-12-01", "3.3.3.3", "🟢 فعال", "ssh"),
                ("src_v2ray", "p4", "2026-12-01", "1.1.1.1", "🟢 فعال", "v2ray"),
                ("legacy_default", "p5", "2026-12-01", None, "🟢 فعال", "ssh"),
            ],
        )
        conn.commit()
        conn.close()
        return tmp.name

    def test_helper_fetch_is_scoped_to_source_active_ssh(self):
        db = self._make_db()
        rows = standby_helper._fetch_accounts(db, "1.1.1.1", include_inactive=False)
        self.assertEqual(rows, [("src_active", "p1", "2026-12-01")])

    def test_helper_include_inactive_stays_source_and_ssh_scoped(self):
        db = self._make_db()
        rows = standby_helper._fetch_accounts(db, "1.1.1.1", include_inactive=True)
        self.assertEqual(
            {row[0] for row in rows},
            {"src_active", "src_inactive"},
        )


    def test_helper_can_include_legacy_unassigned_default_accounts(self):
        db = self._make_db()
        rows = standby_helper._fetch_accounts(
            db,
            "1.1.1.1",
            include_inactive=False,
            include_unassigned=True,
        )
        self.assertEqual(
            {row[0] for row in rows},
            {"src_active", "legacy_default"},
        )


class Phase6GBotSafetyRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.helper_source = HELPER_PATH.read_text(encoding="utf-8")

    def _region(self, start_marker, end_marker):
        start = self.source.index(start_marker)
        end = self.source.index(end_marker, start)
        return self.source[start:end]

    def test_release_marker_includes_phase6h_on_top_of_phase6g_engine(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B2D-2026-10-06-direct-inbound-profile"',
            self.source,
        )

    def test_failover_operation_schema_and_lock_exist(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS failover_operations", self.source)
        lock_region = self._region(
            "def _db_acquire_failover_lock(",
            "def _db_update_failover_operation(",
        )
        self.assertIn("BEGIN IMMEDIATE", lock_region)
        self.assertIn("FAILOVER_STATUS_ABORTED_STALE", lock_region)
        self.assertIn("FAILOVER_LOCK_STALE_SECONDS", lock_region)

    def test_helper_is_rebuild_only_by_default(self):
        self.assertIn("--commit-db", self.helper_source)
        self.assertIn("if complete_success and args.commit_db", self.helper_source)
        self.assertIn('"db_committed": db_committed', self.helper_source)
        self.assertIn("service_type='ssh'", self.helper_source)

    def test_preflight_requires_same_customer_port_and_core_port_reachability(self):
        region = self._region(
            "async def _safe_manual_failover_preflight(",
            "async def _run_phase6g_rebuild_helper(",
        )
        self.assertIn("SERVICE_PORT_MISMATCH", region)
        self.assertIn("CORE_FALLBACK_SERVICE_DOWN", region)
        self.assertIn("_tcp_health_check(", region)
        self.assertIn("_probe_wireguard_edge_sync", region)
        self.assertIn("TARGET_NOT_STANDBY", region)
        self.assertIn("errors = list(dict.fromkeys(errors))", region)

    def test_preflight_fails_closed_on_global_domain_multi_edge_conflict(self):
        region = self._region(
            "async def _safe_manual_failover_preflight(",
            "async def _run_phase6g_rebuild_helper(",
        )
        self.assertIn("_db_count_other_explicit_active_ssh_hosts", region)
        self.assertIn("GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT", region)

    def test_legacy_unassigned_accounts_follow_default_source_safely(self):
        snapshot = self._region(
            "def _db_get_failover_accounts(",
            "def _db_count_other_explicit_active_ssh_hosts(",
        )
        self.assertIn("(host=? OR host IS NULL OR host='')", snapshot)

        commit = self._region(
            "def _db_commit_failover_account_state(",
            "def _db_rollback_failover_account_state(",
        )
        self.assertIn("(host=? OR host IS NULL OR host='')", commit)

        helper_runner = self._region(
            "async def _run_phase6g_rebuild_helper(",
            "async def _safe_manual_failover(",
        )
        self.assertIn('"--include-unassigned"', helper_runner)

    def test_manual_engine_never_uses_broad_account_move(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertNotIn("_db_set_all_accounts_host", region)
        self.assertIn("_db_commit_failover_account_state", region)
        self.assertIn("_db_rollback_failover_account_state", region)
        self.assertIn("validate_complete_rebuild", region)

    def test_commit_revalidates_exact_source_set_inside_immediate_transaction(self):
        region = self._region(
            "def _db_commit_failover_account_state(",
            "def _db_rollback_failover_account_state(",
        )
        self.assertIn("BEGIN IMMEDIATE", region)
        self.assertIn("SOURCE_ACCOUNT_SET_CHANGED", region)
        self.assertIn("current_usernames", region)
        self.assertIn("expected_usernames", region)

    def test_commit_consumes_standby_role_and_rollback_restores_it_atomically(self):
        commit = self._region(
            "def _db_commit_failover_account_state(",
            "def _db_rollback_failover_account_state(",
        )
        self.assertIn("BEGIN IMMEDIATE", commit)
        self.assertIn("SET is_standby=0", commit)
        self.assertIn("TARGET_STANDBY_STATE_CHANGED", commit)

        rollback = self._region(
            "def _db_rollback_failover_account_state(",
            "def _db_acquire_failover_lock(",
        )
        self.assertIn("BEGIN IMMEDIATE", rollback)
        self.assertIn("SET is_standby=1", rollback)
        self.assertIn("target host could not be restored to standby", rollback)

    def test_ssh_finalize_is_atomic_with_host_and_respects_failover_write_lock(self):
        region = self._region(
            "def _db_finalize_reserved_user(",
            "def _db_finalize_v2ray_user(",
        )
        self.assertIn("BEGIN IMMEDIATE", region)
        self.assertIn("_db_assert_account_write_allowed", region)
        self.assertIn("host=?", region)
        self.assertIn("status='⏳ درحال ساخت'", region)
        self.assertNotIn(
            "await asyncio.to_thread(_db_set_account_host, un, target_host)",
            self.source,
        )

    def test_manual_engine_uses_core_before_final_target_dns(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        core_pos = region.index("_cf_switch_public_domain(core_public_ip")
        db_pos = region.index("_db_commit_failover_account_state")
        target_pos = region.index("_cf_switch_public_domain(target_host")
        self.assertLess(core_pos, db_pos)
        self.assertLess(db_pos, target_pos)

    def test_final_dns_failure_restores_core_before_db_rollback(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertIn("FAILOVER_STATUS_ROLLED_BACK", region)
        self.assertIn("_db_rollback_failover_account_state", region)
        self.assertIn("FINAL_DNS_SWITCH_FAILED", region)
        self.assertIn("FINAL_DNS_FAILED_AND_CORE_RESTORE_FAILED", region)
        self.assertIn("core_restore_ok", region)

    def test_post_handoff_exception_retains_target_state_instead_of_split_brain(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertIn("target_route_active", region)
        self.assertIn("retained_target_state", region)
        self.assertIn('db_state_retained": "target"', region)

    def test_phase6h_keeps_legacy_traffic_signal_notification_only(self):
        legacy_region = self._region(
            "async def _filter_detect_tick(app):",
            "async def _filter_detect_loop(app):",
        )
        self.assertNotIn("_safe_manual_failover", legacy_region)
        self.assertNotIn("_phase6h_auto_failover_tick", legacy_region)

        post_init = self._region(
            "async def _post_init(app):",
            "async def _post_shutdown(app):",
        )
        self.assertNotIn("_db_update_setting, 'auto_failover_mode', '0'", post_init)
        self.assertIn("phase6h_auto_failover_enabled", post_init)
        self.assertIn("Phase6H automatic filtering failover startup state", post_init)

    def test_ui_requires_pick_then_confirm(self):
        for fragment in (
            'callback_data=f"flt_failover_{host}"',
            'd.startswith("flt_failover_pick_")',
            'd.startswith("flt_failover_confirm_")',
            "در حال بررسی ایمنی",
            "✅ تأیید و اجرا",
        ):
            self.assertIn(fragment, self.source)

    def test_legacy_wrapper_requires_explicit_target(self):
        region = self._region(
            "async def _activate_standby_for_filtered_edge",
            "async def _ip_pressure_monitor_tick",
        )
        self.assertIn("MANUAL_TARGET_REQUIRED", region)
        self.assertIn("_safe_manual_failover", region)


if __name__ == "__main__":
    unittest.main()
