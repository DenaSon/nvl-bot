"""Static regression checks for the legacy Telegram Core -> Edge migration."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TelegramCoreMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        cls.core = (ROOT / "core_side_failover.sh").read_text(encoding="utf-8")
        cls.promote = (ROOT / "promote_edge_to_core.sh").read_text(encoding="utf-8")
        cls.demote = (ROOT / "demote_core_to_edge.sh").read_text(encoding="utf-8")
        cls.sync = (ROOT / "update_all_edges_endpoint.sh").read_text(encoding="utf-8")
        cls.edge = (ROOT / "setup_edge_relay.sh").read_text(encoding="utf-8")

    def test_legacy_edge_installer_never_uses_customer_port_as_management(self):
        installer = self.bot.split("def _provision_new_edge_sync(")[1].split(
            "async def _provision_new_edge(")[0]
        self.assertIn("candidate_ports = [22]", installer)
        self.assertNotIn("candidate_ports = [22] +", installer)
        self.assertIn("await asyncio.to_thread(_db_set_host_admin_ssh_port, edge_ip, 22)", self.bot)
        self.assertIn("await asyncio.to_thread(_db_set_host_service_port, edge_ip, int(customer_port))", self.bot)

    def test_installer_is_fail_closed_before_active_host_pool(self):
        source = self.bot.split("def _provision_new_edge_sync(")[1].split(
            "async def _provision_new_edge(")[0]
        self.assertIn("stdout.channel.recv_exit_status()", source)
        self.assertIn("if exit_status != 0:", source)
        self.assertIn("if not ok_key:", source)
        self.assertIn("if not tunnel_ok:", source)
        self.assertIn("wg0", source)
        self.assertIn("latest-handshakes", source)
        self.assertIn("original_wg_config", source)
        self.assertIn('if f"# {edge_name}" in original_wg_config', source)
        self.assertLess(source.index("if not tunnel_ok:"), source.index('return True, "", {'))
        pool_region = self.bot.split("async def _provision_new_edge(")[1].split(
            "# پایان بخش «افزودن خودکار Edge جدید»")[0]
        self.assertLess(pool_region.index("if not ok:"), pool_region.index(
            "await asyncio.to_thread(_db_add_host_pool, edge_ip)"))

    def test_legacy_relay_nat_preserves_management_and_is_persistent(self):
        self.assertIn('[[ "$CUSTOMER_SSH_PORT" != 22', self.edge)
        self.assertIn('-m addrtype --dst-type LOCAL', self.edge)
        self.assertIn('iptables -t nat -C POSTROUTING -o wg0 -d 10.77.0.1', self.edge)
        self.assertIn('iptables -C FORWARD -d 10.77.0.1', self.edge)
        self.assertNotIn('iptables -t nat -A POSTROUTING -j MASQUERADE', self.edge)
        self.assertIn('netfilter-persistent save >/dev/null ||', self.edge)

    def test_telegram_edge_to_core_navigation_rechecks_readiness(self):
        self.assertIn('callback_data=f"srv_ready_{edge_ip}"', self.bot)
        self.assertIn('callback_data=f"srv_ready_{host}"', self.bot)
        self.assertIn('elif d.startswith("srv_ready_") and role == \'admin\':', self.bot)
        self.assertIn('async def _legacy_edge_promotion_ready(', self.bot)
        self.assertIn('_probe_wireguard_edge_sync, host', self.bot)
        self.assertIn('if wg.get("wg_peer_ok") is not True', self.bot)
        self.assertIn('iptables -t nat -S PREROUTING', self.bot)
        self.assertIn('iptables -t nat -S POSTROUTING', self.bot)
        self.assertIn('iptables -S FORWARD', self.bot)
        self.assertIn('ready, detail = await _legacy_edge_promotion_ready(target_ip)', self.bot)
        self.assertIn('ready, detail = await _legacy_edge_promotion_ready(target_ip, int(cust_port))', self.bot)

    def test_promoted_core_database_and_dns_finish_are_honest(self):
        self.assertIn("CORE_DB_OK", self.promote)
        self.assertIn("DB_CORE_POOL=", self.promote)
        self.assertIn("DNS_UNCHANGED", self.demote)
        self.assertIn("MIGRATION_COMPLETE", self.demote)

    def test_all_migration_scripts_parse(self):
        for name in (
            "core_side_failover.sh", "promote_edge_to_core.sh", "setup_edge_relay.sh",
            "demote_core_to_edge.sh", "update_edge_endpoint.sh",
            "update_all_edges_endpoint.sh",
        ):
            with self.subTest(script=name):
                subprocess.run(["bash", "-n", str(ROOT / name)], check=True)

    def test_telegram_confirms_before_launch(self):
        self.assertIn("srv_promote_confirm", self.bot)
        self.assertIn("SRV_PROMOTE_AWAIT_CONFIRM", self.bot)
        self.assertIn("systemd-run", self.bot)
        self.assertIn("ok, detail, kind = await run_cmd(", self.bot)
        self.assertIn("demote_core_to_edge.sh", self.bot)
        handler = self.bot.split("# Promote: explicit confirmation")[1].split(
            "# 📉 ویزارد Demote")[0]
        self.assertNotIn("root_pass", handler)
        self.assertNotIn("SRV_PROMOTE_GOST_PORTS", handler)

    def test_final_confirm_callback_is_not_shadowed_by_generic_promote_route(self):
        generic = 'elif d.startswith("srv_promote_") and d != "srv_promote_confirm" and role == \'admin\':'
        confirmed = 'elif d == "srv_promote_confirm" and role == \'admin\':'
        self.assertIn(generic, self.bot)
        self.assertIn(confirmed, self.bot)
        self.assertLess(self.bot.index(generic), self.bot.index(confirmed))
        self.assertIn('context.user_data.get(\'state\') != \'SRV_PROMOTE_AWAIT_CONFIRM\'', self.bot)

    def test_preflight_is_before_stopping_source(self):
        marker = self.core.index("۲.۶) انتقال نسخه دقیق")
        stop = self.core.index("systemctl stop nvlbot 2>/dev/null || true")
        self.assertLess(marker, stop)
        self.assertIn("python3 -m venv --clear /root/venv", self.core)
        self.assertIn("python3 -m pip --version", self.core)
        self.assertIn("demote_core_to_edge.sh --prepare", self.core)
        self.assertIn("systemctl is-active --quiet nvlbot", self.core)
        self.assertNotIn("با cp خام کپی شد", self.core)

    def test_promote_uses_pinned_main_and_existing_venv(self):
        self.assertIn(".nvl_promotion_main", self.promote)
        self.assertIn("-m pip --version", self.promote)
        self.assertNotIn('cp -r "${STANDBY_DIR}/venv"', self.promote)
        self.assertNotIn("find \"$STANDBY_DIR\" -maxdepth", self.promote)
        self.assertIn("systemctl is-active --quiet nvlbot", self.promote)
        self.assertIn("PROMOTE_SUCCESS=1", self.promote)

    def test_demote_uses_retired_edge_identity_and_nat(self):
        self.assertIn("PREPARE_OK", self.demote)
        self.assertIn("core_pub", self.demote)
        self.assertIn("net.ipv4.ip_forward=1", self.demote)
        self.assertIn("DNAT --to-destination", self.demote)
        self.assertIn("MIGRATION_COMPLETE", self.demote)
        self.assertIn('systemctl disable --now nvlbot', self.demote)

    def test_private_runtime_and_systemd_dropins_restored_before_bot_start(self):
        self.assertIn('nvlbot_etc.tar.gz', self.core)
        self.assertIn('nvlbot_dropins.tar.gz', self.core)
        self.assertIn('nvlbot_etc.tar.gz', self.promote)
        self.assertIn('nvlbot_dropins.tar.gz', self.promote)
        self.assertIn('chmod 600 /etc/nvlbot/nvlbot.env', self.promote)
        self.assertLess(
            self.promote.index('tar -xzf "${MIGRATION_DIR}/nvlbot_etc.tar.gz"'),
            self.promote.index('systemctl enable --now nvlbot'),
        )
        self.assertIn('REQUIRED_ENV_FILE=', self.promote)

    def test_endpoint_propagation_fails_on_unreachable_edges(self):
        self.assertIn('[ "$FAIL" -eq 0 ]', self.sync)


if __name__ == "__main__":
    unittest.main()
