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

    def test_all_migration_scripts_parse(self):
        for name in (
            "core_side_failover.sh", "promote_edge_to_core.sh",
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
        stop = self.core.index("if ! systemctl stop nvlbot || systemctl is-active --quiet nvlbot; then")
        self.assertLess(marker, stop)
        self.assertIn("python3 -m venv --clear /root/venv", self.core)
        self.assertIn("python3 -m pip --version", self.core)
        self.assertIn("demote_core_to_edge.sh --prepare", self.core)
        self.assertIn("systemctl is-active --quiet nvlbot", self.core)
        self.assertNotIn("با cp خام کپی شد", self.core)

    def test_promote_preserves_ssh_admin_port_and_validates_config(self):
        # Port 22 must be explicit, not left to sshd's implicit default:
        # adding a single non-22 Port otherwise removes that default.
        self.assertIn("Port 22", self.promote)
        self.assertIn('sshd -t', self.promote)
        self.assertIn('sshd -T', self.promote)
        self.assertIn('PROMOTE_POSTCHECK_OK', self.promote)
        self.assertIn('PRAGMA quick_check;', self.promote)
        self.assertIn('wg show wg0 public-key', self.promote)
        self.assertLess(
            self.promote.index("if ! sshd -t; then"),
            self.promote.index("if ! systemctl restart ssh"),
        )
        self.assertLess(
            self.promote.index("mkdir -p /run/sshd"),
            self.promote.index("if ! sshd -t; then"),
        )

    def test_source_frozen_before_copy_and_wg_exclusive_before_promote(self):
        self.assertIn("if ! systemctl stop nvlbot || systemctl is-active --quiet nvlbot; then", self.core)
        self.assertIn("if wg show wg0 >/dev/null 2>&1; then", self.core)
        self.assertLess(
            self.core.index("if ! systemctl stop nvlbot || systemctl is-active --quiet nvlbot; then"),
            self.core.index('sqlite3 "$DB_PATH" ".backup'),
        )
        self.assertLess(
            self.core.index("if wg show wg0 >/dev/null 2>&1; then"),
            self.core.index('PROMOTE_EXIT=$?'),
        )

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
