"""Legacy Core migration checks; shell fault tests never call real host services."""
import base64
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def runtime_fixture(stage, missing=None):
    """A bot import chain covering both lost packages; its body must never run."""
    stage.mkdir(parents=True, exist_ok=True)
    for package in ("ops", "server_migration"):
        folder = stage / package
        folder.mkdir()
        (folder / "__init__.py").write_text("# package fixture\n")
        (folder / "runtime_fixture.py").write_text("VALUE = 1\n")
    (stage / "runtime_helper.py").write_text(
        "from server_migration.runtime_fixture import VALUE\n"
        "from ops.runtime_fixture import VALUE as OTHER\n")
    (stage / "bot_final_v49-2.py").write_text(
        "from runtime_helper import VALUE, OTHER\n"
        "raise RuntimeError('BOT_BODY_MUST_NOT_RUN')\n")
    shutil.copy2(ROOT / "bot_import_preflight.py", stage / "bot_import_preflight.py")
    (stage / "02_recreate_ssh_users.py").write_text("# fixture\n")
    (stage / "fixture.sh").write_text("#!/bin/bash\nexit 0\n")
    (stage / "requirements.txt").write_text("# offline fixture\n")
    if missing:
        shutil.rmtree(stage / missing)


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

    def test_python_preflight_prepares_source_builds_and_blocks_failed_preparation(self):
        start = self.core.index("# --clear is intentional:")
        finish = self.core.index('\necho "   ✅ Python', start)
        preflight = self.core[start:finish].replace(
            "/root/venv/bin/python3", "venv_python").replace(
            "/root/nvlbot_standby/.nvl_promotion_main", '"$TEST_MAIN"').replace(
            "/root/nvlbot_standby", '"$TEST_STATE"')
        for failure in ("none", "apt", "pip", "compile", "ops", "server_migration"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                trace = Path(tmp) / "trace"
                marker = Path(tmp) / "main"
                runtime_fixture(Path(tmp), failure if failure in ("ops", "server_migration") else None)
                env = dict(os.environ, TRACE=str(trace), TEST_STATE=tmp,
                           TEST_MAIN=str(marker), FAIL_STAGE=failure,
                           TEST_PYTHON=sys.executable, PYTHONPATH="")
                harness = r'''
set -u
apt-get() {
    printf 'apt-get %s\n' "$*" >> "$TRACE"
    [ "$FAIL_STAGE" != apt ] || return 13
    for package in "$@"; do
        case "$package" in
            build-essential) touch "$TEST_STATE/compiler" ;;
            python3-dev) touch "$TEST_STATE/headers" ;;
        esac
    done
}
python3() { printf 'python3 %s\n' "$*" >> "$TRACE"; }
venv_python() {
    printf 'venv_python %s\n' "$*" >> "$TRACE"
    if [ "$1 $2 $3" = '-m pip install' ]; then
        [ -f "$TEST_STATE/compiler" ] && [ -f "$TEST_STATE/headers" ] || return 21
        [ "$FAIL_STAGE" != pip ] || return 22
    elif [ "$1 $2" = '-m py_compile' ]; then
        [ "$FAIL_STAGE" != compile ] || return 23
    elif [ "$1" = "$TEST_STATE/bot_import_preflight.py" ]; then
        "$TEST_PYTHON" "$@"
    fi
}
export -f apt-get python3 venv_python
ssh() { bash -c "${!#}"; }
SSH_OPTS=()
TARGET_EDGE=192.0.2.2
'''
                result = subprocess.run(
                    ["bash", "-c", harness + preflight + '\necho PREFLIGHT_ACCEPTED\n'],
                    env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if failure == "none" else 1,
                                 result.stdout + result.stderr)
                self.assertEqual(marker.exists(), failure == "none")
                self.assertEqual("PREFLIGHT_ACCEPTED" in result.stdout, failure == "none")
                if failure == "none":
                    calls = trace.read_text()
                    self.assertLess(calls.index("apt-get install"),
                                    calls.index("venv_python -m pip install"))

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

    def test_destination_installs_importable_staged_package_and_rejects_missing_package(self):
        start = self.promote.index('STANDBY_DIR="/root/nvlbot_standby"')
        finish = self.promote.index("# Always prefer the service unit", start)
        for missing in ("ops", "server_migration", None):
            with self.subTest(missing_package=missing), tempfile.TemporaryDirectory() as tmp:
                stage, dest = Path(tmp) / "stage", Path(tmp) / "destination"
                runtime_fixture(stage, missing)
                (dest / "venv/bin").mkdir(parents=True)
                (dest / "venv/bin/python3").symlink_to(sys.executable)
                (stage / ".nvl_promotion_main").write_text("bot_final_v49-2.py\n")
                body = self.promote[start:finish].replace("/root/nvlbot_standby", str(stage))
                result = subprocess.run(
                    ["bash", "-ec", 'systemctl() { :; }; BOT_DIR="$TEST_DEST";\n' + body],
                    env=dict(os.environ, TEST_DEST=str(dest), PYTHONPATH=""), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if missing is None else 1,
                                 result.stdout + result.stderr)
                if missing is None:
                    for name in ("runtime_helper.py", "ops/runtime_fixture.py", "server_migration/runtime_fixture.py", "fixture.sh"):
                        self.assertTrue((dest / name).is_file(), name)
                    self.assertIn("BOT_IMPORTS_OK=", result.stdout)

    def test_bot_import_checker_never_runs_application_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            runtime_fixture(stage)
            # Invoke the checker from outside the bundle to test import isolation.
            result = subprocess.run(
                [sys.executable, str(ROOT / "bot_import_preflight.py"), str(stage / "bot_final_v49-2.py")],
                env=dict(os.environ, PYTHONPATH=""), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("BOT_IMPORTS_OK=1", result.stdout)

    def test_old_stage_is_preserved_but_cannot_supply_missing_modules(self):
        start = self.core.index("# Preserve the previous stage")
        finish = self.core.index("if ! rsync", start)
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            (stage / "ops").mkdir(parents=True)
            (stage / "ops/stale.py").write_text("# must not mask an omitted package\n")
            body = self.core[start:finish].replace("/root/nvlbot_standby", str(stage)).replace(
                "/root/nvlbot-stage-backup-XXXXXX", str(Path(tmp) / "backup-XXXXXX"))
            harness = 'SSH_OPTS=(); TARGET_EDGE=fixture; ssh() { bash -c "${!#}"; };\n'
            subprocess.run(["bash", "-ec", harness + body], check=True)
            self.assertEqual(list(stage.iterdir()), [])
            self.assertEqual(len(list(Path(tmp).glob("backup-*/code/ops/stale.py"))), 1)

    @unittest.skipUnless(shutil.which("rsync"), "rsync unavailable")
    def test_transferred_bundle_contains_python_packages_but_no_runtime_secrets(self):
        start = self.core.index("if ! rsync -az --prune-empty-dirs")
        finish = self.core.index("# --clear is intentional", start)
        with tempfile.TemporaryDirectory() as tmp:
            source, stage = Path(tmp) / "source", Path(tmp) / "stage"
            runtime_fixture(source)
            stage.mkdir()
            for name in (".env", "master_bot.db", "ops/private.json", "ops/key.pem"):
                (source / name).write_text("private fixture\n")
            body = self.core[start:finish].replace(
                '"root@${TARGET_EDGE}:/root/nvlbot_standby/"', '"$TEST_STAGE/"').replace("/root/", str(source) + "/")
            harness = 'EDGE_SSH_KEY=unused; EDGE_PORT=22; TARGET_EDGE=fixture;\n'
            subprocess.run(["bash", "-ec", harness + body],
                           env=dict(os.environ, TEST_STAGE=str(stage)), check=True)
            for name in ("runtime_helper.py", "ops/runtime_fixture.py", "server_migration/runtime_fixture.py"):
                self.assertTrue((stage / name).is_file(), name)
            for name in (".env", "master_bot.db", "ops/private.json", "ops/key.pem"):
                self.assertFalse((stage / name).exists(), name)

    def test_snapshot_streams_checked_target_code_and_recovers_failed_transfer(self):
        start = self.core.index("# Archive the exact code-only stage")
        finish = self.core.index('\necho "   ✅ تمام اسکریپت', start)
        for failure in (False, True):
            with self.subTest(ssh_failure=failure), tempfile.TemporaryDirectory() as tmp:
                remote_stage = Path(tmp) / "remote-stage"
                runtime_fixture(remote_stage)
                export = Path(tmp) / "export"
                export.mkdir()
                trace = Path(tmp) / "trace"
                body = self.core[start:finish].replace("/root/nvlbot_standby", str(remote_stage))
                harness = r'''
set -u
SSH_OPTS=()
TARGET_EDGE=fixture
ssh() {
    printf 'REMOTE_SNAPSHOT\n' >> "$TRACE"
    if [ "$FAIL_SSH" = 1 ]; then printf partial; return 22; fi
    bash -c "${!#}"
}
rollback_start_nvlbot() { printf 'SOURCE_RECOVERY\n' >> "$TRACE"; }
'''
                result = subprocess.run(
                    ["bash", "-c", harness + body + '\necho SNAPSHOT_ACCEPTED\n'],
                    env=dict(os.environ, EXPORT_DIR=str(export), TRACE=str(trace),
                             FAIL_SSH=str(int(failure))), capture_output=True, text=True)
                self.assertEqual(result.returncode, 1 if failure else 0,
                                 result.stdout + result.stderr)
                self.assertIn("REMOTE_SNAPSHOT", trace.read_text())
                self.assertEqual("SOURCE_RECOVERY" in trace.read_text(), failure)
                self.assertEqual("SNAPSHOT_ACCEPTED" in result.stdout, not failure)
                if not failure:
                    with tarfile.open(export / "root_full_snapshot.tar.gz") as archive:
                        for name in ("./ops/runtime_fixture.py", "./server_migration/runtime_fixture.py",
                                     "./runtime_helper.py", "./bot_import_preflight.py"):
                            self.assertIn(name, archive.getnames())

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

    @staticmethod
    def _function(source, name):
        return name + "() {" + source.split(name + "() {", 1)[1].split("\n}", 1)[0] + "\n}\n"

    def test_prepare_preserves_padded_wireguard_key(self):
        # Run the actual SSH/awk line, substituting stdin for the remote file.
        line = next(line for line in self.demote.splitlines()
                    if '"${SSH[@]}"' in line and '> "$STATE/private"' in line)
        key = base64.b64encode(bytes(range(32))).decode("ascii")
        for assignment in (f"PrivateKey = {key}\n", f"  PrivateKey\t=\t{key}\r\n"):
            with self.subTest(assignment=assignment[:16]), tempfile.TemporaryDirectory() as tmp:
                harness = r'''
set -euo pipefail
STATE="$1"
remote() { bash -c "${1//\/etc\/wireguard\/wg0.conf/\/dev\/stdin}"; }
SSH=(remote)
'''
                subprocess.run(["bash", "-c", harness + line, "test", tmp],
                               input=assignment, text=True, check=True, capture_output=True)
                saved = (Path(tmp) / "private").read_text().strip()
                self.assertEqual(saved, key)
                self.assertEqual(len(base64.b64decode(saved, validate=True)), 32)

    def test_ssh_admin_check_accepts_existing_localport_match(self):
        sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)
        if not sshd:
            self.skipTest("OpenSSH server is unavailable")
        # -G prints the same effective config before host-key/privsep checks;
        # combined with the script's -T, this needs no host keys or daemon.
        probe = subprocess.run([sshd, "-G", "-f", "/dev/null"], capture_output=True, text=True)
        if "unknown option" in probe.stderr or "illegal option" in probe.stderr:
            self.skipTest("OpenSSH lacks configuration-only -G mode")
        start = self.promote.index("if ! sshd -T")
        check = self.promote[start:].split("\nfi", 1)[0] + "\nfi\n"
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "sshd_config"
            conf.write_text("Port 22\nMatch LocalPort 22\n    AllowUsers root\nMatch all\n")
            harness = 'sshd() { "$TEST_SSHD" -G -f "$TEST_CONFIG" "$@"; }\nset -o pipefail\n'
            env = dict(os.environ, TEST_SSHD=sshd, TEST_CONFIG=str(conf))
            result = subprocess.run(["bash", "-c", harness + check], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_target_exit_cleanup_and_source_restart_order(self):
        rollback = self._function(self.promote, "rollback_on_failure")
        cases = (
            # changed, success, stopped_old, bot_active, wg_active, wg_interface
            (1, 0, 0, 0, 0, 0),  # wrapper stopped old Core; only clean target
            (1, 0, 1, 0, 0, 0),  # standalone flow may resume source after cleanup
            (1, 0, 1, 1, 0, 0),  # incomplete bot shutdown: do not revive source
            (1, 0, 1, 0, 1, 0),  # incomplete WG service shutdown
            (1, 0, 1, 0, 0, 1),  # raw WG identity survives inactive service
            (0, 0, 0, 0, 0, 0),  # validation failed before target mutations
            (1, 1, 0, 1, 1, 1),  # successful promotion must keep target alive
        )
        for changed, success, stopped_old, bot, service, interface in cases:
            with self.subTest(case=(changed, success, stopped_old, bot, service, interface)), tempfile.TemporaryDirectory() as tmp:
                trace = Path(tmp) / "trace"
                env = dict(os.environ, TRACE=str(trace), BOT_ACTIVE=str(bot),
                           WG_ACTIVE=str(service), WG_INTERFACE=str(interface))
                harness = '''
set -u
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$TRACE"
    if [ "$1" = is-active ]; then
        if [ "$3" = nvlbot ]; then [ "$BOT_ACTIVE" = 1 ]; else [ "$WG_ACTIVE" = 1 ]; fi
    else return 0; fi
}
wg() { printf 'wg %s\n' "$*" >> "$TRACE"; [ "$WG_INTERFACE" = 1 ]; }
ssh() { printf 'ssh %s\n' "$*" >> "$TRACE"; return 0; }
OLD_CORE_IP=192.0.2.1
CUSTOMER_SSH_PORT=8443
'''
                harness += f"TARGET_ROLE_CHANGED={changed}; PROMOTE_SUCCESS={success}; OLD_CORE_STOPPED_BY_US={stopped_old}\n"
                harness += rollback + "trap rollback_on_failure EXIT\nexit 17\n"
                result = subprocess.run(["bash", "-c", harness], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
                calls = trace.read_text() if trace.exists() else ""
                if success or not changed:
                    self.assertEqual(calls, "")
                else:
                    self.assertIn("systemctl disable --now nvlbot", calls)
                    self.assertIn("systemctl disable --now wg-quick@wg0", calls)
                    should_restart = stopped_old and not (bot or service or interface)
                    self.assertEqual("ssh " in calls, bool(should_restart))
                    if should_restart:
                        self.assertLess(calls.index("wg show wg0"), calls.index("ssh "))

    def test_source_rollback_requires_target_bot_and_wg_to_be_down(self):
        rollback = self._function(self.core, "rollback_start_nvlbot")
        for bot, interface in ((0, 0), (1, 0), (0, 1)):
            with self.subTest(bot=bot, interface=interface), tempfile.TemporaryDirectory() as tmp:
                trace = Path(tmp) / "trace"
                env = dict(os.environ, TRACE=str(trace), BOT_ACTIVE=str(bot), WG_INTERFACE=str(interface))
                harness = '''
set -u
systemctl() {
    printf '%s systemctl %s\n' "${SIDE:-source}" "$*" >> "$TRACE"
    if [ "$1" = is-active ]; then [ "$3" = nvlbot ] && [ "$BOT_ACTIVE" = 1 ]; else return 0; fi
}
wg() { [ "$WG_INTERFACE" = 1 ]; }
ssh() { SIDE=target bash -c "${!#}"; }
export -f systemctl wg
SSH_OPTS=()
TARGET_EDGE=192.0.2.2
SOURCE_WG_STOPPED=1
'''
                result = subprocess.run(["bash", "-c", harness + rollback + "rollback_start_nvlbot\n"],
                                        env=env, capture_output=True, text=True)
                calls = trace.read_text()
                should_restart = not (bot or interface)
                self.assertEqual(result.returncode, 0 if should_restart else 1, result.stdout + result.stderr)
                self.assertEqual("source systemctl start nvlbot" in calls, should_restart)

    def test_failed_stop_restores_source_only_if_it_became_inactive(self):
        start = self.core.index("if ! systemctl stop nvlbot ||")
        stop_check = self.core[start:self.core.index('\necho "   ✅ توقف nvlbot', start)]
        rollback = self._function(self.core, "rollback_start_nvlbot")
        for stopped in (0, 1):
            with self.subTest(stopped=stopped), tempfile.TemporaryDirectory() as tmp:
                trace = Path(tmp) / "trace"
                env = dict(os.environ, TRACE=str(trace), STOPPED=str(stopped))
                harness = '''
set -u
active=1
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$TRACE"
    case "$1 $2" in
        'stop nvlbot') [ "$STOPPED" = 1 ] && active=0; return 1 ;;
        'is-active --quiet') [ "$active" = 1 ] ;;
        *) return 0 ;;
    esac
}
ssh() { return 1; }
SSH_OPTS=()
TARGET_EDGE=192.0.2.2
SOURCE_WG_STOPPED=0
'''
                result = subprocess.run(["bash", "-c", harness + rollback + stop_check],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual("systemctl start nvlbot" in trace.read_text(), bool(stopped))

    def test_remote_failure_reaches_source_recovery_even_with_errexit(self):
        start = self.core.index('echo "🔹 ۶) اجرای remote')
        finish = self.core.index('echo "🔹 ۷) تأیید', start)
        harness = '''
set -euo pipefail
SSH_OPTS=()
TARGET_EDGE=192.0.2.2
SELF_IP=192.0.2.1
REMOTE_MIGRATION_DIR=/unused
CUSTOMER_SSH_PORT=8443
ssh() { return 27; }
rollback_start_nvlbot() { printf 'SOURCE_RECOVERY_CALLED\n'; }
'''
        result = subprocess.run(["bash", "-c", harness + self.core[start:finish]],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 27)
        self.assertIn("SOURCE_RECOVERY_CALLED", result.stdout)


if __name__ == "__main__":
    unittest.main()
