import io
import json
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from server_migration.final_sync import rewrite_hosts_address
from server_migration.models import CommandResult, ServerCredentials, ServerFacts
from server_migration.phase4 import build_phase4_plan, run_phase4
from server_migration.phase4_cli import main as phase4_cli_main
from server_migration.ssh import SSHConnectionError
from server_migration.phase4_models import (
    PHASE4_MODE_FINALIZE,
    PHASE4_MODE_PLAN,
    Phase4Error,
    Phase4Plan,
    Phase4Policy,
)


JOB_ID = "chg-20261004T174439Z-706f2540"
OLD_IP = "107.189.22.94"
NEW_IP = "107.189.22.229"


def facts(role, host, *, running=False, integrity="ok"):
    return ServerFacts(
        role=role,
        host=host,
        ssh_port=22,
        ssh_user="root",
        ssh_ok=True,
        uid=0,
        os_id="ubuntu",
        os_version="24.04",
        os_pretty_name="Ubuntu 24.04.3 LTS",
        architecture="x86_64",
        primary_ipv4=host,
        memory_mb=961,
        root_free_mb=20000,
        docker_installed=True,
        docker_version="Docker version 29.7.2",
        compose_version="Docker Compose version v5.6.0",
        marzban_compose_file="/opt/marzban/docker-compose.yml",
        marzban_dir="/opt/marzban",
        marzban_env_file="/opt/marzban/.env",
        database_path="/var/lib/marzban/db.sqlite3",
        database_integrity=integrity,
        xray_config_path="/var/lib/marzban/xray_config.json",
        api_port=2053,
        ssl_cert_path="/var/lib/marzban/certs/fullchain.pem",
        ssl_key_path="/var/lib/marzban/certs/key.pem",
        ssl_cert_exists=True,
        ssl_key_exists=True,
        compose_images=("nvl/marzban:xray-26.6.1-compat",),
        local_image_details=(
            "nvl/marzban:xray-26.6.1-compat|"
            "sha256:11578c1c7f4419060d935e35821ff952aefd169f08a48b3905f3afe56cb47915"
            "|amd64|linux",
        ),
        listener_ports=(22,),
        xray_ports=(80, 443, 1080, 5430, 8080, 8443),
        required_tools=("gzip", "python3", "sha256sum", "tar"),
        payload_size_mb=26,
    )


def metadata():
    return {
        "schema_version": 1,
        "job_id": JOB_ID,
        "source": {
            "host": OLD_IP,
            "primary_ipv4": OLD_IP,
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
        },
        "marzban": {
            "compose_file": "/opt/marzban/docker-compose.yml",
            "directory": "/opt/marzban",
            "environment_file": "/opt/marzban/.env",
            "database_path": "/var/lib/marzban/db.sqlite3",
            "xray_config_path": "/var/lib/marzban/xray_config.json",
            "api_port": 2053,
            "ssl_cert_path": "/var/lib/marzban/certs/fullchain.pem",
            "ssl_key_path": "/var/lib/marzban/certs/key.pem",
            "compose_images": ["nvl/marzban:xray-26.6.1-compat"],
            "local_image_details": [
                "nvl/marzban:xray-26.6.1-compat|"
                "sha256:11578c1c7f4419060d935e35821ff952aefd169f08a48b3905f3afe56cb47915"
                "|amd64|linux"
            ],
        },
        "archives": {
            "config_restore_parent": "/opt",
            "config_member_root": "marzban",
            "data_restore_parent": "/var/lib",
            "data_member_root": "marzban",
        },
        "runtime_extras": [],
        "letsencrypt_included": True,
    }


class RecordingExecutor:
    def __init__(self, host=""):
        self.host = host
        self.commands = []
        self.closed = False

    def run(self, command, timeout=None):
        self.commands.append(command)
        return CommandResult(command, 0, "", "")

    def close(self):
        self.closed = True


class RewriteExecutor(RecordingExecutor):
    def run(self, command, timeout=None):
        self.commands.append(command)
        if "UPDATE hosts SET address=?" in command:
            return CommandResult(command, 0, "1\n", "")
        return CommandResult(command, 0, "", "")


class ChangeServerPhase4CliTests(unittest.TestCase):
    @patch("server_migration.phase4_cli._password", return_value="secret")
    @patch(
        "server_migration.phase4_cli.run_phase4",
        side_effect=SSHConnectionError(
            "SSH connection failed for 107.189.22.94:22: TimeoutError: timed out"
        ),
    )
    def test_ssh_failure_is_clean_json_without_traceback(
        self,
        _run,
        _password,
    ):
        argv = [
            "phase4_cli",
            "--source",
            OLD_IP,
            "--destination",
            NEW_IP,
            "--job-id",
            JOB_ID,
            "--plan-only",
        ]
        buffer = io.StringIO()
        with patch.object(sys, "argv", argv), redirect_stderr(buffer):
            code = phase4_cli_main()

        self.assertEqual(code, 4)
        output = buffer.getvalue()
        self.assertNotIn("Traceback", output)
        payload = json.loads(output)
        self.assertEqual(payload["phase"], 4)
        self.assertEqual(payload["status"], "failed")
        self.assertIn("SSH connection failed", payload["error"])


class ChangeServerPhase4SafetyTests(unittest.TestCase):
    def test_rewrite_is_targeted_to_hosts_address_exact_match(self):
        executor = RewriteExecutor()
        changed = rewrite_hosts_address(
            executor,
            database_path="/var/lib/marzban/db.sqlite3",
            old_ip=OLD_IP,
            new_ip=NEW_IP,
        )
        self.assertEqual(changed, 1)
        command = "\n".join(executor.commands)
        self.assertIn("UPDATE hosts SET address=? WHERE address=?", command)
        self.assertNotIn("replace(", command.lower())
        self.assertNotIn("UPDATE users", command)

    @patch("server_migration.phase4.matching_host_rows", return_value=1)
    @patch("server_migration.phase4.database_integrity", return_value="ok")
    @patch("server_migration.phase4._exists")
    @patch("server_migration.phase4.compose_running")
    @patch("server_migration.phase4.verify_incoming_bundle")
    @patch("server_migration.phase4.inspect_server")
    def test_plan_is_non_disruptive_and_blocks_running_destination(
        self,
        inspect_server,
        verify_bundle,
        compose_running,
        exists,
        _integrity,
        _rows,
    ):
        src = facts("source", OLD_IP)
        dst = facts("destination", NEW_IP)
        inspect_server.side_effect = [src, dst]
        verify_bundle.return_value = (
            f"/root/nvl-migrations/{JOB_ID}/incoming",
            metadata(),
            {"bundle.json": "a"},
        )
        compose_running.side_effect = [False, True]
        exists.side_effect = [False, False, False]

        source_executor = RecordingExecutor(OLD_IP)
        destination_executor = RecordingExecutor(NEW_IP)
        plan, _meta, _src, _dst = build_phase4_plan(
            source_executor,
            destination_executor,
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            policy=Phase4Policy(mode=PHASE4_MODE_PLAN),
        )

        self.assertFalse(plan.finalization_ready)
        self.assertTrue(plan.destination_running)
        self.assertTrue(
            any("destination Marzban is running" in x for x in plan.blockers)
        )
        self.assertTrue(
            any("RESTORE_COMPLETE" in x for x in plan.blockers)
        )
        joined = "\n".join(
            source_executor.commands + destination_executor.commands
        ).lower()
        self.assertNotIn("docker compose stop", joined)
        self.assertNotIn("docker compose up", joined)
        self.assertNotIn("update hosts", joined)

    @patch("server_migration.phase4.matching_host_rows", return_value=1)
    @patch("server_migration.phase4.database_integrity", return_value="ok")
    @patch("server_migration.phase4._exists")
    @patch("server_migration.phase4.compose_running")
    @patch("server_migration.phase4.verify_incoming_bundle")
    @patch("server_migration.phase4.inspect_server")
    def test_retry_after_cutover_rollback_allows_new_final_sync(
        self,
        inspect_server,
        verify_bundle,
        compose_running,
        exists,
        _integrity,
        _rows,
    ):
        src = facts("source", OLD_IP)
        dst = facts("destination", NEW_IP)
        inspect_server.side_effect = [src, dst]
        verify_bundle.return_value = (
            f"/root/nvl-migrations/{JOB_ID}/incoming",
            metadata(),
            {"bundle.json": "a"},
        )
        compose_running.side_effect = [True, False]
        # Phase 3 complete, prior Phase 4 complete, and verified cutover rollback.
        exists.side_effect = [True, True, True]

        plan, _meta, _src, _dst = build_phase4_plan(
            RecordingExecutor(OLD_IP),
            RecordingExecutor(NEW_IP),
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            policy=Phase4Policy(
                mode=PHASE4_MODE_PLAN,
                retry_after_cutover_rollback=True,
            ),
        )

        self.assertTrue(plan.finalization_ready)
        self.assertEqual(plan.blockers, ())

    @patch("server_migration.phase4.matching_host_rows", return_value=1)
    @patch("server_migration.phase4.database_integrity", return_value="ok")
    @patch("server_migration.phase4._exists")
    @patch("server_migration.phase4.compose_running")
    @patch("server_migration.phase4.verify_incoming_bundle")
    @patch("server_migration.phase4.inspect_server")
    def test_retry_after_cutover_rollback_requires_rollback_marker(
        self,
        inspect_server,
        verify_bundle,
        compose_running,
        exists,
        _integrity,
        _rows,
    ):
        src = facts("source", OLD_IP)
        dst = facts("destination", NEW_IP)
        inspect_server.side_effect = [src, dst]
        verify_bundle.return_value = (
            f"/root/nvl-migrations/{JOB_ID}/incoming",
            metadata(),
            {"bundle.json": "a"},
        )
        compose_running.side_effect = [True, False]
        exists.side_effect = [True, True, False]

        plan, _meta, _src, _dst = build_phase4_plan(
            RecordingExecutor(OLD_IP),
            RecordingExecutor(NEW_IP),
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            policy=Phase4Policy(
                mode=PHASE4_MODE_PLAN,
                retry_after_cutover_rollback=True,
            ),
        )

        self.assertFalse(plan.finalization_ready)
        self.assertTrue(
            any("CUTOVER_ROLLBACK_COMPLETE" in x for x in plan.blockers)
        )

    @patch("server_migration.phase4.build_phase4_plan")
    def test_finalize_requires_exact_confirmation_before_mutation(
        self,
        build_plan,
    ):
        src = facts("source", OLD_IP)
        dst = facts("destination", NEW_IP)
        build_plan.return_value = (
            Phase4Plan(
                job_id=JOB_ID,
                source_host=OLD_IP,
                destination_host=NEW_IP,
                old_ip=OLD_IP,
                new_ip=NEW_IP,
                source_running=True,
                destination_running=False,
                phase3_restore_complete=True,
                source_database_integrity="ok",
                destination_database_integrity="ok",
                matching_host_rows=1,
                finalization_ready=True,
                blockers=(),
            ),
            metadata(),
            src,
            dst,
        )
        executors = {
            OLD_IP: RecordingExecutor(OLD_IP),
            NEW_IP: RecordingExecutor(NEW_IP),
        }

        with self.assertRaises(Phase4Error):
            run_phase4(
                ServerCredentials(OLD_IP, password="a"),
                ServerCredentials(NEW_IP, password="b"),
                job_id=JOB_ID,
                confirmation="wrong",
                policy=Phase4Policy(mode=PHASE4_MODE_FINALIZE),
                executor_factory=lambda c: executors[c.host],
            )

        for executor in executors.values():
            self.assertEqual(executor.commands, [])


class ChangeServerPhase4OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.src = facts("source", OLD_IP)
        self.dst = facts("destination", NEW_IP)
        self.plan = Phase4Plan(
            job_id=JOB_ID,
            source_host=OLD_IP,
            destination_host=NEW_IP,
            old_ip=OLD_IP,
            new_ip=NEW_IP,
            source_running=True,
            destination_running=False,
            phase3_restore_complete=True,
            source_database_integrity="ok",
            destination_database_integrity="ok",
            matching_host_rows=1,
            finalization_ready=True,
            blockers=(),
        )
        self.executors = {
            OLD_IP: RecordingExecutor(OLD_IP),
            NEW_IP: RecordingExecutor(NEW_IP),
        }

    def factory(self, credentials):
        return self.executors[credentials.host]

    @patch("server_migration.phase4.mark_phase4_complete")
    @patch("server_migration.phase4.start_runtime_and_verify", return_value=(True, True, (80, 443, 2053, 8443)))
    @patch("server_migration.phase4.database_integrity", return_value="ok")
    @patch("server_migration.phase4.scan_runtime_configs_for_old_ip", return_value=())
    @patch("server_migration.phase4.scan_database_for_old_ip", return_value=())
    @patch("server_migration.phase4.rewrite_hosts_address", return_value=1)
    @patch("server_migration.phase4.install_final_database")
    @patch("server_migration.phase4.backup_destination_database", return_value="/root/nvl-migrations/job/final-sync/backup.sqlite3")
    @patch("server_migration.phase4.relay_final_database", return_value="/var/lib/nvl/migrations/job/final.sqlite3")
    @patch("server_migration.phase4.create_final_source_snapshot", return_value="a" * 64)
    @patch("server_migration.phase4.stop_compose")
    @patch("server_migration.phase4.compose_running")
    @patch("server_migration.phase4.release_final_sync_lock")
    @patch("server_migration.phase4.acquire_final_sync_lock")
    @patch("server_migration.phase4.new_attempt_id", return_value="attempt-deadbeef1234")
    @patch("server_migration.phase4.build_phase4_plan")
    def test_successful_finalize_keeps_dns_out_of_scope(
        self,
        build_plan,
        _attempt,
        acquire_lock,
        release_lock,
        compose_running,
        stop_compose,
        snapshot,
        relay,
        backup,
        install_db,
        rewrite,
        scan_db,
        scan_configs,
        integrity,
        start_runtime,
        marker,
    ):
        build_plan.return_value = (
            self.plan,
            metadata(),
            self.src,
            self.dst,
        )
        # After stop, source must report stopped.
        compose_running.return_value = False

        result = run_phase4(
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            confirmation="FINAL-SYNC",
            policy=Phase4Policy(mode=PHASE4_MODE_FINALIZE),
            executor_factory=self.factory,
        )

        self.assertTrue(result.source_stopped)
        self.assertEqual(result.rewritten_host_rows, 1)
        self.assertTrue(result.destination_started)
        self.assertTrue(result.api_healthy)
        self.assertEqual(acquire_lock.call_count, 2)
        self.assertEqual(release_lock.call_count, 2)
        stop_compose.assert_called_once()
        rewrite.assert_called_once()
        start_runtime.assert_called_once()
        marker.assert_called_once()
        self.assertNotIn("cloudflare", str(result.to_dict()).lower())
        self.assertNotIn("dns", str(result.to_dict()).lower())

    @patch("server_migration.phase4.mark_phase4_complete")
    @patch("server_migration.phase4.start_runtime_and_verify", return_value=(True, True, (80, 443, 2053, 8443)))
    @patch("server_migration.phase4.restore_destination_database")
    @patch("server_migration.phase4.scan_database_for_old_ip", side_effect=Phase4Error("scan failed"))
    @patch("server_migration.phase4.rewrite_hosts_address", return_value=1)
    @patch("server_migration.phase4.install_final_database")
    @patch("server_migration.phase4.backup_destination_database", return_value="/root/nvl-migrations/job/final-sync/backup.sqlite3")
    @patch("server_migration.phase4.relay_final_database", return_value="/var/lib/nvl/migrations/job/final.sqlite3")
    @patch("server_migration.phase4.create_final_source_snapshot", return_value="b" * 64)
    @patch("server_migration.phase4.stop_compose")
    @patch("server_migration.phase4.compose_running", return_value=False)
    @patch("server_migration.phase4.release_final_sync_lock")
    @patch("server_migration.phase4.acquire_final_sync_lock")
    @patch("server_migration.phase4.new_attempt_id", return_value="attempt-deadbeef5678")
    @patch("server_migration.phase4.build_phase4_plan")
    def test_failure_after_db_install_restores_destination_and_source(
        self,
        build_plan,
        _attempt,
        _acquire,
        _release,
        _running,
        _stop,
        _snapshot,
        _relay,
        _backup,
        _install,
        _rewrite,
        _scan,
        restore_db,
        start_runtime,
        marker,
    ):
        build_plan.return_value = (
            self.plan,
            metadata(),
            self.src,
            self.dst,
        )

        with self.assertRaises(Phase4Error) as ctx:
            run_phase4(
                ServerCredentials(OLD_IP, password="a"),
                ServerCredentials(NEW_IP, password="b"),
                job_id=JOB_ID,
                confirmation="FINAL-SYNC",
                policy=Phase4Policy(mode=PHASE4_MODE_FINALIZE),
                executor_factory=self.factory,
            )

        self.assertIn("source service recovered", str(ctx.exception))
        restore_db.assert_called_once()
        # Destination start was never reached; this invocation is source recovery.
        start_runtime.assert_called_once()
        marker.assert_called_once()


if __name__ == "__main__":
    unittest.main()
