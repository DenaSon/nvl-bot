import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from unittest.mock import patch

from server_migration.models import CommandResult, ServerCredentials, ServerFacts
from server_migration.phase5 import run_phase5
from server_migration.phase5_cli import (
    DEFAULT_CLOUDFLARE_TOKEN_ENV,
    main as phase5_cli_main,
)
from server_migration.phase5_models import (
    PHASE5_MODE_CUTOVER,
    PHASE5_MODE_PLAN,
    CloudflareRecordSnapshot,
    Phase5Error,
    Phase5Plan,
    Phase5Policy,
)


JOB_ID = "chg-20261004T183445Z-a741b4ef"
OLD_IP = "107.189.22.229"
NEW_IP = "144.172.116.250"
HOSTNAME = "gate.nvlsup.xyz"
ZONE = "nvlsup.xyz"


def facts(role, host):
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
        database_integrity="ok",
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


def record(content=OLD_IP):
    return CloudflareRecordSnapshot(
        zone_id="zone-1",
        record_id="record-1",
        name=HOSTNAME,
        record_type="A",
        content=content,
        proxied=True,
        ttl=1,
    )


def ready_plan():
    return Phase5Plan(
        job_id=JOB_ID,
        hostname=HOSTNAME,
        zone_name=ZONE,
        old_ip=OLD_IP,
        new_ip=NEW_IP,
        phase4_complete=True,
        source_running=False,
        destination_running=True,
        cloudflare_record=record(),
        destination_api_precheck=True,
        destination_direct_ports=(80, 443, 1080, 5430, 8080, 8443),
        cutover_ready=True,
        blockers=(),
    )


class RecordingExecutor:
    def __init__(self, host):
        self.host = host
        self.commands = []
        self.closed = False

    def run(self, command, timeout=None):
        self.commands.append(command)
        return CommandResult(command, 0, "", "")

    def close(self):
        self.closed = True


class FakeCloudflare:
    def __init__(self, _token="secret"):
        self.current = record()
        self.patches = []

    def resolve_zone_id(self, zone_name):
        return "zone-1"

    def get_a_record(self, *, zone_id, hostname):
        return self.current

    def patch_record_content(self, snapshot, new_ip):
        self.patches.append(new_ip)
        self.current = replace(snapshot, content=new_ip)
        return self.current


class ChangeServerPhase5CliTests(unittest.TestCase):
    @patch("server_migration.phase5_cli.run_phase5")
    @patch(
        "server_migration.phase5_cli._secret",
        side_effect=["source-secret", "destination-secret"],
    )
    def test_cli_uses_default_cloudflare_env_without_token_prompt(
        self,
        secret,
        run,
    ):
        run.return_value = ready_plan()
        argv = [
            "phase5_cli",
            "--source", OLD_IP,
            "--destination", NEW_IP,
            "--job-id", JOB_ID,
            "--hostname", HOSTNAME,
            "--zone", ZONE,
            "--plan-only",
        ]
        stdout = io.StringIO()
        with patch.object(sys, "argv", argv), patch.dict(
            os.environ,
            {DEFAULT_CLOUDFLARE_TOKEN_ENV: "cf-secret"},
            clear=False,
        ), redirect_stdout(stdout):
            code = phase5_cli_main()

        self.assertEqual(code, 0)
        self.assertEqual(secret.call_count, 2)
        labels = [call.args[0] for call in secret.call_args_list]
        self.assertEqual(
            labels,
            ["Source SSH password", "Destination SSH password"],
        )
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["cloudflare_api_token"], "cf-secret")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "completed")

    @patch("server_migration.phase5_cli._secret")
    def test_cli_missing_default_env_fails_before_ssh_prompts(self, secret):
        argv = [
            "phase5_cli",
            "--source", OLD_IP,
            "--destination", NEW_IP,
            "--job-id", JOB_ID,
            "--hostname", HOSTNAME,
            "--zone", ZONE,
            "--plan-only",
        ]
        stderr = io.StringIO()
        with patch.object(sys, "argv", argv), patch.dict(
            os.environ,
            {},
            clear=True,
        ), redirect_stderr(stderr):
            code = phase5_cli_main()

        self.assertEqual(code, 5)
        secret.assert_not_called()
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "failed")
        self.assertIn(DEFAULT_CLOUDFLARE_TOKEN_ENV, payload["error"])

    @patch("server_migration.phase5_cli.run_phase5")
    @patch(
        "server_migration.phase5_cli._secret",
        side_effect=[
            "cf-prompt-secret",
            "source-secret",
            "destination-secret",
        ],
    )
    def test_cli_token_prompt_requires_explicit_flag(self, secret, run):
        run.return_value = ready_plan()
        argv = [
            "phase5_cli",
            "--source", OLD_IP,
            "--destination", NEW_IP,
            "--job-id", JOB_ID,
            "--hostname", HOSTNAME,
            "--zone", ZONE,
            "--plan-only",
            "--prompt-cloudflare-token",
        ]
        with patch.object(sys, "argv", argv), patch.dict(
            os.environ,
            {},
            clear=True,
        ), redirect_stdout(io.StringIO()):
            code = phase5_cli_main()

        self.assertEqual(code, 0)
        labels = [call.args[0] for call in secret.call_args_list]
        self.assertEqual(
            labels,
            [
                "Cloudflare API token",
                "Source SSH password",
                "Destination SSH password",
            ],
        )
        self.assertEqual(
            run.call_args.kwargs["cloudflare_api_token"],
            "cf-prompt-secret",
        )


class ChangeServerPhase5PlanTests(unittest.TestCase):
    @patch("server_migration.phase5.verify_tcp_ports", return_value=())
    @patch("server_migration.phase5.verify_origin_api", return_value=False)
    @patch("server_migration.phase5.compose_running")
    @patch("server_migration.phase5._exists", return_value=False)
    @patch("server_migration.phase5.inspect_server")
    def test_plan_before_phase4_is_read_only_and_blocked(
        self,
        inspect_server,
        _exists,
        compose_running,
        _origin,
        _ports,
    ):
        inspect_server.side_effect = [facts("source", OLD_IP), facts("destination", NEW_IP)]
        compose_running.side_effect = [True, False]
        executors = {
            OLD_IP: RecordingExecutor(OLD_IP),
            NEW_IP: RecordingExecutor(NEW_IP),
        }
        cf = FakeCloudflare()

        result = run_phase5(
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            hostname=HOSTNAME,
            zone_name=ZONE,
            cloudflare_api_token="secret",
            policy=Phase5Policy(mode=PHASE5_MODE_PLAN),
            executor_factory=lambda c: executors[c.host],
            cloudflare_factory=lambda _token: cf,
        )

        self.assertFalse(result.cutover_ready)
        self.assertFalse(result.phase4_complete)
        self.assertTrue(any("FINAL_SYNC_COMPLETE" in x for x in result.blockers))
        self.assertEqual(cf.patches, [])


class ChangeServerPhase5OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.source = facts("source", OLD_IP)
        self.destination = facts("destination", NEW_IP)
        self.executors = {
            OLD_IP: RecordingExecutor(OLD_IP),
            NEW_IP: RecordingExecutor(NEW_IP),
        }

    def factory(self, credentials):
        return self.executors[credentials.host]

    @patch("server_migration.phase5.build_phase5_plan")
    def test_cutover_requires_exact_confirmation_before_mutation(self, build_plan):
        build_plan.return_value = (
            ready_plan(),
            self.source,
            self.destination,
            {"job_id": JOB_ID},
        )
        cf = FakeCloudflare()

        with self.assertRaises(Phase5Error):
            run_phase5(
                ServerCredentials(OLD_IP, password="a"),
                ServerCredentials(NEW_IP, password="b"),
                job_id=JOB_ID,
                hostname=HOSTNAME,
                zone_name=ZONE,
                cloudflare_api_token="secret",
                confirmation="wrong",
                policy=Phase5Policy(mode=PHASE5_MODE_CUTOVER),
                executor_factory=self.factory,
                cloudflare_factory=lambda _token: cf,
            )

        self.assertEqual(cf.patches, [])

    @patch("server_migration.phase5.mark_phase4_complete")
    @patch(
        "server_migration.phase5.verify_tcp_ports",
        return_value=(80, 443, 1080, 5430, 8080, 8443),
    )
    @patch("server_migration.phase5.wait_for_hostname_api", return_value=(True, "HTTP 200"))
    @patch("server_migration.phase5.wait_for_record_content")
    @patch("server_migration.phase5.release_final_sync_lock")
    @patch("server_migration.phase5.acquire_final_sync_lock")
    @patch("server_migration.phase5.build_phase5_plan")
    def test_successful_cutover_updates_only_to_new_ip(
        self,
        build_plan,
        acquire,
        release,
        wait_record,
        wait_api,
        ports,
        marker,
    ):
        build_plan.return_value = (
            ready_plan(),
            self.source,
            self.destination,
            {"job_id": JOB_ID},
        )
        cf = FakeCloudflare()
        wait_record.side_effect = lambda client, **kwargs: replace(
            cf.current, content=kwargs["expected_ip"]
        )

        result = run_phase5(
            ServerCredentials(OLD_IP, password="a"),
            ServerCredentials(NEW_IP, password="b"),
            job_id=JOB_ID,
            hostname=HOSTNAME,
            zone_name=ZONE,
            cloudflare_api_token="secret",
            confirmation="CUTOVER",
            policy=Phase5Policy(mode=PHASE5_MODE_CUTOVER),
            executor_factory=self.factory,
            cloudflare_factory=lambda _token: cf,
        )

        self.assertEqual(cf.patches, [NEW_IP])
        self.assertTrue(result.dns_updated)
        self.assertTrue(result.cloudflare_record_verified)
        self.assertTrue(result.hostname_api_healthy)
        self.assertFalse(result.rollback_performed)
        self.assertEqual(acquire.call_count, 2)
        self.assertEqual(release.call_count, 2)
        marker.assert_called_once()

    @patch("server_migration.phase5.mark_phase4_complete")
    @patch("server_migration.phase5.start_runtime_and_verify", return_value=(True, True, (80, 443, 2053, 8443)))
    @patch("server_migration.phase5.stop_compose")
    @patch("server_migration.phase5.compose_running")
    @patch("server_migration.phase5.wait_for_hostname_api", return_value=(False, "HTTP 522 cf-error-type=52x"))
    @patch("server_migration.phase5.wait_for_record_content")
    @patch("server_migration.phase5.release_final_sync_lock")
    @patch("server_migration.phase5.acquire_final_sync_lock")
    @patch("server_migration.phase5.build_phase5_plan")
    def test_failed_post_cutover_verification_rolls_back(
        self,
        build_plan,
        _acquire,
        _release,
        wait_record,
        _wait_api,
        compose_running,
        stop_compose,
        start_runtime,
        marker,
    ):
        build_plan.return_value = (
            ready_plan(),
            self.source,
            self.destination,
            {"job_id": JOB_ID},
        )
        cf = FakeCloudflare()
        wait_record.side_effect = lambda client, **kwargs: replace(
            cf.current, content=kwargs["expected_ip"]
        )

        calls = {OLD_IP: 0, NEW_IP: 0}

        def running(executor, *, marzban_dir):
            calls[executor.host] += 1
            if executor.host == NEW_IP:
                return calls[NEW_IP] == 1
            if executor.host == OLD_IP:
                return calls[OLD_IP] >= 2
            return False

        compose_running.side_effect = running

        with self.assertRaises(Phase5Error) as ctx:
            run_phase5(
                ServerCredentials(OLD_IP, password="a"),
                ServerCredentials(NEW_IP, password="b"),
                job_id=JOB_ID,
                hostname=HOSTNAME,
                zone_name=ZONE,
                cloudflare_api_token="secret",
                confirmation="CUTOVER",
                policy=Phase5Policy(mode=PHASE5_MODE_CUTOVER),
                executor_factory=self.factory,
                cloudflare_factory=lambda _token: cf,
            )

        self.assertEqual(cf.patches, [NEW_IP, OLD_IP])
        self.assertIn("rollback_record_verified=True", str(ctx.exception))
        stop_compose.assert_called_once()
        start_runtime.assert_called_once()
        marker.assert_called_once()


if __name__ == "__main__":
    unittest.main()
