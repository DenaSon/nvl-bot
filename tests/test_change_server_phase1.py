import unittest

from server_migration.detector import STATIC_READ_ONLY_COMMANDS, assert_read_only_command
from server_migration.models import (
    CHECK_FAIL,
    CHECK_WARN,
    PreflightPolicy,
    ServerCredentials,
    ServerFacts,
)
from server_migration.preflight import evaluate_preflight


TOOLS = ("gzip", "python3", "sha256sum", "tar")


def source_facts(**overrides):
    values = dict(
        role="source",
        host="107.189.22.94",
        ssh_port=22,
        ssh_user="root",
        ssh_ok=True,
        uid=0,
        os_id="ubuntu",
        os_version="24.04",
        os_pretty_name="Ubuntu 24.04.3 LTS",
        architecture="x86_64",
        primary_ipv4="107.189.22.94",
        memory_mb=1024,
        root_free_mb=18000,
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
            "sha256:11578c1c7f44|amd64|linux",
        ),
        listener_ports=(22, 80, 443, 1080, 2053, 5430, 8080, 8443),
        xray_ports=(80, 443, 1080, 5430, 8080, 8443),
        required_tools=TOOLS,
        payload_size_mb=700,
    )
    values.update(overrides)
    return ServerFacts(**values)


def destination_facts(**overrides):
    values = dict(
        role="destination",
        host="107.189.22.229",
        ssh_port=22,
        ssh_user="root",
        ssh_ok=True,
        uid=0,
        os_id="ubuntu",
        os_version="24.04",
        os_pretty_name="Ubuntu 24.04.3 LTS",
        architecture="x86_64",
        primary_ipv4="107.189.22.229",
        memory_mb=961,
        root_free_mb=22000,
        docker_installed=False,
        docker_version="",
        compose_version="",
        marzban_compose_file="",
        marzban_dir="",
        marzban_env_file="",
        database_path="",
        database_integrity="",
        xray_config_path="",
        api_port=None,
        ssl_cert_path="",
        ssl_key_path="",
        ssl_cert_exists=False,
        ssl_key_exists=False,
        compose_images=(),
        local_image_details=(),
        listener_ports=(22,),
        xray_ports=(),
        required_tools=TOOLS,
        payload_size_mb=0,
    )
    values.update(overrides)
    return ServerFacts(**values)


class ChangeServerPhase1Tests(unittest.TestCase):
    def test_real_migration_shape_is_ready_even_if_destination_needs_docker(self):
        report = evaluate_preflight(
            source_facts(),
            destination_facts(),
            observed_at="2026-10-04T16:30:00Z",
        )
        self.assertTrue(report.ready)
        self.assertFalse(report.blockers)
        self.assertTrue(
            any(
                check.code == "DEST_DOCKER" and check.status == CHECK_WARN
                for check in report.checks
            )
        )

    def test_broken_source_database_blocks_migration(self):
        report = evaluate_preflight(
            source_facts(database_integrity="database disk image is malformed"),
            destination_facts(),
        )
        self.assertFalse(report.ready)
        self.assertTrue(
            any(
                check.code == "SOURCE_DATABASE"
                and check.status == CHECK_FAIL
                and check.blocking
                for check in report.checks
            )
        )

    def test_existing_destination_marzban_blocks_by_default(self):
        report = evaluate_preflight(
            source_facts(),
            destination_facts(
                marzban_compose_file="/opt/marzban/docker-compose.yml",
                marzban_dir="/opt/marzban",
            ),
        )
        self.assertFalse(report.ready)
        self.assertIn("DEST_CLEAN", {check.code for check in report.blockers})

    def test_existing_destination_can_be_warning_under_explicit_policy(self):
        report = evaluate_preflight(
            source_facts(),
            destination_facts(
                marzban_compose_file="/opt/marzban/docker-compose.yml",
                marzban_dir="/opt/marzban",
            ),
            policy=PreflightPolicy(require_clean_destination=False),
        )
        self.assertTrue(report.ready)
        self.assertTrue(
            any(
                check.code == "DEST_CLEAN" and check.status == CHECK_WARN
                for check in report.checks
            )
        )

    def test_same_server_is_rejected(self):
        report = evaluate_preflight(
            source_facts(),
            destination_facts(
                host="107.189.22.94",
                primary_ipv4="107.189.22.94",
            ),
        )
        self.assertFalse(report.ready)
        self.assertIn("PAIR_DISTINCT", {check.code for check in report.blockers})

    def test_service_port_conflict_on_destination_is_rejected(self):
        report = evaluate_preflight(
            source_facts(),
            destination_facts(listener_ports=(22, 8443)),
        )
        self.assertFalse(report.ready)
        self.assertIn("DEST_PORTS", {check.code for check in report.blockers})

    def test_disk_headroom_is_fail_closed(self):
        report = evaluate_preflight(
            source_facts(payload_size_mb=4000),
            destination_facts(root_free_mb=5000),
        )
        self.assertFalse(report.ready)
        self.assertIn("DEST_DISK", {check.code for check in report.blockers})

    def test_ssh_failure_blocks_without_hiding_other_endpoint(self):
        report = evaluate_preflight(
            None,
            destination_facts(),
            source_error="SSHConnectionError: authentication failed",
        )
        self.assertFalse(report.ready)
        self.assertIsNone(report.source)
        self.assertIsNotNone(report.destination)
        self.assertIn("SOURCE_SSH", {check.code for check in report.blockers})

    def test_password_is_not_visible_in_repr_or_report_shape(self):
        credentials = ServerCredentials(
            host="203.0.113.10",
            username="root",
            password="super-secret",
        )
        self.assertNotIn("super-secret", repr(credentials))
        report = evaluate_preflight(source_facts(), destination_facts())
        self.assertNotIn("password", str(report.to_dict()).lower())
        self.assertNotIn("super-secret", str(report.to_dict()))

    def test_static_detector_commands_are_read_only(self):
        for command in STATIC_READ_ONLY_COMMANDS:
            assert_read_only_command(command)

    def test_mutating_commands_are_rejected_by_guard(self):
        for command in (
            "rm -rf /opt/marzban",
            "systemctl restart docker",
            "docker compose up -d",
            "apt install docker-ce",
            "cp /tmp/a /tmp/b",
        ):
            with self.assertRaises(ValueError, msg=command):
                assert_read_only_command(command)


if __name__ == "__main__":
    unittest.main()
