import unittest

import marzban_node_bootstrap as bootstrap
import marzban_node_install as installer
from server_migration.models import CommandResult


VALID_CERT = """-----BEGIN CERTIFICATE-----
MIIBFAKECERTIFICATE
-----END CERTIFICATE-----
"""


class InstallFakeExecutor:
    def __init__(
        self,
        credentials,
        *,
        expected_host_key_sha256=None,
        command_timeout=None,
        ownership="fresh",
        docker_present=False,
        compose_present=False,
        fail_stage=None,
    ):
        self.credentials = credentials
        self.expected_host_key_sha256 = expected_host_key_sha256
        self.command_timeout = command_timeout
        self.ownership = ownership
        self.docker_present = docker_present
        self.compose_present = compose_present
        self.fail_stage = fail_stage
        self.started = False
        self.commands = []
        self.writes = {}
        self.closed = False

    def run(self, command, timeout=None):
        self.commands.append(command)

        def ok(stdout=""):
            return CommandResult(command=command, exit_code=0, stdout=stdout, stderr="")

        def bad(stderr="failed"):
            return CommandResult(command=command, exit_code=1, stdout="", stderr=stderr)

        if self.fail_stage and self.fail_stage in command:
            return bad("forced failure")

        if command == "id -u":
            return ok("0\n")

        if command.startswith("if [ -e /opt/marzban-node ]"):
            return ok(self.ownership + "\n")

        if command == "ss -H -ltn":
            ports = [22]
            if self.started:
                ports += [62050, 62051]
            return ok("\n".join(
                f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*"
                for port in ports
            ))

        if command == "command -v curl":
            return ok("/usr/bin/curl\n")

        if command == "command -v docker":
            return ok("/usr/bin/docker\n") if self.docker_present else bad()

        if "https://get.docker.com" in command:
            self.docker_present = True
            self.compose_present = True
            return ok()

        if command == "systemctl enable --now docker":
            return ok()

        if command == "docker --version":
            return ok("Docker version 29.0.0\n")

        if command == "docker compose version":
            if self.compose_present or self.docker_present:
                self.compose_present = True
                return ok("Docker Compose version v2.40.0\n")
            return bad()

        if "docker-compose-plugin" in command or "docker-compose-v2" in command:
            self.compose_present = True
            return ok()

        if command == "docker info >/dev/null":
            return ok()

        if command.startswith("install -d -m 755 /opt/marzban-node"):
            return ok()

        if command.startswith("test -s /var/lib/marzban-node/cert.pem"):
            return ok()

        if command == "docker compose -f /opt/marzban-node/docker-compose.yml config -q":
            return ok()

        if command.endswith("-p marzban-node pull"):
            return ok()

        if "-p marzban-node up -d --remove-orphans" in command:
            self.started = True
            return ok()

        if command == "docker inspect -f '{{.State.Running}}' marzban-node":
            return ok("true\n")

        if command.startswith("for i in $(seq 1 30); do"):
            return ok()

        if command.startswith("docker image inspect gozargah/marzban-node:latest"):
            return ok("sha256:abc123\n")

        return ok()

    def write_text(self, remote_path, content, *, mode=0o600):
        self.writes[remote_path] = (content, mode)

    def close(self):
        self.closed = True


def install_ready_session(chat_id=500):
    report = bootstrap.NodePreflightReport(
        node_id=1,
        host="172.86.117.246",
        ssh_port=22,
        host_key_algorithm="ssh-ed25519",
        host_key_sha256="SHA256:pinned",
        os_id="ubuntu",
        os_version="24.04",
        os_pretty_name="Ubuntu 24.04.3 LTS",
        architecture="x86_64",
        service_port=62050,
        api_port=62051,
        ready=True,
    )
    session = bootstrap.NodeBootstrapSession(
        chat_id=chat_id,
        node_id=1,
        host="172.86.117.246",
        service_port=62050,
        api_port=62051,
        ssh_port=22,
        stage="PREFLIGHT_COMPLETE",
        host_key_algorithm="ssh-ed25519",
        host_key_sha256="SHA256:pinned",
        last_report=report,
    )
    installer.prepare_install(session)
    installer.set_install_password(session, "temporary-secret")
    return session


class NodeInstallTests(unittest.TestCase):
    def test_fresh_install_matches_official_marzban_node_contract(self):
        session = install_ready_session()
        captured = {}

        def factory(credentials, **kwargs):
            executor = InstallFakeExecutor(credentials, **kwargs)
            captured["executor"] = executor
            return executor

        report = installer.run_install(
            session,
            certificate=VALID_CERT,
            executor_factory=factory,
        )

        self.assertTrue(report.success)
        self.assertTrue(report.container_running)
        self.assertTrue(report.service_port_listening)
        self.assertEqual(report.image_id, "sha256:abc123")
        self.assertTrue(report.docker_installed_now)
        self.assertEqual(session.stage, "REMOTE_INSTALL_COMPLETE")
        self.assertIsNone(session.password)
        executor = captured["executor"]
        self.assertTrue(executor.closed)
        self.assertEqual(executor.expected_host_key_sha256, "SHA256:pinned")

        cert, cert_mode = executor.writes[installer.CERT_PATH]
        compose, compose_mode = executor.writes[installer.COMPOSE_PATH]
        marker, marker_mode = executor.writes[installer.MANAGED_MARKER]

        self.assertEqual(cert_mode, 0o600)
        self.assertTrue(cert.endswith("\n"))
        self.assertIn("BEGIN CERTIFICATE", cert)
        self.assertEqual(compose_mode, 0o600)
        self.assertIn("image: gozargah/marzban-node:latest", compose)
        self.assertIn('SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/cert.pem"', compose)
        self.assertIn('SERVICE_PORT: "62050"', compose)
        self.assertIn('XRAY_API_PORT: "62051"', compose)
        self.assertIn('SERVICE_PROTOCOL: "rest"', compose)
        self.assertIn("- /var/lib/marzban-node:/var/lib/marzban", compose)
        self.assertIn("- /var/lib/marzban-node:/var/lib/marzban-node", compose)
        self.assertEqual(marker_mode, 0o600)
        self.assertIn("managed-by=NVL", marker)

    def test_unmanaged_existing_install_is_fail_closed(self):
        session = install_ready_session()
        captured = {}

        def factory(credentials, **kwargs):
            executor = InstallFakeExecutor(
                credentials,
                ownership="unmanaged",
                **kwargs,
            )
            captured["executor"] = executor
            return executor

        report = installer.run_install(
            session,
            certificate=VALID_CERT,
            executor_factory=factory,
        )

        self.assertFalse(report.success)
        self.assertEqual(report.stage, "ownership-check")
        self.assertIn("refusing to overwrite", report.error)
        self.assertEqual(session.stage, "INSTALL_FAILED")
        self.assertIsNone(session.password)
        self.assertFalse(captured["executor"].writes)

    def test_nvl_managed_retry_is_allowed_and_idempotent(self):
        session = install_ready_session()
        captured = {}

        def factory(credentials, **kwargs):
            executor = InstallFakeExecutor(
                credentials,
                ownership="nvl",
                docker_present=True,
                compose_present=True,
                **kwargs,
            )
            captured["executor"] = executor
            return executor

        report = installer.run_install(
            session,
            certificate=VALID_CERT,
            executor_factory=factory,
        )

        self.assertTrue(report.success)
        self.assertTrue(report.managed_retry)
        self.assertFalse(report.docker_installed_now)
        self.assertNotIn(
            "https://get.docker.com",
            "\n".join(captured["executor"].commands),
        )

    def test_install_failure_is_stage_specific_and_scrubs_password(self):
        session = install_ready_session()

        def factory(credentials, **kwargs):
            return InstallFakeExecutor(
                credentials,
                fail_stage="-p marzban-node pull",
                **kwargs,
            )

        report = installer.run_install(
            session,
            certificate=VALID_CERT,
            executor_factory=factory,
        )

        self.assertFalse(report.success)
        self.assertEqual(report.stage, "image-pull")
        self.assertIn("forced failure", report.error)
        self.assertEqual(session.stage, "INSTALL_FAILED")
        self.assertIsNone(session.password)
        self.assertNotIn("temporary-secret", str(report.to_dict()))

    def test_invalid_certificate_is_safe_failure_and_scrubs_password(self):
        session = install_ready_session()

        report = installer.run_install(
            session,
            certificate="not-a-certificate",
            executor_factory=lambda *args, **kwargs: self.fail(
                "executor should not be created for invalid certificate"
            ),
        )

        self.assertFalse(report.success)
        self.assertEqual(report.stage, "certificate")
        self.assertIn("invalid PEM", report.error)
        self.assertIsNone(session.password)

    def test_prepare_install_requires_successful_phase6(self):
        session = bootstrap.NodeBootstrapSession(
            chat_id=900,
            node_id=1,
            host="172.86.117.246",
            service_port=62050,
            api_port=62051,
            stage="PREFLIGHT_BLOCKED",
        )
        with self.assertRaises(bootstrap.NodeBootstrapError):
            installer.prepare_install(session)


if __name__ == "__main__":
    unittest.main()
