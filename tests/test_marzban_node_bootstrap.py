import unittest
from unittest.mock import Mock

import marzban_node_bootstrap as bootstrap
from server_migration.models import CHECK_FAIL, CHECK_PASS, CHECK_WARN, CommandResult
from server_migration.ssh import SSHHostKeyInfo


class FakeExecutor:
    def __init__(self, credentials, *, expected_host_key_sha256=None, outputs=None):
        self.credentials = credentials
        self.expected_host_key_sha256 = expected_host_key_sha256
        self.outputs = outputs or {}
        self.commands = []
        self.closed = False

    def run(self, command, timeout=None):
        self.commands.append(command)
        value = self.outputs.get(command)
        if isinstance(value, Exception):
            raise value
        if value is None:
            return CommandResult(command=command, exit_code=1, stdout="", stderr="")
        exit_code, stdout = value
        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr="",
        )

    def close(self):
        self.closed = True


def healthy_outputs(*, docker=True, ports=(22,)):
    listeners = "\n".join(
        f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*"
        for port in ports
    )
    outputs = {
        "id -u": (0, "0\n"),
        "cat /etc/os-release": (
            0,
            'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
        ),
        "uname -m": (0, "x86_64\n"),
        "command -v docker": (0 if docker else 1, "/usr/bin/docker\n" if docker else ""),
        "ss -H -ltn": (0, listeners),
        (
            "test -d /var/lib/marzban-node || "
            "test -d /opt/marzban-node || "
            "test -f /etc/systemd/system/marzban-node.service"
        ): (1, ""),
    }
    if docker:
        outputs.update({
            "docker --version": (0, "Docker version 29.0.0\n"),
            "docker compose version": (0, "Docker Compose version v2.40.0\n"),
            "docker ps -a --format '{{.Names}}'": (0, ""),
        })
    return outputs


class SessionTests(unittest.TestCase):
    def tearDown(self):
        bootstrap.cancel_session(100)
        bootstrap.cancel_session(101)

    def test_password_is_hidden_from_repr_and_safe_summary(self):
        session = bootstrap.begin_session(
            100,
            node_id=9,
            host="203.0.113.20",
            service_port=62050,
            api_port=62051,
        )
        bootstrap.set_ssh_port(session, 22)
        bootstrap.discover_host_key(
            session,
            probe=lambda host, port: SSHHostKeyInfo(
                algorithm="ssh-ed25519",
                sha256="SHA256:abc",
            ),
        )
        bootstrap.confirm_host_key(session, session.host_key_nonce)
        bootstrap.set_password(session, "super-secret")

        self.assertNotIn("super-secret", repr(session))
        self.assertNotIn("password", str(session.safe_summary()).lower())
        self.assertNotIn("super-secret", str(session.safe_summary()))

    def test_stale_host_key_confirmation_is_rejected(self):
        session = bootstrap.begin_session(
            100,
            node_id=9,
            host="node.example.com",
            service_port=62050,
            api_port=62051,
        )
        bootstrap.set_ssh_port(session, 22)
        bootstrap.discover_host_key(
            session,
            probe=lambda host, port: SSHHostKeyInfo(
                algorithm="ssh-ed25519",
                sha256="SHA256:abc",
            ),
        )
        with self.assertRaises(bootstrap.NodeBootstrapError):
            bootstrap.confirm_host_key(session, "wrong")

    def test_expired_session_scrubs_password(self):
        session = bootstrap.begin_session(
            100,
            node_id=9,
            host="node.example.com",
            service_port=62050,
            api_port=62051,
        )
        session.password = "secret"
        session.started_at -= bootstrap.SESSION_TTL_SECONDS + 1

        self.assertIsNone(bootstrap.get_session(100))
        self.assertIsNone(session.password)


class PreflightTests(unittest.TestCase):
    def tearDown(self):
        bootstrap.cancel_session(101)

    def _ready_session(self):
        session = bootstrap.begin_session(
            101,
            node_id=11,
            host="203.0.113.21",
            service_port=62050,
            api_port=62051,
        )
        bootstrap.set_ssh_port(session, 2222)
        bootstrap.discover_host_key(
            session,
            probe=lambda host, port: SSHHostKeyInfo(
                algorithm="ssh-ed25519",
                sha256="SHA256:pinned",
            ),
        )
        bootstrap.confirm_host_key(session, session.host_key_nonce)
        bootstrap.set_password(session, "temporary-password")
        return session

    def test_ready_preflight_is_read_only_pins_fingerprint_and_scrubs_password(self):
        session = self._ready_session()
        captured = {}

        def factory(credentials, *, expected_host_key_sha256=None):
            executor = FakeExecutor(
                credentials,
                expected_host_key_sha256=expected_host_key_sha256,
                outputs=healthy_outputs(),
            )
            captured["executor"] = executor
            return executor

        report = bootstrap.run_preflight(session, executor_factory=factory)

        self.assertTrue(report.ready)
        self.assertEqual(report.host_key_sha256, "SHA256:pinned")
        self.assertEqual(captured["executor"].expected_host_key_sha256, "SHA256:pinned")
        self.assertEqual(captured["executor"].credentials.username, "root")
        self.assertIsNone(session.password)
        self.assertTrue(captured["executor"].closed)
        self.assertEqual(session.stage, "PREFLIGHT_COMPLETE")
        self.assertTrue(any(c.code == "SERVICE_PORT" and c.status == CHECK_PASS for c in report.checks))
        self.assertFalse(any(
            token in command
            for command in captured["executor"].commands
            for token in ("apt install", "systemctl restart", "docker compose up", "rm -", "cp ")
        ))

    def test_missing_docker_is_warning_not_blocker(self):
        session = self._ready_session()

        def factory(credentials, *, expected_host_key_sha256=None):
            return FakeExecutor(
                credentials,
                expected_host_key_sha256=expected_host_key_sha256,
                outputs=healthy_outputs(docker=False),
            )

        report = bootstrap.run_preflight(session, executor_factory=factory)

        self.assertTrue(report.ready)
        self.assertTrue(any(c.code == "DOCKER" and c.status == CHECK_WARN for c in report.checks))
        self.assertIsNone(session.password)

    def test_occupied_node_port_blocks_install(self):
        session = self._ready_session()

        def factory(credentials, *, expected_host_key_sha256=None):
            return FakeExecutor(
                credentials,
                expected_host_key_sha256=expected_host_key_sha256,
                outputs=healthy_outputs(ports=(22, 62050)),
            )

        report = bootstrap.run_preflight(session, executor_factory=factory)

        self.assertFalse(report.ready)
        self.assertTrue(any(
            c.code == "SERVICE_PORT"
            and c.status == CHECK_FAIL
            and c.blocking
            for c in report.checks
        ))
        self.assertEqual(session.stage, "PREFLIGHT_BLOCKED")
        self.assertIsNone(session.password)

    def test_non_root_blocks_preflight(self):
        session = self._ready_session()
        outputs = healthy_outputs()
        outputs["id -u"] = (0, "1000\n")

        def factory(credentials, *, expected_host_key_sha256=None):
            return FakeExecutor(
                credentials,
                expected_host_key_sha256=expected_host_key_sha256,
                outputs=outputs,
            )

        report = bootstrap.run_preflight(session, executor_factory=factory)

        self.assertFalse(report.ready)
        self.assertTrue(any(
            c.code == "ROOT_ACCESS" and c.status == CHECK_FAIL and c.blocking
            for c in report.checks
        ))

    def test_connection_error_becomes_safe_blocking_report_and_scrubs_password(self):
        session = self._ready_session()

        class FailingExecutor(FakeExecutor):
            def run(self, command, timeout=None):
                raise RuntimeError("authentication failed")

        captured = {}

        def factory(credentials, *, expected_host_key_sha256=None):
            executor = FailingExecutor(
                credentials,
                expected_host_key_sha256=expected_host_key_sha256,
            )
            captured["executor"] = executor
            return executor

        report = bootstrap.run_preflight(session, executor_factory=factory)

        self.assertFalse(report.ready)
        self.assertEqual(report.checks[0].code, "SSH_AUTH")
        self.assertTrue(report.checks[0].blocking)
        self.assertIsNone(session.password)
        self.assertNotIn("temporary-password", str(report.to_dict()))
        self.assertTrue(captured["executor"].closed)


if __name__ == "__main__":
    unittest.main()
