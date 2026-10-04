import json
import pathlib
import unittest
from unittest.mock import patch

from server_migration.models import CommandResult, ServerCredentials, ServerFacts
from server_migration.phase3 import run_phase3
from server_migration.phase3_models import (
    PHASE3_MODE_INSPECT,
    PHASE3_MODE_RESTORE,
    Phase3Error,
    Phase3Policy,
)
from server_migration.restore import (
    _safe_abs_path,
    inspect_docker_image_archive,
    validate_restore_target,
    verify_incoming_bundle,
)


JOB_ID = "chg-20261004T174439Z-706f2540"
INCOMING = f"/root/nvl-migrations/{JOB_ID}/incoming"
IMAGE = "nvl/marzban:xray-26.6.1-compat"
IMAGE_ID = "11578c1c7f4419060d935e35821ff952aefd169f08a48b3905f3afe56cb47915"


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
        root_free_mb=20000,
        docker_installed=True,
        docker_version="Docker version 29.7.2",
        compose_version="Docker Compose version v5.6.0",
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
        required_tools=("gzip", "python3", "sha256sum", "tar"),
        payload_size_mb=0,
    )
    values.update(overrides)
    return ServerFacts(**values)


def metadata():
    return {
        "schema_version": 1,
        "job_id": JOB_ID,
        "source": {
            "host": "107.189.22.94",
            "primary_ipv4": "107.189.22.94",
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
            "compose_images": [IMAGE],
            "local_image_details": [
                f"{IMAGE}|sha256:{IMAGE_ID}|amd64|linux"
            ],
        },
        "archives": {
            "config_restore_parent": "/opt",
            "config_member_root": "marzban",
            "data_restore_parent": "/var/lib",
            "data_member_root": "marzban",
            "letsencrypt_restore_parent": "/",
            "runtime_extras_restore_parent": None,
        },
        "runtime_extras": [],
        "letsencrypt_included": True,
        "database_snapshot_method": "python-sqlite3-backup-api",
    }


class IncomingExecutor:
    def __init__(self, *, existing=(), image_manifest=None):
        self.existing = set(existing)
        self.commands = []
        self.image_manifest = image_manifest or {
            IMAGE: {
                "config_sha256": "2" * 64,
                "architecture": "amd64",
                "os": "linux",
            }
        }

    def run(self, command, timeout=None):
        self.commands.append(command)
        if command.startswith("test -d "):
            path = command[len("test -d "):].strip().strip("'")
            return CommandResult(command, 0 if path == INCOMING else 1, "", "")
        if command.startswith("test -e "):
            path = command[len("test -e "):].strip().strip("'")
            exists = (
                path in self.existing
                or path in {
                    f"{INCOMING}/SHA256SUMS",
                    f"{INCOMING}/bundle.json",
                }
            )
            return CommandResult(command, 0 if exists else 1, "", "")
        if "sha256sum -c SHA256SUMS" in command:
            names = [
                "bundle.json",
                "marzban-config.tar.gz",
                "marzban-data-snapshot.tar.gz",
                "etc-letsencrypt.tar.gz",
                "docker-images.tar.gz",
            ]
            return CommandResult(
                command,
                0,
                "\n".join(f"{name}: OK" for name in names) + "\n",
                "",
            )
        if command == f"cat {INCOMING}/SHA256SUMS":
            names = [
                "bundle.json",
                "marzban-config.tar.gz",
                "marzban-data-snapshot.tar.gz",
                "etc-letsencrypt.tar.gz",
                "docker-images.tar.gz",
            ]
            body = "\n".join(f"{'a' * 64}  {name}" for name in names)
            return CommandResult(command, 0, body + "\n", "")
        if command == f"cat {INCOMING}/bundle.json":
            return CommandResult(command, 0, json.dumps(metadata()), "")
        if "manifest.json" in command and "tarfile" in command:
            return CommandResult(
                command,
                0,
                json.dumps(self.image_manifest),
                "",
            )
        if command.startswith("du -sm "):
            return CommandResult(command, 0, "140", "")
        return CommandResult(command, 0, "", "")

    def close(self):
        pass


class ChangeServerPhase3SafetyTests(unittest.TestCase):
    def test_safe_path_rejects_traversal_and_root(self):
        self.assertEqual(
            _safe_abs_path("/var/lib/marzban/db.sqlite3", label="db"),
            "/var/lib/marzban/db.sqlite3",
        )
        for value in ("/", "../etc/passwd", "/var/lib/../etc/passwd", "relative"):
            with self.assertRaises(Phase3Error, msg=value):
                _safe_abs_path(value, label="test")

    def test_verify_incoming_bundle_accepts_phase2_real_shape(self):
        executor = IncomingExecutor()
        incoming, meta, manifest = verify_incoming_bundle(
            executor,
            job_id=JOB_ID,
        )
        self.assertEqual(incoming, INCOMING)
        self.assertEqual(meta["marzban"]["database_path"], "/var/lib/marzban/db.sqlite3")
        self.assertIn("docker-images.tar.gz", manifest)

    def test_verify_incoming_bundle_rejects_job_id_mismatch(self):
        executor = IncomingExecutor()
        bad = metadata()
        bad["job_id"] = "chg-20261004T174439Z-deadbeef"

        original_run = executor.run

        def run(command, timeout=None):
            if command == f"cat {INCOMING}/bundle.json":
                return CommandResult(command, 0, json.dumps(bad), "")
            return original_run(command, timeout)

        executor.run = run
        with self.assertRaises(Phase3Error):
            verify_incoming_bundle(executor, job_id=JOB_ID)

    def test_docker_archive_verifies_tag_config_and_platform(self):
        executor = IncomingExecutor()
        valid, ids_match = inspect_docker_image_archive(
            executor,
            INCOMING,
            metadata(),
        )
        self.assertTrue(valid)
        self.assertTrue(identity_verified)

        bad = IncomingExecutor(image_manifest={IMAGE: "0" * 64})
        with self.assertRaises(Phase3Error):
            inspect_docker_image_archive(bad, INCOMING, metadata())

    def test_restore_target_refuses_existing_runtime_paths(self):
        executor = IncomingExecutor(existing={"/opt/marzban"})
        with self.assertRaises(Phase3Error):
            validate_restore_target(
                executor,
                destination_facts(),
                metadata(),
                (80, 443, 8443),
                incoming_dir=INCOMING,
                policy=Phase3Policy(mode=PHASE3_MODE_RESTORE),
            )

    def test_restore_target_refuses_service_port_conflict(self):
        executor = IncomingExecutor()
        with self.assertRaises(Phase3Error):
            validate_restore_target(
                executor,
                destination_facts(listener_ports=(22, 8443)),
                metadata(),
                (80, 443, 8443),
                incoming_dir=INCOMING,
                policy=Phase3Policy(mode=PHASE3_MODE_RESTORE),
            )

    def test_restore_target_accepts_clean_destination(self):
        executor = IncomingExecutor()
        validate_restore_target(
            executor,
            destination_facts(),
            metadata(),
            (80, 443, 8443),
            incoming_dir=INCOMING,
            policy=Phase3Policy(
                mode=PHASE3_MODE_RESTORE,
                minimum_destination_free_mb=1024,
            ),
        )


class ChangeServerPhase3OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.credentials = ServerCredentials(
            "107.189.22.229",
            password="secret",
        )

    @patch("server_migration.phase3.start_runtime_and_verify")
    @patch("server_migration.phase3.restore_runtime_from_preview")
    @patch("server_migration.phase3.load_docker_images")
    @patch("server_migration.phase3.validate_restore_target")
    @patch("server_migration.phase3.validate_preview_compose", return_value=True)
    @patch("server_migration.phase3.ensure_docker")
    @patch("server_migration.phase3.preview_xray_ports", return_value=(80, 443, 8443))
    @patch("server_migration.phase3.preview_database_integrity", return_value="ok")
    @patch("server_migration.phase3.prepare_preview", return_value=f"/root/nvl-migrations/{JOB_ID}/restore-preview")
    @patch("server_migration.phase3.inspect_docker_image_archive", return_value=(True, True))
    @patch("server_migration.phase3.validate_bundle_archives")
    @patch("server_migration.phase3.verify_incoming_bundle", return_value=(INCOMING, metadata(), {"bundle.json": "a"}))
    @patch("server_migration.phase3.inspect_server", return_value=destination_facts())
    def test_inspect_only_never_restores_or_loads_images(
        self,
        _inspect,
        _verify,
        _archives,
        _image_archive,
        _preview,
        _db,
        _ports,
        _docker,
        _compose,
        _target,
        load_images,
        restore_runtime,
        start_runtime,
    ):
        executor = IncomingExecutor()
        result = run_phase3(
            self.credentials,
            job_id=JOB_ID,
            policy=Phase3Policy(mode=PHASE3_MODE_INSPECT),
            executor_factory=lambda _credentials: executor,
        )
        self.assertEqual(result.mode, PHASE3_MODE_INSPECT)
        self.assertFalse(result.runtime_restored)
        self.assertFalse(result.docker_images_loaded)
        load_images.assert_not_called()
        restore_runtime.assert_not_called()
        start_runtime.assert_not_called()
        _target.assert_not_called()

    @patch("server_migration.phase3.start_runtime_and_verify")
    @patch("server_migration.phase3.validate_restored_compose", return_value=True)
    @patch("server_migration.phase3.validate_restored_database", return_value="ok")
    @patch("server_migration.phase3.restore_runtime_from_preview")
    @patch("server_migration.phase3.load_docker_images", return_value=True)
    @patch("server_migration.phase3.validate_restore_target")
    @patch("server_migration.phase3.validate_preview_compose", return_value=True)
    @patch("server_migration.phase3.ensure_docker")
    @patch("server_migration.phase3.preview_xray_ports", return_value=(80, 443, 8443))
    @patch("server_migration.phase3.preview_database_integrity", return_value="ok")
    @patch("server_migration.phase3.prepare_preview", return_value=f"/root/nvl-migrations/{JOB_ID}/restore-preview")
    @patch("server_migration.phase3.inspect_docker_image_archive", return_value=(True, True))
    @patch("server_migration.phase3.validate_bundle_archives")
    @patch("server_migration.phase3.verify_incoming_bundle", return_value=(INCOMING, metadata(), {"bundle.json": "a"}))
    @patch("server_migration.phase3.inspect_server", return_value=destination_facts())
    def test_restore_mode_does_not_start_runtime_by_default(
        self,
        _inspect,
        _verify,
        _archives,
        _image_archive,
        _preview,
        _db,
        _ports,
        _docker,
        _compose,
        target,
        load_images,
        restore_runtime,
        _restored_db,
        _restored_compose,
        start_runtime,
    ):
        executor = IncomingExecutor()
        result = run_phase3(
            self.credentials,
            job_id=JOB_ID,
            policy=Phase3Policy(
                mode=PHASE3_MODE_RESTORE,
                start_runtime=False,
            ),
            executor_factory=lambda _credentials: executor,
        )
        self.assertTrue(result.runtime_restored)
        self.assertTrue(result.docker_images_loaded)
        self.assertFalse(result.runtime_started)
        target.assert_called_once()
        load_images.assert_called_once()
        restore_runtime.assert_called_once()
        start_runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
