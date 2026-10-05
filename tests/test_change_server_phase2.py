import hashlib
import os
import pathlib
import shutil
import tempfile
import unittest

from server_migration.backup import (
    create_source_bundle,
    parse_checksum_manifest,
    validate_job_id,
)
from server_migration.models import (
    CHECK_FAIL,
    CommandResult,
    MigrationPreflightReport,
    PreflightCheck,
    ServerCredentials,
    ServerFacts,
)
from server_migration.phase2 import run_phase2
from server_migration.phase2_models import (
    BundleArtifact,
    Phase2Error,
    Phase2Policy,
    SourceBundle,
)
from server_migration.transfer import relay_bundle


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
            "nvl/marzban:xray-26.6.1-compat|sha256:abc|amd64|linux",
        ),
        listener_ports=(22,),
        xray_ports=(80, 443, 1080, 5430, 8080, 8443),
        required_tools=("gzip", "python3", "sha256sum", "tar"),
        payload_size_mb=26,
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
        root_free_mb=20000,
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
        required_tools=("gzip", "python3", "sha256sum", "tar"),
        payload_size_mb=0,
    )
    values.update(overrides)
    return ServerFacts(**values)


class RecordingBundleExecutor:
    def __init__(self):
        self.commands = []
        self.closed = False

    def run(self, command, timeout=None):
        self.commands.append(command)
        if command.startswith("test -d "):
            if "/etc/letsencrypt" in command:
                return CommandResult(command, 0, "", "")
            return CommandResult(command, 1, "", "")

        if command.startswith("cat ") and command.endswith("SHA256SUMS"):
            names = (
                "bundle.json",
                "marzban-config.tar.gz",
                "marzban-data-snapshot.tar.gz",
                "etc-letsencrypt.tar.gz",
                "docker-images.tar.gz",
            )
            body = "\n".join(
                f"{hashlib.sha256(name.encode()).hexdigest()}  {name}"
                for name in names
            )
            return CommandResult(command, 0, body + "\n", "")

        if command.startswith("wc -c < "):
            return CommandResult(command, 0, "123\n", "")

        if "s.backup(d)" in command:
            return CommandResult(command, 0, "ok|ok\n", "")

        return CommandResult(command, 0, "", "")

    def close(self):
        self.closed = True


class FakeRelayExecutor:
    def __init__(self, *, source_dir=None, destination_dir=None):
        self.source_dir = pathlib.Path(source_dir) if source_dir else None
        self.destination_dir = (
            pathlib.Path(destination_dir) if destination_dir else None
        )
        self.uploaded = []
        self.commands = []

    def download(self, remote_path, local_path):
        shutil.copy2(self.source_dir / pathlib.PurePosixPath(remote_path).name, local_path)

    def upload(self, local_path, remote_path):
        self.destination_dir.mkdir(parents=True, exist_ok=True)
        target = self.destination_dir / pathlib.PurePosixPath(remote_path).name
        shutil.copy2(local_path, target)
        self.uploaded.append(target.name)

    def run(self, command, timeout=None):
        self.commands.append(command)
        if "sha256sum -c SHA256SUMS" in command:
            manifest = parse_checksum_manifest(
                (self.destination_dir / "SHA256SUMS").read_text(encoding="utf-8")
            )
            lines = []
            for name, expected in manifest.items():
                actual = hashlib.sha256(
                    (self.destination_dir / name).read_bytes()
                ).hexdigest()
                if actual != expected:
                    return CommandResult(command, 1, "", f"{name}: FAILED")
                lines.append(f"{name}: OK")
            return CommandResult(command, 0, "\n".join(lines) + "\n", "")
        return CommandResult(command, 0, "", "")

    def close(self):
        pass


def make_bundle_files(root):
    root = pathlib.Path(root)
    root.mkdir(parents=True, exist_ok=True)
    payloads = {
        "bundle.json": b'{"schema_version":1}',
        "marzban-config.tar.gz": b"config",
        "marzban-data-snapshot.tar.gz": b"data",
        "docker-images.tar.gz": b"image",
    }
    artifacts = []
    lines = []
    for name, payload in payloads.items():
        path = root / name
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        lines.append(f"{digest}  {name}")
        artifacts.append(BundleArtifact(name, digest, len(payload)))
    (root / "SHA256SUMS").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return tuple(artifacts)


class ChangeServerPhase2Tests(unittest.TestCase):
    def test_job_id_validation_rejects_path_traversal(self):
        self.assertEqual(
            validate_job_id("chg-20261004T170000Z-deadbeef"),
            "chg-20261004T170000Z-deadbeef",
        )
        for bad in ("x", "../escape", "abc/defgh", "bad space", "/root/job"):
            with self.assertRaises(Phase2Error, msg=bad):
                validate_job_id(bad)

    def test_checksum_manifest_rejects_unsafe_names(self):
        good = "a" * 64 + "  bundle.json\n"
        self.assertEqual(parse_checksum_manifest(good)["bundle.json"], "a" * 64)
        with self.assertRaises(Phase2Error):
            parse_checksum_manifest("a" * 64 + "  ../secret\n")
        with self.assertRaises(Phase2Error):
            parse_checksum_manifest("not-a-checksum  bundle.json\n")

    def test_live_bundle_uses_sqlite_backup_and_never_stops_runtime(self):
        executor = RecordingBundleExecutor()
        policy = Phase2Policy(
            remote_root="/root/nvl-migrations",
            keep_source_snapshot_tree=False,
        )
        bundle = create_source_bundle(
            executor,
            source_facts(),
            job_id="chg-20261004T170000Z-deadbeef",
            policy=policy,
        )

        self.assertEqual(bundle.source_host, "107.189.22.94")
        self.assertEqual(len(bundle.artifacts), 5)
        joined = "\n".join(executor.commands).lower()
        self.assertIn("s.backup(d)", joined)
        self.assertIn("s.backup(d)", joined)
        self.assertIn("docker save", joined)
        self.assertIn("sha256sum -c sha256sums", joined)
        self.assertIn("./db.sqlite3-journal", joined)
        self.assertIn("tar: .: file changed as we read it", joined)
        self.assertIn("pipe_status", joined)
        self.assertIn("wc -l", joined)
        self.assertNotIn("docker compose stop", joined)
        self.assertNotIn("docker compose down", joined)
        self.assertNotIn("systemctl stop", joined)
        self.assertNotIn("systemctl restart", joined)

    def test_source_integrity_must_be_ok_before_bundle(self):
        executor = RecordingBundleExecutor()
        with self.assertRaises(Phase2Error):
            create_source_bundle(
                executor,
                source_facts(database_integrity="malformed"),
                job_id="chg-20261004T170000Z-deadbeef",
            )
        self.assertEqual(executor.commands, [])

    def test_source_staging_disk_is_checked_before_writes(self):
        executor = RecordingBundleExecutor()
        with self.assertRaises(Phase2Error):
            create_source_bundle(
                executor,
                source_facts(root_free_mb=100, payload_size_mb=26),
                job_id="chg-20261004T170000Z-deadbeef",
            )
        self.assertEqual(executor.commands, [])

    def test_relay_verifies_source_local_and_destination_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = pathlib.Path(temp)
            source_dir = temp / "remote-source"
            dest_dir = temp / "remote-dest"
            local_root = temp / "nvl-local"
            artifacts = make_bundle_files(source_dir)
            bundle = SourceBundle(
                job_id="chg-20261004T170000Z-deadbeef",
                source_host="107.189.22.94",
                remote_job_dir="/root/nvl-migrations/chg-20261004T170000Z-deadbeef",
                remote_bundle_dir="/root/nvl-migrations/chg-20261004T170000Z-deadbeef/bundle",
                checksum_file="SHA256SUMS",
                artifacts=artifacts,
                metadata={},
            )
            source = FakeRelayExecutor(source_dir=source_dir)
            destination = FakeRelayExecutor(destination_dir=dest_dir)
            report = relay_bundle(
                source,
                destination,
                bundle,
                policy=Phase2Policy(
                    local_root=os.fspath(local_root),
                    minimum_local_reserve_mb=0,
                ),
            )

            self.assertTrue(report.source_verified)
            self.assertTrue(report.local_verified)
            self.assertTrue(report.destination_verified)
            self.assertEqual(set(destination.uploaded), {
                "bundle.json",
                "marzban-config.tar.gz",
                "marzban-data-snapshot.tar.gz",
                "docker-images.tar.gz",
                "SHA256SUMS",
            })
            self.assertEqual(
                (local_root / bundle.job_id / "bundle").stat().st_mode & 0o777,
                0o700,
            )

    def test_relay_blocks_corrupted_download_before_destination_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = pathlib.Path(temp)
            source_dir = temp / "remote-source"
            dest_dir = temp / "remote-dest"
            artifacts = make_bundle_files(source_dir)
            (source_dir / "marzban-config.tar.gz").write_bytes(b"corrupted")
            bundle = SourceBundle(
                job_id="chg-20261004T170000Z-deadbeef",
                source_host="107.189.22.94",
                remote_job_dir="/root/nvl-migrations/chg-20261004T170000Z-deadbeef",
                remote_bundle_dir="/root/nvl-migrations/chg-20261004T170000Z-deadbeef/bundle",
                checksum_file="SHA256SUMS",
                artifacts=artifacts,
                metadata={},
            )
            source = FakeRelayExecutor(source_dir=source_dir)
            destination = FakeRelayExecutor(destination_dir=dest_dir)
            with self.assertRaises(Phase2Error):
                relay_bundle(
                    source,
                    destination,
                    bundle,
                    policy=Phase2Policy(
                        local_root=os.fspath(temp / "local"),
                        minimum_local_reserve_mb=0,
                    ),
                )
            self.assertEqual(destination.uploaded, [])
            self.assertEqual(destination.commands, [])

    def test_phase2_is_fail_closed_on_preflight_blocker(self):
        report = MigrationPreflightReport(
            source=source_facts(),
            destination=destination_facts(),
            checks=(
                PreflightCheck(
                    code="SOURCE_DATABASE",
                    status=CHECK_FAIL,
                    role="source",
                    message="broken",
                    blocking=True,
                ),
            ),
            ready=False,
            observed_at="2026-10-04T17:00:00Z",
        )
        with self.assertRaises(Phase2Error):
            run_phase2(
                report,
                ServerCredentials("107.189.22.94", password="a"),
                ServerCredentials("107.189.22.229", password="b"),
            )

    def test_staging_override_cannot_bypass_source_safety_failure(self):
        report = MigrationPreflightReport(
            source=source_facts(),
            destination=destination_facts(),
            checks=(
                PreflightCheck(
                    code="DEST_CLEAN",
                    status=CHECK_FAIL,
                    role="destination",
                    message="existing",
                    blocking=True,
                ),
                PreflightCheck(
                    code="SOURCE_DATABASE",
                    status=CHECK_FAIL,
                    role="source",
                    message="broken",
                    blocking=True,
                ),
            ),
            ready=False,
            observed_at="2026-10-04T17:00:00Z",
        )
        with self.assertRaises(Phase2Error):
            run_phase2(
                report,
                ServerCredentials("107.189.22.94", password="a"),
                ServerCredentials("107.189.22.229", password="b"),
                policy=Phase2Policy(require_preflight_ready=False),
            )


if __name__ == "__main__":
    unittest.main()
