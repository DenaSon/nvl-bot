import unittest

from server_migration.models import ServerCredentials
from server_migration.ssh import ParamikoRemoteExecutor, SSHConnectionError


class FakeRemoteFile:
    def __init__(self):
        self.value = ""
        self.flushed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def write(self, value):
        self.value += value

    def flush(self):
        self.flushed = True


class FakeSFTP:
    def __init__(self):
        self.files = {}
        self.modes = {}

    def file(self, path, mode):
        remote = FakeRemoteFile()
        self.files[path] = remote
        return remote

    def chmod(self, path, mode):
        self.modes[path] = mode


class FailingSFTP(FakeSFTP):
    def file(self, path, mode):
        raise RuntimeError("write failed")


class SSHWriteTextTests(unittest.TestCase):
    def test_write_text_uses_sftp_without_local_temp_file(self):
        executor = ParamikoRemoteExecutor(
            ServerCredentials(host="203.0.113.20", password="secret")
        )
        executor._sftp = FakeSFTP()

        executor.write_text(
            "/var/lib/marzban-node/cert.pem",
            "certificate-data\n",
            mode=0o600,
        )

        remote = executor._sftp.files["/var/lib/marzban-node/cert.pem"]
        self.assertEqual(remote.value, "certificate-data\n")
        self.assertTrue(remote.flushed)
        self.assertEqual(
            executor._sftp.modes["/var/lib/marzban-node/cert.pem"],
            0o600,
        )

    def test_write_text_failure_does_not_expose_password(self):
        executor = ParamikoRemoteExecutor(
            ServerCredentials(host="203.0.113.20", password="super-secret")
        )
        executor._sftp = FailingSFTP()

        with self.assertRaises(SSHConnectionError) as ctx:
            executor.write_text("/tmp/a", "x")

        self.assertNotIn("super-secret", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
