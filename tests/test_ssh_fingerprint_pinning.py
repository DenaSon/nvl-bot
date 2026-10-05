import sys
import types
import unittest
from unittest.mock import patch

from server_migration.models import ServerCredentials
from server_migration.ssh import (
    ParamikoRemoteExecutor,
    SSHConnectionError,
    _host_key_sha256,
)


class FakeKey:
    def __init__(self, payload=b"server-key"):
        self.payload = payload

    def asbytes(self):
        return self.payload

    def get_name(self):
        return "ssh-ed25519"


class FakeHostKeys:
    def __init__(self):
        self.added = []

    def add(self, hostname, key_type, key):
        self.added.append((hostname, key_type, key))


class FakeMissingHostKeyPolicy:
    pass


class FakeAutoAddPolicy(FakeMissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)


class FakeSSHClient:
    instances = []

    def __init__(self):
        self.policy = None
        self.host_keys = FakeHostKeys()
        self.closed = False
        self.connect_kwargs = None
        self.__class__.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.host_keys

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        self.policy.missing_host_key(self, kwargs["hostname"], FakeKey())

    def close(self):
        self.closed = True


class SSHFingerprintPinningTests(unittest.TestCase):
    def setUp(self):
        FakeSSHClient.instances.clear()
        self.fake_paramiko = types.SimpleNamespace(
            SSHClient=FakeSSHClient,
            MissingHostKeyPolicy=FakeMissingHostKeyPolicy,
            AutoAddPolicy=FakeAutoAddPolicy,
        )

    def test_matching_pinned_fingerprint_allows_connection(self):
        expected = _host_key_sha256(FakeKey())
        credentials = ServerCredentials(
            host="203.0.113.20",
            port=2222,
            username="root",
            password="secret",
        )

        with patch.dict(sys.modules, {"paramiko": self.fake_paramiko}):
            executor = ParamikoRemoteExecutor(
                credentials,
                expected_host_key_sha256=expected,
            )
            client = executor._ensure_client()

        self.assertIs(client, FakeSSHClient.instances[0])
        self.assertEqual(
            client.host_keys.added[0][:2],
            ("203.0.113.20", "ssh-ed25519"),
        )
        self.assertEqual(client.connect_kwargs["port"], 2222)
        self.assertEqual(client.connect_kwargs["password"], "secret")

    def test_mismatched_pinned_fingerprint_is_rejected_fail_closed(self):
        credentials = ServerCredentials(
            host="203.0.113.20",
            username="root",
            password="secret",
        )

        with patch.dict(sys.modules, {"paramiko": self.fake_paramiko}):
            executor = ParamikoRemoteExecutor(
                credentials,
                expected_host_key_sha256="SHA256:not-the-server-key",
            )
            with self.assertRaises(SSHConnectionError) as ctx:
                executor._ensure_client()

        self.assertIn("fingerprint mismatch", str(ctx.exception))
        self.assertTrue(FakeSSHClient.instances[0].closed)
        self.assertNotIn("secret", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
