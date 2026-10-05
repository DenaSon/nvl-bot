from __future__ import annotations

import base64
import hashlib
import os
import socket
from dataclasses import dataclass
from typing import Protocol

from .models import CommandResult, ServerCredentials


class RemoteExecutor(Protocol):
    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        ...

    def write_text(
        self,
        remote_path: str,
        content: str,
        *,
        mode: int = 0o600,
    ) -> None:
        """Write UTF-8 text directly over SFTP without a local temp file."""
        remote_path = str(remote_path)
        try:
            sftp = self._ensure_sftp()
            with sftp.file(remote_path, "w") as remote_file:
                remote_file.write(str(content))
                remote_file.flush()
            sftp.chmod(remote_path, int(mode))
        except Exception as exc:
            raise SSHConnectionError(
                f"SFTP write failed on {self.credentials.host}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def close(self) -> None:
        ...


class RemoteFileTransport(Protocol):
    def download(self, remote_path: str, local_path: str) -> None:
        ...

    def upload(self, local_path: str, remote_path: str) -> None:
        ...

    def write_text(
        self,
        remote_path: str,
        content: str,
        *,
        mode: int = 0o600,
    ) -> None:
        ...


class SSHConnectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SSHHostKeyInfo:
    algorithm: str
    sha256: str


def _host_key_sha256(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def probe_ssh_host_key(
    host: str,
    port: int = 22,
    *,
    timeout: int = 8,
) -> SSHHostKeyInfo:
    """Read the server SSH host key without authenticating.

    This is a read-only handshake used by operator-facing workflows before
    collecting a password. The returned fingerprint can then be pinned during
    the authenticated connection.
    """
    host = str(host or "").strip()
    port = int(port)
    if not host:
        raise ValueError("host is required")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    try:
        import paramiko
    except ImportError as exc:
        raise SSHConnectionError("paramiko is required for SSH host-key probing") from exc

    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=max(1, int(timeout)))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=max(1, int(timeout)))
        key = transport.get_remote_server_key()
        if key is None:
            raise SSHConnectionError("SSH server did not present a host key")
        return SSHHostKeyInfo(
            algorithm=str(key.get_name() or "unknown"),
            sha256=_host_key_sha256(key),
        )
    except SSHConnectionError:
        raise
    except Exception as exc:
        raise SSHConnectionError(
            f"SSH host-key probe failed for {host}:{port}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass


class ParamikoRemoteExecutor:
    """SSH/SFTP wrapper shared by migration phases.

    Paramiko is imported lazily so pure unit tests do not require the runtime
    dependency. Passwords are never logged or included in CommandResult.

    Phase 1 uses only command execution and remains read-only. Phase 2
    additionally uses SFTP download/upload to relay staged migration artifacts
    through the NVL control host.
    """

    def __init__(
        self,
        credentials: ServerCredentials,
        *,
        connect_timeout: int = 8,
        command_timeout: int = 20,
        expected_host_key_sha256: str | None = None,
    ):
        self.credentials = credentials
        self.connect_timeout = max(1, int(connect_timeout))
        self.command_timeout = max(1, int(command_timeout))
        self.expected_host_key_sha256 = (
            str(expected_host_key_sha256 or "").strip() or None
        )
        self._client = None
        self._sftp = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import paramiko
        except ImportError as exc:
            raise SSHConnectionError(
                "paramiko is required for live server migration"
            ) from exc

        client = paramiko.SSHClient()
        if self.expected_host_key_sha256:
            expected = self.expected_host_key_sha256

            class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    actual = _host_key_sha256(key)
                    if actual != expected:
                        raise SSHConnectionError(
                            "SSH host-key fingerprint mismatch: "
                            f"expected {expected}, got {actual}"
                        )
                    # Pin only in this in-memory client. Never persist known_hosts.
                    client.get_host_keys().add(hostname, key.get_name(), key)

            client.set_missing_host_key_policy(_PinnedHostKeyPolicy())
        else:
            # Existing migration workflows keep their current TOFU behavior.
            # New node bootstrap passes an explicitly confirmed fingerprint.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.credentials.host,
                port=self.credentials.port,
                username=self.credentials.username,
                password=self.credentials.password,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                look_for_keys=self.credentials.password is None,
                allow_agent=self.credentials.password is None,
            )
        except Exception as exc:
            client.close()
            raise SSHConnectionError(
                f"SSH connection failed for {self.credentials.host}:"
                f"{self.credentials.port}: {type(exc).__name__}: {exc}"
            ) from exc

        self._client = client
        return client

    def _ensure_sftp(self):
        if self._sftp is None:
            try:
                self._sftp = self._ensure_client().open_sftp()
            except Exception as exc:
                raise SSHConnectionError(
                    f"SFTP setup failed for {self.credentials.host}:"
                    f"{self.credentials.port}: {type(exc).__name__}: {exc}"
                ) from exc
        return self._sftp

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        client = self._ensure_client()
        try:
            _stdin, stdout, stderr = client.exec_command(
                command,
                timeout=max(1, int(timeout or self.command_timeout)),
            )
            exit_code = stdout.channel.recv_exit_status()
            return CommandResult(
                command=command,
                exit_code=int(exit_code),
                stdout=stdout.read().decode("utf-8", "replace"),
                stderr=stderr.read().decode("utf-8", "replace"),
            )
        except Exception as exc:
            raise SSHConnectionError(
                f"SSH command failed on {self.credentials.host}:"
                f" {type(exc).__name__}: {exc}"
            ) from exc

    def download(self, remote_path: str, local_path: str) -> None:
        """Download one staged artifact without altering the remote file."""
        local_path = os.fspath(local_path)
        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            self._ensure_sftp().get(str(remote_path), local_path)
            os.chmod(local_path, 0o600)
        except Exception as exc:
            raise SSHConnectionError(
                f"SFTP download failed from {self.credentials.host}:"
                f" {type(exc).__name__}: {exc}"
            ) from exc

    def upload(self, local_path: str, remote_path: str) -> None:
        """Upload one local staged artifact to an already-created remote path."""
        try:
            self._ensure_sftp().put(os.fspath(local_path), str(remote_path))
            self._ensure_sftp().chmod(str(remote_path), 0o600)
        except Exception as exc:
            raise SSHConnectionError(
                f"SFTP upload failed to {self.credentials.host}:"
                f" {type(exc).__name__}: {exc}"
            ) from exc

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            finally:
                self._sftp = None
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
