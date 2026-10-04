from __future__ import annotations

from typing import Protocol

from .models import CommandResult, ServerCredentials


class RemoteExecutor(Protocol):
    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        ...

    def close(self) -> None:
        ...


class SSHConnectionError(RuntimeError):
    pass


class ParamikoRemoteExecutor:
    """Small SSH wrapper used by migration discovery.

    Paramiko is imported lazily so pure unit tests do not require the optional
    runtime dependency. Passwords are never logged or included in CommandResult.
    """

    def __init__(
        self,
        credentials: ServerCredentials,
        *,
        connect_timeout: int = 8,
        command_timeout: int = 20,
    ):
        self.credentials = credentials
        self.connect_timeout = max(1, int(connect_timeout))
        self.command_timeout = max(1, int(command_timeout))
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import paramiko
        except ImportError as exc:
            raise SSHConnectionError(
                "paramiko is required for live server migration preflight"
            ) from exc

        client = paramiko.SSHClient()
        # New destination servers usually have no local known-host entry. This
        # policy accepts the host key only in this in-memory client; we never
        # call save_host_keys(), so Phase 1 does not mutate local known_hosts.
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

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
