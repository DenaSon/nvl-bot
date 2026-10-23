"""Small, standalone Cloudzy Developer API v1 client for NVL.

The routes and request bodies follow CloudzyVPS/cli src/api/ops.rs
(https://github.com/CloudzyVPS/cli). No Telegram, SSH/WireGuard, database or
background-worker integration lives here.

Developer tokens use the new dash.cloudzy.com API; never mix them with the
legacy api.cloudzy.com/developers API-Token interface.
"""

from __future__ import annotations

import json as jsonlib
import os
import time
import uuid
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from urllib.parse import quote

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class _Response:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content

    def json(self):
        return jsonlib.loads(self.content)


class _StdlibSession:
    """Minimal verified-HTTPS transport; never follows provider redirects."""

    def __init__(self):
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(self, method, url, *, headers, json, timeout, allow_redirects):
        if allow_redirects:
            raise ValueError("Cloudzy redirects must be disabled")
        data = jsonlib.dumps(json).encode("utf-8") if json is not None else None
        request = urllib.request.Request(url, headers=headers, data=data, method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return _Response(response.status, response.read())
        except urllib.error.HTTPError as exc:
            return _Response(exc.code, exc.read())


DEFAULT_BASE_URL = "https://dash.cloudzy.com/api/v1"
BILLING_CYCLES = frozenset({
    "hourly", "daily", "weekly", "monthly", "quarterly",
    "semi-annually", "annually",
})
_FAILED_STATES = frozenset({"failed", "error", "terminated", "deleted", "cancelled"})


class CloudzyError(RuntimeError):
    """Base for safe-to-report client failures."""


class CloudzyAPIError(CloudzyError):
    """Definite HTTP API rejection (or a failed read request)."""

    def __init__(self, status: int, message: str, code: str | None = None):
        self.status = status
        self.code = code
        super().__init__(f"Cloudzy HTTP {status}" + (f" [{code}]" if code else "") + f": {message}")


class CloudzyUncertainError(CloudzyError):
    """A write may have completed; reconcile provider state before retrying."""

    def __init__(self, operation: str, *, idempotency_key: str | None = None):
        self.operation = operation
        self.idempotency_key = idempotency_key
        super().__init__(
            f"Cloudzy {operation} outcome is uncertain; inspect provider state before retrying"
        )


class CloudzyTimeout(CloudzyError):
    """Server did not reach ACTIVE before the local wait deadline."""


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a non-empty, trimmed string")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{field} contains control characters")
    return value


def _resource(value: str) -> str:
    return quote(_required(value, "id"), safe="")


def _items(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for name in ("data", "items"):
            if isinstance(value.get(name), list):
                return value[name]
    return []


class CloudzyService:
    """Only the 20 owner-selected Cloudzy operations.

    Reads return the provider JSON unchanged, except list_plans(), which pairs
    catalog plans with their region/cycle price and marks base-price fallbacks.
    Prices and balance are provider amounts in cents (not dollars).

    No mutating request is automatically retried. create_server() uses a
    Cloudzy Idempotency-Key: preserve it when a mutation result is uncertain.
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        session=None,
        read_timeout: float = 15,
        write_timeout: float = 120,
        sleep=None,
        monotonic=None,
    ):
        self._token = _required(token if token is not None else os.environ.get("CLOUDZY_TOKEN", ""), "CLOUDZY_TOKEN")
        if not isinstance(base_url, str) or not base_url.startswith("https://"):
            raise ValueError("Cloudzy base URL must use HTTPS")
        if "?" in base_url or "#" in base_url or "@" in base_url.split("/")[2]:
            raise ValueError("invalid Cloudzy base URL")
        self.base_url = base_url.rstrip("/")
        if not self.base_url.endswith("/api/v1"):
            raise ValueError("Cloudzy base URL must end with /api/v1")
        if read_timeout <= 0 or write_timeout <= 0:
            raise ValueError("timeouts must be positive")
        self._session = session if session is not None else _StdlibSession()
        self._read_timeout = read_timeout
        self._write_timeout = write_timeout
        self._sleep = sleep if sleep is not None else time.sleep
        self._monotonic = monotonic if monotonic is not None else time.monotonic

    def _request(self, method: str, path: str, *, body=None, headers=None):
        mutation = method not in ("GET", "HEAD")
        operation = f"{method} {path}"
        key = (headers or {}).get("Idempotency-Key")
        request_headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        try:
            response = self._session.request(
                method, self.base_url + path,
                headers=request_headers,
                json=body,
                timeout=self._write_timeout if mutation else self._read_timeout,
                allow_redirects=False,
            )
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            if mutation:
                raise CloudzyUncertainError(operation, idempotency_key=key) from None
            raise CloudzyError(f"Cloudzy read request failed: {type(exc).__name__}") from None
        if not 200 <= response.status_code < 300:
            try:
                payload = response.json()
            except (ValueError, TypeError):
                payload = None
            raw_code = payload.get("code") if isinstance(payload, dict) else None
            raw_message = (
                payload.get("error") or payload.get("message") or payload.get("title")
                if isinstance(payload, dict) else None
            )
            code = str(raw_code)[:80] if isinstance(raw_code, str) else None
            message = str(raw_message)[:240] if isinstance(raw_message, str) else "request rejected"
            message = message.replace(self._token, "[REDACTED]")
            if mutation and response.status_code >= 500:
                raise CloudzyUncertainError(operation, idempotency_key=key)
            raise CloudzyAPIError(response.status_code, message, code)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except (ValueError, TypeError):
            if mutation:
                raise CloudzyUncertainError(operation, idempotency_key=key) from None
            raise CloudzyError("Cloudzy returned invalid JSON") from None

    # 01: Regions.
    def list_regions(self):
        return self._request("GET", "/regions")

    # 02: Plans and region-specific cycle prices (catalog base, not final quote).
    def list_plans(self, *, region: str | None = None, billing_cycle: str = "monthly"):
        if region is not None:
            _required(region, "region")
        if billing_cycle not in BILLING_CYCLES:
            raise ValueError("unsupported billing cycle")
        catalog = self._request("GET", "/pricing/catalog")
        data = catalog.get("data", catalog) if isinstance(catalog, dict) else None
        if not isinstance(data, dict):
            raise CloudzyError("invalid Cloudzy pricing catalog")
        plans = _items(data.get("plans"))
        prices = _items(data.get("prices"))
        result = []
        for item in plans:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            eligible = [
                price for price in prices if isinstance(price, dict)
                and price.get("planId") == item["id"]
                and price.get("billingCycle") == billing_cycle
            ]
            selected = next(
                (p for p in eligible if region is not None and p.get("regionId") == region),
                None,
            )
            fallback = next(
                (p for p in eligible if not p.get("regionId")), None
            )
            selected = selected or fallback
            entry = dict(item)
            entry["price"] = selected
            entry["priceScope"] = (
                "regional_catalog_base" if selected and region is not None
                and selected.get("regionId") == region
                else "general_catalog_base" if selected else "unavailable"
            )
            result.append(entry)
        return {
            "region": region,
            "billingCycle": billing_cycle,
            "notice": "Base prices exclude extras (including possible IPv4 fees); stock is advisory.",
            "plans": result,
        }

    # 06: Charged VPS creation. Explicit confirmation is required at the call site.
    def create_server(
        self, *, hostname: str, plan_id: str, region: str,
        os_template_id: str | None = None,
        billing_cycle: str | None = None,
        ssh_public_keys: Sequence[str] = (),
        user_data: str | None = None,
        ip_version: str | None = None,
        idempotency_key: str | None = None,
        confirm: bool = False,
    ):
        if confirm is not True:
            raise ValueError("create_server requires confirm=True (chargeable operation)")
        body = {
            "hostname": _required(hostname, "hostname"),
            "planId": _required(plan_id, "plan_id"),
            "region": _required(region, "region"),
        }
        if os_template_id is not None:
            body["osTemplateId"] = _required(os_template_id, "os_template_id")
        if billing_cycle is not None:
            if billing_cycle not in BILLING_CYCLES:
                raise ValueError("unsupported billing cycle")
            body["billingCycle"] = billing_cycle
        if ip_version is not None:
            if ip_version not in ("ipv4", "ipv6", "dual"):
                raise ValueError("unsupported ip_version")
            body["ipVersion"] = ip_version
        if isinstance(ssh_public_keys, (str, bytes)) or not isinstance(ssh_public_keys, Sequence):
            raise ValueError("ssh_public_keys must be a sequence of public key lines")
        if ssh_public_keys:
            body["sshAuthorizedKeys"] = [
                _required(key, "SSH public key") for key in ssh_public_keys
            ]
            if any("PRIVATE KEY" in key for key in body["sshAuthorizedKeys"]):
                raise ValueError("SSH private key cannot be sent to Cloudzy")
        if user_data is not None:
            if not isinstance(user_data, str) or not user_data.strip():
                raise ValueError("user_data must be non-empty cloud-init text")
            body["config"] = {"userData": user_data}
        key = _required(idempotency_key, "idempotency_key") if idempotency_key else str(uuid.uuid4())
        return self._request("POST", "/services", body=body, headers={"Idempotency-Key": key})

    # 07-10: Server inventory, details, status and bounded readiness polling.
    def list_servers(self):
        return self._request("GET", "/services")

    def get_server(self, server_id: str):
        return self._request("GET", f"/services/{_resource(server_id)}")

    def get_server_status(self, server_id: str):
        return self._request("GET", f"/services/{_resource(server_id)}/status")

    def wait_for_ready(
        self, server_id: str, *, timeout: float = 900, interval: float = 5
    ):
        _required(server_id, "server_id")
        if timeout <= 0 or interval <= 0:
            raise ValueError("timeout and interval must be positive")
        deadline = self._monotonic() + timeout
        while True:
            server = self.get_server(server_id)
            if not isinstance(server, Mapping):
                raise CloudzyError("invalid Cloudzy server details")
            status = str(server.get("state") or "").lower()
            if status == "active":
                return server  # Provider readiness, NOT SSH/WireGuard acceptance.
            if status in _FAILED_STATES:
                raise CloudzyError(f"Cloudzy server entered terminal state: {status}")
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise CloudzyTimeout(f"Cloudzy server {server_id} did not become active")
            self._sleep(min(interval, remaining))

    # 11-14: Rename and supported power transitions.
    def rename_server(self, server_id: str, hostname: str):
        return self._request(
            "PATCH", f"/services/{_resource(server_id)}",
            body={"hostname": _required(hostname, "hostname")},
        )

    def power_on(self, server_id: str):
        return self._power(server_id, "start")

    def power_off(self, server_id: str):
        return self._power(server_id, "stop")

    def restart_server(self, server_id: str):
        return self._power(server_id, "reboot")

    def _power(self, server_id: str, action: str):
        return self._request(
            "POST", f"/services/{_resource(server_id)}/power", body={"action": action}
        )

    # 16, 17, 18, 20: Destructive operations, usage, deletion.
    def rebuild_server(
        self, server_id: str, *, os_template_id: str, confirm: bool = False
    ):
        if confirm is not True:
            raise ValueError("rebuild_server erases the disk; confirm=True required")
        return self._request(
            "POST", f"/services/{_resource(server_id)}/rebuild",
            body={"osTemplate": _required(os_template_id, "os_template_id")},
        )

    def reset_server_password(self, server_id: str, *, confirm: bool = False):
        if confirm is not True:
            raise ValueError("reset_server_password requires confirm=True")
        # The password is returned by Cloudzy once; caller must not log it.
        return self._request(
            "POST", f"/services/{_resource(server_id)}/reset-password", body={}
        )

    def get_server_usage(self, server_id: str):
        return self._request("GET", f"/services/{_resource(server_id)}/usage")

    def delete_server(self, server_id: str, *, confirm: bool = False):
        if confirm is not True:
            raise ValueError("delete_server is irreversible; confirm=True required")
        return self._request("DELETE", f"/services/{_resource(server_id)}")

    # 21-23: Saved public SSH keys.
    def list_ssh_keys(self):
        return self._request("GET", "/ssh-keys")

    def add_ssh_key(self, name: str, public_key: str):
        key = _required(public_key, "public_key")
        if "PRIVATE KEY" in key or not key.startswith(
            ("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-")
        ):
            raise ValueError("expected one OpenSSH public key, not a private key")
        return self._request(
            "POST", "/ssh-keys",
            body={"name": _required(name, "name"), "publicKey": key},
        )

    def delete_ssh_key(self, key_id: str, *, confirm: bool = False):
        if confirm is not True:
            raise ValueError("delete_ssh_key requires confirm=True")
        return self._request("DELETE", f"/ssh-keys/{_resource(key_id)}")

    # 41-42: Account information and wallet balance (cents).
    def whoami(self):
        return self._request("GET", "/auth/me")

    def get_balance(self):
        return self._request("GET", "/billing/summary")
