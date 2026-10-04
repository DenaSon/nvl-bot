from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .phase5_models import CloudflareRecordSnapshot, Phase5Error


_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareClient:
    def __init__(self, api_token: str, *, timeout: float = 12.0):
        token = str(api_token or "").strip()
        if not token:
            raise Phase5Error("Cloudflare API token is required")
        self._token = token
        self.timeout = float(timeout)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = _API_BASE + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if len(body) > 1200:
                body = body[-1200:]
            raise Phase5Error(
                f"Cloudflare API HTTP {exc.code}"
                + (f": {body}" if body else "")
            ) from exc
        except Exception as exc:
            raise Phase5Error(
                f"Cloudflare API request failed: {type(exc).__name__}: {exc}"
            ) from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise Phase5Error("Cloudflare API returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise Phase5Error("Cloudflare API returned an unexpected payload")
        if parsed.get("success") is not True:
            errors = parsed.get("errors") or []
            raise Phase5Error(
                "Cloudflare API reported failure"
                + (f": {json.dumps(errors, ensure_ascii=False)}" if errors else "")
            )
        return parsed

    def resolve_zone_id(self, zone_name: str) -> str:
        zone_name = str(zone_name or "").strip().rstrip(".")
        if not zone_name:
            raise Phase5Error("Cloudflare zone name is required")
        payload = self._request(
            "GET",
            "/zones",
            query={"name": zone_name, "status": "active", "per_page": "50"},
        )
        rows = payload.get("result") or []
        exact = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("name") or "").rstrip(".") == zone_name
        ]
        if len(exact) != 1:
            raise Phase5Error(
                f"expected exactly one active Cloudflare zone for {zone_name!r}, "
                f"found {len(exact)}"
            )
        zone_id = str(exact[0].get("id") or "").strip()
        if not zone_id:
            raise Phase5Error("Cloudflare zone ID is missing")
        return zone_id

    def get_a_record(
        self,
        *,
        zone_id: str,
        hostname: str,
    ) -> CloudflareRecordSnapshot:
        hostname = str(hostname or "").strip().rstrip(".")
        payload = self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"type": "A", "name": hostname, "per_page": "100"},
        )
        rows = payload.get("result") or []
        exact = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("type") or "").upper() == "A"
            and str(row.get("name") or "").rstrip(".") == hostname
        ]
        if len(exact) != 1:
            raise Phase5Error(
                f"expected exactly one Cloudflare A record for {hostname!r}, "
                f"found {len(exact)}"
            )
        row = exact[0]
        record_id = str(row.get("id") or "").strip()
        content = str(row.get("content") or "").strip()
        if not record_id or not content:
            raise Phase5Error("Cloudflare DNS record is incomplete")
        proxied = row.get("proxied")
        if proxied is not None:
            proxied = bool(proxied)
        ttl = row.get("ttl")
        if not isinstance(ttl, int):
            ttl = None
        return CloudflareRecordSnapshot(
            zone_id=zone_id,
            record_id=record_id,
            name=hostname,
            record_type="A",
            content=content,
            proxied=proxied,
            ttl=ttl,
        )

    def patch_record_content(
        self,
        record: CloudflareRecordSnapshot,
        new_ip: str,
    ) -> CloudflareRecordSnapshot:
        self._request(
            "PATCH",
            f"/zones/{record.zone_id}/dns_records/{record.record_id}",
            payload={"content": str(new_ip)},
        )
        return self.get_a_record(
            zone_id=record.zone_id,
            hostname=record.name,
        )


def verify_origin_api(
    *,
    ip: str,
    hostname: str,
    port: int,
    timeout: float = 6.0,
) -> bool:
    """Probe the origin directly while preserving TLS SNI + HTTP Host.

    TLS certificate verification is intentionally disabled here because
    Cloudflare Origin CA certificates are not generally trusted by public
    system trust stores. The probe still uses the real hostname as SNI.
    """
    raw_sock = socket.create_connection((ip, int(port)), timeout=timeout)
    try:
        context = ssl._create_unverified_context()
        tls_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
        try:
            request = (
                f"GET /docs HTTP/1.1\r\n"
                f"Host: {hostname}:{int(port)}\r\n"
                "User-Agent: NVL-Phase5/1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            first = b""
            while b"\r\n" not in first and len(first) < 4096:
                chunk = tls_sock.recv(1024)
                if not chunk:
                    break
                first += chunk
            line = first.split(b"\r\n", 1)[0].decode("ascii", "replace")
            parts = line.split()
            if len(parts) < 2:
                return False
            try:
                status = int(parts[1])
            except ValueError:
                return False
            return 200 <= status < 500
        finally:
            tls_sock.close()
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def verify_hostname_api(
    *,
    hostname: str,
    port: int,
    timeout: float = 8.0,
) -> tuple[bool, str]:
    url = f"https://{hostname}:{int(port)}/docs"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NVL-Phase5/1",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 0))
            return 200 <= status < 500, f"HTTP {status}"
    except urllib.error.HTTPError as exc:
        error_type = str(exc.headers.get("cf-error-type") or "").strip()
        retry_after = str(exc.headers.get("Retry-After") or "").strip()
        detail = f"HTTP {exc.code}"
        if error_type:
            detail += f" cf-error-type={error_type}"
        if retry_after:
            detail += f" retry-after={retry_after}"
        try:
            body = exc.read(1200).decode("utf-8", "replace")
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                name = str(parsed.get("error_name") or "").strip()
                if name:
                    detail += f" error_name={name}"
        except Exception:
            pass
        return False, detail
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def verify_tcp_ports(
    *,
    ip: str,
    ports: tuple[int, ...],
    timeout: float = 4.0,
) -> tuple[int, ...]:
    verified: list[int] = []
    for port in sorted(set(int(p) for p in ports)):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                verified.append(port)
        except OSError:
            continue
    return tuple(verified)


def wait_for_record_content(
    client: CloudflareClient,
    *,
    zone_id: str,
    hostname: str,
    expected_ip: str,
    attempts: int,
    interval_seconds: float,
) -> CloudflareRecordSnapshot:
    last: CloudflareRecordSnapshot | None = None
    for index in range(max(1, int(attempts))):
        last = client.get_a_record(zone_id=zone_id, hostname=hostname)
        if last.content == expected_ip:
            return last
        if index + 1 < max(1, int(attempts)):
            time.sleep(max(0.0, float(interval_seconds)))
    actual = last.content if last is not None else "<unknown>"
    raise Phase5Error(
        f"Cloudflare record did not converge to {expected_ip}; current={actual}"
    )


def wait_for_hostname_api(
    *,
    hostname: str,
    port: int,
    attempts: int,
    interval_seconds: float,
    timeout: float,
) -> tuple[bool, str]:
    last_detail = "not attempted"
    for index in range(max(1, int(attempts))):
        healthy, detail = verify_hostname_api(
            hostname=hostname,
            port=port,
            timeout=timeout,
        )
        last_detail = detail
        if healthy:
            return True, detail
        if index + 1 < max(1, int(attempts)):
            time.sleep(max(0.0, float(interval_seconds)))
    return False, last_detail
