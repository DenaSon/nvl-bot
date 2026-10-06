"""Cloudflare DNS helpers for NVL managed Marzban Public Endpoints.

V123C deliberately keeps this module independent from the legacy/global SSH
Cloudflare switcher in bot_final_v49-2.py.  It operates on exactly one A record
identified by a Stable Public Endpoint hostname and is fail-closed on ambiguity,
stale state, proxied records, or provider/API uncertainty.

Secrets are passed in by the caller and are never persisted or included in
result dictionaries.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareDNSError(RuntimeError):
    """Bounded provider/configuration failure safe to surface to operators."""


def normalize_hostname(value: Any) -> str:
    raw = str(value or "").strip().rstrip(".").lower()
    if not raw or "." not in raw or "://" in raw or any(ch.isspace() for ch in raw):
        raise CloudflareDNSError("invalid DNS hostname")
    try:
        raw.encode("idna")
    except UnicodeError as exc:
        raise CloudflareDNSError("invalid DNS hostname") from exc
    return raw


def normalize_ipv4(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise CloudflareDNSError("expected a valid IPv4 address") from exc
    if ip.version != 4:
        raise CloudflareDNSError("only IPv4 A records are supported")
    return str(ip)


def resolve_single_ipv4(value: Any, *, resolver=None) -> str:
    """Resolve an address/hostname to exactly one IPv4 target.

    Node.address may be a hostname, but a Cloudflare A record must be compared
    against a concrete IPv4 address.  Multiple answers are intentionally
    rejected because a one-record cutover would otherwise be ambiguous.
    """
    raw = str(value or "").strip().strip("[]")
    try:
        return normalize_ipv4(raw)
    except CloudflareDNSError:
        pass

    if resolver is not None:
        values = resolver(raw)
    else:
        infos = socket.getaddrinfo(raw, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        values = [info[4][0] for info in infos if info and len(info) > 4 and info[4]]

    ips = sorted({normalize_ipv4(item) for item in values if str(item).strip()})
    if len(ips) != 1:
        raise CloudflareDNSError(
            f"Node address must resolve to exactly one IPv4 for DNS automation; got {len(ips)}"
        )
    return ips[0]


def record_fingerprint(record: Dict[str, Any], *, zone_id: Any) -> str:
    if not isinstance(record, dict):
        raise CloudflareDNSError("invalid Cloudflare DNS record")
    payload = {
        "zone_id": str(zone_id or ""),
        "id": str(record.get("id") or ""),
        "type": str(record.get("type") or ""),
        "name": normalize_hostname(record.get("name")),
        "content": normalize_ipv4(record.get("content")),
        "proxied": bool(record.get("proxied")),
        "ttl": record.get("ttl"),
        "modified_on": str(record.get("modified_on") or ""),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


Transport = Callable[[str, str, Dict[str, str], Optional[bytes], int], Dict[str, Any]]


def _urllib_transport(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    timeout: int,
) -> Dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8", errors="replace"))
            messages = detail.get("errors") if isinstance(detail, dict) else None
            bounded = json.dumps(messages, ensure_ascii=False)[:500] if messages else str(exc.reason)
        except Exception:
            bounded = str(exc.reason)
        raise CloudflareDNSError(f"Cloudflare HTTP {exc.code}: {bounded}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudflareDNSError(f"Cloudflare network error: {type(exc).__name__}") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise CloudflareDNSError("Cloudflare returned invalid JSON") from exc
    if not isinstance(payload, dict) or not payload.get("success"):
        errors = payload.get("errors") if isinstance(payload, dict) else None
        bounded = json.dumps(errors, ensure_ascii=False)[:500] if errors else "unknown API failure"
        raise CloudflareDNSError(f"Cloudflare API failed: {bounded}")
    return payload


class CloudflareDNSClient:
    """Minimal stale-safe Cloudflare A-record client for one managed endpoint."""

    def __init__(
        self,
        api_token: str,
        *,
        zone_id: Optional[str] = None,
        timeout: int = 15,
        transport: Optional[Transport] = None,
    ) -> None:
        token = str(api_token or "").strip()
        if not token:
            raise CloudflareDNSError("Cloudflare API token is not configured")
        self._token = token
        self.zone_id = str(zone_id or "").strip() or None
        self.timeout = max(1, int(timeout))
        self._transport = transport or _urllib_transport

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = API_BASE + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {key: value for key, value in query.items() if value is not None}
            )
        body = (
            json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            if json_body is not None
            else None
        )
        return self._transport(method, url, self._headers, body, self.timeout)

    def resolve_zone(self, hostname: Any) -> Dict[str, str]:
        host = normalize_hostname(hostname)
        if self.zone_id:
            return {"id": self.zone_id, "name": ""}

        page = 1
        zones = []
        while page <= 5:
            payload = self._request(
                "GET",
                "/zones",
                query={"page": page, "per_page": 50},
            )
            result = payload.get("result")
            if not isinstance(result, list):
                raise CloudflareDNSError("invalid Cloudflare zone list")
            zones.extend(item for item in result if isinstance(item, dict))
            info = payload.get("result_info") if isinstance(payload.get("result_info"), dict) else {}
            total_pages = int(info.get("total_pages") or page)
            if page >= total_pages or not result:
                break
            page += 1

        matches = []
        for zone in zones:
            name = normalize_hostname(zone.get("name")) if zone.get("name") else ""
            zone_id = str(zone.get("id") or "").strip()
            if not name or not zone_id:
                continue
            if host == name or host.endswith("." + name):
                matches.append((len(name), zone_id, name))
        if not matches:
            raise CloudflareDNSError(
                f"no accessible Cloudflare zone owns {host}; configure NVL_CLOUDFLARE_ZONE_ID or grant Zone Read"
            )
        _size, zone_id, name = max(matches)
        return {"id": zone_id, "name": name}

    def inspect_a_record(self, hostname: Any) -> Dict[str, Any]:
        host = normalize_hostname(hostname)
        zone = self.resolve_zone(host)
        payload = self._request(
            "GET",
            f"/zones/{zone['id']}/dns_records",
            query={"type": "A", "name": host, "per_page": 100},
        )
        records = payload.get("result")
        if not isinstance(records, list):
            raise CloudflareDNSError("invalid Cloudflare DNS record list")
        exact = [
            record for record in records
            if isinstance(record, dict)
            and str(record.get("type") or "").upper() == "A"
            and normalize_hostname(record.get("name")) == host
        ]
        if len(exact) > 1:
            raise CloudflareDNSError(
                f"multiple A records exist for {host}; automatic mutation is blocked"
            )
        if not exact:
            return {
                "exists": False,
                "hostname": host,
                "zone_id": zone["id"],
                "zone_name": zone["name"],
                "record": None,
                "fingerprint": None,
            }

        record = exact[0]
        content = normalize_ipv4(record.get("content"))
        normalized = dict(record)
        normalized["name"] = host
        normalized["content"] = content
        return {
            "exists": True,
            "hostname": host,
            "zone_id": zone["id"],
            "zone_name": zone["name"],
            "record": normalized,
            "fingerprint": record_fingerprint(normalized, zone_id=zone["id"]),
        }

    def create_a_record(
        self,
        hostname: Any,
        target_ip: Any,
        *,
        ttl: int = 60,
    ) -> Dict[str, Any]:
        host = normalize_hostname(hostname)
        target = normalize_ipv4(target_ip)
        before = self.inspect_a_record(host)
        if before.get("exists"):
            raise CloudflareDNSError(
                f"A record already exists for {host}; refusing implicit overwrite"
            )
        zone_id = str(before.get("zone_id") or "")
        self._request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json_body={
                "type": "A",
                "name": host,
                "content": target,
                "ttl": max(60, int(ttl)),
                "proxied": False,
            },
        )
        after = self.inspect_a_record(host)
        if (
            not after.get("exists")
            or str((after.get("record") or {}).get("content") or "") != target
            or bool((after.get("record") or {}).get("proxied"))
        ):
            raise CloudflareDNSError("Cloudflare A record did not verify after create")
        return {
            "changed": True,
            "created": True,
            "hostname": host,
            "zone_id": zone_id,
            "before": before,
            "after": after,
        }

    def switch_a_record(
        self,
        hostname: Any,
        target_ip: Any,
        *,
        expected_content: Any = None,
        expected_fingerprint: Optional[str] = None,
        expected_record_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Patch exactly one existing DNS-only A record and verify provider state."""
        host = normalize_hostname(hostname)
        target = normalize_ipv4(target_ip)
        before = self.inspect_a_record(host)
        if not before.get("exists"):
            raise CloudflareDNSError(f"A record does not exist for {host}")
        record = before.get("record") or {}

        if expected_record_id and str(record.get("id") or "") != str(expected_record_id):
            raise CloudflareDNSError("Cloudflare record identity changed since preview")
        if expected_fingerprint and str(before.get("fingerprint") or "") != str(expected_fingerprint):
            raise CloudflareDNSError("Cloudflare record changed since preview")
        if expected_content is not None:
            expected = normalize_ipv4(expected_content)
            if str(record.get("content") or "") != expected:
                raise CloudflareDNSError(
                    f"Cloudflare record content changed since preview: {record.get('content')}"
                )
        if bool(record.get("proxied")):
            raise CloudflareDNSError(
                "Cloudflare record is proxied; managed VPN Public Endpoints must be DNS-only"
            )

        if str(record.get("content") or "") == target:
            return {
                "changed": False,
                "created": False,
                "hostname": host,
                "zone_id": before["zone_id"],
                "before": before,
                "after": before,
            }

        self._request(
            "PATCH",
            f"/zones/{before['zone_id']}/dns_records/{record.get('id')}",
            json_body={"content": target, "proxied": False},
        )
        after = self.inspect_a_record(host)
        after_record = after.get("record") or {}
        if (
            not after.get("exists")
            or str(after_record.get("id") or "") != str(record.get("id") or "")
            or str(after_record.get("content") or "") != target
            or bool(after_record.get("proxied"))
        ):
            raise CloudflareDNSError("Cloudflare A record did not verify after update")
        return {
            "changed": True,
            "created": False,
            "hostname": host,
            "zone_id": before["zone_id"],
            "before": before,
            "after": after,
        }
