"""K: bounded Cloudflare Edge->Edge DNS port; no Core fallback or DB writes.

Uses the existing bot's Cloudflare settings shape through an injected
config_loader, but MUST NOT call the legacy _cf_update_dns_record_sync:
that API quite correctly refuses protected mode. Caller holds 6G lock.
Partial provider writes are uncertain and intentionally require 6G HOLD.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from hashlib import sha256
import urllib.parse
import urllib.request


class DnsHold(ValueError):
    pass


def _public(ip: str) -> str:
    try:
        value = ipaddress.IPv4Address(ip)
    except (TypeError, ipaddress.AddressValueError) as exc:
        raise DnsHold("INVALID_EDGE_IPV4") from exc
    if str(value) != ip or not value.is_global:
        raise DnsHold("INVALID_PUBLIC_EDGE_IPV4")
    return ip


def _domains(config: dict) -> tuple[str, ...]:
    if not isinstance(config, dict):
        raise DnsHold("CF_CONFIG_UNAVAILABLE")
    names = [config.get("public_domain")]
    if config.get("tls_passthrough") == "1":
        names.append(config.get("tls_domain"))
    result = tuple(dict.fromkeys(name for name in names if name))
    if not result or any(
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+", name)
        for name in result
    ):
        raise DnsHold("INVALID_DOMAIN_CONFIGURATION")
    return result


@dataclass(frozen=True)
class PinnedDnsRecord:
    name: str
    record_id: str
    content: str
    fingerprint: str


@dataclass(frozen=True)
class PinnedDnsCutover:
    source: str
    target: str
    zone_id: str
    records: tuple[PinnedDnsRecord, ...]

    def __post_init__(self):
        if (self.source == self.target or not self.records
                or len(set(r.name for r in self.records)) != len(self.records)):
            raise DnsHold("DNS_PLAN_INVALID")


def _fingerprint(zone: str, record: dict) -> str:
    """Stable per-record CAS over identity, content, TTL, proxy and modified_on."""
    if (not isinstance(record, dict)
            or not re.fullmatch(r"[a-f0-9]{32}", str(record.get("id", "")))
            or record.get("type") != "A"
            or record.get("proxied") is not False
            or type(record.get("ttl")) is not int
            or not 1 <= record["ttl"] <= 86400):
        raise DnsHold("DNS_RECORD_FINGERPRINT_UNTRUSTED")
    value = {
        "zone": zone, "id": record["id"], "type": record["type"],
        "name": str(record.get("name", "")).rstrip(".").lower(),
        "content": _public(record.get("content")), "ttl": record["ttl"],
        "proxied": record["proxied"],
        "modified_on": str(record.get("modified_on") or ""),
    }
    return sha256(json.dumps(value, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()


class ProtectedCloudflareDNS:
    def __init__(self, config_loader, *, opener=None):
        self.loader = config_loader
        self.opener = opener or urllib.request.urlopen

    def _config(self):
        cfg = self.loader()
        if not isinstance(cfg, dict) or not cfg.get("token") or not cfg.get("zone"):
            raise DnsHold("CF_AUTH_NOT_CONFIGURED")
        if not re.fullmatch(r"[a-f0-9]{32}", str(cfg["zone"])):
            raise DnsHold("CF_ZONE_UNTRUSTED")
        return cfg

    def _request(self, config, path, method="GET", payload=None):
        url = "https://api.cloudflare.com/client/v4/zones/" + config["zone"] + path
        headers = {"Authorization": "Bearer " + config["token"],
                   "Content-Type": "application/json"}
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener(req, timeout=12) as response:
                output = json.load(response)
        except (OSError, ValueError, TypeError) as exc:
            raise DnsHold("CF_REQUEST_UNCERTAIN") from exc
        if not isinstance(output, dict) or output.get("success") is not True:
            raise DnsHold("CF_RESPONSE_UNTRUSTED")
        return output.get("result")

    def _records(self, cfg, name):
        path = "/dns_records?" + urllib.parse.urlencode({
            "name": name, "type": "A", "per_page": 100,
        })
        # Do not silently accept a truncated list or multiple identities.
        result = self._request(cfg, path)
        if not isinstance(result, list) or len(result) != 1:
            raise DnsHold("CF_A_RECORD_UNIQUE_REQUIRED")
        record = result[0]
        if (not isinstance(record, dict) or record.get("type") != "A"
                or str(record.get("name", "")).rstrip(".").lower() != name.lower()
                or record.get("proxied") is not False
                or not re.fullmatch(r"[a-f0-9]{32}", str(record.get("id", "")))):
            raise DnsHold("CF_RECORD_IDENTITY_CHANGED")
        _fingerprint(cfg["zone"], record)
        return record

    def _assert_no_aaaa(self, cfg, name):
        path = "/dns_records?" + urllib.parse.urlencode({
            "name": name, "type": "AAAA", "per_page": 100,
        })
        records = self._request(cfg, path)
        if not isinstance(records, list) or records:
            raise DnsHold("CF_AAAA_RECORD_UNVERIFIED_OR_PRESENT")

    def preview_edge_to_edge(self, source: str, target: str) -> PinnedDnsCutover:
        source, target = _public(source), _public(target)
        if source == target:
            raise DnsHold("SAME_EDGE_NOT_A_SWITCH")
        cfg = self._config()
        names = _domains(cfg)
        result = []
        for name in names:
            self._assert_no_aaaa(cfg, name)
            rec = self._records(cfg, name)
            if rec.get("content") != source:
                raise DnsHold("CF_SOURCE_RECORD_CAS_LOST")
            result.append(PinnedDnsRecord(
                name, rec["id"], source, _fingerprint(cfg["zone"], rec),
            ))
        return PinnedDnsCutover(source, target, cfg["zone"], tuple(result))

    def assert_target(self, target: str):
        target = _public(target)
        cfg = self._config()
        for name in _domains(cfg):
            self._assert_no_aaaa(cfg, name)
            if self._records(cfg, name).get("content") != target:
                raise DnsHold("CF_DNS_NOT_AT_TARGET")

    def switch_edge_to_edge(self, source: str, target: str, *,
                            pinned_plan: PinnedDnsCutover | None = None,
                            guard=None):
        """Provider-level best effort, NOT an atomic multi-record CAS.

        Caller MUST own a persisted protected 6G intent and keep every UID
        denied until all records and subsequent admission checks are proven.
        Never automatically roll back an unknown partial provider mutation.
        """
        source, target = _public(source), _public(target)
        cfg = self._config()
        plan = pinned_plan if pinned_plan is not None else self.preview_edge_to_edge(
            source, target
        )
        if (not isinstance(plan, PinnedDnsCutover)
                or plan.source != source or plan.target != target
                or cfg["zone"] != plan.zone_id
                or tuple(_domains(cfg)) != tuple(x.name for x in plan.records)):
            raise DnsHold("CF_PINNED_PLAN_CHANGED")
        if guard is not None and not callable(guard):
            raise DnsHold("CF_LEASE_GUARD_INVALID")
        # Confirm ALL records are unchanged from immutable operator preview
        # BEFORE first mutation. Guard callback may enforce 6G/DB/UID fences.
        for item in plan.records:
            if guard is not None:
                guard()
            self._assert_no_aaaa(cfg, item.name)
            current = self._records(cfg, item.name)
            if (current["id"] != item.record_id
                    or _fingerprint(cfg["zone"], current) != item.fingerprint
                    or current["content"] != source):
                raise DnsHold("CF_PINNED_CAS_LOST")
        for item in plan.records:
            if guard is not None:
                guard()
            self._assert_no_aaaa(cfg, item.name)
            now = self._records(cfg, item.name)
            if (now["id"] != item.record_id or now["content"] != source
                    or _fingerprint(cfg["zone"], now) != item.fingerprint):
                raise DnsHold("CF_RECORD_CAS_LOST_BEFORE_WRITE")
            result = self._request(
                cfg, "/dns_records/" + item.record_id, method="PATCH",
                payload={"content": target, "proxied": False},
            )
            if (not isinstance(result, dict) or result.get("id") != item.record_id
                    or result.get("type") != "A"
                    or result.get("content") != target
                    or result.get("proxied") is not False):
                raise DnsHold("CF_WRITE_RESULT_UNTRUSTED")
            # Detect independent post-write changes before attempting next.
            self._assert_no_aaaa(cfg, item.name)
            after = self._records(cfg, item.name)
            if after.get("id") != item.record_id or after.get("content") != target:
                raise DnsHold("CF_POST_WRITE_IDENTITY_CHANGED")
        if guard is not None:
            guard()
        self.assert_target(target)
        return plan
