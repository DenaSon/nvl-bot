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
        path = "/dns_records?" + urllib.parse.urlencode({"name": name, "type": "A"})
        result = self._request(cfg, path)
        if not isinstance(result, list) or len(result) != 1:
            raise DnsHold("CF_A_RECORD_UNIQUE_REQUIRED")
        record = result[0]
        if (not isinstance(record, dict) or record.get("type") != "A"
                or str(record.get("name", "")).rstrip(".") != name
                or record.get("proxied") is not False
                or not re.fullmatch(r"[a-f0-9]{32}", str(record.get("id", "")))):
            raise DnsHold("CF_RECORD_IDENTITY_CHANGED")
        return record

    def assert_target(self, target: str):
        target = _public(target)
        cfg = self._config()
        for name in _domains(cfg):
            if self._records(cfg, name).get("content") != target:
                raise DnsHold("CF_DNS_NOT_AT_TARGET")

    def switch_edge_to_edge(self, source: str, target: str):
        source, target = _public(source), _public(target)
        if source == target:
            raise DnsHold("SAME_EDGE_NOT_A_SWITCH")
        cfg = self._config()
        records = [(name, self._records(cfg, name)) for name in _domains(cfg)]
        # Read ALL records and ensure they still resolve to the same old
        # public Edge before writing the FIRST one.
        if any(rec.get("content") != source for _, rec in records):
            raise DnsHold("CF_SOURCE_RECORD_CAS_LOST")
        for name, rec in records:
            self._request(
                cfg, "/dns_records/" + rec["id"], method="PUT",
                payload={
                    "type": "A", "name": name, "content": target,
                    "ttl": rec.get("ttl", 1), "proxied": False,
                },
            )
        # Cloudflare multi-record PUT is not atomic. Never claim success
        # after only an HTTP 200: verify every actual record again.
        self.assert_target(target)
