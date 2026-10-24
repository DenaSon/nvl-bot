"""CZ-04B Cloudflare exact-record read/compare/write adapter.

Only records explicitly configured in NVL are touched. A proxied or ambiguous
A record fails closed. Core database settings are NEVER updated by this adapter;
the CZ-04B coordinator commits those after verifying live DNS.
"""
from __future__ import annotations
import ipaddress
import json
from urllib.parse import quote
from urllib.request import Request, urlopen


class DNSHold(RuntimeError):
    pass


def _ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except ValueError as exc:
        raise DNSHold("INVALID_IPV4") from exc


class CloudflareExactDNS:
    def __init__(self, config, *, transport=None):
        self.config = config
        self.transport = transport or self._transport

    @staticmethod
    def _transport(url, headers, payload=None, method="GET"):
        request = Request(
            url, headers=headers, data=payload, method=method,
        )
        with urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    def _access(self):
        cfg = self.config()
        zone = str(cfg.get("zone") or "").strip()
        token = str(cfg.get("token") or "").strip()
        if not zone or not token or not cfg.get("public_domain"):
            raise DNSHold("CLOUDFLARE_CONFIG_MISSING")
        if cfg.get("email"):
            headers = {"X-Auth-Email": cfg["email"], "X-Auth-Key": token}
        else:
            headers = {"Authorization": "Bearer " + token}
        headers["Content-Type"] = "application/json"
        return cfg, zone, headers

    def snapshot(self):
        cfg, zone, headers = self._access()
        names = [str(cfg["public_domain"]).strip().lower()]
        if str(cfg.get("tls_passthrough", "1")) == "1":
            tls = str(cfg.get("tls_domain") or "").strip().lower()
            if not tls:
                raise DNSHold("TLS_DOMAIN_MISSING")
            if tls not in names:
                names.append(tls)
        entries = []
        for name in names:
            url = ("https://api.cloudflare.com/client/v4/zones/"
                   + quote(zone, safe="") + "/dns_records?type=A&name="
                   + quote(name, safe=""))
            payload = self.transport(url, headers)
            if payload.get("success") is not True:
                raise DNSHold("DNS_READ_ERROR")
            rows = [row for row in (payload.get("result") or [])
                    if row.get("type") == "A"
                    and str(row.get("name") or "").lower() == name]
            if len(rows) != 1 or rows[0].get("proxied") is not False:
                raise DNSHold("DNS_RECORD_AMBIGUOUS_OR_PROXIED")
            record = rows[0]
            if not record.get("id"):
                raise DNSHold("DNS_RECORD_ID_MISSING")
            entries.append({
                "name": name, "id": str(record["id"]),
                "ip": _ip(record.get("content")),
                "ttl": int(record.get("ttl") or 1),
            })
        return entries

    def set_all(self, expected, new_ip):
        """Check exact record identity and values before each external mutation."""
        new_ip = _ip(new_ip)
        if not expected:
            raise DNSHold("DNS_SNAPSHOT_EMPTY")
        for expected_record in expected:
            current = {r["name"]: r for r in self.snapshot()}
            wanted = current.get(expected_record["name"])
            if not wanted or any(
                wanted.get(k) != expected_record.get(k)
                for k in ("name", "id", "ip", "ttl")
            ):
                raise DNSHold("DNS_CHANGED_CONCURRENTLY")
            cfg, zone, headers = self._access()
            url = ("https://api.cloudflare.com/client/v4/zones/"
                   + quote(zone, safe="") + "/dns_records/"
                   + quote(expected_record["id"], safe=""))
            body = json.dumps({
                "type": "A", "name": expected_record["name"],
                "content": new_ip, "ttl": expected_record["ttl"], "proxied": False,
            }).encode("utf-8")
            result = self.transport(url, headers, body, method="PUT")
            if result.get("success") is not True:
                raise DNSHold("DNS_WRITE_REJECTED")
        actual = self.snapshot()
        if len(actual) != len(expected) or any(r["ip"] != new_ip for r in actual):
            raise DNSHold("DNS_POSTCHECK_MISMATCH")
        return actual
