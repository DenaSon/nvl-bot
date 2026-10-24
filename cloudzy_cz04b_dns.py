"""CZ-04B Cloudflare exact-record read/compare/write adapter.

Only records explicitly configured in NVL are touched. A proxied or ambiguous
A record fails closed. Core database settings are NEVER updated by this adapter;
the CZ-04B coordinator commits those after verifying live DNS.
"""
from __future__ import annotations
import ipaddress
import json
from urllib.error import HTTPError
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
        # Only use an auth mode after a successful DNS GET. Never retry DNS writes.
        self._auth_identity = None
        self._auth_mode = None

    @staticmethod
    def _transport(url, headers, payload=None, method="GET"):
        request = Request(
            url, headers=headers, data=payload, method=method,
        )
        with urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _headers(cfg, mode):
        if mode == "global":
            headers = {
                "X-Auth-Email": cfg["email"],
                "X-Auth-Key": str(cfg["token"]).strip(),
            }
        else:
            headers = {"Authorization": "Bearer " + str(cfg["token"]).strip()}
        headers["Content-Type"] = "application/json"
        return headers

    @staticmethod
    def _auth_rejected(payload):
        # Cloudflare: 9106=authentication failed, 10000=authentication error.
        # Never switch credentials for ordinary DNS/permission failures.
        return isinstance(payload, dict) and any(
            isinstance(err, dict) and str(err.get("code")) in ("9106", "10000")
            for err in (payload.get("errors") or [])
        )

    def _access(self):
        cfg = self.config()
        zone = str(cfg.get("zone") or "").strip()
        token = str(cfg.get("token") or "").strip()
        if not zone or not token or not cfg.get("public_domain"):
            raise DNSHold("CLOUDFLARE_CONFIG_MISSING")
        identity = (zone, token, str(cfg.get("email") or ""))
        if identity != self._auth_identity:
            self._auth_identity = identity
            self._auth_mode = None
        # Email may be left over from an older Global API Key configuration.
        # It does not prove that the configured credential is a Global Key.
        return cfg, zone, self._headers(cfg, self._auth_mode or "bearer")

    def _read(self, url, cfg, headers):
        """Discover Global-Key auth using GET only, and pin it for subsequent PUTs."""
        try:
            payload = self.transport(url, headers)
        except HTTPError as exc:
            if not cfg.get("email") or self._auth_mode is not None:
                raise
            try:
                error = json.loads(exc.read().decode("utf-8"))
            except (ValueError, UnicodeError) as parse_error:
                raise DNSHold("DNS_AUTH_RESPONSE_INVALID") from parse_error
            if not self._auth_rejected(error):
                raise DNSHold("DNS_READ_ERROR") from exc
            payload = self.transport(url, self._headers(cfg, "global"))
            if payload.get("success") is True:
                self._auth_mode = "global"
            return payload
        if (self._auth_mode is None and cfg.get("email")
                and self._auth_rejected(payload)):
            payload = self.transport(url, self._headers(cfg, "global"))
            if payload.get("success") is True:
                self._auth_mode = "global"
        elif self._auth_mode is None and payload.get("success") is True:
            self._auth_mode = "bearer"
        return payload

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
            # A preceding GET may have verified a legacy Global Key. Rebuild the
            # headers for each record instead of reusing an earlier Bearer header.
            headers = self._headers(cfg, self._auth_mode or "bearer")
            payload = self._read(url, cfg, headers)
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
