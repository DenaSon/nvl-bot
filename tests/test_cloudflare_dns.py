import json
import unittest
import urllib.parse

import cloudflare_dns


class FakeCloudflareTransport:
    def __init__(self):
        self.zone_id = "zone-1"
        self.zone_name = "nvlsup.xyz"
        self.records = {}
        self.calls = []
        self.counter = 0

    def add_record(self, name, content, *, proxied=False, ttl=60, record_id=None):
        self.counter += 1
        rid = record_id or f"rec-{self.counter}"
        self.records[name] = {
            "id": rid,
            "type": "A",
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
            "modified_on": f"2026-10-06T00:00:{self.counter:02d}Z",
        }
        return self.records[name]

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, body))
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        prefix = "/client/v4"
        if path.startswith(prefix):
            path = path[len(prefix):]

        if method == "GET" and path == "/zones":
            return {
                "success": True,
                "result": [{"id": self.zone_id, "name": self.zone_name}],
                "result_info": {"total_pages": 1},
            }

        if method == "GET" and path == f"/zones/{self.zone_id}/dns_records":
            name = (query.get("name") or [""])[0]
            rec = self.records.get(name)
            return {"success": True, "result": [dict(rec)] if rec else []}

        if method == "POST" and path == f"/zones/{self.zone_id}/dns_records":
            payload = json.loads(body.decode())
            if payload["name"] in self.records:
                raise AssertionError("test transport received duplicate create")
            rec = self.add_record(
                payload["name"],
                payload["content"],
                proxied=payload.get("proxied", False),
                ttl=payload.get("ttl", 60),
            )
            return {"success": True, "result": dict(rec)}

        if method == "PATCH" and path.startswith(f"/zones/{self.zone_id}/dns_records/"):
            rid = path.rsplit("/", 1)[-1]
            payload = json.loads(body.decode())
            for name, rec in self.records.items():
                if rec["id"] == rid:
                    rec.update(payload)
                    self.counter += 1
                    rec["modified_on"] = f"2026-10-06T00:01:{self.counter:02d}Z"
                    return {"success": True, "result": dict(rec)}
            raise AssertionError("unknown record id")

        raise AssertionError(f"unexpected call: {method} {url}")


class CloudflareDnsTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeCloudflareTransport()
        self.client = cloudflare_dns.CloudflareDNSClient(
            "secret-token",
            transport=self.transport,
        )

    def test_zone_discovery_and_exact_record_inspection(self):
        self.transport.add_record("argus.nvlsup.xyz", "45.61.149.116")
        result = self.client.inspect_a_record("ARGUS.NVLSUP.XYZ.")

        self.assertTrue(result["exists"])
        self.assertEqual(result["zone_id"], "zone-1")
        self.assertEqual(result["record"]["content"], "45.61.149.116")
        self.assertFalse(result["record"]["proxied"])
        self.assertTrue(result["fingerprint"])

    def test_switch_is_stale_safe_and_uses_patch(self):
        self.transport.add_record("argus.nvlsup.xyz", "172.86.72.203")
        before = self.client.inspect_a_record("argus.nvlsup.xyz")

        with self.assertRaises(cloudflare_dns.CloudflareDNSError):
            self.client.switch_a_record(
                "argus.nvlsup.xyz",
                "45.61.149.116",
                expected_content="172.86.72.203",
                expected_fingerprint="stale",
                expected_record_id=before["record"]["id"],
            )
        self.assertFalse(any(call[0] == "PATCH" for call in self.transport.calls))

        result = self.client.switch_a_record(
            "argus.nvlsup.xyz",
            "45.61.149.116",
            expected_content="172.86.72.203",
            expected_fingerprint=before["fingerprint"],
            expected_record_id=before["record"]["id"],
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["after"]["record"]["content"], "45.61.149.116")
        patch = [call for call in self.transport.calls if call[0] == "PATCH"][-1]
        self.assertEqual(
            json.loads(patch[2].decode()),
            {"content": "45.61.149.116", "proxied": False},
        )

    def test_proxied_record_is_never_mutated(self):
        self.transport.add_record(
            "argus.nvlsup.xyz",
            "172.86.72.203",
            proxied=True,
        )
        before = self.client.inspect_a_record("argus.nvlsup.xyz")
        with self.assertRaisesRegex(cloudflare_dns.CloudflareDNSError, "DNS-only"):
            self.client.switch_a_record(
                "argus.nvlsup.xyz",
                "45.61.149.116",
                expected_content="172.86.72.203",
                expected_fingerprint=before["fingerprint"],
            )
        self.assertFalse(any(call[0] == "PATCH" for call in self.transport.calls))

    def test_create_is_missing_only_and_verified(self):
        result = self.client.create_a_record(
            "new.nvlsup.xyz",
            "203.0.113.20",
        )
        self.assertTrue(result["created"])
        self.assertEqual(result["after"]["record"]["content"], "203.0.113.20")
        self.assertFalse(result["after"]["record"]["proxied"])

        with self.assertRaisesRegex(cloudflare_dns.CloudflareDNSError, "already exists"):
            self.client.create_a_record(
                "new.nvlsup.xyz",
                "203.0.113.21",
            )

    def test_single_ipv4_resolution_fails_closed_on_multiple_answers(self):
        one = cloudflare_dns.resolve_single_ipv4(
            "node.example",
            resolver=lambda _host: ["203.0.113.20"],
        )
        self.assertEqual(one, "203.0.113.20")

        with self.assertRaises(cloudflare_dns.CloudflareDNSError):
            cloudflare_dns.resolve_single_ipv4(
                "node.example",
                resolver=lambda _host: ["203.0.113.20", "203.0.113.21"],
            )


if __name__ == "__main__":
    unittest.main()
