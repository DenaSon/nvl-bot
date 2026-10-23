"""Hermetic CloudzyService tests: no token, network, purchase or VPS mutation."""

import json
import unittest

from cloudzy_service import (
    CloudzyAPIError,
    CloudzyError,
    CloudzyService,
    CloudzyTimeout,
    CloudzyUncertainError,
)


class FakeResponse:
    def __init__(self, payload=None, status=200, *, invalid_json=False):
        self.status_code = status
        self._payload = payload
        self._invalid_json = invalid_json
        self.content = b"" if payload is None else b"response"

    def json(self):
        if self._invalid_json:
            raise ValueError("invalid JSON")
        return self._payload


class FakeSession:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0) if self.responses else FakeResponse({"ok": True})
        if isinstance(response, Exception):
            raise response
        return response


class CloudzyServiceTests(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession()
        self.client = CloudzyService(token="hpt_TEST_DO_NOT_EXPOSE", session=self.session)

    def last(self):
        return self.session.calls[-1]

    def assert_route(self, method, path):
        got_method, url, kw = self.last()
        self.assertEqual(got_method, method)
        self.assertEqual(url, "https://dash.cloudzy.com/api/v1" + path)
        self.assertEqual(kw["headers"]["Authorization"], "Bearer hpt_TEST_DO_NOT_EXPOSE")
        return kw

    def test_catalog_and_account_routes(self):
        expected = [
            (self.client.list_regions, "/regions"),
            (self.client.list_servers, "/services"),
            (self.client.list_ssh_keys, "/ssh-keys"),
            (self.client.whoami, "/auth/me"),
            (self.client.get_balance, "/billing/summary"),
        ]
        for fn, path in expected:
            with self.subTest(path=path):
                fn()
                self.assert_route("GET", path)

    def test_server_read_routes_with_encoded_id(self):
        expected = [
            (self.client.get_server, "/services/a%2Fb"),
            (self.client.get_server_status, "/services/a%2Fb/status"),
            (self.client.get_server_usage, "/services/a%2Fb/usage"),
        ]
        for fn, path in expected:
            with self.subTest(path=path):
                fn("a/b")
                self.assert_route("GET", path)

    def test_plan_pricing_regional_and_fallback(self):
        self.session.responses.append(FakeResponse({
            "plans": [
                {"id": "one", "slug": "small"},
                {"id": "two", "slug": "large"},
                {"id": "three", "slug": "unpriced"},
            ],
            "prices": [
                {"planId": "one", "regionId": "", "billingCycle": "monthly", "monthlyEquivCents": 400},
                {"planId": "one", "regionId": "fra", "billingCycle": "monthly", "monthlyEquivCents": 500},
                {"planId": "two", "regionId": "", "billingCycle": "monthly", "monthlyEquivCents": 900},
                {"planId": "one", "regionId": "fra", "billingCycle": "hourly", "monthlyEquivCents": 600},
            ],
        }))
        out = self.client.list_plans(region="fra")
        self.assert_route("GET", "/pricing/catalog")
        self.assertEqual([p["price"]["monthlyEquivCents"] if p["price"] else None for p in out["plans"]], [500, 900, None])
        self.assertEqual([p["priceScope"] for p in out["plans"]], [
            "regional_catalog_base", "general_catalog_base", "unavailable",
        ])
        self.assertIn("exclude extras", out["notice"])
        with self.assertRaises(ValueError):
            self.client.list_plans(billing_cycle="invalid")

    def test_create_server_body_and_idempotency(self):
        result = self.client.create_server(
            hostname="edge-1", plan_id="plan-uuid", region="fra",
            os_template_id="ubuntu-24.04", billing_cycle="monthly",
            ssh_public_keys=["ssh-ed25519 AAAA test"], user_data="#cloud-config",
            ip_version="ipv4", idempotency_key="replay-key", confirm=True,
        )
        self.assertEqual(result, {"ok": True})
        kw = self.assert_route("POST", "/services")
        self.assertEqual(kw["headers"]["Idempotency-Key"], "replay-key")
        self.assertEqual(kw["json"], {
            "hostname": "edge-1", "planId": "plan-uuid", "region": "fra",
            "osTemplateId": "ubuntu-24.04", "billingCycle": "monthly",
            "sshAuthorizedKeys": ["ssh-ed25519 AAAA test"],
            "config": {"userData": "#cloud-config"}, "ipVersion": "ipv4",
        })
        self.assertEqual(kw["timeout"], 120)

    def test_create_rejects_no_confirmation_and_bad_inputs(self):
        with self.assertRaises(ValueError):
            self.client.create_server(hostname="x", plan_id="y", region="z")
        with self.assertRaises(ValueError):
            self.client.create_server(hostname="x", plan_id="y", region="z", ssh_public_keys="key", confirm=True)
        with self.assertRaises(ValueError):
            self.client.create_server(hostname="x", plan_id="y", region="z", ssh_public_keys=["-----BEGIN PRIVATE KEY-----"], confirm=True)
        with self.assertRaises(ValueError):
            self.client.create_server(hostname="x", plan_id="y", region="z", ip_version="bad", confirm=True)
        self.assertEqual(self.session.calls, [])

    def test_create_auto_generates_idempotency_key(self):
        self.client.create_server(hostname="edge", plan_id="p", region="r", confirm=True)
        key = self.last()[2]["headers"].get("Idempotency-Key")
        self.assertTrue(isinstance(key, str) and len(key) > 20)

    def test_power_and_rename_routes(self):
        for func, action in [
            (self.client.power_on, "start"),
            (self.client.power_off, "stop"),
            (self.client.restart_server, "reboot"),
        ]:
            func("s/1")
            kw = self.assert_route("POST", "/services/s%2F1/power")
            self.assertEqual(kw["json"], {"action": action})
        self.client.rename_server("s/1", "new-host")
        kw = self.assert_route("PATCH", "/services/s%2F1")
        self.assertEqual(kw["json"], {"hostname": "new-host"})

    def test_destructive_operations_need_confirmation(self):
        for run in [
            lambda: self.client.rebuild_server("id", os_template_id="ubuntu-24.04"),
            lambda: self.client.reset_server_password("id"),
            lambda: self.client.delete_server("id"),
            lambda: self.client.delete_ssh_key("key"),
        ]:
            with self.assertRaises(ValueError):
                run()
        self.assertEqual(self.session.calls, [])

    def test_destructive_routes_and_returns_one_time_password(self):
        self.client.rebuild_server("id", os_template_id="ubuntu-24.04", confirm=True)
        self.assertEqual(self.assert_route("POST", "/services/id/rebuild")["json"], {"osTemplate": "ubuntu-24.04"})
        self.session.responses.append(FakeResponse({"password": "shown-once"}))
        self.assertEqual(self.client.reset_server_password("id", confirm=True), {"password": "shown-once"})
        self.assertEqual(self.assert_route("POST", "/services/id/reset-password")["json"], {})
        self.client.delete_server("id", confirm=True)
        self.assert_route("DELETE", "/services/id")
        self.client.delete_ssh_key("key/id", confirm=True)
        self.assert_route("DELETE", "/ssh-keys/key%2Fid")

    def test_ssh_keys_add(self):
        self.client.add_ssh_key("edge key", "ssh-ed25519 AAAA comment")
        self.assertEqual(
            self.assert_route("POST", "/ssh-keys")["json"],
            {"name": "edge key", "publicKey": "ssh-ed25519 AAAA comment"},
        )
        with self.assertRaises(ValueError):
            self.client.add_ssh_key("secret", "-----BEGIN PRIVATE KEY-----")
        with self.assertRaises(ValueError):
            self.client.add_ssh_key("bad", "unexpected-key")

    def test_wait_until_active(self):
        self.session.responses = [
            FakeResponse({"state": "provisioning"}),
            FakeResponse({"state": "active", "ipAddress": "203.0.113.4"}),
        ]
        current = [0.0]
        self.client._monotonic = lambda: current[0]
        self.client._sleep = lambda seconds: current.__setitem__(0, current[0] + seconds)
        out = self.client.wait_for_ready("id", timeout=20, interval=3)
        self.assertEqual(out["ipAddress"], "203.0.113.4")
        self.assertEqual(len(self.session.calls), 2)

    def test_wait_terminal_state_and_timeout(self):
        self.session.responses = [FakeResponse({"state": "failed"})]
        with self.assertRaises(CloudzyError):
            self.client.wait_for_ready("id", interval=1)
        self.session.responses = [FakeResponse({"state": "pending"}) for _ in range(4)]
        clock = [0.0]
        self.client._monotonic = lambda: clock[0]
        self.client._sleep = lambda secs: clock.__setitem__(0, clock[0] + secs)
        with self.assertRaises(CloudzyTimeout):
            self.client.wait_for_ready("id", timeout=2, interval=1)

    def test_http_error_and_token_redaction(self):
        self.session.responses.append(FakeResponse({
            "error": "wrong hpt_TEST_DO_NOT_EXPOSE",
            "code": "unauthorized",
        }, status=401))
        with self.assertRaises(CloudzyAPIError) as ctx:
            self.client.list_regions()
        self.assertEqual(ctx.exception.status, 401)
        self.assertNotIn("hpt_TEST_DO_NOT_EXPOSE", str(ctx.exception))

    def test_uncertain_mutation_does_not_retry(self):
        self.session.responses = [TimeoutError("timed out")]
        with self.assertRaises(CloudzyUncertainError) as ctx:
            self.client.create_server(
                hostname="e", plan_id="p", region="fra",
                idempotency_key="safe-retry-1", confirm=True,
            )
        self.assertEqual(ctx.exception.idempotency_key, "safe-retry-1")
        self.assertEqual(len(self.session.calls), 1)
        self.session.responses = [FakeResponse({"error": "upstream"}, status=503)]
        with self.assertRaises(CloudzyUncertainError):
            self.client.delete_server("s", confirm=True)

    def test_read_network_and_bad_json_are_distinct(self):
        self.session.responses = [OSError("failed")]
        with self.assertRaises(CloudzyError):
            self.client.list_servers()
        self.session.responses = [FakeResponse({"ignored": True}, invalid_json=True)]
        with self.assertRaises(CloudzyError):
            self.client.whoami()
        self.session.responses = [FakeResponse({"ignored": True}, invalid_json=True)]
        with self.assertRaises(CloudzyUncertainError):
            self.client.restart_server("id")

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            CloudzyService(token="", session=self.session)
        with self.assertRaises(ValueError):
            CloudzyService(token="t", base_url="http://dash.cloudzy.com/api/v1")
        with self.assertRaises(ValueError):
            CloudzyService(token="t", base_url="https://dash.cloudzy.com/api")

    def test_empty_delete_response(self):
        self.session.responses = [FakeResponse(None, status=204)]
        self.assertIsNone(self.client.delete_server("id", confirm=True))


if __name__ == "__main__":
    unittest.main()
