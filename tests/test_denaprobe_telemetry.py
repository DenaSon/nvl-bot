"""Isolated DenaProbe ingestion security and data-contract tests (no live services)."""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from denaprobe_ingest import LocalHTTPServer, load_config, make_handler
from denaprobe_store import InvalidReport, init_db, latest_reports, save_report, validate_report
from denaprobe_telegram import _is_authorized, render_dashboard

DEVICE = "probe_01"
TOKEN = "local-test-token-" + "d" * 40
HOST = "n1.example.test"


def example_report(**patch):
    sample = {
        "schema_version": 1,
        "device_id": DEVICE,
        "boot_id": "1234abcd",
        "sequence": 1,
        "uptime_ms": 22843,
        "edge_host": HOST,
        "edge_ipv4": "198.51.100.15",
        "edge_port": 2252,
        "carrier_declared": "MCI",
        "wifi_rssi_dbm": -48,
        "dns_ok": True,
        "dns_ms": 26,
        "tcp_ok": True,
        "tcp_ms": 320,
        "ssh_id_ok": True,
        "ssh_id_ms": 213,
        "control_ok": None,
        "control_ms": None,
    }
    sample.update(patch)
    return sample


class ReportTests(unittest.TestCase):
    def test_valid_ssh_id_pass(self):
        parsed = validate_report(example_report(), allowed_host=HOST, authenticated_device=DEVICE)
        self.assertEqual(parsed["stage"], "SSH_ID_PASS")
        self.assertEqual(parsed["carrier_declared"], "MCI")

    def test_failures_not_misclassified_as_filtering(self):
        sample = example_report(dns_ok=False, dns_ms=4000, tcp_ok=None,
                                tcp_ms=None, ssh_id_ok=None, ssh_id_ms=None)
        parsed = validate_report(sample, allowed_host=HOST, authenticated_device=DEVICE)
        self.assertEqual(parsed["stage"], "DNS_FAIL")
        self.assertNotIn("FILTER", parsed["stage"])

    def test_fail_closed_invalid_values(self):
        for patch in (
            {"device_id": "other"},
            {"edge_host": "wrong-host.invalid"},
            {"edge_ipv4": "::1"},
            {"wifi_rssi_dbm": False},
            {"sequence": -1},
            {"dns_ok": "true"},
            {"dns_ok": False, "tcp_ok": True},
            {"tcp_ok": False, "ssh_id_ok": True},
            {"carrier_declared": "VERIFIED_MCI"},
            {"ssh_id_ms": 200000},
            {"schema_version": 2},
        ):
            with self.subTest(patch=patch):
                with self.assertRaises(InvalidReport):
                    validate_report(example_report(**patch), allowed_host=HOST,
                                    authenticated_device=DEVICE)

    def test_sqlite_dedup_isolated_and_latest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "reports.sqlite3")
            init_db(path)
            parsed = validate_report(example_report(), allowed_host=HOST,
                                     authenticated_device=DEVICE)
            self.assertTrue(save_report(path, parsed, received_at=100))
            self.assertFalse(save_report(path, parsed, received_at=101))
            latest = latest_reports(path)
            self.assertEqual(len(latest), 1)
            self.assertEqual(latest[0]["received_at"], 100)
            parsed2 = validate_report(example_report(sequence=2, uptime_ms=85000,
                                                     ssh_id_ms=218),
                                      allowed_host=HOST, authenticated_device=DEVICE)
            self.assertTrue(save_report(path, parsed2, received_at=200))
            self.assertEqual(latest_reports(path)[0]["seq"], 2)

    def test_bad_receiver_config_is_disabled(self):
        with self.assertRaises(ValueError):
            load_config({"DENAPROBE_EDGE_HOST": HOST})
        with self.assertRaises(ValueError):
            load_config({"DENAPROBE_EDGE_HOST": HOST,
                         "DENAPROBE_DEVICE_TOKENS_JSON": json.dumps({DEVICE: "weak"})})


class TelegramDashboardTests(unittest.TestCase):
    def test_private_active_admin_only(self):
        actor = SimpleNamespace(id=123)
        private = SimpleNamespace(id=123, type="private")
        update = SimpleNamespace(effective_user=actor, effective_chat=private)
        context = SimpleNamespace(user_data={"logged_in": True, "role": "admin"})
        self.assertTrue(_is_authorized(update, context, {123}))
        self.assertFalse(_is_authorized(update, context, set()))
        self.assertFalse(_is_authorized(update,
                                       SimpleNamespace(user_data={"logged_in": True, "role": "agent"}),
                                       {123}))
        self.assertFalse(_is_authorized(
            SimpleNamespace(effective_user=actor,
                            effective_chat=SimpleNamespace(id=456, type="group")),
            context, {123}
        ))

    def test_stale_data_is_not_presented_as_healthy(self):
        report = validate_report(example_report(),
                                 allowed_host=HOST, authenticated_device=DEVICE)
        # DB-facing render includes server time and statuses.
        row = {
            **report, "received_at": 1000,
            "dns_ok": 1, "tcp_ok": 1, "ssh_id_ok": 1, "control_ok": None,
        }
        self.assertIn("DNS/TCP/SSH Banner", render_dashboard([row], now=1010))
        self.assertIn("گزارش قدیمی", render_dashboard([row], now=1200))
        self.assertIn("هنوز گزارشی", render_dashboard([], now=1010))


class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "reports.sqlite3")
        init_db(self.path)
        self.server = LocalHTTPServer(
            ("127.0.0.1", 0),
            make_handler(db_path=self.path, allowed_host=HOST, keys={DEVICE: TOKEN}),
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _request(self, data=None, *, token=TOKEN, device=DEVICE,
                 path="/v1/reports", method="POST"):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {
            "X-DenaProbe-Device": device,
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        }
        body = b"" if data is None else json.dumps(data).encode()
        client.request(method, path, body=body, headers=headers)
        response = client.getresponse()
        status, parsed = response.status, json.loads(response.read().decode())
        client.close()
        return status, parsed

    def test_auth_and_idempotent_ingest(self):
        self.assertEqual(self._request(example_report(), token="wrong")[0], 401)
        self.assertEqual(self._request(example_report(), device="other")[0], 401)
        status, result = self._request(example_report())
        self.assertEqual(status, 200)
        self.assertEqual(result, {"ok": True, "duplicate": False})
        status, result = self._request(example_report())
        self.assertEqual(status, 200)
        self.assertEqual(result, {"ok": True, "duplicate": True})
        self.assertEqual(len(latest_reports(self.path)), 1)

    def test_bounded_body_and_schema_validation(self):
        self.assertEqual(self._request(example_report(edge_host="unknown.invalid"))[0], 400)
        self.assertEqual(self._request({**example_report(), "filler": "a" * 3000})[0], 413)
        self.assertEqual(self._request(example_report(), path="/invalid")[0], 404)

    def test_healthz_is_only_loopback_receiver(self):
        status, result = self._request(method="GET", path="/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
