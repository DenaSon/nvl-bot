"""Standalone DPT/1 contract tests. No real network, NVLBot DB or production keys."""
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from denaprobe_ingest import collector as dpt

PUBLIC_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
DEVICE = "dp-lte-01"
BOOT = "57fce203c6e94baf8d32749c11f0a65d"
OTHER_BOOT = "8af37b68cf1d4662acd8d9512b70f305"
RAW_VECTOR = ('{"v":1,"id":"dp-lte-01","b":"57fce203c6e94baf8d32749c11f0a65d",'
              '"q":16,"u":453000,"k":1,"t":1,"w":1,"r":-39,"s":1,"p":52,'
              '"o":255,"d":1,"x":3298,"a":198}').encode()
EXPECTED = "FvC6ftohQqvxpjiMdAQx-nCdsU3NccQdfZQKBGQpoBA"


def probe(q=2, u=5000, boot=BOOT, **changes):
    b = {"v": 1, "id": DEVICE, "b": boot, "q": q, "u": u, "k": 1,
         "t": 1, "w": 1, "r": -47, "s": 1, "p": 52, "o": 255,
         "d": 1, "x": 3300, "a": 180}
    b.update(changes)
    return b


def boot(boot_id=BOOT, uptime=1000):
    return {"v": 1, "id": DEVICE, "b": boot_id, "q": 1, "u": uptime, "k": 3, "w": 1}


def encoded(body):
    return json.dumps(body, separators=(",", ":")).encode()


class TestDptIngest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "events.sqlite3"
        self.keys = Path(self.tmp.name) / "devices.json"
        dpt.initialize(self.db)
        dpt.atomic_devices(self.keys, {
            DEVICE: {"enabled": True, "keys": {"k1": PUBLIC_KEY}, "targets": [1]}
        })
        dpt.register_target(self.db, 1, "n1.nvlsup.com", 2252)

    def submit(self, body, sent=None, allowed=[1]):
        u = body["u"]
        sent = sent if sent is not None else u + 50
        return dpt.store(self.db, body, encoded(body), sent, allowed_targets=allowed,
                         now_ms=1780000000000)

    def test_golden_vector(self):
        self.assertEqual(dpt.signed_mac(RAW_VECTOR, DEVICE, "k1", "453500", PUBLIC_KEY),
                         EXPECTED)
        headers = {"x-dpt-device": [DEVICE], "x-dpt-key-id": ["k1"],
                   "x-dpt-sent-uptime-ms": ["453500"],
                   "x-dpt-signature": [EXPECTED]}
        who, sent = dpt.authenticate(RAW_VECTOR, headers, dpt.load_devices(self.keys))
        self.assertEqual((who, sent), (DEVICE, 453500))
        for k in headers:
            bad = dict(headers)
            bad[k] = ["bad-value"]
            with self.assertRaises(dpt.DptError):
                dpt.authenticate(RAW_VECTOR, bad, dpt.load_devices(self.keys))
        changed = RAW_VECTOR.replace(b'"d":1', b'"d":2')
        with self.assertRaises(dpt.DptError):
            dpt.authenticate(changed, headers, dpt.load_devices(self.keys))
        headers["x-dpt-device"] = [DEVICE, DEVICE]
        with self.assertRaises(dpt.DptError):
            dpt.authenticate(RAW_VECTOR, headers, dpt.load_devices(self.keys))

    def test_schema_rejects_semantic_and_shape_errors(self):
        candidates = [
            dict(probe(), v=2), dict(probe(), v=True),
            dict(probe(), q=0), dict(probe(), q=1.5),
            dict(probe(), s=50), dict(probe(), s=41, p=40),
            dict(probe(), s=1, o=127),
            dict(probe(), w=0), dict(probe(), id="bad space"),
            dict(probe(), h={"c": 1, "u": 5100, "n": 120}),
            dict(probe(), unused=12),
        ]
        for row in candidates:
            with self.subTest(row=row), self.assertRaises(dpt.DptError):
                dpt.validate(row, 5150)
        ok = probe(h={"c": 11, "u": 5200})
        self.assertEqual(dpt.validate(ok, 5300), (1, False))
        unknown = probe(s=199, p=199, h={"c": 555, "u": 5200})
        self.assertEqual(dpt.validate(unknown, 5300), (1, True))
        with self.assertRaises(dpt.DptError):
            dpt.json_body(b'{"v":1,"v":1}')
        with self.assertRaises(dpt.DptError):
            dpt.json_body(b'{"v":NaN}')

    def test_first_boot_and_exact_duplicate(self):
        b = boot()
        self.assertEqual(self.submit(b), 0)
        self.assertEqual(self.submit(b), 1)
        self.assertEqual(self.submit(probe()), 0)
        self.assertEqual(self.submit(probe()), 1)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0], 2)
            latest = db.execute("SELECT * FROM device_latest_state").fetchone()
            self.assertEqual(latest["ssh_sequence"], 2)
            self.assertEqual(latest["boot_id"], BOOT)
        malicious = probe(d=2)
        with self.assertRaises(dpt.DptError) as exc:
            self.submit(malicious)
        self.assertEqual(exc.exception.http_status, 409)

    def test_delayed_and_out_of_order_never_become_live(self):
        self.assertEqual(self.submit(boot()), 0)
        self.assertEqual(self.submit(probe(q=4)), 2)  # q2/q3 gap
        self.assertEqual(self.submit(probe(q=2)), 2)  # old sample
        self.assertEqual(self.submit(probe(q=5)), 0)  # contiguous from 4
        with dpt.connect_db(self.db) as db:
            latest = db.execute("SELECT ssh_sequence,monitoring_gap FROM device_latest_state").fetchone()
            self.assertEqual(latest["ssh_sequence"], 5)
            self.assertEqual(latest["monitoring_gap"], 1)  # prior sequence gap not erased
        self.assertEqual(self.submit(probe(q=6, u=8000), sent=100000), 2)
        self.assertEqual(self.submit(probe(q=7, s=199, p=199)), 2)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT ssh_sequence FROM device_latest_state").fetchone()[0], 5)

    def test_boot_replay_cannot_reactivate(self):
        self.assertEqual(self.submit(boot()), 0)
        self.assertEqual(self.submit(probe()), 0)
        self.assertEqual(self.submit(boot(OTHER_BOOT, uptime=1000)), 0)
        self.assertEqual(self.submit(probe(2, 2000, boot=OTHER_BOOT)), 0)
        self.assertEqual(self.submit(probe(3, 9000, boot=BOOT)), 2)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT current_boot FROM devices").fetchone()[0], OTHER_BOOT)
            self.assertEqual(db.execute("SELECT boot_id FROM device_latest_state").fetchone()[0], OTHER_BOOT)

    def test_unregistered_or_unknown_target_is_history_only(self):
        self.assertEqual(self.submit(probe()), 2)
        self.assertEqual(self.submit(boot()), 2)  # out-of-order orphan boot cannot replace history
        self.assertEqual(self.submit(boot(OTHER_BOOT)), 0)
        self.assertEqual(self.submit(probe(2, boot=OTHER_BOOT), allowed=[]), 2)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT ssh_sequence FROM device_latest_state").fetchone()[0], None)

    def test_two_fresh_results_reestablish_continuity(self):
        self.assertEqual(self.submit(boot()), 0)
        self.assertEqual(self.submit(probe(q=2)), 0)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT monitoring_gap FROM device_latest_state").fetchone()[0], 1)
        self.assertEqual(self.submit(probe(q=3, u=9000)), 0)
        with dpt.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT monitoring_gap FROM device_latest_state").fetchone()[0], 0)

    def test_device_event_does_not_override_ssh(self):
        self.assertEqual(self.submit(boot()), 0)
        self.assertEqual(self.submit(probe()), 0)
        e = {"v": 1, "id": DEVICE, "b": BOOT, "q": 3, "u": 6000,
             "k": 2, "s": 96, "w": 0}
        self.assertEqual(self.submit(e), 0)
        with dpt.connect_db(self.db) as db:
            row = db.execute("SELECT ssh_sequence,monitoring_gap FROM device_latest_state").fetchone()
            self.assertEqual(row["ssh_sequence"], 2)
            self.assertEqual(row["monitoring_gap"], 1)

    def test_key_permissions_and_rotation(self):
        self.keys.chmod(0o644)
        with self.assertRaises(ValueError):
            dpt.load_devices(self.keys)
        self.keys.chmod(0o600)
        self.assertEqual(len(dpt.load_devices(self.keys)[DEVICE]["keys"]["k1"]), 64)

    def test_http_real_ack_and_refusals(self):
        srv = dpt.CollectorHTTP(("127.0.0.1", 0), self.db, self.keys)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), thread.join(timeout=3)))
        port = srv.server_address[1]
        def request(method, path, body=None, signed=True, overrides=None):
            raw = encoded(body) if isinstance(body, dict) else (body or b"")
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            headers = {"Content-Type": "application/json"}
            if signed:
                headers.update({
                    "X-DPT-Device": DEVICE, "X-DPT-Key-Id": "k1",
                    "X-DPT-Sent-Uptime-Ms": str((body["u"] if isinstance(body, dict) else 0) + 100),
                    "X-DPT-Signature": dpt.signed_mac(raw, DEVICE, "k1",
                       str((body["u"] if isinstance(body, dict) else 0) + 100), PUBLIC_KEY),
                })
            headers.update(overrides or {})
            conn.request(method, path, body=raw if method == "POST" else None, headers=headers)
            response = conn.getresponse()
            payload = response.read()
            status = response.status
            conn.close()
            return status, json.loads(payload)
        self.assertEqual(request("GET", "/healthz")[0], 200)
        self.assertEqual(request("GET", "/private")[0], 404)
        self.assertEqual(request("POST", dpt.ENDPOINT, boot())[1]["ack"]["r"], 0)
        self.assertEqual(request("POST", dpt.ENDPOINT, boot())[1]["ack"]["r"], 1)
        self.assertEqual(request("POST", dpt.ENDPOINT, probe())[1]["ack"]["r"], 0)
        self.assertEqual(request("POST", dpt.ENDPOINT, probe(d=2))[0], 409)
        self.assertEqual(request("POST", dpt.ENDPOINT, probe(q=3),
                                 overrides={"X-DPT-Signature": "x" * 43})[0], 403)
        self.assertEqual(request("POST", dpt.ENDPOINT, probe(q=3),
                                 signed=False)[0], 403)
        self.assertEqual(request("POST", dpt.ENDPOINT, b"x" * 1025)[0], 413)
        self.assertEqual(request("POST", "/other", probe(q=3))[0], 404)
        self.assertEqual(request("POST", dpt.ENDPOINT, probe(q=3, v=2))[0], 422)


if __name__ == "__main__":
    unittest.main()
