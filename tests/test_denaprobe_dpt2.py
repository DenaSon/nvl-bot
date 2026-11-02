"""Hermetic DPT/2 v1-compatibility, HMAC, edge cases and HTTP gates."""
import hashlib
import hmac
import base64
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from denaprobe_ingest import collector as v1
from denaprobe_ingest import dpt2

DEVICE = "dp-lab-01"
BOOT = "0123456789abcdef0123456789abcdef"
KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
GOLDEN = '{"v":2,"id":"dp-lab-01","b":"0123456789abcdef0123456789abcdef","q":5,"u":120000,"k":1,"t":1,"w":1,"r":-48,"s":1,"p":52,"o":255,"d":12,"x":3200,"a":140,"c":{"u":119000,"s":1,"ms":150},"z":{"u":151500,"s":1,"am":400,"sm":25500,"f":{"s":1,"r":65536,"n":65536,"ms":600},"g":{"s":1,"r":65536,"n":65536,"ms":700}},"h":{"c":1,"u":155000,"n":65536,"bt":2500,"ms":4900}}'
SIGNATURE = "bOVcMQ_VBaf5Fu2RgZmlwGubhM47QsxhDRgcSZ3LYFc"


def encode(body):
    return json.dumps(body, separators=(",", ":")).encode()


def boot(b=BOOT):
    return dict(v=2, id=DEVICE, b=b, q=1, u=500, k=3, w=1)


def probe(q=2, **values):
    p = dict(v=2, id=DEVICE, b=BOOT, q=q, u=2000, k=1, t=1, w=1,
             r=-48, s=1, p=52, o=255, d=10, x=3000, a=200)
    p.update(values)
    return p


class TestDpt2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "db.sqlite3"
        self.keys = Path(self.tmp.name) / "keys.json"
        v1.initialize(self.db)
        dpt2.initialize(self.db)
        v1.atomic_devices(self.keys, {DEVICE: {
            "enabled": True, "keys": {"v2-k1": KEY, "k1": KEY}, "targets": [1]}})
        v1.register_target(self.db, 1, "example.net", 2252)

    def accept(self, body, sent=None):
        raw = encode(body)
        sent = sent if sent is not None else max(
            body["u"], body.get("h", {}).get("u", 0),
            body.get("c", {}).get("u", 0), body.get("z", {}).get("u", 0)) + 50
        return dpt2.store(self.db, body, raw, sent, allowed_targets=[1],
                          now_ms=1790000000000)

    def test_golden_mac_matches_cross_language_draft(self):
        raw = GOLDEN.encode()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "01c3b4075cacf88c899e7652a360b5fae7b75863812da23b17c4a4e94b4d5889")
        self.assertEqual(dpt2.sign(raw, DEVICE, "k-test", "156000", KEY), SIGNATURE)
        headers = {"x-dpt-device": [DEVICE], "x-dpt-key-id": ["v2-k1"],
                   "x-dpt-sent-uptime-ms": ["156000"],
                   "x-dpt-signature": [dpt2.sign(raw, DEVICE, "v2-k1", "156000", KEY)]}
        self.assertEqual(dpt2.authenticate(raw, headers, v1.load_devices(self.keys)),
                         (DEVICE, 156000))
        with self.assertRaises(v1.DptError):
            dpt2.authenticate(raw, {**headers, "x-dpt-key-id": ["k1"]},
                              v1.load_devices(self.keys))
        headers["x-dpt-signature"].append(headers["x-dpt-signature"][0])
        with self.assertRaises(v1.DptError):
            dpt2.authenticate(raw, headers, v1.load_devices(self.keys))

    def test_d0_no_deep_and_d1_first_full_second_timeout(self):
        self.assertEqual(self.accept(boot()), 0)
        d0 = probe(q=2, s=30, p=30, o=0,
                   c={"u": 1900, "s": 20, "ms": 3000})
        self.assertEqual(self.accept(d0), 0)
        d1 = probe(q=3, u=34000, c={"u": 34010, "s": 1, "ms": 100},
                   z={"u": 72000, "s": 20, "am": 300, "sm": 33000,
                      "f": {"s": 1, "r": 65536, "n": 65536, "ms": 650},
                      "g": {"s": 20, "r": 65536, "n": 0, "ms": 10000}})
        self.assertEqual(self.accept(d1), 0)
        with v1.connect_db(self.db) as db:
            v = db.execute("SELECT tcp_code,deep_code,first_bytes,second_bytes "
                           "FROM dpt2_events WHERE sequence=3").fetchone()
            self.assertEqual(tuple(v), (1, 20, 65536, 0))
            self.assertEqual(db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0], 0)

    def test_complete_and_fresh_https_stays_live(self):
        self.assertEqual(self.accept(boot()), 0)
        completed = {"u": 42000, "s": 1,
                     "f": {"s": 1, "r": 100, "n": 100, "ms": 600},
                     "g": {"s": 1, "r": 100, "n": 100, "ms": 900}}
        p = probe(q=2, c={"u": 1900, "s": 1, "ms": 100}, z=completed,
                  h={"c": 1, "u": 45000, "n": 65536, "bt": 1900})
        self.assertEqual(self.accept(p), 0)
        self.assertEqual(self.accept(probe(q=3, u=60000)), 0)
        with v1.connect_db(self.db) as db:
            row = db.execute("SELECT ssh_sequence,https_sequence,monitoring_gap "
                             "FROM dpt2_latest").fetchone()
            self.assertEqual(tuple(row), (3, 2, 0))

    def test_invalid_deep_shapes_and_timestamp_semantics(self):
        p = probe(z={"u": 2100, "s": 1})
        with self.assertRaises(v1.DptError):
            dpt2.validate(p, 2400)
        p = probe(z={"u": 2100, "s": 10,
                     "f": {"s": 1, "r": 10, "n": 10, "ms": 100}})
        with self.assertRaises(v1.DptError):
            dpt2.validate(p, 2400)
        p = probe(z={"u": 2100, "s": 1,
                     "f": {"s": 1, "r": 10, "n": 11, "ms": 100},
                     "g": {"s": 1, "r": 10, "n": 10, "ms": 100}})
        with self.assertRaises(v1.DptError):
            dpt2.validate(p, 2400)
        p = probe(z={"u": 2100, "s": 90})
        with self.assertRaises(v1.DptError):
            dpt2.validate(p, 2050)
        p = probe(s=30, p=30, o=0, z={"u": 2100, "s": 90})
        with self.assertRaises(v1.DptError):
            dpt2.validate(p, 2200)
        with self.assertRaises(v1.DptError):
            dpt2.validate(dict(boot(), c={"u": 300, "s": 1}), 1200)

    def test_unknown_and_expired_cannot_be_promoted(self):
        self.assertEqual(self.accept(boot()), 0)
        self.assertEqual(self.accept(probe(q=2, c={"u": 1800, "s": 777})), 2)
        self.assertEqual(self.accept(probe(q=3, u=5000), sent=100000), 2)
        with v1.connect_db(self.db) as db:
            self.assertIsNone(db.execute("SELECT ssh_sequence FROM dpt2_latest").fetchone()[0])

    def test_idempotent_duplicate_conflict_and_old_v1_independence(self):
        self.assertEqual(self.accept(boot()), 0)
        self.assertEqual(self.accept(boot()), 1)
        self.assertEqual(self.accept(probe()), 0)
        with self.assertRaises(v1.DptError) as err:
            self.accept(probe(d=12))
        self.assertEqual(err.exception.http_status, 409)
        with v1.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM dpt2_events").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0], 0)

    def test_http_disabled_default_enabled_auth_and_signed_ack(self):
        def server(enable):
            s = v1.CollectorHTTP(("127.0.0.1", 0), self.db, self.keys,
                                 enable_v2=enable)
            t = threading.Thread(target=s.serve_forever, daemon=True)
            t.start()
            self.addCleanup(lambda: (s.shutdown(), s.server_close(), t.join(3)))
            return s
        no = server(False)
        yes = server(True)
        def call(s, body, signed=True, token="v2-k1"):
            raw = encode(body)
            sent = str(max(body["u"], body.get("c", {}).get("u", 0)) + 100)
            conn = http.client.HTTPConnection("127.0.0.1", s.server_address[1], timeout=4)
            h = {"Content-Type": "application/json"}
            if signed:
                h.update({"X-DPT-Device": DEVICE, "X-DPT-Key-Id": token,
                          "X-DPT-Sent-Uptime-Ms": sent,
                          "X-DPT-Signature": dpt2.sign(raw, DEVICE, token, sent, KEY)})
            conn.request("POST", dpt2.ENDPOINT, body=raw, headers=h)
            res = conn.getresponse()
            status, data = res.status, json.loads(res.read())
            conn.close()
            return status, data
        self.assertEqual(call(no, boot())[0], 404)
        self.assertEqual(call(yes, boot(), signed=False)[0], 403)
        self.assertEqual(call(yes, boot(), token="k1")[0], 403)
        status, body = call(yes, boot())
        self.assertEqual((status, body["v"], body["ack"]["r"]), (200, 2, 0))
        self.assertEqual(call(yes, boot())[1]["ack"]["r"], 1)


if __name__ == "__main__":
    unittest.main()
