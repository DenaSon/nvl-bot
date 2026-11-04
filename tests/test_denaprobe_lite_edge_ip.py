"""DenaProbe Lite signed Edge target/IP, auth/transfer and Rich alert regressions."""
import json
from pathlib import Path
import tempfile
import unittest

from denaprobe_ingest import collector, detector, dpt2
from denaprobe_rich_admin import render_home, render_detail, render_transition

BOOT = "0123456789abcdef0123456789abcdef"
DEVICE = "dp-lite-test"
NOW = 2_000_000_000_000


def make(q, *, ip="198.51.100.22", mode="good", route=2):
    u = 100000 + q * 30000
    d = dict(v=2, id=DEVICE, b=BOOT, q=q, u=u, k=1, t=1,
             w=1, r=-47, s=1, p=52, o=255, d=12, x=3100, a=180,
             c={"u": u - 17000, "s": 1, "ms": 120})
    if ip is not None:
        d["ei"] = ip
    if mode == "dns":
        d.update(s=20, p=20, o=0)
        d.pop("a")
        d.pop("c")
        return d
    if mode == "tcp":
        d.update(s=30, p=30, o=0)
        d.pop("a")
        d["c"]["s"] = 20
        return d
    d["j"] = {"u": u - 16000, "s": 1, "ms": 300}
    complete = {"s": 1, "r": 8192, "n": 8192, "ms": 1100}
    failed = {"s": 20, "r": 8192, "n": 0, "ms": 12000}
    d["z"] = {"u": u - 100, "s": 1, "am": 300, "sm": 13500,
              "rt": route, "f": complete, "g": complete}
    if mode == "stalled":
        d["z"]["s"] = 40
        d["z"]["g"] = failed
    if mode == "http_status":
        d["z"]["s"] = 41
        d["z"]["g"] = {"s": 24, "r": 8192, "n": 0, "ms": 50}
    if mode == "forward_denied":
        d["z"] = {"u": u - 100, "s": 30, "am": 300, "sm": 500,
                  "rt": route, "f": {"s": 23, "r": 8192, "n": 0, "ms": 30}}
    if mode == "auth_rejected":
        d["j"]["s"] = 10
        d["z"] = {"u": u - 100, "s": 10, "am": 300, "sm": 300, "rt": route}
    return d


class LiteEdgeIp(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "lite.sqlite3"
        collector.initialize(self.db)
        dpt2.initialize(self.db)
        collector.register_target(self.db, 1, "n1.nvlsup.com", 2252)
        raw = {"v": 2, "id": DEVICE, "b": BOOT, "q": 1,
               "u": 500, "k": 3, "w": 1}
        self.assertEqual(dpt2.store(self.db, raw,
                         json.dumps(raw).encode(), 700, now_ms=NOW), 0)
        self.q = 1
        self.now = NOW

    def send(self, *, ip="198.51.100.22", mode="good", route=2, evaluate=True):
        self.q += 1
        self.now += 30000
        body = make(self.q, ip=ip, mode=mode, route=route)
        sent = max(body["u"], body.get("j", {}).get("u", 0),
                   body.get("z", {}).get("u", 0)) + 500
        self.assertEqual(dpt2.store(
            self.db, body, json.dumps(body, separators=(",", ":")).encode(),
            sent, allowed_targets=[1], now_ms=self.now), 0)
        if evaluate:
            detector.evaluate(self.db, now_ms=self.now + 1000)
        return body

    def test_lite_signed_fields_and_zero_legacy_impact(self):
        healthy = make(2)
        self.assertEqual(dpt2.validate(healthy, healthy["u"] + 50)[0], 1)
        self.assertEqual(detector.classify(healthy, direct_ok=False)[0],
                         detector.HEALTHY)
        stalled = make(2, mode="stalled")
        self.assertEqual(dpt2.validate(stalled, stalled["u"] + 50)[0], 1)
        self.assertEqual(detector.classify(stalled, direct_ok=False)[0],
                         detector.D2)
        rejected = make(2, mode="auth_rejected")
        self.assertEqual(dpt2.validate(rejected, rejected["u"] + 50)[0], 1)
        self.assertEqual(detector.classify(rejected, direct_ok=False)[0],
                         detector.UNKNOWN)
        old = make(2)
        old.pop("j")
        old.pop("z")
        old.pop("ei")
        self.assertEqual(dpt2.validate(old, old["u"] + 100)[0], 1)

    def test_reject_bad_edge_ipv4_and_invalid_semantics(self):
        good = make(2)
        for bad in ("", "localhost", "127.0.0.1:2252",
                    "1.2.3.4\nadmin", "256.0.0.1", "::1", "01.2.3.4",
                    None, True, 123):
            trial = dict(good, ei=bad)
            with self.subTest(ip=bad), self.assertRaises(collector.DptError):
                dpt2.validate(trial, good["u"] + 50)
        dns = make(2, mode="dns", ip=None)
        self.assertEqual(dpt2.validate(dns, dns["u"] + 100)[0], 1)
        dns["ei"] = "198.51.100.22"
        with self.assertRaises(collector.DptError):
            dpt2.validate(dns, dns["u"] + 100)
        invalid = make(2)
        invalid["j"]["s"] = 10  # cannot claim data success after auth denial
        with self.assertRaises(collector.DptError):
            dpt2.validate(invalid, invalid["u"] + 100)

    def test_dashboard_registered_hostname_measured_ip_and_port(self):
        self.send(ip="198.51.100.22")
        self.send(ip="198.51.100.22")
        model = detector.read_dashboard(self.db, now_ms=self.now + 1000)
        p = model["probes"][0]
        self.assertEqual((p["edge_hostname"], p["edge_port"], p["edge_ip"]),
                         ("n1.nvlsup.com", 2252, "198.51.100.22"))
        self.assertEqual((p["auth_code"], p["deep_route"]), (1, 2))
        card = str(render_home(model))
        for val in ("n1.nvlsup.com", "198.51.100.22", "2252"):
            self.assertIn(val, card)
        self.assertNotIn("Loopback داخلی", card)

    def test_http_route3_verified_body_and_non_censorship_failures(self):
        good = make(2, route=3)
        self.assertEqual(dpt2.validate(good, good["u"] + 100)[0], 1)
        self.assertEqual(detector.classify(good, direct_ok=False)[0],
                         detector.HEALTHY)
        stalled = make(2, mode="stalled", route=3)
        self.assertEqual(dpt2.validate(stalled, stalled["u"] + 100)[0], 1)
        self.assertEqual(detector.classify(stalled, direct_ok=False)[0],
                         detector.D2)
        for mode in ("http_status", "forward_denied"):
            failure = make(2, mode=mode, route=3)
            self.assertEqual(dpt2.validate(failure, failure["u"] + 100)[0], 1)
            self.assertEqual(detector.classify(failure, direct_ok=False)[0],
                             detector.UNKNOWN)
        bogus = make(2, mode="stalled", route=3)
        bogus["z"]["g"]["s"] = 24  # Cannot claim a timeout from 3xx/404.
        with self.assertRaises(collector.DptError):
            dpt2.validate(bogus, bogus["u"] + 100)
        legacy = make(2, route=2)
        self.assertEqual(dpt2.validate(legacy, legacy["u"] + 100)[0], 1)

    def test_http_stall_creates_one_Rich_incident_then_two_passes_recover(self):
        self.send(route=3)
        self.send(route=3)
        self.send(route=3, mode="stalled")
        self.assertFalse(detector.read_dashboard(
            self.db, now_ms=self.now+1000)["active"])  # first suspect
        self.send(route=3, mode="stalled")
        model = detector.read_dashboard(self.db, now_ms=self.now+1000)
        self.assertEqual(len(model["active"]), 1)
        self.assertEqual(model["active"][0]["observed_class"], detector.D2)
        with collector.connect_db(self.db) as db:
            tr = dict(db.execute(
                "SELECT id,incident_id,kind,confidence,occurred_at,"
                "evidence_sequence FROM dp3_transitions "
                "ORDER BY id DESC LIMIT 1").fetchone())
        msg = str(render_transition(model, {
            "transition_id": tr["id"], **tr,
        }))
        self.assertIn("HTTP", msg)
        self.assertIn("speedtest.tele2.net:80", msg)
        self.assertIn("198.51.100.22", msg)
        self.send(route=3)
        self.assertEqual(len(detector.read_dashboard(
            self.db, now_ms=self.now+1000)["active"]), 1)
        self.send(route=3)
        self.assertFalse(detector.read_dashboard(
            self.db, now_ms=self.now+1000)["active"])

    def test_notification_uses_trigger_sample_ip_not_newer_dns(self):
        self.send(ip="198.51.100.10")
        self.send(ip="198.51.100.10")
        self.send(ip="198.51.100.22", mode="tcp")
        with collector.connect_db(self.db) as db:
            tr = db.execute(
                "SELECT id,incident_id,occurred_at,evidence_sequence "
                "FROM dp3_transitions ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(tr)
            transition = dict(tr)
        # Newer DNS change arrives but no new detector evaluation yet.
        self.send(ip="198.51.100.33", mode="tcp", evaluate=False)
        model = detector.read_dashboard(self.db, now_ms=self.now+1000)
        self.assertEqual(model["probes"][0]["edge_ip"], "198.51.100.33")
        entry = {"transition_id": transition["id"],
                 "incident_id": transition["incident_id"],
                 "kind": "OPEN", "confidence": detector.EARLY,
                 "occurred_at": transition["occurred_at"],
                 "evidence_sequence": transition["evidence_sequence"]}
        msg = str(render_transition(model, entry))
        self.assertIn("198.51.100.22", msg)
        self.assertNotIn("198.51.100.33", msg)
        self.assertIn("n1.nvlsup.com", msg)
        self.assertIn("2252", msg)
        detail = str(render_detail(model, transition["incident_id"]))
        self.assertIn("دامنه Edge", detail)


if __name__ == "__main__":
    unittest.main()
