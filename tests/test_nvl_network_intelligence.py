"""P0/P1 tests: synthetic telemetry only; never contact production Core."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ops.nvl_network_intelligence import (
    EvidenceError, archive, build_baseline, classify, load_samples,
    observation, replay, verify,
)


T0 = datetime(2026, 11, 22, 11, 0, tzinfo=timezone.utc)


def sample(at, ssh=150, udpgw=140, cw=10, rx=4600, tx=36000,
           with_netdata=False, missing_awg=False):
    row = {
        "timestamp_utc": at.isoformat(),
        "sample_type": "unlabeled",
        "ports": {
            "established": {"by_port": {
                "2252": {"local": ssh, "remote": 0},
                "7300": {"local": udpgw, "remote": udpgw}}},
            "close-wait": {"by_port": {
                "7300": {"local": 0, "remote": cw}}}},
        "interface_rates_kbps": {} if missing_awg else {
            "awg0": {"received": rx, "sent": tx}},
        "errors": ["netdata/api: URLError"] if with_netdata else [],
        "netdata_1m_average": {} if with_netdata else {
            "net.awg0": {"received": rx, "sent": -tx}},
    }
    return row


def write_data(folder, records):
    folder.mkdir(exist_ok=True, parents=True)
    with (folder / "nvl-samples-20261122.jsonl").open("w") as stream:
        for record in records:
            stream.write(json.dumps(record) + "\n")


class P0P1Tests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.samples = self.root / "samples"

    def test_port_direction_and_units(self):
        row = sample(T0, ssh=208, udpgw=107, cw=133,
                     rx=2330, tx=22750)
        m = observation(row)
        self.assertEqual(m["ssh"], 208)
        self.assertEqual(m["udpgw"], 107)
        self.assertEqual(m["close_wait"], 133)
        self.assertEqual(m["awg_rx_mbps"], 2.33)
        self.assertEqual(m["awg_tx_mbps"], 22.75)
        self.assertTrue(m["valid"])

    def test_netdata_down_fallback_survives(self):
        m = observation(sample(T0, with_netdata=True))
        self.assertTrue(m["valid"])
        self.assertEqual(m["awg_tx_mbps"], 36)

    def test_missing_awg_is_unknown_not_zero(self):
        m = observation(sample(T0, missing_awg=True))
        self.assertFalse(m["valid"])
        self.assertIsNone(m["awg_rx_mbps"])
        self.assertIn("awg_tx_mbps", m["missing"])

    def test_strict_baseline_requires_hour(self):
        rows = [(T0 + timedelta(minutes=i), observation(sample(T0)))
                for i in range(29)]
        with self.assertRaises(EvidenceError):
            build_baseline(rows, T0, T0 + timedelta(minutes=30))

    def test_baseline_coverage_and_research_qualification(self):
        rows = [(T0 + timedelta(minutes=i),
                 observation(sample(T0, ssh=154)))
                for i in range(29)]
        b = build_baseline(rows, T0, T0 + timedelta(minutes=30), research=True)
        self.assertEqual(b["status"], "RESEARCH_ONLY")
        self.assertEqual(b["values"]["ssh"], 154)
        self.assertGreater(b["coverage"], .95)

    def test_low_coverage_rejected(self):
        rows = [(T0 + timedelta(minutes=i), observation(sample(T0)))
                for i in range(20)]
        with self.assertRaises(EvidenceError):
            build_baseline(rows, T0, T0 + timedelta(minutes=30), research=True)

    def test_complete_hour_baseline(self):
        rows = [(T0 + timedelta(minutes=i), observation(sample(T0)))
                for i in range(60)]
        b = build_baseline(rows, T0, T0 + timedelta(minutes=60))
        self.assertEqual(b["status"], "NORMAL_VERIFIED")

    def test_replay_multisignal_incident_and_recovery(self):
        rows = []
        for i in range(100):
            t = T0 + timedelta(minutes=i)
            if 60 <= i < 64:
                row = sample(t, ssh=200, cw=55, tx=35000)
            elif 64 <= i < 75:
                row = sample(t, ssh=290, udpgw=105, cw=140,
                             rx=2500, tx=22000)
            else:
                row = sample(t)
            rows.append((t, observation(row)))
        baseline = build_baseline(rows, T0, T0 + timedelta(minutes=60))
        report = replay(rows, baseline, T0 + timedelta(minutes=60),
                        T0 + timedelta(minutes=100))
        states = [t["to"] for t in report["transitions"]]
        self.assertIn("SUSPECTED", states)
        self.assertIn("DEGRADED", states)
        self.assertIn("RECOVERING", states)
        self.assertEqual(report["state"], "NORMAL")
        self.assertEqual(report["telegram_messages_sent"], 0)

    def test_gap_does_not_silently_close_open_incident(self):
        rows = []
        for i in range(70):
            t = T0 + timedelta(minutes=i)
            degraded = i >= 60
            rows.append((t, observation(sample(
                t, ssh=290 if degraded else 150,
                udpgw=105 if degraded else 140,
                cw=140 if degraded else 10,
                tx=22000 if degraded else 36000
            ))))
        # Following a telemetry gap, only five recovery points exist.
        # An unresolved incident must remain UNKNOWN, never NORMAL.
        for i in range(75, 80):
            t = T0 + timedelta(minutes=i)
            rows.append((t, observation(sample(t))))
        b = build_baseline(rows, T0, T0 + timedelta(minutes=60))
        result = replay(rows, b, T0 + timedelta(minutes=60),
                        T0 + timedelta(minutes=80))
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertTrue(any(t["reason"] == "SAMPLE_GAP"
                            for t in result["transitions"]))

    def test_unlabeled_normal_not_accepted_as_training(self):
        rows = [sample(T0 + timedelta(minutes=i), ssh=150)
                for i in range(30)]
        # An early 'normal' snapshot is not even part of the JSONL
        # verified interval and must not contaminate baseline.
        early_normal = sample(T0 + timedelta(minutes=35), ssh=300, cw=190)
        early_normal["condition"] = "normal"
        write_data(self.samples, rows + [early_normal])
        loaded = load_samples(self.samples, T0, T0 + timedelta(minutes=36))
        baseline = build_baseline(loaded, T0, T0 + timedelta(minutes=30),
                                  research=True)
        self.assertEqual(baseline["values"]["ssh"], 150)

    def test_archive_is_lossless_and_verifiable(self):
        records = [sample(T0 + timedelta(minutes=i)) for i in range(8)]
        write_data(self.samples, records)
        snapshot = sample(T0 + timedelta(minutes=3))
        snapshot["condition"] = "disruption"
        snapshot["netdata_10m_average"] = {"net.awg0": {
            "received": 4000, "sent": -30000}}
        name = "20261122T110300.000000Z_disruption.json"
        (self.samples / name).write_text(json.dumps(snapshot) + "\n")
        original = (self.samples / name).read_bytes()
        result = archive(self.samples, self.root / "archives", "NVL-INC-TEST",
                         T0 + timedelta(minutes=2),
                         T0 + timedelta(minutes=6))
        output = Path(result["path"])
        self.assertEqual((output / name).read_bytes(), original)
        lines = (output / "nvl-samples-20261122.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertEqual(verify(output)["status"], "PASS")
        with self.assertRaises(EvidenceError):
            archive(self.samples, self.root / "archives", "NVL-INC-TEST",
                    T0, T0 + timedelta(minutes=8))
        with (output / name).open("a") as f:
            f.write("tampered")
        with self.assertRaises(EvidenceError):
            verify(output)

    def test_archive_rejects_sensitive_fields(self):
        r = sample(T0)
        r["client_ip"] = "not-even-a-real-ip"
        write_data(self.samples, [r])
        with self.assertRaises(EvidenceError):
            archive(self.samples, self.root / "archive", "EVT-1",
                    T0, T0 + timedelta(minutes=1))

    def test_snapshot_absence_aborts_archive(self):
        write_data(self.samples, [sample(T0)])
        with self.assertRaises(EvidenceError):
            archive(self.samples, self.root / "archive", "EVT-2",
                    T0, T0 + timedelta(minutes=1))


if __name__ == "__main__":
    unittest.main()
