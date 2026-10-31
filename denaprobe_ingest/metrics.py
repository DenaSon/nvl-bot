"""R2-D1 read-only telemetry metrics for DenaProbe; never imports NVLBot.

Evidence quality: per-boot sequence gaps are observable gaps (not proof of
on-wire packet loss); sender_age is device-reported queue age (not network RTT).
Missing traffic and absent HTTPS samples are NOT network failures.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import math
from pathlib import Path
import re
import sqlite3
import time

DEFAULT_DB = Path("/var/lib/denaprobe/telemetry.sqlite3")
DEVICE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
MAX_ROWS = 30000
SSH_FRESH_MS = 90000
HTTPS_FRESH_MS = 360000
DELIVERY_FRESH_MS = 180000
PATH_CODES = frozenset((20, 30, 31, 50, 51))
LOCAL_CODES = frozenset((10, 90, 91, 92, 93, 94, 95, 96))
TRUST_CODES = frozenset((40, 41))


def _p(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"count": 0, "p50_ms": None, "p95_ms": None}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50_ms": ordered[math.ceil(.50 * len(ordered)) - 1],
        "p95_ms": ordered[math.ceil(.95 * len(ordered)) - 1],
    }


def _fresh(now_ms: int, stamp_ms: int | None, threshold: int) -> str:
    if stamp_ms is None:
        return "NOT_TESTED"
    age = now_ms - stamp_ms
    if age < 0:
        return "CLOCK_ANOMALY"
    return "FRESH" if age <= threshold else "STALE"


def build_report(db_path: Path, device: str, hours: int = 24,
                 now_ms: int | None = None) -> dict:
    """Inspect only the requested device; every SQLite handle is query-only."""
    if not isinstance(device, str) or not DEVICE_ID.fullmatch(device):
        raise ValueError("invalid device id")
    if type(hours) is not int or hours not in (24, 168):
        raise ValueError("hours must be 24 or 168")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    db_uri = db_path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(db_uri, uri=True, timeout=3.0)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        device_row = db.execute(
            "SELECT current_boot,last_seen_ms FROM devices WHERE id=?", (device,)
        ).fetchone()
        if device_row is None:
            raise ValueError("device not found")
        latest = db.execute("""
            SELECT boot_id,ssh_sequence,https_sequence,ssh_received_ms,
                   https_received_ms,last_event_sequence,monitoring_gap
            FROM device_latest_state WHERE device_id=?
        """, (device,)).fetchone()
        window_start = now_ms - hours * 3600000
        rows = db.execute("""
            SELECT boot_id,sequence,event_kind,ssh_code,https_code,
                   history_only,unknown_code,sender_age_ms,
                   https_sender_age_ms,received_at_ms,raw_json
            FROM telemetry_events
            WHERE device_id=? AND received_at_ms>=? AND received_at_ms<=?
            ORDER BY received_at_ms DESC,sequence DESC
            LIMIT ?
        """, (device, window_start, now_ms, MAX_ROWS + 1)).fetchall()

    truncated = len(rows) > MAX_ROWS
    rows = list(reversed(rows[:MAX_ROWS]))
    by_boot: dict[str, list[int]] = {}
    ages, https_ages, dns, transport, service, body_time = [], [], [], [], [], []
    kind_counts = {"boot": 0, "device": 0, "ssh": 0}
    ssh = {"pass": 0, "path_nonpass": 0, "local": 0, "trust": 0, "unknown": 0}
    https = {"pass": 0, "slow": 0, "other": 0, "unmeasurable": 0}
    histories = unknown_codes = invalid_payload = 0
    for row in rows:
        kind = row["event_kind"]
        kind_counts[{1:"ssh", 2:"device", 3:"boot"}[kind]] += 1
        by_boot.setdefault(row["boot_id"], []).append(row["sequence"])
        histories += row["history_only"]
        unknown_codes += row["unknown_code"]
        if type(row["sender_age_ms"]) is int and row["sender_age_ms"] >= 0:
            ages.append(row["sender_age_ms"])
        if type(row["https_sender_age_ms"]) is int and row["https_sender_age_ms"] >= 0:
            https_ages.append(row["https_sender_age_ms"])
        if kind != 1 or row["history_only"] or row["unknown_code"]:
            continue
        code = row["ssh_code"]
        if code == 1:
            ssh["pass"] += 1
        elif code in PATH_CODES:
            ssh["path_nonpass"] += 1
        elif code in LOCAL_CODES:
            ssh["local"] += 1
        elif code in TRUST_CODES:
            ssh["trust"] += 1
        else:
            ssh["unknown"] += 1
        if row["https_code"] is not None:
            hcode = row["https_code"]
            if hcode == 1:
                https["pass"] += 1
            elif hcode == 2:
                https["slow"] += 1
            elif hcode in (10, 11, 12):
                https["unmeasurable"] += 1
            else:
                https["other"] += 1
        try:
            body = json.loads(row["raw_json"])
            if not isinstance(body, dict):
                raise ValueError("not object")
        except (TypeError, ValueError, UnicodeError):
            invalid_payload += 1
            continue
        if code == 1:
            for key, bucket in (("d", dns), ("x", transport), ("a", service)):
                value = body.get(key)
                if type(value) is int and 0 <= value <= 600000:
                    bucket.append(value)
        h = body.get("h")
        if isinstance(h, dict):
            value = h.get("bt")
            if h.get("c") in (1, 2) and type(value) is int and value >= 0:
                body_time.append(value)

    # Count only *observed interior gaps* in a boot within the selected window;
    # do not treat new boots or the unknown first/last window edges as loss.
    observed_missing = 0
    for sequences in by_boot.values():
        unique = sorted(set(sequences))
        observed_missing += sum(max(0, b - a - 1)
                                for a, b in zip(unique, unique[1:]))
    live = dict(latest) if latest is not None else {}
    latest_boot = live.get("boot_id")
    last_received = device_row["last_seen_ms"]
    return {
        "schema": 1, "device_id": device, "window_hours": hours,
        "generated_at_ms": now_ms, "truncated": truncated,
        "events": {"stored": len(rows), "kinds": kind_counts,
                   "observed_missing_sequences": observed_missing,
                   "history_only": histories, "unknown_codes": unknown_codes,
                   "malformed_stored_payloads": invalid_payload},
        "sender_age": _p(ages),
        "https_sender_age": _p(https_ages),
        "ssh": {**ssh, "dns": _p(dns), "transport": _p(transport),
                "service_accept": _p(service)},
        "https": {**https, "body_transfer": _p(body_time)},
        "live": {
            "boot_id": latest_boot,
            "ssh_sequence": live.get("ssh_sequence"),
            "https_sequence": live.get("https_sequence"),
            "last_event_sequence": live.get("last_event_sequence"),
            "monitoring_gap": live.get("monitoring_gap", 1),
            "ssh_freshness": _fresh(now_ms, live.get("ssh_received_ms"),
                                    SSH_FRESH_MS),
            "https_freshness": _fresh(now_ms, live.get("https_received_ms"),
                                      HTTPS_FRESH_MS),
            "delivery_freshness": _fresh(now_ms, last_received,
                                         DELIVERY_FRESH_MS),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Local read-only DPT/1 metrics")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="action", required=True)
    summary = sub.add_parser("summary")
    summary.add_argument("--hours", type=int, choices=(24, 168), default=24)
    summary.add_argument("--device")
    detail = sub.add_parser("report")
    detail.add_argument("--device", required=True)
    detail.add_argument("--hours", type=int, choices=(24, 168), default=24)
    detail.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.action == "report":
        data = [build_report(args.db, args.device, args.hours)]
    else:
        if args.device:
            ids = [args.device]
        else:
            with closing(sqlite3.connect(
                    args.db.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                ids = [r[0] for r in db.execute(
                    "SELECT id FROM devices ORDER BY id LIMIT 100")]
        data = [build_report(args.db, device, args.hours) for device in ids]
    print(json.dumps(data[0] if args.action == "report" else data,
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
