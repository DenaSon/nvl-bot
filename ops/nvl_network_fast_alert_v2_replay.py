#!/usr/bin/env python3
"""Read-only Fast Alert V2 replay of Core JSONL telemetry.

This command NEVER uses the production SQLite state or Telegram API. The
verified baseline is loaded read-only, and event delivery is an in-memory
outbox. The normal, historical P1 replay remains unchanged.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from . import nvl_network_live_alerts as live
    from .nvl_network_intelligence import iter_samples, observation, utc
except ImportError:
    import nvl_network_live_alerts as live
    from nvl_network_intelligence import iter_samples, observation, utc


def replay(source: Path, store: Path, start: datetime, end: datetime):
    if end <= start:
        raise ValueError("End must follow start")
    baseline = live.baseline_load(store)  # reads JSON; does not modify it
    state = live.default_state()
    candidates = Counter()
    phases = Counter()
    transitions = []
    seen = 0
    # Never open or mutate the on-host state.sqlite3 or Telegram configuration.
    with sqlite3.connect(":memory:") as db:
        db.execute("""CREATE TABLE outbox (
            event_key TEXT PRIMARY KEY, message TEXT NOT NULL,
            status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt INTEGER NOT NULL DEFAULT 0, message_id INTEGER,
            created_at TEXT NOT NULL
        )""")
        for stamp, raw, _, _ in iter_samples(source, start, end):
            obs = observation(raw)
            iface = (raw.get("interface_rates_kbps") or {}).get("eth0") or {}
            for field, direction in (("eth_rx_mbps", "received"),
                                     ("eth_tx_mbps", "sent")):
                value = iface.get(direction)
                obs[field] = value / 1000 if (
                    isinstance(value, (float, int))
                    and not isinstance(value, bool) and value >= 0
                ) else None
            previous = state["phase"]
            live.process_sample(state, stamp, obs, baseline, db)
            seen += 1
            candidates[obs["alert_candidate"]] += 1
            phases[state["phase"]] += 1
            if previous != state["phase"]:
                transitions.append({
                    "utc": stamp.isoformat(),
                    "from": previous, "to": state["phase"],
                    "reason": obs.get("decision_reason", "UNKNOWN"),
                })
        alerts = [
            {"event_key": key, "created_at_utc": stamp}
            for key, stamp in db.execute(
                "SELECT event_key,created_at FROM outbox ORDER BY created_at"
            ).fetchall()
        ]
    return {
        "mode": "OFFLINE_READ_ONLY_REPLAY_V2",
        "window": [start.isoformat(), end.isoformat()],
        "samples": seen,
        "candidates": dict(candidates),
        "phases": dict(phases),
        "transitions": transitions,
        "would_queue": alerts,
        "telegram_messages_sent": 0,
        "production_state_modified": False,
        "baseline_modified": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", required=True, help="UTC or offset ISO8601")
    parser.add_argument("--end", required=True, help="UTC or offset ISO8601")
    parser.add_argument(
        "--source", type=Path, default=live.SOURCE)
    parser.add_argument(
        "--store", type=Path, default=live.STATE_DIR)
    args = parser.parse_args(argv)
    result = replay(args.source, args.store, utc(args.start), utc(args.end))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
