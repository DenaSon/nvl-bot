"""NVL Network Intelligence P0/P1: offline, read-only evidence archive and replay.

No service, socket, route, SSH process, bot or Netdata API is modified.
Compatible with the Core's nvl_network_sampler.py JSONL contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import tempfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("ssh", "udpgw", "close_wait", "awg_rx_mbps", "awg_tx_mbps")
SAMPLE_PATTERN = "nvl-samples-*.jsonl"
SNAP_PATTERN = "*_normal.json"
SNAP_DISRUPTION_PATTERN = "*_disruption.json"
SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "username",
                  "client_ip", "source_ip", "remote_ip", "chat_id", "user_id"}


class EvidenceError(ValueError):
    """A read-only validation error; never silently infer missing metrics."""


def utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise EvidenceError("Invalid timestamp: " + str(value)) from exc
    if result.tzinfo is None:
        raise EvidenceError("Timezone is required: " + value)
    return result.astimezone(timezone.utc)


def inspect_no_secrets(value) -> None:
    if isinstance(value, dict):
        if SENSITIVE_KEYS.intersection(value):
            raise EvidenceError("Potentially sensitive field in evidence")
        for item in value.values():
            inspect_no_secrets(item)
    elif isinstance(value, list):
        for item in value:
            inspect_no_secrets(item)


def metric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return float(value)


def path_get(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def observation(row: dict) -> dict:
    """Use port direction explicitly; do not double-count UDPGW loopback."""
    raw = {
        "ssh": path_get(row, "ports", "established", "by_port", "2252", "local"),
        "udpgw": path_get(row, "ports", "established", "by_port", "7300", "local"),
        "close_wait": path_get(row, "ports", "close-wait", "by_port", "7300", "remote"),
        "awg_rx_mbps": path_get(row, "interface_rates_kbps", "awg0", "received"),
        "awg_tx_mbps": path_get(row, "interface_rates_kbps", "awg0", "sent"),
    }
    result = {key: metric(value) for key, value in raw.items()}
    for key in ("awg_rx_mbps", "awg_tx_mbps"):
        if result[key] is not None:
            result[key] /= 1000.0  # kernel sampler records kilobits/second
    result["valid"] = all(result[key] is not None for key in FIELDS)
    result["missing"] = [key for key in FIELDS if result[key] is None]
    return result


def iter_samples(source: Path, start: datetime, end: datetime):
    if not source.is_dir():
        raise EvidenceError("Source directory not found")
    for path in sorted(source.glob(SAMPLE_PATTERN)):
        if path.is_symlink() or not path.is_file():
            raise EvidenceError("Invalid sample path: " + path.name)
        with path.open(encoding="utf-8") as stream:
            for lineno, raw in enumerate(stream, 1):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw)
                    if not isinstance(row, dict):
                        raise ValueError("not an object")
                    timestamp = utc(row["timestamp_utc"])
                except (ValueError, KeyError, TypeError, EvidenceError) as exc:
                    raise EvidenceError(f"{path.name}:{lineno}: bad sample") from exc
                if start <= timestamp < end:
                    inspect_no_secrets(row)
                    yield timestamp, row, path.name, raw


def load_samples(source: Path, start: datetime, end: datetime):
    records = [(stamp, observation(row)) for stamp, row, _, _ in
               iter_samples(source, start, end)]
    records.sort(key=lambda x: x[0])
    stamps = [stamp for stamp, _ in records]
    if len(stamps) != len(set(stamps)):
        raise EvidenceError("Duplicate timestamps: aborting replay")
    return records


def build_baseline(records, start: datetime, end: datetime, research=False):
    duration = (end - start).total_seconds() / 60
    minimum = 20 if research else 60
    if duration < minimum:
        raise EvidenceError(f"Baseline needs >= {minimum} verified minutes")
    selected = [(t, m) for t, m in records if start <= t < end]
    valid = [(t, m) for t, m in selected if m["valid"]]
    # Count distinct UTC minute slots, not duplicate samples.
    covered = len({t.replace(second=0, microsecond=0) for t, _ in valid})
    expected = math.ceil(duration)
    coverage = covered / expected if expected else 0
    if coverage < 0.80:
        raise EvidenceError(f"Insufficient baseline coverage: {coverage:.1%}")
    baselines = {field: statistics.median(m[field] for _, m in valid)
                 for field in FIELDS}
    if baselines["ssh"] <= 0 or baselines["awg_tx_mbps"] <= 0:
        raise EvidenceError("Baseline has zero SSH or AWG TX")
    return {"values": baselines, "sample_count": len(selected),
            "valid_count": len(valid), "coverage": round(coverage, 4),
            "window_start": start.isoformat(), "window_end": end.isoformat(),
            "status": "RESEARCH_ONLY" if research else "NORMAL_VERIFIED"}


def classify(metrics, base):
    if not metrics["valid"]:
        return "UNKNOWN"
    b = base["values"]
    ssh, cw = metrics["ssh"], metrics["close_wait"]
    suspected = ssh >= b["ssh"] * 1.25 and cw >= max(
        b["close_wait"] * 3, b["close_wait"] + 20)
    degraded = ssh >= b["ssh"] * 1.40 and cw >= max(
        b["close_wait"] * 5, b["close_wait"] + 40) and (
            metrics["awg_tx_mbps"] <= b["awg_tx_mbps"] * 0.75 or
            metrics["udpgw"] <= b["udpgw"] * 0.80)
    recovered = ssh <= b["ssh"] * 1.20 and cw <= max(
        b["close_wait"] * 2, 20)
    if degraded:
        return "DEGRADED"
    if suspected:
        return "SUSPECTED"
    return "RECOVERY_CANDIDATE" if recovered else "NEUTRAL"


def replay(records, baseline, start, end):
    window = deque(maxlen=5)
    recovery = deque(maxlen=7)
    state = "NORMAL"
    transitions = []
    valid_count = 0
    unknown_count = 0
    last = None
    recovery_streak = 0

    for stamp, row in records:
        if not start <= stamp < end:
            continue
        if last is not None and (stamp - last).total_seconds() > 150:
            # A sensor gap is unknown, NOT a recovery event.
            window.clear()
            recovery.clear()
            recovery_streak = 0
            if state != "UNKNOWN":
                transitions.append({"at": stamp.isoformat(), "from": state,
                                    "to": "UNKNOWN", "reason": "SAMPLE_GAP"})
                state = "UNKNOWN"
        last = stamp
        kind = classify(row, baseline)
        if kind == "UNKNOWN":
            unknown_count += 1
            window.clear()
            recovery.clear()
            recovery_streak = 0
            if state != "UNKNOWN":
                transitions.append({"at": stamp.isoformat(), "from": state,
                                    "to": "UNKNOWN", "reason": ",".join(row["missing"])})
                state = "UNKNOWN"
            continue
        valid_count += 1
        window.append(kind)
        recovery.append(kind == "RECOVERY_CANDIDATE")
        recovery_streak = recovery_streak + 1 if kind == "RECOVERY_CANDIDATE" else 0
        proposed = None

        if len(window) == 5 and sum(v == "DEGRADED" for v in window) >= 3:
            proposed = "DEGRADED"
        elif len(window) == 5 and sum(v in ("SUSPECTED", "DEGRADED") for v in window) >= 3:
            if state not in ("DEGRADED", "RECOVERING"):
                proposed = "SUSPECTED"
        elif state in ("SUSPECTED", "DEGRADED", "RECOVERING") and (
                len(recovery) == 7 and sum(recovery) >= 5):
            proposed = "RECOVERING"
            if state == "RECOVERING" and recovery_streak >= 10:
                proposed = "NORMAL"
        elif state == "UNKNOWN" and len(window) == 5:
            # Resume observation without claiming a recovered incident.
            proposed = "NORMAL"

        if proposed is not None and proposed != state:
            transitions.append({"at": stamp.isoformat(), "from": state,
                                "to": proposed, "reason": "MULTI_SIGNAL"})
            state = proposed

    return {"state": state, "transitions": transitions,
            "samples_valid": valid_count, "samples_unknown": unknown_count,
            "false_positive_rate": "NOT_ESTIMABLE_FROM_ONE_LABELED_EVENT",
            "telegram_messages_sent": 0, "production_alerts_enabled": False}


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def archive(source: Path, dest: Path, event_id: str, start: datetime, end: datetime):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{3,64}", event_id):
        raise EvidenceError("Unsafe event ID")
    if end <= start:
        raise EvidenceError("End must follow start")
    if not source.is_dir():
        raise EvidenceError("Source directory not found")
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = dest / event_id
    if final.exists():
        raise EvidenceError("Archive already exists; never overwrite evidence")

    staging = Path(tempfile.mkdtemp(prefix=".nvl-stage-", dir=dest))
    try:
        files = []
        for path in sorted(set(source.glob(SNAP_PATTERN)) |
                           set(source.glob(SNAP_DISRUPTION_PATTERN))):
            if path.is_symlink() or not path.is_file():
                raise EvidenceError("Invalid snapshot path")
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
                stamp = utc(row["timestamp_utc"])
            except (ValueError, KeyError, EvidenceError) as exc:
                raise EvidenceError("Invalid snapshot: " + path.name) from exc
            if start <= stamp < end:
                inspect_no_secrets(row)
                target = staging / path.name
                shutil.copyfile(path, target)
                target.chmod(0o600)
                files.append({"file": path.name, "kind": "snapshot",
                              "sha256": digest(target), "bytes": target.stat().st_size})

        rows_by_day = {}
        for _, _, name, raw in iter_samples(source, start, end):
            rows_by_day.setdefault(name, []).append(raw)
        for name, lines in sorted(rows_by_day.items()):
            target = staging / name
            with target.open("w", encoding="utf-8", newline="") as stream:
                stream.writelines(lines)  # exact original JSONL records, scoped to incident
            target.chmod(0o600)
            files.append({"file": name, "kind": "jsonl_slice", "records": len(lines),
                          "sha256": digest(target), "bytes": target.stat().st_size})

        if not files or not rows_by_day:
            raise EvidenceError("No matching raw JSONL and snapshots; archive aborted")
        manifest = {
            "schema": "nvl-network-evidence-1",
            "event_id": event_id,
            "window_start_utc": start.isoformat(), "window_end_utc": end.isoformat(),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "note": "JSONL is a lossless window slice; snapshots are exact copies",
            "files": files,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (staging / "manifest.json").chmod(0o600)
        # Guard against overwrites if the event was concurrently archived.
        if final.exists():
            raise EvidenceError("Archive concurrently created")
        staging.rename(final)
        return {"path": str(final), "manifest": manifest}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def verify(folder: Path):
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "nvl-network-evidence-1":
        raise EvidenceError("Unsupported manifest schema")
    for entry in manifest["files"]:
        name = entry["file"]
        if Path(name).name != name or name == "manifest.json":
            raise EvidenceError("Unsafe manifest entry")
        path = folder / name
        if path.is_symlink() or not path.is_file() or digest(path) != entry["sha256"]:
            raise EvidenceError("SHA256 mismatch: " + name)
        if path.stat().st_size != entry["bytes"]:
            raise EvidenceError("Size mismatch: " + name)
    return {"status": "PASS", "file_count": len(manifest["files"]),
            "event_id": manifest["event_id"]}


def command_line(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    audit_cmd = subs.add_parser("audit", help="Read-only coverage/schema inspection")
    replay_cmd = subs.add_parser("replay", help="Offline detection replay; no messages")
    archive_cmd = subs.add_parser("archive", help="Lossless evidence slice with SHA256")
    verify_cmd = subs.add_parser("verify", help="Check archived SHA256 hashes")
    for cmd in (audit_cmd, replay_cmd, archive_cmd):
        cmd.add_argument("--source", type=Path, required=True)
        cmd.add_argument("--start", required=True, help="ISO8601 inclusive, with UTC offset")
        cmd.add_argument("--end", required=True, help="ISO8601 exclusive, with UTC offset")
    for cmd in (audit_cmd, replay_cmd):
        cmd.add_argument("--baseline-start", required=True)
        cmd.add_argument("--baseline-end", required=True)
        cmd.add_argument("--research", action="store_true", help="Explicit provisional 20m baseline")
    archive_cmd.add_argument("--dest", type=Path, required=True)
    archive_cmd.add_argument("--event-id", required=True)
    verify_cmd.add_argument("--folder", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.action == "verify":
            output = verify(args.folder)
        else:
            start, end = utc(args.start), utc(args.end)
            if end <= start:
                raise EvidenceError("End must follow start")
            if args.action == "archive":
                output = archive(args.source, args.dest, args.event_id, start, end)
            else:
                bstart, bend = utc(args.baseline_start), utc(args.baseline_end)
                if not start <= bstart < bend <= end:
                    raise EvidenceError("Baseline must be inside the requested input window")
                records = load_samples(args.source, start, end)
                baseline = build_baseline(records, bstart, bend, research=args.research)
                output = {"baseline": baseline,
                          "observations": len(records),
                          "scope": "OFFLINE_RESEARCH" if args.research else "OFFLINE_VALIDATED"}
                if args.action == "replay":
                    output["replay"] = replay(records, baseline, bend, end)
                else:
                    output["read_only"] = True
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(command_line())
