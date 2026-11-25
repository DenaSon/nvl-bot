#!/usr/bin/env python3
"""NVL Core-only live alert pilot: persistent, multi-signal, Telegram group-only.

Separate from the NVL bot, SSH, Edge, Netdata and the read-only sampler.
No daemon is started by importing or running the configure/baseline commands.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import getpass
import html
import json
import math
import os
import re
import sqlite3
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    from .nvl_network_intelligence import (EvidenceError, FIELDS, build_baseline,
                                            classify, iter_samples, load_samples, observation, utc)
except ImportError:  # direct file installation beside nvl_network_intelligence.py
    from nvl_network_intelligence import (EvidenceError, FIELDS, build_baseline,
                                          classify, iter_samples, load_samples, observation, utc)

def instant(value):
    """Normalize P1 ISO strings and runtime aware datetime objects to UTC."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise EvidenceError("Naive runtime timestamp")
        return value.astimezone(timezone.utc)
    return utc(value)


IRAN = ZoneInfo("Asia/Tehran")
SOURCE = Path("/root/nvl-network-observations")
STATE_DIR = Path("/var/lib/nvl-network-alerts")
CONFIG = Path("/etc/nvl-network-alerts/telegram.json")
BOT_ENV = Path("/etc/nvlbot/nvlbot.env")
TOKEN_RE = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{20,}$")
ETH_REFERENCE_SCHEMA = "nvl-network-eth-reference-1"
EXTRA_FIELDS = ("eth_rx_mbps", "eth_tx_mbps")
METRIC_LABELS = {
    "eth_rx_mbps": "ETH RX",
    "eth_tx_mbps": "ETH TX",
    "ssh": "SSH :2252",
    "udpgw": "UDPGW :7300",
    "close_wait": "UDPGW CLOSE-WAIT",
    "awg_rx_mbps": "AWG RX",
    "awg_tx_mbps": "AWG TX",
}
STATE_VERSION = 1


def secure_parent(path: Path):
    # Never chmod an existing parent such as /etc, /root or /var/lib.
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise EvidenceError("Unsafe storage directory")
    if not existed:
        path.chmod(0o700)


def atomic_json(path: Path, data: dict):
    secure_parent(path.parent)
    if path.is_symlink():
        raise EvidenceError("Refusing symlink destination")
    fd, tmp = tempfile.mkstemp(prefix=".nvl-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path):
    if path.is_symlink():
        raise EvidenceError("Symlink not allowed")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def parse_env_token(path: Path):
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("Bot token file missing or unsafe")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("BOT_TOKEN="):
            token = line.split("=", 1)[1].strip().strip("'\"")
            if TOKEN_RE.fullmatch(token):
                return token
    raise EvidenceError("BOT_TOKEN not found in bot environment file")


def configure(bot_env: Path, chat_id: str | None, topic: int | None,
              config_path: Path):
    # Only the original NVL bot's sending token is reused; no second poller.
    token = parse_env_token(bot_env)
    if chat_id is None:
        chat_id = input("Telegram target group chat ID (negative): ").strip()
    if not re.fullmatch(r"-[1-9][0-9]{5,20}", chat_id):
        raise EvidenceError("Group chat ID must be a negative Telegram chat ID")
    if topic is not None and topic <= 0:
        raise EvidenceError("Topic ID must be positive")
    atomic_json(config_path, {
        "schema": "nvl-group-telegram-1",
        "chat_id": chat_id,
        "bot_token": token,
        "message_thread_id": topic,
    })
    print(json.dumps({"status": "CONFIGURED", "group_id": chat_id,
                      "topic_id": topic, "secret_printed": False}))


def config_load(path: Path):
    if path.stat().st_mode & 0o077:
        raise EvidenceError("Telegram config must be owner-only (0600)")
    data = read_json(path)
    if (data.get("schema") != "nvl-group-telegram-1"
            or not re.fullmatch(r"-[1-9][0-9]{5,20}", str(data.get("chat_id", "")))
            or not TOKEN_RE.fullmatch(str(data.get("bot_token", "")))):
        raise EvidenceError("Missing/invalid Telegram group config")
    return data


def fmt_time(stamp):
    return instant(stamp).astimezone(IRAN).strftime("%Y-%m-%d %H:%M:%S")


def baseline_fingerprint(base):
    """Bind supplementary ETH medians to the original, immutable live baseline."""
    identity = {
        "window_start": base["window_start"],
        "window_end": base["window_end"],
        "created_utc": base.get("created_utc"),
        "values": {field: base["values"][field] for field in FIELDS},
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def derive_eth_reference(source: Path, base: dict):
    """Median ETH0 rates from the SAME verified baseline window.

    Uses raw JSONL rather than the normalized P1 observation, because
    observation() intentionally excludes eth0. Neither metric is required
    by the Core detector; no AWG/ETH traffic sums are computed.
    """
    start, end = instant(base["window_start"]), instant(base["window_end"])
    expected = math.ceil((end - start).total_seconds() / 60)
    if expected < 60 or base.get("status") != "NORMAL_VERIFIED":
        raise EvidenceError("ETH reference requires verified 60+ minute baseline")
    slots = {field: {} for field in EXTRA_FIELDS}
    for stamp, raw, _, _ in iter_samples(source, start, end):
        if not observation(raw)["valid"]:
            continue
        iface = (raw.get("interface_rates_kbps") or {}).get("eth0") or {}
        slot = stamp.replace(second=0, microsecond=0)
        for field, direction in (("eth_rx_mbps", "received"),
                                 ("eth_tx_mbps", "sent")):
            number = iface.get(direction)
            if (isinstance(number, (int, float))
                    and not isinstance(number, bool)
                    and math.isfinite(number) and number >= 0):
                slots[field].setdefault(slot, number / 1000)
    coverage = {f: round(len(slots[f]) / expected, 4) for f in EXTRA_FIELDS}
    if any(coverage[f] < 0.80 for f in EXTRA_FIELDS):
        raise EvidenceError("Insufficient ETH0 coverage in verified baseline")
    values = {f: statistics.median(slots[f].values()) for f in EXTRA_FIELDS}
    return values, coverage


def enrich_eth_baseline(source: Path, store: Path):
    """One-time sidecar migration; never modify baseline.json or SQLite."""
    path = store / "eth-reference.json"
    if path.exists() or path.is_symlink():
        raise EvidenceError("ETH reference already exists; refusing overwrite")
    base = baseline_load(store)
    if all(field in base["values"] for field in EXTRA_FIELDS):
        raise EvidenceError("Baseline already contains ETH references")
    values, coverage = derive_eth_reference(source, base)
    reference = {
        "schema": ETH_REFERENCE_SCHEMA,
        "base_fingerprint": baseline_fingerprint(base),
        "window_start": base["window_start"],
        "window_end": base["window_end"],
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "values": values,
        "coverage": coverage,
        "source": "original_verified_baseline_window",
    }
    atomic_json(path, reference)
    print(json.dumps({"status": "ETH_REFERENCE_READY",
                      "baseline_unchanged": True,
                      "state_unchanged": True,
                      "window": [base["window_start"], base["window_end"]],
                      "coverage": coverage, "median_mbps": values},
                     ensure_ascii=False))
    return reference


def baseline_build(source, store, start, end, confirmed):
    if not confirmed:
        raise EvidenceError("Operator must confirm a clean 60+ minute window")
    if (store / "state.sqlite3").exists():
        raise EvidenceError("Detector state exists: no live baseline replacement")
    begin, finish = instant(start), instant(end)
    if finish > datetime.now(timezone.utc) + timedelta(minutes=2):
        raise EvidenceError("Baseline cannot be in the future")
    if (datetime.now(timezone.utc) - finish) > timedelta(days=7):
        raise EvidenceError("Baseline too old; choose recent healthy data")
    records = load_samples(source, begin, finish)
    base = build_baseline(records, begin, finish, research=False)
    b = base["values"]
    # Sanity checks against an obviously incident-contaminated baseline.
    if (b["close_wait"] > max(30, b["ssh"] * .20)
            or b["udpgw"] < b["ssh"] * .45
            or b["awg_tx_mbps"] < .5):
        raise EvidenceError("Baseline seems degraded; select verified healthy window")
    # Optional corroboration: use raw ETH0 samples (not P1-normalized rows).
    # A missing ETH interface must never invalidate the Core detector.
    try:
        extras, _coverage = derive_eth_reference(source, base)
        base["values"].update(extras)
    except EvidenceError:
        pass
    # Keep existing live incident history; a baseline update only when no active
    # detector is running is enforced by preflight/runbook, not by relabeling.
    obj = {"schema": "nvl-network-live-baseline-1",
           "source": "operator_confirmed_core_kernel_sampler",
           "created_utc": datetime.now(timezone.utc).isoformat(),
           "mode": "LIVE_PILOT_EVALUATION",
           "normal_verified": True, **base}
    atomic_json(store / "baseline.json", obj)
    print(json.dumps({"status": "BASELINE_READY", "normal_verified": True,
                      "window": [begin.isoformat(), finish.isoformat()],
                      "coverage": base["coverage"],
                      "median": b}, ensure_ascii=False))


def baseline_load(folder):
    value = read_json(folder / "baseline.json")
    if (value.get("schema") != "nvl-network-live-baseline-1"
            or value.get("status") != "NORMAL_VERIFIED"
            or value.get("mode") != "LIVE_PILOT_EVALUATION"
            or value.get("normal_verified") is not True):
        raise EvidenceError("Verified live baseline missing or research-only")
    path = folder / "eth-reference.json"
    if path.exists() or path.is_symlink():
        ref = read_json(path)
        if (ref.get("schema") != ETH_REFERENCE_SCHEMA
                or ref.get("base_fingerprint") != baseline_fingerprint(value)
                or ref.get("window_start") != value["window_start"]
                or ref.get("window_end") != value["window_end"]):
            raise EvidenceError("ETH reference does not match live baseline")
        fields = ref.get("values")
        if not isinstance(fields, dict) or set(fields) != set(EXTRA_FIELDS):
            raise EvidenceError("ETH reference has unexpected fields")
        for field in EXTRA_FIELDS:
            number = fields[field]
            if (not isinstance(number, (float, int))
                    or isinstance(number, bool)
                    or not math.isfinite(number) or number < 0):
                raise EvidenceError("ETH reference contains invalid metric")
        value["values"] = dict(value["values"])
        value["values"].update(fields)
    return value


def default_state():
    return {"version": STATE_VERSION, "policy_version": DETECTION_POLICY_VERSION,
            "phase": "NORMAL", "incident": None,
            "seq": 0, "last_sample": None, "window": [], "recovery": [],
            "recovering_since": None, "recovery_streak": 0,
            "incident_open": False, "unknown_alerted": False,
            "incomplete_streak": 0,
            "latest_metrics": None, "last_closed": None,
            "alerted_phases": [], "recent_good": [], "latest_reason": None}


def db_connect(folder):
    secure_parent(folder)
    db = sqlite3.connect(folder / "state.sqlite3", timeout=8)
    os.chmod(folder / "state.sqlite3", 0o600)
    db.execute("PRAGMA busy_timeout=8000")
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("""CREATE TABLE IF NOT EXISTS kv (
        k TEXT PRIMARY KEY, v TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS outbox (
        event_key TEXT PRIMARY KEY,
        message TEXT NOT NULL, status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt INTEGER NOT NULL DEFAULT 0,
        message_id INTEGER,
        created_at TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS decisions (
        sample_utc TEXT PRIMARY KEY,
        recorded_utc TEXT NOT NULL,
        candidate TEXT NOT NULL,
        phase TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        baseline_start TEXT NOT NULL
    )""")
    db.commit()
    return db


def state_read(db):
    row = db.execute("SELECT v FROM kv WHERE k='detector'").fetchone()
    data = json.loads(row[0]) if row else default_state()
    if data.get("version") != STATE_VERSION:
        raise EvidenceError("Unsupported persisted detector version")
    policy = data.get("policy_version", 1)
    if (not isinstance(policy, int) or isinstance(policy, bool)
            or policy > DETECTION_POLICY_VERSION):
        raise EvidenceError("Unsupported persisted detection policy")
    if policy != DETECTION_POLICY_VERSION:
        # Old two-sample confirmation windows are not valid evidence under
        # the stricter three-sample policy. Preserve incident/outbox/history.
        data["window"] = []
        data["policy_version"] = DETECTION_POLICY_VERSION
    return data


def state_write(db, state):
    db.execute("INSERT INTO kv(k,v) VALUES('detector',?) "
               "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
               (json.dumps(state, ensure_ascii=False, allow_nan=False),))


def queue(db, key, text, stamp):
    db.execute("""INSERT OR IGNORE INTO outbox
        (event_key,message,status,created_at) VALUES (?,?,'PENDING',?)""",
        (key, text, stamp))


def pct(value, reference):
    if value is None or reference is None or reference <= 0:
        return "N/A"
    # Avoid misleading negative zero for small changes.
    change = (value / reference - 1) * 100
    return "0%" if abs(change) < .5 else f"{change:+.0f}%"


def fmt_metric(value, label):
    if value is None:
        return "N/A"
    return f"{value:.2f}" if label.startswith(("AWG ", "ETH ")) else f"{value:.0f}"


def incident_begin(incident):
    """Extract first DETECTION time, not the physical start of filtering."""
    if not incident:
        return None
    match = re.fullmatch(r"NVL-(\d{8}T\d{6}Z)-\d{3,}", incident)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def render_metric(field, metrics, base, *, compact_label=None):
    """One tight, escaped Telegram HTML metric: current value and % vs baseline."""
    label = METRIC_LABELS[field]
    current = metrics.get(field)
    reference = base["values"].get(field)
    name = compact_label if compact_label is not None else label
    return (f"{html.escape(name)} <b>{html.escape(fmt_metric(current, label))}</b>"
            f" <i>{html.escape(pct(current, reference))}</i>")


ALERT_MENTIONS = "@raad_co @ja_va_dd"
LIVE_MAX_GAP_SECONDS = 25
LIVE_CONFIRMATION_SAMPLES = 3
DETECTION_POLICY_VERSION = 2


def render(phase, incident, stamp, metrics, baseline, *, reason=None):
    """Only the Persian alert title is localized; body is concise English."""
    captions = {
        "INFO": "🔵 <b>NVL | اختلال احتمالی ارتباط</b>",
        "SUSPECTED": "🔴 <b>NVL | تأیید اختلال ارتباط</b>",
        "DEGRADED": "🔴 <b>NVL | تشدید اختلال ارتباط</b>",
        "RECOVERED": "🟢 <b>NVL | بازگشت شاخص‌های شبکه</b>",
        "UNKNOWN": "⚪ <b>NVL | وقفه در پایش شبکه</b>",
        "RESUMED": "🔵 <b>NVL | دریافت داده از سر گرفته شد</b>",
        "TEST": "🧪 <b>NVL | آزمایش ارسال هشدار گروه</b>",
    }
    stamp_dt = instant(stamp)
    lines = [
        captions[phase],
        f"Core · {html.escape(fmt_time(stamp_dt))} Tehran",
    ]
    if incident:
        identifier = f"ID <code>{html.escape(incident)}</code>"
        first = incident_begin(incident)
        if first is not None:
            age_minutes = max(0, int((stamp_dt - first).total_seconds() // 60))
            if age_minutes > 0:
                identifier += f" · Age {age_minutes}m"
        lines.append(identifier)

    # Monitor-only messages should be short and never imply a customer outage.
    if phase == "UNKNOWN":
        lines.append("Telemetry unavailable · Recovery not confirmed.")
    elif phase == "RESUMED":
        lines.append("Telemetry resumed · Connectivity not independently verified.")
    elif phase == "TEST":
        lines.append("Delivery test OK · No incident reported.")
    elif phase == "INFO":
        if metrics is not None and baseline is not None:
            lines.extend([
                render_metric("close_wait", metrics, baseline,
                              compact_label="CLOSE-WAIT"),
                f"Baseline: {fmt_metric(baseline['values']['close_wait'], 'CLOSE-WAIT')}",
            ])
        lines.extend(["Signal: CLOSE-WAIT spike · Early detection.",
                      "<i>Core telemetry only · ISP filtering not confirmed.</i>"])
    elif phase in ("SUSPECTED", "DEGRADED", "RECOVERED"):
        if metrics is not None and baseline is not None:
            lines.extend([
                "",
                "<b>Connections</b> <i>· vs baseline</i>",
                (render_metric("ssh", metrics, baseline, compact_label="SSH")
                 + " · " +
                 render_metric("udpgw", metrics, baseline, compact_label="UDPGW")),
                render_metric("close_wait", metrics, baseline,
                              compact_label="CLOSE-WAIT"),
                "",
                "<b>Traffic</b> <i>· Mbps · vs baseline</i>",
                ("AWG  " +
                 render_metric("awg_rx_mbps", metrics, baseline,
                               compact_label="RX") + " · " +
                 render_metric("awg_tx_mbps", metrics, baseline,
                               compact_label="TX")),
                ("ETH  " +
                 render_metric("eth_rx_mbps", metrics, baseline,
                               compact_label="RX") + " · " +
                 render_metric("eth_tx_mbps", metrics, baseline,
                               compact_label="TX")),
            ])
        summary = {
            "SUSPECTED": "Signal: Sustained connection / traffic degradation.",
            "DEGRADED": "Signal: Connection surge + AWG TX / UDPGW decline.",
            "RECOVERED": "Core metrics stabilized · Client access not verified.",
        }
        signal = summary[phase]
        if reason and phase in ("SUSPECTED", "DEGRADED") and not reason.startswith("LEGACY_"):
            signal = "Signal: " + html.escape(reason.replace("_", " ")) + "."
        lines.extend([
            "",
            signal,
            "<i>Core telemetry only · ISP filtering not confirmed.</i>",
        ])
    if phase in ("INFO", "SUSPECTED"):
        lines.extend(["", ALERT_MENTIONS])
    return "\n".join(lines)


def make_incident(stamp, state):
    state["seq"] += 1
    return "NVL-" + instant(stamp).strftime("%Y%m%dT%H%M%SZ") + f"-{state['seq']:03d}"


def transition(state, next_phase, stamp, metrics, base, db, *, reason=None):
    prev = state["phase"]
    if prev == next_phase:
        return
    state["phase"] = next_phase
    if next_phase in ("INFO", "SUSPECTED"):
        if not state["incident_open"]:
            state["incident"] = make_incident(stamp, state)
            state["incident_open"] = True
            state["alerted_phases"] = []
        announced = state["alerted_phases"]
        # Legacy confirmed incidents already have SUSPECTED or DEGRADED keys.
        confirmed = any(p in announced for p in ("SUSPECTED", "DEGRADED"))
        if next_phase not in announced and not confirmed:
            key = f"{state['incident']}:{next_phase}"
            queue(db, key, render(next_phase, state["incident"], stamp, metrics,
                                  base, reason=reason), instant(stamp).isoformat())
            announced.append(next_phase)
    elif next_phase == "NORMAL" and state["incident_open"]:
        if any(p in state["alerted_phases"] for p in ("SUSPECTED", "DEGRADED")):
            key = f"{state['incident']}:RECOVERED"
            queue(db, key, render("RECOVERED", state["incident"], stamp, metrics, base),
                  instant(stamp).isoformat())
        state["last_closed"] = instant(stamp).isoformat()
        state["incident_open"] = False
        state["incident"] = None
        state["alerted_phases"] = []
        state["recovering_since"] = None
        state["window"] = []
        state["recovery"] = []
        state["recovery_streak"] = 0
    # UNKNOWN never closes an incident or counts as recovery.


# Adaptive Fast Alert V2: additive high-sensitivity paths, no baseline rewrite.
ADAPTIVE_FIELDS = ("ssh", "udpgw", "close_wait", "awg_tx_mbps")


def adaptive_reference(state, stamp):
    """Medians of healthy 45m/last 5 minutes; frozen during an incident."""
    history = state.get("recent_good", [])
    if not isinstance(history, list):
        return None
    if not state.get("incident_open"):
        cutoff = instant(stamp) - timedelta(minutes=45)
        history = [h for h in history if instant(h["utc"]) >= cutoff]
    if (len(history) < 12 or
            (instant(history[-1]["utc"]) - instant(history[0]["utc"])).total_seconds() < 660):
        return None
    recent = history[-180:]
    short_cutoff = instant(recent[-1]["utc"]) - timedelta(minutes=5)
    short = [h for h in recent if instant(h["utc"]) > short_cutoff]
    if any(not all(isinstance(h.get(f), (int, float))
                   and not isinstance(h.get(f), bool) for f in ADAPTIVE_FIELDS)
           for h in recent):
        return None
    return (
        {f: statistics.median(h[f] for h in recent) for f in ADAPTIVE_FIELDS},
        {f: statistics.median(h[f] for h in short) for f in ADAPTIVE_FIELDS},
    )


def high_sensitivity_candidate(metrics, baseline, state, stamp):
    """Require independent evidence of connection loss or traffic collapse.

    CLOSE-WAIT and the legacy SSH/CLOSE-WAIT heuristic are diagnostic only.
    Neither may confirm a customer-facing disruption without corroboration.
    """
    legacy = classify(metrics, baseline)
    if legacy == "UNKNOWN":
        return "UNKNOWN", "LEGACY_UNKNOWN"

    reference = adaptive_reference(state, stamp)
    if reference is None:
        # Safe warm-up uses the verified baseline, but applies the same
        # independent-signal requirements as the adaptive path.
        ref = baseline["values"]
        ssh, udp, cw, tx = (
            metrics["ssh"], metrics["udpgw"], metrics["close_wait"],
            metrics["awg_tx_mbps"]
        )
        ssh_drop = ssh <= ref["ssh"] * .85 and ref["ssh"] - ssh >= 10
        udp_drop = udp <= ref["udpgw"] * .85 and ref["udpgw"] - udp >= 10
        tx_drop = (ref["awg_tx_mbps"] >= 8
                   and tx <= ref["awg_tx_mbps"] * .60
                   and ref["awg_tx_mbps"] - tx >= 8)
        connection_collapse = (
            ssh <= ref["ssh"] * .75
            and udp <= ref["udpgw"] * .75
            and ref["ssh"] - ssh >= 12
            and ref["udpgw"] - udp >= 10)
        traffic_collapse = tx_drop and (ssh_drop or udp_drop)
        cw_spike = cw >= max(15, ref["close_wait"] * 2,
                             ref["close_wait"] + 15)
        if connection_collapse:
            return "SUSPECTED", "CONNECTION_COLLAPSE_WARMUP"
        if traffic_collapse:
            corroboration = "UDPGW_DROP" if udp_drop else "SSH_DROP"
            prefix = "CW_SPIKE+" if cw_spike else ""
            return "SUSPECTED", prefix + "TRAFFIC_COLLAPSE_WARMUP+" + corroboration
        return (("RECOVERY_CANDIDATE", "LEGACY_RECOVERY_CANDIDATE")
                if legacy == "RECOVERY_CANDIDATE"
                else ("NEUTRAL", "LEGACY_NEUTRAL"))

    ref, _short = reference
    ssh, udp, cw, tx = (
        metrics["ssh"], metrics["udpgw"], metrics["close_wait"],
        metrics["awg_tx_mbps"]
    )
    cw_spike = cw >= max(15, ref["close_wait"] * 2,
                         ref["close_wait"] + 15)
    udp_drop = (udp <= ref["udpgw"] * .85
                and ref["udpgw"] - udp >= 10)
    ssh_drop = (ssh <= ref["ssh"] * .85
                and ref["ssh"] - ssh >= 10)
    tx_drop = (ref["awg_tx_mbps"] >= 8
               and tx <= ref["awg_tx_mbps"] * .60
               and ref["awg_tx_mbps"] - tx >= 8)

    # A connection collapse needs both independent connection counters to
    # fall materially. A single UDPGW dip is not sufficient.
    connection_collapse = (
        ssh <= ref["ssh"] * .75
        and udp <= ref["udpgw"] * .75
        and ref["ssh"] - ssh >= 12
        and ref["udpgw"] - udp >= 10
    )
    # A traffic collapse needs a sustained AWG throughput drop plus at least
    # one independent connection-count drop. CLOSE-WAIT is never corroboration.
    traffic_collapse = tx_drop and (ssh_drop or udp_drop)

    if connection_collapse:
        return "SUSPECTED", "CONNECTION_COLLAPSE"
    if traffic_collapse:
        corroboration = "UDPGW_DROP" if udp_drop else "SSH_DROP"
        prefix = "CW_SPIKE+" if cw_spike else ""
        return "SUSPECTED", prefix + "TRAFFIC_COLLAPSE+" + corroboration

    # Preserve the old recovery behavior, but suppress legacy SSH/CW alarms.
    # A rising SSH count or a CLOSE-WAIT spike alone is not an outage signal.
    if (state.get("incident_open") and legacy == "RECOVERY_CANDIDATE"
            and ssh <= ref["ssh"] * .80
            and udp <= ref["udpgw"] * .80):
        return "NEUTRAL", "ONGOING_CONNECTION_DROP"
    if legacy == "RECOVERY_CANDIDATE":
        return "RECOVERY_CANDIDATE", "LEGACY_RECOVERY_CANDIDATE"
    return "NEUTRAL", "LEGACY_NEUTRAL"


def record_healthy_reference(state, stamp, metrics):
    if state.get("incident_open") or state["phase"] != "NORMAL":
        return
    if metrics.get("alert_candidate") != "RECOVERY_CANDIDATE":
        return
    history = state.get("recent_good", [])
    cutoff = instant(stamp) - timedelta(minutes=45)
    history = [h for h in history if instant(h["utc"]) >= cutoff]
    history.append({"utc": instant(stamp).isoformat(),
                    **{f: metrics[f] for f in ADAPTIVE_FIELDS}})
    state["recent_good"] = history[-180:]


def early_cw_reference(state, stamp, base):
    reference = adaptive_reference(state, stamp)
    return (reference[0]["close_wait"] if reference is not None
            else base["values"]["close_wait"])


def process_sample(state, stamp, obs, base, db, *,
                   max_gap_seconds=LIVE_MAX_GAP_SECONDS):
    stamp_iso = instant(stamp).isoformat()
    previous = instant(state["last_sample"]) if state["last_sample"] else None
    if previous and instant(stamp) <= previous:
        return
    if previous and (instant(stamp) - previous).total_seconds() > max_gap_seconds:
        state["window"] = []
        if not state["incident_open"]:
            state["recent_good"] = []
        state["recovery"] = []
        state["recovery_streak"] = 0
        transition(state, "UNKNOWN", stamp_iso, obs, base, db)
    state["last_sample"] = stamp_iso
    state["latest_metrics"] = obs

    # INFO depends only on valid CLOSE-WAIT evidence.
    cw = obs.get("close_wait")
    cw_ref = early_cw_reference(state, stamp_iso, base)
    cw_spike = (isinstance(cw, (int, float)) and not isinstance(cw, bool)
                and math.isfinite(cw) and cw >= max(cw_ref * 2, cw_ref + 10))
    obs["early_cw_spike"] = cw_spike
    obs["early_cw_reference"] = cw_ref
    if cw_spike and not state["incident_open"]:
        info_base = {**base, "values": {**base["values"], "close_wait": cw_ref}}
        transition(state, "INFO", stamp_iso, obs, info_base, db,
                   reason="CW_SPIKE")

    if not obs["valid"]:
        state["incomplete_streak"] = state.get("incomplete_streak", 0) + 1
        if not state["incident_open"]:
            state["recent_good"] = []
        obs["alert_candidate"] = "UNKNOWN"
        obs["decision_reason"] = "INCOMPLETE_TELEMETRY"
        state["window"] = []
        state["recovery"] = []
        state["recovery_streak"] = 0
        transition(state, "UNKNOWN", stamp_iso, obs, base, db)
        if state["incomplete_streak"] >= 5 and not state["unknown_alerted"]:
            queue(db, f"MONITOR:{instant(stamp).strftime('%Y%m%dT%H%M%SZ')}:UNKNOWN",
                  render("UNKNOWN", state["incident"], stamp_iso, None, None),
                  stamp_iso)
            state["unknown_alerted"] = True
        return
    state["incomplete_streak"] = 0
    kind, reason = high_sensitivity_candidate(obs, base, state, stamp_iso)
    obs["alert_candidate"] = kind
    obs["decision_reason"] = reason
    state["latest_reason"] = reason
    state["window"] = (state["window"] + [kind])[-LIVE_CONFIRMATION_SAMPLES:]
    healthy = kind == "RECOVERY_CANDIDATE" and not cw_spike
    state["recovery_streak"] = state["recovery_streak"] + 1 if healthy else 0
    win = state["window"]
    confirmed = (len(win) == LIVE_CONFIRMATION_SAMPLES
                 and all(k in ("SUSPECTED", "DEGRADED") for k in win))
    if confirmed:
        transition(state, "SUSPECTED", stamp_iso, obs, base, db, reason=reason)
    elif state["incident_open"]:
        if state["recovery_streak"] >= 5:
            transition(state, "NORMAL", stamp_iso, obs, base, db)
        elif state["phase"] == "UNKNOWN":
            phase = ("SUSPECTED" if any(p in state["alerted_phases"]
                     for p in ("SUSPECTED", "DEGRADED")) else "INFO")
            transition(state, phase, stamp_iso, obs, base, db)
    elif state["phase"] == "UNKNOWN" and state["recovery_streak"] >= 5:
        transition(state, "NORMAL", stamp_iso, obs, base, db)

    record_healthy_reference(state, stamp_iso, obs)
    if state["phase"] != "UNKNOWN" and state["unknown_alerted"]:
        key = f"MONITOR:{instant(stamp).strftime('%Y%m%dT%H%M%SZ')}:RESUMED"
        queue(db, key, render("RESUMED", state["incident"], stamp_iso, obs, base),
              stamp_iso)
        state["unknown_alerted"] = False


def telegram_send(config, message, timeout=8):
    token = config["bot_token"]
    path = "https://api.telegram.org/bot" + token + "/sendMessage"
    payload = {"chat_id": config["chat_id"], "text": message, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    if config.get("message_thread_id") is not None:
        payload["message_thread_id"] = config["message_thread_id"]
    request = urllib.request.Request(
        path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.load(response)
            if not body.get("ok"):
                raise EvidenceError("Telegram API returned not-ok")
            return int(body["result"]["message_id"])
    except urllib.error.HTTPError as exc:
        # Never propagate the original URL; it embeds BOT_TOKEN.
        raise EvidenceError(f"Telegram HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise EvidenceError("Telegram network error") from None


def drain_outbox(db, config, now, send=telegram_send):
    row = db.execute("""SELECT event_key, message, attempts, next_attempt FROM outbox
        WHERE status='PENDING'
        ORDER BY created_at, event_key LIMIT 1""").fetchone()
    if row is None:
        return "IDLE"
    key, message, attempts, retry_at = row
    if retry_at > int(now.timestamp()):
        return "IDLE"
    try:
        msg_id = send(config, message)
    except Exception as exc:
        # No raw urllib exception or token-bearing URL in logs.
        tries = attempts + 1
        next_retry = int(now.timestamp()) + min(1800, 30 * (2 ** min(tries, 6)))
        db.execute("""UPDATE outbox SET attempts=?, next_attempt=?
            WHERE event_key=?""", (tries, next_retry, key))
        db.commit()
        return "SEND_ERROR:" + (str(exc) if isinstance(exc, EvidenceError)
                                else type(exc).__name__)
    db.execute("""UPDATE outbox SET status='SENT', attempts=?,
        message_id=? WHERE event_key=?""", (attempts + 1, msg_id, key))
    db.commit()
    return "SENT"


def recent_samples(source: Path, start: datetime, end: datetime):
    """Live tail-only reader: a stale malformed historical record cannot
    block today's notifications. P0 evidence validation remains strict.
    A recent corrupt row means a missing minute, never a zero metric.
    """
    if not source.is_dir():
        raise EvidenceError("Sampler source directory missing")
    records = []
    malformed = 0
    days = {start.date(), (end - timedelta(microseconds=1)).date()}
    for day in sorted(days):
        path = source / ("nvl-samples-" + day.strftime("%Y%m%d") + ".jsonl")
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise EvidenceError("Unsafe sampler input path")
        with path.open(encoding="utf-8", errors="replace") as f:
            tail = deque(f, maxlen=360)
        for raw in tail:
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("Not a JSON object")
                stamp = instant(row["timestamp_utc"])
            except (ValueError, KeyError, TypeError, EvidenceError):
                malformed += 1
                continue
            if start <= stamp < end:
                records.append((stamp, row))
    records.sort(key=lambda r: r[0])
    unique = {}
    for stamp, row in records:
        if stamp in unique:
            malformed += 1
        else:
            unique[stamp] = row
    return list(unique.items()), malformed


def tick(source, store, config_path, *, now=None, send=telegram_send,
         max_gap_seconds=LIVE_MAX_GAP_SECONDS):
    now = now or datetime.now(timezone.utc)
    base = baseline_load(store)
    conf = config_load(config_path)
    # Kernel counter observations; Netdata charts are optional.
    lookback = now - timedelta(minutes=12)
    samples, malformed = recent_samples(
        source, lookback, now + timedelta(seconds=5))
    # Avoid sending historical, already-ended incidents after a long outage.
    fresh = []
    for t, raw in samples:
        if (now - t).total_seconds() > 360:
            continue
        obs = observation(raw)
        iface = (raw.get("interface_rates_kbps") or {}).get("eth0") or {}
        for key, direction in (("eth_rx_mbps", "received"),
                               ("eth_tx_mbps", "sent")):
            value = iface.get(direction)
            obs[key] = (value / 1000 if isinstance(value, (int, float))
                        and not isinstance(value, bool)
                        and math.isfinite(value) and value >= 0 else None)
        fresh.append((t, obs))
    with db_connect(store) as db:
        state = state_read(db)
        # The old escalation event is retired; retain rows for audit.
        db.execute("UPDATE outbox SET status='SUPPRESSED' "
                   "WHERE status='PENDING' AND event_key LIKE '%:DEGRADED'")
        for stamp, obs in fresh:
            previous = state["last_sample"]
            process_sample(state, stamp, obs, base, db,
                           max_gap_seconds=max_gap_seconds)
            if state["last_sample"] != previous:
                db.execute("""INSERT OR IGNORE INTO decisions
                    (sample_utc, recorded_utc, candidate, phase,
                     metrics_json, baseline_start)
                    VALUES (?,?,?,?,?,?)""",
                    (instant(stamp).isoformat(), now.isoformat(),
                     obs.get("alert_candidate") or classify(obs, base), state["phase"],
                     json.dumps(obs, ensure_ascii=False, allow_nan=False),
                     base["window_start"]))
        last = instant(state["last_sample"]) if state["last_sample"] else None
        stale = last is None or (now - last).total_seconds() > 300
        if stale and not state["unknown_alerted"]:
            # A genuine monitor fault gets one notice; never classify as filtering.
            queue(db, f"MONITOR:{now.strftime('%Y%m%dT%H%M%SZ')}:UNKNOWN",
                  render("UNKNOWN", state["incident"], now.isoformat(),
                         None, None), now.isoformat())
            state["unknown_alerted"] = True
            state["window"] = []
            state["recovery"] = []
            state["recovery_streak"] = 0
            state["phase"] = "UNKNOWN"
        with db:
            state_write(db, state)
        delivery = drain_outbox(db, conf, now, send=send)
        return {"state": state["phase"], "incident": state["incident"],
                "new_samples": len(fresh), "last_sample": state["last_sample"],
                "delivery": delivery, "bad_recent_lines": malformed,
                "outbox_pending": db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE status='PENDING'").fetchone()[0]}


def command_line(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="cmd", required=True)
    setup = commands.add_parser("configure")
    setup.add_argument("--bot-env", type=Path, default=BOT_ENV)
    setup.add_argument("--chat-id", default=None)
    setup.add_argument("--topic", type=int, default=None)
    setup.add_argument("--config", type=Path, default=CONFIG)
    b = commands.add_parser("baseline")
    b.add_argument("--start", required=True)
    b.add_argument("--end", required=True)
    b.add_argument("--confirmed-normal", action="store_true", required=True)
    b.add_argument("--source", type=Path, default=SOURCE)
    b.add_argument("--store", type=Path, default=STATE_DIR)
    x = commands.add_parser("tick")
    x.add_argument("--source", type=Path, default=SOURCE)
    x.add_argument("--store", type=Path, default=STATE_DIR)
    x.add_argument("--config", type=Path, default=CONFIG)
    commands.add_parser("enrich-eth-baseline", help="Add ETH0 reference from existing verified baseline without rewriting it")
    x = commands.add_parser("send-test")
    x.add_argument("--config", type=Path, default=CONFIG)
    x = commands.add_parser("status")
    x.add_argument("--store", type=Path, default=STATE_DIR)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.cmd == "configure":
            configure(args.bot_env, args.chat_id, args.topic, args.config)
        elif args.cmd == "baseline":
            baseline_build(args.source, args.store, args.start,
                           args.end, args.confirmed_normal)
        elif args.cmd == "enrich-eth-baseline":
            enrich_eth_baseline(SOURCE, STATE_DIR)
        elif args.cmd == "tick":
            secure_parent(args.store)
            lock_file = args.store / ".tick.lock"
            with lock_file.open("a+") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    print('{"status":"ALREADY_RUNNING"}')
                    return 0
                print(json.dumps(tick(args.source, args.store, args.config),
                                 ensure_ascii=False))
        elif args.cmd == "send-test":
            conf = config_load(args.config)
            msg_id = telegram_send(conf, render(
                "TEST", None, datetime.now(timezone.utc).isoformat(), None, None))
            print(json.dumps({"status": "TEST_SENT", "message_id": msg_id}))
        elif args.cmd == "status":
            base = baseline_load(args.store)
            with db_connect(args.store) as db:
                state = state_read(db)
                pending = db.execute("SELECT COUNT(*) FROM outbox WHERE status='PENDING'").fetchone()[0]
                sent = db.execute("SELECT COUNT(*) FROM outbox WHERE status='SENT'").fetchone()[0]
                recent = db.execute("""SELECT sample_utc, candidate, phase
                    FROM decisions ORDER BY sample_utc DESC LIMIT 5""").fetchall()
            print(json.dumps({"phase": state["phase"], "incident": state["incident"],
                              "last_sample": state["last_sample"],
                              "baseline_quality": base["status"],
                              "eth_reference_active": all(f in base["values"] for f in EXTRA_FIELDS),
                              "baseline_window": [base["window_start"], base["window_end"]],
                              "pending": pending, "sent": sent,
                              "recent_decisions": [
                                  {"utc": t, "candidate": c, "phase": p}
                                  for t, c, p in recent]}, ensure_ascii=False))
        return 0
    except (EvidenceError, OSError, ValueError, json.JSONDecodeError,
            sqlite3.Error) as exc:
        # All errors are expected not to contain Telegram tokens.
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(command_line())
