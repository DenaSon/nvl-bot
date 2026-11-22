#!/usr/bin/env python3
"""NVL Core-only live alert pilot: persistent, multi-signal, Telegram group-only.

Separate from the NVL bot, SSH, Edge, Netdata and the read-only sampler.
No daemon is started by importing or running the configure/baseline commands.
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import html
import json
import math
import os
import re
import sqlite3
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
                                            classify, load_samples, observation, utc)
except ImportError:  # direct file installation beside nvl_network_intelligence.py
    from nvl_network_intelligence import (EvidenceError, FIELDS, build_baseline,
                                          classify, load_samples, observation, utc)

IRAN = ZoneInfo("Asia/Tehran")
SOURCE = Path("/root/nvl-network-observations")
STATE_DIR = Path("/var/lib/nvl-network-alerts")
CONFIG = Path("/etc/nvl-network-alerts/telegram.json")
BOT_ENV = Path("/etc/nvlbot/nvlbot.env")
TOKEN_RE = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{20,}$")
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
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise EvidenceError("Unsafe storage directory")
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
    data = read_json(path)
    if (data.get("schema") != "nvl-group-telegram-1"
            or not re.fullmatch(r"-[1-9][0-9]{5,20}", str(data.get("chat_id", "")))
            or not TOKEN_RE.fullmatch(str(data.get("bot_token", "")))):
        raise EvidenceError("Missing/invalid Telegram group config")
    return data


def fmt_time(stamp):
    return utc(stamp).astimezone(IRAN).strftime("%Y-%m-%d %H:%M:%S")


def baseline_build(source, store, start, end, confirmed):
    if not confirmed:
        raise EvidenceError("Operator must confirm a clean 60+ minute window")
    if (store / "state.sqlite3").exists():
        raise EvidenceError("Detector state exists: no live baseline replacement")
    begin, finish = utc(start), utc(end)
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
    # ETH is corroborating evidence, never required for the primary classifier.
    # Missing ETH leaves it absent instead of inventing a zero or blocking alerting.
    for field, direction in (("eth_rx_mbps", "received"), ("eth_tx_mbps", "sent")):
        vals = []
        for _, row in records:
            v = (row.get("interface_rates_kbps") or {}).get("eth0") or {}
            num = v.get(direction)
            if isinstance(num, (int, float)) and not isinstance(num, bool) and math.isfinite(num) and num >= 0:
                vals.append(num / 1000)
        if len(vals) >= .8 * base["valid_count"]:
            from statistics import median
            base["values"][field] = median(vals)
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
    return value


def default_state():
    return {"version": STATE_VERSION, "phase": "NORMAL", "incident": None,
            "seq": 0, "last_sample": None, "window": [], "recovery": [],
            "recovering_since": None, "recovery_streak": 0,
            "incident_open": False, "unknown_alerted": False,
            "incomplete_streak": 0,
            "latest_metrics": None, "last_closed": None,
            "alerted_phases": []}


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
    if reference is None or reference <= 0:
        return "N/A"
    return f"{(value/reference-1)*100:+.0f}%"


def fmt_metric(value, label):
    if value is None:
        return "نامشخص"
    return f"{value:.2f} Mbps" if "AWG " in label else f"{value:.0f}"


def render(phase, incident, stamp, metrics, baseline):
    captions = {
        "SUSPECTED": "🟠 <b>NVL | اختلال احتمالی ارتباط</b>",
        "DEGRADED": "🔴 <b>NVL | تشدید اختلال ارتباط</b>",
        "RECOVERED": "🟢 <b>NVL | بازگشت شاخص‌های شبکه</b>",
        "UNKNOWN": "⚪ <b>NVL | وقفه در پایش شبکه</b>",
        "RESUMED": "🔵 <b>NVL | دریافت داده از سر گرفته شد</b>",
        "TEST": "🧪 <b>NVL | آزمایش ارسال هشدار گروه</b>",
    }
    lines = [captions[phase], f"شناسه: <code>{html.escape(incident or 'MONITOR')}</code>",
             f"زمان: {html.escape(fmt_time(stamp))} تهران",
             "وضعیت: پایش آزمایشیِ فعال (بدون Shadow)"]
    if metrics and baseline:
        for field in (*FIELDS, *EXTRA_FIELDS):
            val = metrics.get(field)
            label = METRIC_LABELS[field]
            ref = baseline["values"].get(field)
            if val is not None:
                lines.append(f"{label}: <b>{fmt_metric(val, label)}</b> "
                             f"({pct(val, ref)})")
            else:
                lines.append(f"{label}: نامشخص")
    if phase == "UNKNOWN":
        lines.append("داده تازه در دسترس نیست؛ این به معنی رفع اختلال نیست.")
    if phase == "RECOVERED":
        lines.append("بازیابی شاخص‌ها تأیید شده؛ اتصال تک‌تک کاربران آزمایش نشده است.")
    if phase == "TEST":
        lines.append("تست ارسال به همین گروه؛ هیچ اختلالی اعلام نشده است.")
    else:
        lines.append("شواهد فقط از Core هستند؛ اثبات قطعی فیلترینگ اپراتور نیستند.")
    return "\n".join(lines)


def make_incident(stamp, state):
    state["seq"] += 1
    return "NVL-" + utc(stamp).strftime("%Y%m%dT%H%M%SZ") + f"-{state['seq']:03d}"


def transition(state, next_phase, stamp, metrics, base, db):
    prev = state["phase"]
    if prev == next_phase:
        return
    state["phase"] = next_phase
    if next_phase in ("SUSPECTED", "DEGRADED"):
        if not state["incident_open"]:
            state["incident"] = make_incident(stamp, state)
            state["incident_open"] = True
            state["alerted_phases"] = []
        if next_phase not in state["alerted_phases"]:
            # Suppress rapid fresh SUSPECTED alerts after a completed incident;
            # DEGRADED always sends, as material escalation.
            just_closed = (state["last_closed"] is not None
                           and (utc(stamp) - utc(state["last_closed"])).total_seconds() < 1200)
            if not (next_phase == "SUSPECTED" and just_closed):
                key = f"{state['incident']}:{next_phase}"
                queue(db, key, render(next_phase, state["incident"], stamp, metrics, base),
                      utc(stamp).isoformat())
                state["alerted_phases"].append(next_phase)
    elif next_phase == "RECOVERING":
        state["recovering_since"] = utc(stamp).isoformat()
    elif next_phase == "NORMAL" and state["incident_open"]:
        if state["alerted_phases"]:
            key = f"{state['incident']}:RECOVERED"
            queue(db, key, render("RECOVERED", state["incident"], stamp, metrics, base),
                  utc(stamp).isoformat())
        state["last_closed"] = utc(stamp).isoformat()
        state["incident_open"] = False
        state["incident"] = None
        state["alerted_phases"] = []
        state["recovering_since"] = None
    # UNKNOWN doesn't close an existing incident. Missing data cannot recover it.


def process_sample(state, stamp, obs, base, db):
    stamp_iso = utc(stamp).isoformat()
    previous = utc(state["last_sample"]) if state["last_sample"] else None
    if previous and utc(stamp) <= previous:
        return
    if previous and (utc(stamp) - previous).total_seconds() > 150:
        state["window"] = []
        state["recovery"] = []
        state["recovery_streak"] = 0
        transition(state, "UNKNOWN", stamp_iso, obs, base, db)
    state["last_sample"] = stamp_iso
    state["latest_metrics"] = obs
    if not obs["valid"]:
        state["incomplete_streak"] = state.get("incomplete_streak", 0) + 1
        state["window"] = []
        state["recovery"] = []
        state["recovery_streak"] = 0
        transition(state, "UNKNOWN", stamp_iso, obs, base, db)
        if state["incomplete_streak"] >= 5 and not state["unknown_alerted"]:
            queue(db, f"MONITOR:{utc(stamp).strftime('%Y%m%dT%H%M%SZ')}:UNKNOWN",
                  render("UNKNOWN", state["incident"], stamp_iso, None, None),
                  stamp_iso)
            state["unknown_alerted"] = True
        return
    state["incomplete_streak"] = 0
    kind = classify(obs, base)
    state["window"] = (state["window"] + [kind])[-5:]
    state["recovery"] = (state["recovery"] + [kind == "RECOVERY_CANDIDATE"])[-7:]
    state["recovery_streak"] = (
        state["recovery_streak"] + 1 if kind == "RECOVERY_CANDIDATE" else 0)
    win = state["window"]
    phase = state["phase"]
    nxt = None
    if len(win) == 5 and sum(k == "DEGRADED" for k in win) >= 3:
        nxt = "DEGRADED"
    elif len(win) == 5 and sum(
            k in ("SUSPECTED", "DEGRADED") for k in win) >= 3:
        if phase not in ("DEGRADED", "RECOVERING"):
            nxt = "SUSPECTED"
    elif (state["incident_open"]
          and phase in ("SUSPECTED", "DEGRADED", "RECOVERING", "UNKNOWN")
          and len(state["recovery"]) == 7
          and sum(state["recovery"]) >= 5):
        nxt = "RECOVERING"
        since = state["recovering_since"]
        if (phase == "RECOVERING" and since is not None
                and state["recovery_streak"] >= 10
                and (utc(stamp) - utc(since)).total_seconds() >= 600):
            nxt = "NORMAL"
    elif phase == "UNKNOWN" and not state["incident_open"] and len(win) == 5:
        nxt = "NORMAL"

    if nxt is not None:
        transition(state, nxt, stamp_iso, obs, base, db)
    if state["phase"] not in ("UNKNOWN",) and state["unknown_alerted"]:
        key = f"MONITOR:{utc(stamp).strftime('%Y%m%dT%H%M%SZ')}:RESUMED"
        queue(db, key, render("RESUMED", state["incident"], stamp_iso,
                              obs, base), stamp_iso)
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
    row = db.execute("""SELECT event_key, message, attempts FROM outbox
        WHERE status='PENDING' AND next_attempt <= ?
        ORDER BY created_at, event_key LIMIT 1""", (int(now.timestamp()),)).fetchone()
    if row is None:
        return "IDLE"
    key, message, attempts = row
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
            tail = deque(f, maxlen=90)
        for raw in tail:
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("Not a JSON object")
                stamp = utc(row["timestamp_utc"])
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


def tick(source, store, config_path, *, now=None, send=telegram_send):
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
        for stamp, obs in fresh:
            previous = state["last_sample"]
            process_sample(state, stamp, obs, base, db)
            if state["last_sample"] != previous:
                db.execute("""INSERT OR IGNORE INTO decisions
                    (sample_utc, recorded_utc, candidate, phase,
                     metrics_json, baseline_start)
                    VALUES (?,?,?,?,?,?)""",
                    (utc(stamp).isoformat(), now.isoformat(),
                     classify(obs, base), state["phase"],
                     json.dumps(obs, ensure_ascii=False, allow_nan=False),
                     base["window_start"]))
        last = utc(state["last_sample"]) if state["last_sample"] else None
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
