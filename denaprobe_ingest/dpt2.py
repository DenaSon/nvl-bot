"""DPT/2 signed measurements. Isolated ingestion only; NEVER a filtering classifier.

DPT/1 continues unchanged in collector.py. This module retains authenticated,
versioned raw evidence in independent tables, never touches customer/bot state.
"""
from __future__ import annotations

from contextlib import closing
import base64
import hashlib
import ipaddress
import hmac
import json
import re
import sqlite3
import time

# Direct-script and package module startup both remain supported. The running
# Collector explicitly binds its own module to avoid duplicated DptError types.
try:
    from . import collector as v1
except ImportError:
    import collector as v1

def bind_collector(module):
    global v1
    v1 = module

ENDPOINT = "/api/dpt/v2/telemetry"
MAX_BODY = 1024
TCP_CODES = frozenset((1, 20, 21, 22, 90))
DEEP_CODES = frozenset((1, 10, 11, 12, 20, 21, 30, 31, 40, 41, 42, 90))
TRANSFER_CODES = frozenset((1, 2, 20, 21, 22, 23, 90))
TCP_FIELDS = frozenset(("u", "s", "ms"))
# Optional authenticated route tag: 1=CORE_LOOPBACK, never NPV egress.
DEEP_FIELDS = frozenset(("u", "s", "am", "sm", "f", "g", "rt"))
AUTH_FIELDS = frozenset(("u", "s", "ms"))
AUTH_CODES = frozenset((1, 10, 11, 12, 90))
TRANSFER_FIELDS = frozenset(("s", "r", "n", "ms"))
FIELDS = v1.FIELDS | frozenset(("c", "z", "j", "ei"))

DDL = """
CREATE TABLE IF NOT EXISTS dpt2_events (
 device_id TEXT NOT NULL, boot_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 kind INTEGER NOT NULL, target_id INTEGER, target_revision INTEGER,
 tcp_code INTEGER, deep_code INTEGER, https_code INTEGER,
 wifi_code INTEGER, first_code INTEGER, second_code INTEGER,
 first_bytes INTEGER, second_bytes INTEGER,
 sender_age_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL,
 history_only INTEGER NOT NULL, unknown_code INTEGER NOT NULL,
 body_sha256 TEXT NOT NULL, raw_json BLOB NOT NULL,
 PRIMARY KEY(device_id, boot_id, sequence)
);
CREATE INDEX IF NOT EXISTS ix_dpt2_history ON dpt2_events(device_id,received_at_ms DESC);
CREATE TABLE IF NOT EXISTS dpt2_boots (
 device_id TEXT NOT NULL, boot_id TEXT NOT NULL, registered INTEGER NOT NULL,
 max_sequence INTEGER NOT NULL, PRIMARY KEY(device_id,boot_id)
);
CREATE TABLE IF NOT EXISTS dpt2_latest (
 device_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL,
 ssh_sequence INTEGER, ssh_received_ms INTEGER, https_sequence INTEGER,
 https_received_ms INTEGER, last_event_sequence INTEGER NOT NULL DEFAULT 1,
 monitoring_gap INTEGER NOT NULL DEFAULT 1
);
"""

def initialize(db_path):
    with closing(v1.connect_db(db_path)) as db:
        db.executescript(DDL)


def sign(raw: bytes, device: str, key_id: str, sent: str, secret_hex: str) -> str:
    message = "\n".join(("DPT2", "POST", ENDPOINT, device, key_id, sent,
                         hashlib.sha256(raw).hexdigest())).encode("ascii")
    digest = hmac.new(bytes.fromhex(secret_hex), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authenticate(raw: bytes, headers: dict, config: dict) -> tuple[str, int]:
    names = ("x-dpt-device", "x-dpt-key-id", "x-dpt-sent-uptime-ms", "x-dpt-signature")
    if any(len(headers.get(name, [])) != 1 for name in names):
        raise v1.DptError(403, "unauthorized")
    device, key_id, sent, signature = (headers[n][0] for n in names)
    # Dedicated key-id namespace to prevent reusing any DPT/1 credential.
    if (not v1.DEVICE_RE.fullmatch(device) or
        not v1.KEY_RE.fullmatch(key_id) or not key_id.startswith("v2-") or
        not v1.DIGITS_RE.fullmatch(sent) or len(sent) > 16 or
        int(sent) > v1.MAX_SAFE_INT or not v1.B64_RE.fullmatch(signature)):
        raise v1.DptError(403, "unauthorized")
    entry = config.get(device)
    if not isinstance(entry, dict) or entry.get("enabled") is not True:
        raise v1.DptError(403, "unauthorized")
    keys = entry.get("keys")
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
        raise v1.DptError(403, "unauthorized")
    expected = sign(raw, device, key_id, sent, key)
    if not hmac.compare_digest(signature, expected):
        raise v1.DptError(403, "unauthorized")
    return device, int(sent)


def _object(value, required, allowed, bounds):
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise v1.DptError(422, "invalid_schema")
    for key, (lo, hi) in bounds.items():
        if key in value and not v1.integer(value[key], lo, hi):
            raise v1.DptError(422, "invalid_schema")


def _transfer(sample: dict) -> bool:
    _object(sample, {"s", "r"}, TRANSFER_FIELDS,
            {"s": (0, 65535), "r": (1, 65536),
             "n": (0, 65536), "ms": (0, 600000)})
    if sample.get("n", 0) > sample["r"]:
        raise v1.DptError(422, "invalid_semantics")
    code = sample["s"]
    if code in (1, 2):
        if sample.get("n") != sample["r"] or "ms" not in sample:
            raise v1.DptError(422, "invalid_semantics")
    return code not in TRANSFER_CODES


def validate(body: dict, sent: int) -> tuple[int, bool]:
    if not isinstance(body, dict) or set(body) - FIELDS or body.get("v") != 2 or type(body.get("v")) is not int:
        raise v1.DptError(422, "unsupported_version")
    # Reuse all frozen DPT/1 structural/semantic validation, preserving old meanings.
    old = {key: val for key, val in body.items() if key not in ("c", "z", "j", "ei")}
    old["v"] = 1
    kind, unknown = v1.validate(old, sent)
    if kind != 1 and ("c" in body or "z" in body or "j" in body or "ei" in body):
        raise v1.DptError(422, "invalid_semantics")
    if "c" in body:
        tcp = body["c"]
        _object(tcp, {"u", "s"}, TCP_FIELDS,
                {"u": (0, v1.MAX_SAFE_INT), "s": (0, 65535), "ms": (0, 600000)})
        if tcp["u"] > sent:
            raise v1.DptError(422, "invalid_semantics")
        unknown |= tcp["s"] not in TCP_CODES
    if "ei" in body:
        value = body["ei"]
        if type(value) is not str or not 7 <= len(value) <= 15:
            raise v1.DptError(422, "invalid_schema")
        try:
            parsed_ip = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise v1.DptError(422, "invalid_schema") from exc
        if str(parsed_ip) != value:
            raise v1.DptError(422, "invalid_schema")
        # A failed Edge DNS resolution cannot yield this-cycle Edge IP.
        if body.get("s") == 20:
            raise v1.DptError(422, "invalid_semantics")
    if "j" in body:
        auth = body["j"]
        _object(auth, {"u", "s", "ms"}, AUTH_FIELDS,
                {"u": (0, v1.MAX_SAFE_INT), "s": (0, 65535),
                 "ms": (0, 600000)})
        if body.get("s") != 1 or not body["u"] <= auth["u"] <= sent:
            raise v1.DptError(422, "invalid_semantics")
        unknown |= auth["s"] not in AUTH_CODES
    if "z" in body:
        z = body["z"]
        _object(z, {"u", "s"}, DEEP_FIELDS,
                {"u": (0, v1.MAX_SAFE_INT), "s": (0, 65535),
                 "am": (0, 600000), "sm": (0, 600000), "rt": (1, 2)})
        if body["s"] != 1 or z["u"] > sent:
            raise v1.DptError(422, "invalid_semantics")
        unknown |= z["s"] not in DEEP_CODES
        if z.get("rt") == 2:
            # Lite's controlled public witness is not NPV end-to-end health.
            # A signed login event must accompany its transfer witness.
            auth = body.get("j")
            if not isinstance(auth, dict) or auth["u"] > z["u"]:
                raise v1.DptError(422, "invalid_semantics")
            if auth["s"] != 1 and (z["s"] != auth["s"] or
                                   "f" in z or "g" in z):
                raise v1.DptError(422, "invalid_semantics")
            for name in ("f", "g"):
                if name in z and (
                    not isinstance(z[name], dict) or z[name].get("r") != 8192
                ):
                    raise v1.DptError(422, "invalid_semantics")
        if z["s"] in (10, 11, 12) and ("f" in z or "g" in z):
            raise v1.DptError(422, "invalid_semantics")
        for name in ("f", "g"):
            if name in z:
                unknown |= _transfer(z[name])
        if z["s"] == 1 and (
            "f" not in z or "g" not in z or
            z["f"]["s"] not in (1, 2) or z["g"]["s"] not in (1, 2)):
            raise v1.DptError(422, "invalid_semantics")
        if z["s"] == 42 and not any(
            isinstance(z.get(k), dict) and z[k]["s"] == 2 for k in ("f", "g")
        ):
            raise v1.DptError(422, "invalid_semantics")
    return kind, bool(unknown)


def store(db_path, body: dict, raw: bytes, sent: int, allowed_targets=None, now_ms=None) -> int:
    kind, unknown = validate(body, sent)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    device, boot_id, q = body["id"], body["b"], body["q"]
    age = sent - max(body["u"], body.get("h", {}).get("u", 0),
                     body.get("c", {}).get("u", 0), body.get("z", {}).get("u", 0),
                     body.get("j", {}).get("u", 0))
    # Each channel has its own freshness; cannot promote old ssh if deep ran later.
    ssh_age = sent - body["u"]
    https_age = sent - body.get("h", {}).get("u", sent)
    tcp_age = sent - body.get("c", {}).get("u", sent)
    deep_age = sent - body.get("z", {}).get("u", sent)
    auth_age = sent - body.get("j", {}).get("u", sent)
    sha = hashlib.sha256(raw).hexdigest()
    with closing(v1.connect_db(db_path)) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT body_sha256 FROM dpt2_events WHERE device_id=? AND boot_id=? AND sequence=?",
            (device, boot_id, q)).fetchone()
        if existing:
            if hmac.compare_digest(existing["body_sha256"], sha):
                db.commit()
                return 1
            raise v1.DptError(409, "identity_conflict")
        previous = db.execute(
            "SELECT registered,max_sequence FROM dpt2_boots WHERE device_id=? AND boot_id=?",
            (device, boot_id)).fetchone()
        current = db.execute("SELECT boot_id FROM dpt2_latest WHERE device_id=?",
                             (device,)).fetchone()
        can_boot = kind == 3 and previous is None and sent - body["u"] <= v1.BOOT_MAX_AGE_MS
        # Independent DPT/2 live state. DPT/1 records are never reinterpreted.
        if can_boot:
            db.execute(
                "INSERT INTO dpt2_latest(device_id,boot_id,monitoring_gap) "
                "VALUES(?,?,1) ON CONFLICT(device_id) DO UPDATE SET "
                "boot_id=excluded.boot_id,ssh_sequence=NULL,ssh_received_ms=NULL,"
                "https_sequence=NULL,https_received_ms=NULL,"
                "last_event_sequence=1,monitoring_gap=1",
                (device, boot_id))
        if previous is None:
            db.execute("INSERT INTO dpt2_boots VALUES(?,?,?,?)",
                       (device, boot_id, 1 if can_boot else 0, q))
            previous_q = 0
        else:
            previous_q = previous["max_sequence"]
            db.execute(
                "UPDATE dpt2_boots SET max_sequence=MAX(max_sequence,?) "
                "WHERE device_id=? AND boot_id=?", (q, device, boot_id))
        current_boot = (boot_id if can_boot else (current["boot_id"] if current else None))
        ordered = bool(previous and previous["registered"] and q == previous_q + 1)
        target = body.get("t")
        target_revision = None
        if kind == 1:
            target_row = db.execute(
                "SELECT revision FROM targets WHERE target_id=? ORDER BY revision DESC LIMIT 1",
                (target,)).fetchone()
            target_revision = target_row["revision"] if target_row else None
        allowed = allowed_targets is None or target in allowed_targets
        eligible = (
            kind == 1 and current_boot == boot_id and ordered and not unknown
            and body.get("w") == 1  # lost/unknown hotspot cannot advance live
            and ssh_age <= v1.SSH_MAX_AGE_MS and
            https_age <= v1.HTTPS_MAX_AGE_MS and
            tcp_age <= v1.SSH_MAX_AGE_MS and
            deep_age <= v1.SSH_MAX_AGE_MS and
            auth_age <= v1.SSH_MAX_AGE_MS and
            allowed and target_revision is not None
        )
        history = (kind == 1 and not eligible or
                   kind == 2 and (current_boot != boot_id or not ordered or
                                  unknown or ssh_age > v1.SSH_MAX_AGE_MS) or
                   kind == 3 and not can_boot)
        z = body.get("z", {})
        db.execute(
            "INSERT INTO dpt2_events(device_id,boot_id,sequence,kind,target_id,target_revision,"
            "tcp_code,deep_code,https_code,wifi_code,first_code,second_code,"
            "first_bytes,second_bytes,sender_age_ms,received_at_ms,history_only,"
            "unknown_code,body_sha256,raw_json) VALUES(" + ",".join(["?"] * 20) + ")",
            (device, boot_id, q, kind, target, target_revision,
             body.get("c", {}).get("s"), z.get("s"), body.get("h", {}).get("c"),
             body.get("w"), z.get("f", {}).get("s"), z.get("g", {}).get("s"),
             z.get("f", {}).get("n"), z.get("g", {}).get("n"),
             age, now, int(bool(history)), int(bool(unknown)), sha, raw))
        if eligible:
            latest = db.execute(
                "SELECT ssh_sequence,ssh_received_ms FROM dpt2_latest "
                "WHERE device_id=? AND boot_id=?", (device, boot_id)).fetchone()
            confirmed = bool(
                latest and latest["ssh_sequence"] == q - 1 and
                latest["ssh_received_ms"] is not None and
                0 <= now - latest["ssh_received_ms"] <= v1.SSH_MAX_AGE_MS)
            db.execute(
                "UPDATE dpt2_latest SET ssh_sequence=?,ssh_received_ms=?,"
                "https_sequence=CASE WHEN ? THEN ? ELSE https_sequence END,"
                "https_received_ms=CASE WHEN ? THEN ? ELSE https_received_ms END,"
                "last_event_sequence=?,monitoring_gap=? WHERE device_id=? AND boot_id=?",
                (q, now, int("h" in body), q, int("h" in body), now,
                 q, 0 if confirmed else 1, device, boot_id))
        elif kind == 2 and not history and current_boot == boot_id:
            db.execute("UPDATE dpt2_latest SET last_event_sequence=?,monitoring_gap=1 "
                       "WHERE device_id=? AND boot_id=?", (q, device, boot_id))
        db.commit()
    return 2 if history else 0
