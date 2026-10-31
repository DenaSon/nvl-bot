"""DPT/1 Core collector. Standalone stdlib-only service; never imports NVLBot or bot DB.

Security boundary: authenticated raw observations only. No filtering detection, alerts,
remote commands, GOST/WireGuard/DNS mutations, or public read API.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile
import time

ENDPOINT = "/api/dpt/v1/telemetry"
MAX_BODY = 1024
MAX_SAFE_INT = (1 << 53) - 1
DEVICE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
KEY_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
BOOT_RE = re.compile(r"^[a-f0-9]{32}$")
B64_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
DIGITS_RE = re.compile(r"^(0|[1-9][0-9]*)$")
FIELDS = frozenset("v id b q u k t w r s p o d x a ts h".split())
HTTPS_FIELDS = frozenset("c u n bt ms ds hd fb hc".split())
PROBE_CODES = frozenset((0, 1, 10, 20, 30, 31, 40, 41, 50, 51, 90, 91, 92, 93, 94, 95, 96))
STAGES = frozenset((0, 10, 20, 21, 30, 31, 32, 33, 34, 35, 40, 50, 51, 52, 90))
HTTPS_CODES = frozenset((0, 1, 2, 10, 11, 12, 20, 30, 31, 32, 40, 41, 42))
SCHEMA_VERSION = 1
SSH_MAX_AGE_MS = 90_000
HTTPS_MAX_AGE_MS = 360_000
BOOT_MAX_AGE_MS = 360_000


class DptError(Exception):
    def __init__(self, http_status: int, code: str):
        self.http_status = http_status
        self.code = code


def unique_pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for k, v in items:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result


def json_body(raw: bytes) -> dict:
    try:
        body = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise DptError(400, "invalid_json") from exc
    if not isinstance(body, dict):
        raise DptError(422, "invalid_schema")
    return body


def integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def validate(body: dict, sent_uptime: int) -> tuple[int, bool]:
    """Structural+semantic DPT/1 subset; preserve unknown numeric codes safely."""
    if set(body) - FIELDS or not all(k in body for k in ("v", "id", "b", "q", "u", "k")):
        raise DptError(422, "invalid_schema")
    if body["v"] != 1 or type(body["v"]) is not int:
        raise DptError(422, "unsupported_version")
    if not isinstance(body["id"], str) or not DEVICE_RE.fullmatch(body["id"]):
        raise DptError(422, "invalid_schema")
    if not isinstance(body["b"], str) or not BOOT_RE.fullmatch(body["b"]):
        raise DptError(422, "invalid_schema")
    if not integer(body["q"], 1, (1 << 32) - 1) or not integer(body["u"], 0, MAX_SAFE_INT):
        raise DptError(422, "invalid_schema")
    kind = body["k"]
    if not integer(kind, 1, 3) or sent_uptime < body["u"]:
        raise DptError(422, "invalid_schema")

    kinds = {1: {"t", "w", "s", "p", "o"}, 2: {"s"}, 3: set()}
    forbidden = {1: set(), 2: {"p", "o", "h", "x", "a", "d", "t"},
                 3: {"s", "p", "o", "h", "t", "x", "a", "d"}}
    if not kinds[kind].issubset(body) or forbidden[kind].intersection(body):
        raise DptError(422, "invalid_schema")
    if kind == 3 and body["q"] != 1:
        raise DptError(422, "invalid_schema")

    rules = {
        "t": (1, 65535), "w": (0, 2), "r": (-127, -1),
        "s": (0, 65535), "p": (0, 65535), "o": (0, 255),
        "d": (0, 600000), "x": (0, 600000), "a": (0, 600000),
        "ts": (1700000000000, MAX_SAFE_INT),
    }
    for key, (lo, hi) in rules.items():
        if key in body and not integer(body[key], lo, hi):
            raise DptError(422, "invalid_schema")
    if "r" in body and body.get("w") != 1:
        raise DptError(422, "invalid_schema")
    if kind == 2 and (not integer(body["s"], 90, 255) or
                      (body["s"] == 96 and "w" not in body)):
        raise DptError(422, "invalid_schema")
    unknown = False
    if kind == 1:
        s, p, o = body["s"], body["p"], body["o"]
        if s == 1 and (p != 52 or o & 224 != 224):
            raise DptError(422, "invalid_semantics")
        if s == 50 and (p != 51 or o & 96 != 96 or o & 128):
            raise DptError(422, "invalid_semantics")
        if s == 41 and (p != 40 or o & 64):
            raise DptError(422, "invalid_semantics")
        unknown = s not in PROBE_CODES or p not in STAGES
    if kind == 2:
        unknown = body["s"] not in PROBE_CODES

    if "h" in body:
        h = body["h"]
        if kind != 1 or not isinstance(h, dict) or set(h) - HTTPS_FIELDS or not {"c", "u"}.issubset(h):
            raise DptError(422, "invalid_schema")
        bounds = {"c": (0, 65535), "u": (0, MAX_SAFE_INT), "n": (0, 65536),
                  "bt": (0, 12000), "ms": (0, 600000), "ds": (0, 600000),
                  "hd": (0, 600000), "fb": (0, 600000), "hc": (100, 599)}
        for name, (lo, hi) in bounds.items():
            if name in h and not integer(h[name], lo, hi):
                raise DptError(422, "invalid_schema")
        if h["u"] < body["u"] or sent_uptime < h["u"]:
            raise DptError(422, "invalid_semantics")
        if h["c"] in (1, 2) and (h.get("n") != 65536 or "bt" not in h):
            raise DptError(422, "invalid_semantics")
        unknown |= h["c"] not in HTTPS_CODES
    return kind, unknown


def load_devices(path: Path) -> dict:
    # Fail closed on absent / too permissive keys file, including on revocations.
    if path.is_symlink():
        raise ValueError("key file must not be symlink")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        raise ValueError("key file must be a private 0600 regular file")
    content = json.loads(path.read_text(encoding="utf-8"))
    devices = content.get("devices")
    if not isinstance(devices, dict):
        raise ValueError("invalid devices config")
    return devices


def signed_mac(raw: bytes, device: str, key_id: str, sent: str, secret_hex: str) -> str:
    msg = "\n".join(("DPT1", "POST", ENDPOINT, device, key_id, sent,
                     hashlib.sha256(raw).hexdigest())).encode("ascii")
    mac = hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def authenticate(raw: bytes, headers: dict[str, list[str]], config: dict) -> tuple[str, int]:
    needed = ("x-dpt-device", "x-dpt-key-id", "x-dpt-sent-uptime-ms", "x-dpt-signature")
    if any(len(headers.get(k, [])) != 1 for k in needed):
        raise DptError(403, "unauthorized")
    device, key_id, sent, signature = (headers[k][0] for k in needed)
    if not DEVICE_RE.fullmatch(device) or not KEY_RE.fullmatch(key_id) or not DIGITS_RE.fullmatch(sent):
        raise DptError(403, "unauthorized")
    if len(sent) > 16 or int(sent) > MAX_SAFE_INT or not B64_RE.fullmatch(signature):
        raise DptError(403, "unauthorized")
    entry = config.get(device)
    if not isinstance(entry, dict) or entry.get("enabled") is not True:
        raise DptError(403, "unauthorized")
    keys = entry.get("keys")
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, str) or not re.fullmatch("[0-9a-f]{64}", key):
        raise DptError(403, "unauthorized")
    expected = signed_mac(raw, device, key_id, sent, key)
    if not hmac.compare_digest(signature, expected):
        raise DptError(403, "unauthorized")
    return device, int(sent)


DDL = """
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
  current_boot TEXT, first_seen_ms INTEGER NOT NULL, last_seen_ms INTEGER
);
CREATE TABLE IF NOT EXISTS targets (
  target_id INTEGER NOT NULL, revision INTEGER NOT NULL,
  hostname TEXT NOT NULL, port INTEGER NOT NULL, effective_ms INTEGER NOT NULL,
  PRIMARY KEY (target_id, revision)
);
CREATE TABLE IF NOT EXISTS device_boots (
  device_id TEXT NOT NULL, boot_id TEXT NOT NULL, registered INTEGER NOT NULL DEFAULT 0,
  first_seen_ms INTEGER NOT NULL, last_seen_ms INTEGER NOT NULL,
  max_sequence INTEGER NOT NULL, PRIMARY KEY(device_id, boot_id)
);
CREATE TABLE IF NOT EXISTS telemetry_events (
  device_id TEXT NOT NULL, boot_id TEXT NOT NULL, sequence INTEGER NOT NULL,
  event_kind INTEGER NOT NULL, ssh_code INTEGER, stop_stage INTEGER, observed_bits INTEGER,
  target_id INTEGER, target_revision INTEGER, wifi_code INTEGER, wifi_rssi INTEGER,
  https_code INTEGER, measurement_uptime_ms INTEGER NOT NULL,
  https_uptime_ms INTEGER, sent_uptime_ms INTEGER NOT NULL,
  sender_age_ms INTEGER NOT NULL, https_sender_age_ms INTEGER,
  received_at_ms INTEGER NOT NULL, history_only INTEGER NOT NULL,
  unknown_code INTEGER NOT NULL, body_sha256 TEXT NOT NULL, raw_json BLOB NOT NULL,
  PRIMARY KEY (device_id, boot_id, sequence)
);
CREATE INDEX IF NOT EXISTS ix_dpt_device_history ON telemetry_events(device_id, received_at_ms DESC);
CREATE INDEX IF NOT EXISTS ix_dpt_target_history ON telemetry_events(target_id, received_at_ms DESC);
CREATE TABLE IF NOT EXISTS device_latest_state (
  device_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL,
  ssh_sequence INTEGER, ssh_received_ms INTEGER, https_sequence INTEGER,
  https_received_ms INTEGER, last_event_sequence INTEGER NOT NULL DEFAULT 1,
  monitoring_gap INTEGER NOT NULL DEFAULT 1
);
"""


def connect_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect_db(db_path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(DDL)
    os.chmod(db_path, 0o600)


def register_target(db_path: Path, target: int, hostname: str, port: int) -> int:
    if not integer(target, 1, 65535) or not hostname or len(hostname) > 253 or not integer(port, 1, 65535):
        raise ValueError("invalid target")
    with connect_db(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT COALESCE(MAX(revision),0) FROM targets WHERE target_id=?", (target,)).fetchone()
        revision = row[0] + 1
        db.execute("INSERT INTO targets VALUES(?,?,?,?,?)",
                   (target, revision, hostname, port, int(time.time() * 1000)))
        db.commit()
    return revision


def store(db_path: Path, payload: dict, raw: bytes, sent: int,
          allowed_targets: list[int] | None = None, now_ms: int | None = None) -> int:
    """Durable atomic insert. Return 0 NEW, 1 EXACT DUPLICATE, 2 HISTORY ONLY."""
    kind, unknown = validate(payload, sent)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    device, boot, q = payload["id"], payload["b"], payload["q"]
    digest = hashlib.sha256(raw).hexdigest()
    age = sent - payload["u"]
    h = payload.get("h")
    h_age = sent - h["u"] if h else None
    with connect_db(db_path) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT body_sha256 FROM telemetry_events WHERE device_id=? AND boot_id=? AND sequence=?",
                         (device, boot, q)).fetchone()
        if old:
            if hmac.compare_digest(old[0], digest):
                db.commit()
                return 1
            raise DptError(409, "identity_conflict")
        db.execute("INSERT OR IGNORE INTO devices(id,first_seen_ms) VALUES(?,?)", (device, now))
        dev = db.execute("SELECT current_boot FROM devices WHERE id=?", (device,)).fetchone()
        prior = db.execute("SELECT registered,max_sequence FROM device_boots WHERE device_id=? AND boot_id=?",
                           (device, boot)).fetchone()
        current_boot = dev["current_boot"]
        new_boot = kind == 3 and prior is None
        can_activate = new_boot and age <= BOOT_MAX_AGE_MS
        if kind == 3 and prior is not None:
            # Orphan boot with pre-registration history never takes over live state.
            can_activate = False
        if can_activate:
            db.execute("UPDATE devices SET current_boot=? WHERE id=?", (boot, device))
            current_boot = boot
            db.execute("""INSERT INTO device_latest_state(device_id,boot_id,monitoring_gap)
                          VALUES(?,?,1) ON CONFLICT(device_id) DO UPDATE SET
                          boot_id=excluded.boot_id,ssh_sequence=NULL,https_sequence=NULL,
                          ssh_received_ms=NULL,https_received_ms=NULL,last_event_sequence=1,
                          monitoring_gap=1""", (device, boot))
        if prior is None:
            db.execute("INSERT INTO device_boots VALUES(?,?,?,?,?,?)",
                       (device, boot, 1 if kind == 3 else 0, now, now, q))
            prev_sequence = 0
        else:
            prev_sequence = prior["max_sequence"]
            db.execute("""UPDATE device_boots SET last_seen_ms=?,
                          max_sequence=MAX(max_sequence,?) WHERE device_id=? AND boot_id=?""",
                       (now, q, device, boot))
        db.execute("UPDATE devices SET last_seen_ms=? WHERE id=?", (now, device))
        revision = None
        target = payload.get("t")
        allowed = allowed_targets is None or target in allowed_targets
        if kind == 1:
            target_row = db.execute("""SELECT revision FROM targets WHERE target_id=?
                                       ORDER BY revision DESC LIMIT 1""", (target,)).fetchone()
            revision = target_row[0] if target_row else None
        # A source can submit backlog; preserve it, but never advance live state.
        fresh = age <= SSH_MAX_AGE_MS and (h_age is None or h_age <= HTTPS_MAX_AGE_MS)
        ordered = (q == prev_sequence + 1) and bool(prior and prior["registered"])
        eligible = (kind == 1 and boot == current_boot and ordered and fresh
                    and not unknown and allowed and revision is not None)
        history = kind == 1 and not eligible or kind == 2 and (boot != current_boot or
                  q != prev_sequence + 1) or kind == 3 and not can_activate
        db.execute("""INSERT INTO telemetry_events(
                    device_id,boot_id,sequence,event_kind,ssh_code,stop_stage,observed_bits,
                    target_id,target_revision,wifi_code,wifi_rssi,https_code,
                    measurement_uptime_ms,https_uptime_ms,sent_uptime_ms,
                    sender_age_ms,https_sender_age_ms,received_at_ms,
                    history_only,unknown_code,body_sha256,raw_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (device, boot, q, kind, payload.get("s"), payload.get("p"),
                    payload.get("o"), target, revision, payload.get("w"),
                    payload.get("r"), h.get("c") if h else None, payload["u"],
                    h.get("u") if h else None, sent, age, h_age, now,
                    1 if history else 0, 1 if unknown else 0, digest, raw))
        if eligible:
            # Two *actual, eligible SSH observations* must be consecutive to
            # clear a gap. A BOOT or DEVICE_EVENT before the first SSH must
            # never count as the first healthy probe; neither may an old
            # replayed/history-only result establish continuity.
            latest = db.execute("""SELECT ssh_sequence,ssh_received_ms
                                   FROM device_latest_state
                                   WHERE device_id=? AND boot_id=?""",
                                (device, boot)).fetchone()
            continuity = bool(
                latest and latest["ssh_sequence"] is not None
                and latest["ssh_sequence"] == q - 1
                and latest["ssh_received_ms"] is not None
                and 0 <= now - latest["ssh_received_ms"] <= SSH_MAX_AGE_MS
            )
            monitoring_gap = 0 if continuity else 1
            db.execute("""UPDATE device_latest_state SET ssh_sequence=?,
                          ssh_received_ms=?,https_sequence=CASE WHEN ? THEN ? ELSE https_sequence END,
                          https_received_ms=CASE WHEN ? THEN ? ELSE https_received_ms END,
                          last_event_sequence=?,monitoring_gap=? WHERE device_id=? AND boot_id=?""",
                       (q, now, bool(h), q, bool(h), now, q, monitoring_gap, device, boot))
        elif kind == 2 and not history and boot == current_boot:
            db.execute("""UPDATE device_latest_state SET last_event_sequence=?,
                          monitoring_gap=1 WHERE device_id=? AND boot_id=?""",
                       (q, device, boot))
        db.commit()
    return 2 if history else 0


class CollectorHTTP(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    allow_reuse_address = True

    def __init__(self, bind: tuple[str, int], db: Path, keys: Path):
        super().__init__(bind, CollectorHandler)
        self.db_path = db
        self.keys_path = keys


class CollectorHandler(BaseHTTPRequestHandler):
    server_version = "DPT-Collector/1"
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(7)

    def respond(self, code: int, value: dict | None = None) -> None:
        raw = json.dumps(value or {"error": "request_rejected"},
                         separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if code in (429, 503):
            self.send_header("Retry-After", "5")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.respond(404)
            return
        try:
            with connect_db(self.server.db_path) as db:
                db.execute("SELECT 1 FROM telemetry_events LIMIT 1")
            load_devices(self.server.keys_path)
        except (OSError, sqlite3.Error, ValueError):
            self.respond(503)
            return
        self.respond(200, {"status": "ok", "service": "denaprobe-core"})

    def do_POST(self) -> None:
        if self.path != ENDPOINT:
            self.respond(404)
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
            self.respond(400)
            return
        if self.headers.get_all("Content-Length", []) == [] or len(self.headers.get_all("Content-Length", [])) != 1:
            self.respond(400)
            return
        length_str = self.headers.get("Content-Length", "")
        if not DIGITS_RE.fullmatch(length_str):
            self.respond(400)
            return
        # Bound numeric parsing before int(); Python guards huge integers and
        # should not throw an uncaught exception on untrusted header content.
        if len(length_str) > 4:
            self.respond(413)
            return
        length = int(length_str)
        if length > MAX_BODY:
            self.respond(413)
            return
        if length < 1 or len(self.headers.get_all("Content-Type", [])) != 1 or (
                self.headers.get("Content-Type", "").lower().strip() not in
                ("application/json", "application/json; charset=utf-8")):
            self.respond(400)
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                self.respond(400)
                return
            headers: dict[str, list[str]] = {}
            for key in ("x-dpt-device", "x-dpt-key-id", "x-dpt-sent-uptime-ms", "x-dpt-signature"):
                headers[key] = self.headers.get_all(key, [])
            config = load_devices(self.server.keys_path)
            device, sent = authenticate(raw, headers, config)
            body = json_body(raw)
            if body.get("id") != device:
                raise DptError(403, "unauthorized")
            kind, _ = validate(body, sent)
            allowed = config[device].get("targets", [])
            outcome = store(self.server.db_path, body, raw, sent, allowed_targets=allowed)
            self.respond(200, {"v": 1, "b": body["b"], "q": body["q"], "ack": {"r": outcome}})
        except DptError as exc:
            # Avoid leaking anything identifying device/secret/signature.
            self.respond(exc.http_status)
        except (OSError, sqlite3.Error):
            self.respond(503)
        except (ValueError, TypeError, UnicodeError):
            self.respond(400)

    def do_PUT(self) -> None:
        self.respond(405)

    def do_DELETE(self) -> None:
        self.respond(405)

    def log_message(self, format: str, *args: object) -> None:
        # Cloudflare health checks and malformed requests can be chatty. Never
        # log signed headers or bodies, and do not log key provisioning.
        pass


def atomic_devices(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".dpt-keys-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"devices": content}, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        folder = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main() -> None:
    parser = argparse.ArgumentParser(description="DPT/1 isolated ingest. No bot DB writes.")
    parser.add_argument("--db", type=Path, default=Path("/var/lib/denaprobe/telemetry.sqlite3"))
    parser.add_argument("--keys", type=Path, default=Path("/var/lib/denaprobe/devices.json"))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    add = sub.add_parser("provision")
    add.add_argument("--id", required=True)
    add.add_argument("--key-id", default="k1")
    add.add_argument("--target-id", type=int, default=1)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--id", required=True)
    revoke.add_argument("--key-id")
    target = sub.add_parser("target")
    target.add_argument("--id", type=int, required=True)
    target.add_argument("--host", required=True)
    target.add_argument("--port", type=int, required=True)
    recent = sub.add_parser("recent")
    recent.add_argument("--limit", type=int, default=20)
    sub.add_parser("check")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    if args.action == "init":
        initialize(args.db)
        if not args.keys.exists():
            atomic_devices(args.keys, {})
        print("DPT_DB_READY keys_file_private=YES")
    elif args.action == "provision":
        if not DEVICE_RE.fullmatch(args.id) or not KEY_RE.fullmatch(args.key_id):
            parser.error("invalid device or key identifier")
        if not integer(args.target_id, 1, 65535):
            parser.error("invalid target")
        entries = load_devices(args.keys)
        entry = entries.setdefault(args.id, {"enabled": True, "keys": {}, "targets": []})
        if args.key_id in entry["keys"]:
            parser.error("key already exists; use a new key id for rotation")
        token = secrets.token_hex(32)
        entry["keys"][args.key_id] = token
        if args.target_id not in entry["targets"]:
            entry["targets"].append(args.target_id)
        atomic_devices(args.keys, entries)
        print("DEVICE=", args.id, "KEY_ID=", args.key_id)
        print("SECRET_HEX=", token)
        print("Store this value in LOCAL IGNORED ESP32 config only; never paste to chat.")
    elif args.action == "revoke":
        entries = load_devices(args.keys)
        if args.id not in entries:
            parser.error("unknown device")
        if args.key_id:
            entries[args.id].get("keys", {}).pop(args.key_id, None)
        else:
            entries[args.id]["enabled"] = False
        atomic_devices(args.keys, entries)
        print("REVOKED")
    elif args.action == "target":
        print("TARGET_REVISION=", register_target(args.db, args.id, args.host, args.port))
    elif args.action == "recent":
        with connect_db(args.db) as db:
            for row in db.execute("""SELECT device_id,boot_id,sequence,event_kind,
                        ssh_code,stop_stage,https_code,sender_age_ms,
                        history_only,received_at_ms FROM telemetry_events
                        ORDER BY received_at_ms DESC,sequence DESC LIMIT ?""",
                                  (max(1, min(args.limit, 100)),)):
                print(dict(row))
    elif args.action == "check":
        with connect_db(args.db) as db:
            result = db.execute("PRAGMA quick_check").fetchone()
            count = db.execute("SELECT count(*) FROM telemetry_events").fetchone()[0]
        load_devices(args.keys)
        print("DPT_CHECK=", result[0], "EVENT_COUNT=", count)
    elif args.action == "serve":
        if args.host != "127.0.0.1":
            parser.error("public listener forbidden; use Cloudflare Tunnel -> loopback")
        if not 1024 <= args.port <= 65535:
            parser.error("invalid port")
        load_devices(args.keys)
        with connect_db(args.db) as db:
            db.execute("SELECT 1 FROM telemetry_events LIMIT 1")
        server = CollectorHTTP((args.host, args.port), args.db, args.keys)
        print("DPT_COLLECTOR_READY loopback_only=YES detection=DISABLED", flush=True)
        try:
            server.serve_forever(poll_interval=0.4)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
