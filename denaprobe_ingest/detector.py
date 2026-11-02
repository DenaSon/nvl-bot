"""R3 server-only DenaProbe incident classifier (DPT/2 verified evidence).

No bot imports, no commands to relay, no changes to DPT/1, no external I/O.
The caller explicitly enables evaluation only after staged field acceptance.
"""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import sqlite3
import time

from . import collector

UNKNOWN = "MONITORING_UNKNOWN"
HEALTHY = "HEALTHY"
D0 = "D0_TCP_UNREACHABLE"
D1 = "D1_SESSION_FAILURE"
D2 = "D2_DATA_DEGRADED"
RECOVERED = "RECOVERED"
EVENT_TYPES = frozenset((D0, D1, D2))
FRESH_MS = 90_000
HTTPS_FRESH_MS = 360_000
# Two DISTINCT, eligible, recent measurements, not two scheduler ticks.
CONFIRM = 2
# This classifier cannot attest a carrier, relay health or DPI from one board.
SUSPECTED = "SUSPECTED"
INCONCLUSIVE = "INCONCLUSIVE"

SCHEMA = """
CREATE TABLE IF NOT EXISTS dp3_states(
 device_id TEXT NOT NULL, target_id INTEGER NOT NULL,
 revision INTEGER NOT NULL, boot_id TEXT NOT NULL,
 last_seq INTEGER NOT NULL DEFAULT 0, candidate TEXT NOT NULL DEFAULT '',
 streak INTEGER NOT NULL DEFAULT 0,
 effective TEXT NOT NULL DEFAULT 'MONITORING_UNKNOWN',
 observation TEXT NOT NULL DEFAULT 'MONITORING_UNKNOWN',
 open_incident TEXT, last_received_at INTEGER NOT NULL DEFAULT 0,
 last_control_at INTEGER, updated_at INTEGER NOT NULL,
 PRIMARY KEY(device_id,target_id,revision)
);
CREATE TABLE IF NOT EXISTS dp3_incidents(
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL, target_id INTEGER NOT NULL,
 revision INTEGER NOT NULL, observed_class TEXT NOT NULL,
 confidence TEXT NOT NULL, reason TEXT NOT NULL,
 opened_at INTEGER NOT NULL, last_evidence_at INTEGER NOT NULL,
 last_sequence INTEGER NOT NULL, recovered_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_dp3_incidents_active
 ON dp3_incidents(recovered_at,opened_at DESC);
CREATE TABLE IF NOT EXISTS dp3_transitions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 incident_id TEXT NOT NULL, kind TEXT NOT NULL,
 observed_class TEXT NOT NULL, confidence TEXT NOT NULL,
 occurred_at INTEGER NOT NULL, evidence_sequence INTEGER NOT NULL,
 UNIQUE(incident_id,kind,evidence_sequence)
);
CREATE INDEX IF NOT EXISTS ix_dp3_transitions_created
 ON dp3_transitions(id);
CREATE TABLE IF NOT EXISTS dp3_delivery(
 transition_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'READY', attempt TEXT,
 reason TEXT, message_id INTEGER, updated_at INTEGER NOT NULL,
 PRIMARY KEY(transition_id,recipient_id)
);
CREATE TABLE IF NOT EXISTS dp3_rich_cards(
 chat_id INTEGER PRIMARY KEY, actor INTEGER NOT NULL,
 message_id INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
"""

def initialize(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _fresh(now: int, received: int, sender_age: int, maximum: int) -> bool:
    return (type(received) is int and type(sender_age) is int and
            0 <= sender_age <= maximum and 0 <= now - received <= maximum - sender_age)


def _direct_control(db: sqlite3.Connection, latest: sqlite3.Row,
                    device: str, now: int) -> tuple[bool, int | None, str]:
    q = latest["https_sequence"]
    if q is None:
        return False, None, "DIRECT_HTTPS_NOT_MEASURED"
    row = db.execute(
        "SELECT raw_json,received_at_ms FROM dpt2_events WHERE "
        "device_id=? AND boot_id=? AND sequence=? AND history_only=0",
        (device, latest["boot_id"], q)
    ).fetchone()
    if not row:
        return False, None, "DIRECT_HTTPS_NOT_LIVE"
    body = json.loads(row["raw_json"])
    h = body.get("h")
    if not h:
        return False, None, "DIRECT_HTTPS_NOT_MEASURED"
    age = body["u"]  # never infer direct age from SSH pre-auth uptime
    del age
    sender_age = (body.get("ts") if False else 0)  # no wallclock claim
    del sender_age
    # Body has only per-stage uptime; sender's sent_uptime_ms in stored event
    # is needed for its own transfer age, not the newest SSH event.
    stored = db.execute(
        "SELECT sent_uptime_ms FROM dpt2_events WHERE 0"
    ).fetchone() if False else None
    del stored
    # R2 DPT/2 persists sender_age_ms = sent - max(completions), not sent-h.u.
    # Conservatively derive only receiver freshness; do not promote a stale
    # control via a q on an old boot or a record beyond HTTPS_FRESH_MS.
    if not _fresh(now, int(row["received_at_ms"]), 0, HTTPS_FRESH_MS):
        return False, int(row["received_at_ms"]), "DIRECT_HTTPS_STALE"
    if h.get("c") != 1 or h.get("n") != 65536:
        return False, int(row["received_at_ms"]), "DIRECT_HTTPS_NOT_PASS"
    return True, int(row["received_at_ms"]), "DIRECT_HTTPS_PASS"


def classify(body: dict, *, direct_ok: bool) -> tuple[str, str]:
    """Observational failure class, not attribution to a filtering actor."""
    if body.get("w") != 1 or not direct_ok:
        return UNKNOWN, "LOCAL_WIFI_OR_DIRECT_CONTROL_UNAVAILABLE"
    c = body.get("c")
    if not isinstance(c, dict) or c.get("s") == 90:
        return UNKNOWN, "INDEPENDENT_TCP_NOT_MEASURED"
    tcp = c.get("s")
    if tcp in (20, 21, 22):
        if body.get("s") == 1:
            return UNKNOWN, "TCP_SSH_OBSERVATION_CONFLICT"
        return D0, "INDEPENDENT_TCP_CONNECT_FAILURE"
    if tcp != 1:
        return UNKNOWN, "UNSUPPORTED_TCP_CODE"
    if body.get("s") != 1:
        return UNKNOWN, "SSH_PREAUTH_UNAVAILABLE"
    z = body.get("z")
    if not isinstance(z, dict):
        return UNKNOWN, "AUTHENTICATED_DATA_NOT_MEASURED"
    code = z.get("s")
    if code in (20, 21, 30, 31):
        return D1, "AUTHENTICATED_SSH_SESSION_OR_CHANNEL_FAILED"
    if code in (40, 41):
        return D2, "AUTHENTICATED_TRANSFER_TIMEOUT_OR_INCOMPLETE"
    if code == 42 or any(
        isinstance(z.get(k), dict) and z[k].get("s") == 2
        for k in ("f", "g")
    ):
        # D2 slow requires an actual calibrated, size-specific baseline.
        return UNKNOWN, "SLOW_BASELINE_NOT_CALIBRATED"
    if code in (10, 11, 12, 90):
        return UNKNOWN, "AUTH_CONFIG_OR_LOCAL_UNMEASURABLE"
    if code == 1:
        samples = (z.get("f"), z.get("g"))
        if all(isinstance(x, dict) and x.get("s") == 1
               and x.get("n") == x.get("r") for x in samples):
            return HEALTHY, "TWO_AUTHENTICATED_TRANSFERS_COMPLETE"
    return UNKNOWN, "UNSUPPORTED_OR_INCOMPLETE_DEEP_EVIDENCE"


def _transition(db, incident, kind, cls, confidence, now, q):
    db.execute(
        "INSERT OR IGNORE INTO dp3_transitions "
        "(incident_id,kind,observed_class,confidence,occurred_at,evidence_sequence) "
        "VALUES (?,?,?,?,?,?)",
        (incident, kind, cls, confidence, now, q)
    )


def evaluate(db_path: Path, *, now_ms: int | None = None) -> list[dict]:
    """One serialized evaluation round. No network/Telegram side effects.

    Existing incidents remain open across silence or monitoring gaps; absence
    of probe data is NEVER RECOVERED. Only two distinct accepted q confirm
    an incident onset/type change/recovery. Target revisions never coalesce.
    """
    now = int(time.time() * 1000) if now_ms is None else now_ms
    changed = []
    with collector.connect_db(db_path) as db:
        db.execute("PRAGMA synchronous=FULL")
        initialize(db)
        db.execute("BEGIN IMMEDIATE")
        latest_rows = db.execute(
            "SELECT device_id,boot_id,ssh_sequence,https_sequence,monitoring_gap "
            "FROM dpt2_latest"
        ).fetchall()
        for latest in latest_rows:
            device = latest["device_id"]
            if latest["ssh_sequence"] is None:
                continue
            row = db.execute(
                "SELECT * FROM dpt2_events WHERE device_id=? AND boot_id=? "
                "AND sequence=? AND kind=1 AND history_only=0",
                (device, latest["boot_id"], latest["ssh_sequence"])
            ).fetchone()
            if row is None or row["target_id"] is None or row["target_revision"] is None:
                continue
            target, revision = row["target_id"], row["target_revision"]
            prev = db.execute(
                "SELECT * FROM dp3_states WHERE device_id=? AND target_id=? AND revision=?",
                (device, target, revision)
            ).fetchone()
            # Preserve existing episode across stale rounds. Never promote
            # backlogged or current-gap observations into a new incident.
            fresh = (not latest["monitoring_gap"] and
                     _fresh(now, int(row["received_at_ms"]),
                            int(row["sender_age_ms"]), FRESH_MS))
            direct_ok, control_at, reason = _direct_control(db, latest, device, now)
            body = json.loads(row["raw_json"])
            observed, detail = classify(body, direct_ok=bool(fresh and direct_ok))
            if not fresh:
                observed, detail = UNKNOWN, "STALE_OR_CONTINUITY_GAP"
            if not prev:
                db.execute(
                    "INSERT INTO dp3_states "
                    "(device_id,target_id,revision,boot_id,last_seq,updated_at) "
                    "VALUES(?,?,?,?,0,?)",
                    (device, target, revision, latest["boot_id"], now))
                prev = db.execute(
                    "SELECT * FROM dp3_states WHERE device_id=? AND target_id=? AND revision=?",
                    (device, target, revision)
                ).fetchone()
            old_q = prev["last_seq"] if prev["boot_id"] == latest["boot_id"] else 0
            if row["sequence"] <= old_q:
                # Even when the collector goes silent, reveal unknown state.
                if observed == UNKNOWN and prev["observation"] != UNKNOWN:
                    db.execute(
                        "UPDATE dp3_states SET observation=?,updated_at=? WHERE "
                        "device_id=? AND target_id=? AND revision=?",
                        (UNKNOWN, now, device, target, revision))
                continue
            candidate = observed if observed != UNKNOWN else ""
            streak = (prev["streak"] + 1 if prev["candidate"] == candidate and
                      prev["boot_id"] == latest["boot_id"] and candidate else
                      1 if candidate else 0)
            effective = prev["effective"]
            incident = prev["open_incident"]
            if streak >= CONFIRM:
                if observed in EVENT_TYPES:
                    if not incident:
                        incident = secrets.token_hex(12)
                        effective = observed
                        db.execute(
                            "INSERT INTO dp3_incidents "
                            "(id,device_id,target_id,revision,observed_class,confidence,"
                            "reason,opened_at,last_evidence_at,last_sequence) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (incident,device,target,revision,observed,SUSPECTED,detail,
                             now,now,row["sequence"]))
                        _transition(db, incident, "OPEN", observed, SUSPECTED,
                                    now, row["sequence"])
                        changed.append({"incident": incident, "kind": "OPEN"})
                    elif effective != observed:
                        effective = observed
                        db.execute(
                            "UPDATE dp3_incidents SET observed_class=?,reason=?,"
                            "last_evidence_at=?,last_sequence=? WHERE id=? AND recovered_at IS NULL",
                            (observed, detail, now, row["sequence"], incident))
                        _transition(db, incident, "CHANGE", observed, SUSPECTED,
                                    now, row["sequence"])
                        changed.append({"incident": incident, "kind": "CHANGE"})
                    else:
                        db.execute(
                            "UPDATE dp3_incidents SET last_evidence_at=?,last_sequence=? "
                            "WHERE id=? AND recovered_at IS NULL",
                            (now,row["sequence"],incident))
                elif observed == HEALTHY:
                    if incident:
                        db.execute(
                            "UPDATE dp3_incidents SET recovered_at=?,last_evidence_at=?,"
                            "last_sequence=? WHERE id=? AND recovered_at IS NULL",
                            (now,now,row["sequence"],incident))
                        _transition(db, incident, "RECOVERED", RECOVERED,
                                    INCONCLUSIVE, now, row["sequence"])
                        changed.append({"incident": incident, "kind": "RECOVERED"})
                        incident = None
                    effective = HEALTHY
            db.execute(
                "UPDATE dp3_states SET boot_id=?,last_seq=?,candidate=?,streak=?,"
                "effective=?,observation=?,open_incident=?,last_received_at=?,"
                "last_control_at=?,updated_at=? WHERE device_id=? AND target_id=? AND revision=?",
                (latest["boot_id"],row["sequence"],candidate,streak,effective,
                 observed,incident,row["received_at_ms"],control_at,now,
                 device,target,revision))
        db.commit()
    return changed


def read_dashboard(db_path: Path, *, now_ms: int | None = None) -> dict:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    uri = f"file:{Path(db_path).resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as db:
        db.row_factory = sqlite3.Row
        states = [dict(r) for r in db.execute(
            "SELECT * FROM dp3_states ORDER BY updated_at DESC LIMIT 50")]
        incidents = [dict(r) for r in db.execute(
            "SELECT * FROM dp3_incidents ORDER BY opened_at DESC LIMIT 50")]
    active = [i for i in incidents if i["recovered_at"] is None]
    fresh = [s for s in states if s["observation"] != UNKNOWN and
             0 <= now - s["last_received_at"] <= FRESH_MS]
    return {"states": states, "incidents": incidents, "active": active,
            "fresh": len(fresh), "stale": len(states) - len(fresh), "now": now}
