"""R3 server-only DenaProbe incident classifier (DPT/2 verified evidence).

No bot imports, no commands to relay, no changes to DPT/1, no external I/O.
The caller explicitly enables evaluation only after staged field acceptance.
"""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3
import time

from . import collector

UNKNOWN = "MONITORING_UNKNOWN"
HEALTHY = "HEALTHY"
# Observed reachability only: no SSH login, tunnel or NPV data-plane test.
PREAUTH_REACHABLE = "PREAUTH_REACHABLE"
D0 = "D0_TCP_UNREACHABLE"
D1 = "D1_SESSION_FAILURE"
D2 = "D2_DATA_DEGRADED"
RECOVERED = "RECOVERED"
EVENT_TYPES = frozenset((D0, D1, D2))
FRESH_MS = 90_000
HTTPS_FRESH_MS = 360_000
# Two DISTINCT, eligible, recent measurements, not two scheduler ticks.
CONFIRM = 2
# Fast TCP alert after the FIRST eligible current-boot observation.
# These are early, uncorroborated warnings; consecutive samples are still
# required to classify an incident as corroborated and to recover it.
EARLY = "EARLY_OBSERVATION"
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
 last_sequence INTEGER NOT NULL, recovered_at INTEGER,
 superseded_at INTEGER
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
CREATE TABLE IF NOT EXISTS dp3_operator_labels(
 device_id TEXT PRIMARY KEY, declared_operator TEXT NOT NULL
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
    # DPT/2 persists sent - max(completion uptimes). Recover the signed
    # sender uptime conservatively and use the actual direct HTTPS age.
    last_completed = max(body["u"], body.get("h", {}).get("u", 0),
                         body.get("c", {}).get("u", 0),
                         body.get("z", {}).get("u", 0))
    stored_age = db.execute(
        "SELECT sender_age_ms FROM dpt2_events WHERE "
        "device_id=? AND boot_id=? AND sequence=?",
        (device, latest["boot_id"], q)
    ).fetchone()["sender_age_ms"]
    direct_sender_age = last_completed + stored_age - h["u"]
    if not _fresh(now, int(row["received_at_ms"]),
                  int(direct_sender_age), HTTPS_FRESH_MS):
        return False, int(row["received_at_ms"]), "DIRECT_HTTPS_STALE"
    if h.get("c") != 1 or h.get("n") != 65536:
        return False, int(row["received_at_ms"]), "DIRECT_HTTPS_NOT_PASS"
    return True, int(row["received_at_ms"]), "DIRECT_HTTPS_PASS"


def classify(body: dict, *, direct_ok: bool) -> tuple[str, str]:
    """Observational failure class, not attribution to a filtering actor."""
    if body.get("w") != 1:
        return UNKNOWN, "LOCAL_WIFI_UNAVAILABLE"
    c = body.get("c")
    if not isinstance(c, dict) or c.get("s") == 90:
        return UNKNOWN, "INDEPENDENT_TCP_NOT_MEASURED"
    tcp = c.get("s")
    if tcp in (20, 21, 22):
        if body.get("s") == 1:
            return UNKNOWN, "TCP_SSH_OBSERVATION_CONFLICT"
        # A fresh signed TCP failure is itself actionable. The separately
        # sampled HTTPS control may be slow, absent or failing during an
        # actual outage. Do not suppress the early notification for that.
        # No provider/filtering attribution follows from this observation.
        reason = ("INDEPENDENT_TCP_CONNECT_FAILURE" if direct_ok else
                  "TCP_FAILURE_DIRECT_CONTROL_UNVERIFIED")
        return D0, reason
    if tcp != 1:
        return UNKNOWN, "UNSUPPORTED_TCP_CODE"
    if body.get("s") != 1:
        return UNKNOWN, "SSH_PREAUTH_UNAVAILABLE"
    z = body.get("z")
    if not isinstance(z, dict):
        # Direct signed TCP+SSH preauth success verifies the previously failed
        # tested path, even if unrelated HTTPS is SLOW/not measured. This
        # never declares end-to-end NPV/VPN health.
        return PREAUTH_REACHABLE, "TCP_SSH_PREAUTH_PASS_DEEP_NOT_MEASURED"
    if not direct_ok:
        return UNKNOWN, "DIRECT_CONTROL_UNAVAILABLE_FOR_DEEP"
    # CORE_LOOPBACK is a controlled responder on the SSH terminator; it does
    # not represent NPV customer public egress or imply a filtering cause.
    # Success is valid only as limited TCP/SSH preauth reachability (D0
    # recovery retains its two independent fresh samples).
    if z.get("rt") == 1:
        if z.get("s") == 1 and all(
            isinstance(z.get(k), dict) and z[k].get("s") == 1 and
            z[k].get("n") == z[k].get("r") for k in ("f", "g")
        ):
            return PREAUTH_REACHABLE, "CORE_LOOPBACK_ONLY_TCP_SSH_REACHABLE"
        return UNKNOWN, "CORE_LOOPBACK_WITNESS_NOT_NPV_EGRESS"
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
    with closing(collector.connect_db(db_path)) as db:
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
            # Old stage data transmitted later is historical, even if a newer
            # HTTPS submeasurement made the event look fresh as a whole.
            z = body.get("z")
            if z is not None:
                latest_completed = max(body["u"], body.get("h", {}).get("u", 0),
                                       body.get("c", {}).get("u", 0), z["u"])
                deep_age = int(row["sender_age_ms"]) + latest_completed - z["u"]
                fresh = fresh and _fresh(
                    now, int(row["received_at_ms"]), deep_age, FRESH_MS)
            observed, detail = classify(body, direct_ok=bool(fresh and direct_ok))
            if not fresh:
                observed, detail = UNKNOWN, "STALE_OR_CONTINUITY_GAP"
            elif observed == PREAUTH_REACHABLE and not (
                prev and prev["effective"] == D0 and prev["open_incident"]
            ):
                # Normal preauth reachability never announces full health.
                # It is only sufficient to resolve a previously confirmed D0.
                observed, detail = UNKNOWN, "AUTHENTICATED_DATA_NOT_MEASURED"
            if not prev:
                # A target revision change is NOT a recovery event.
                db.execute(
                    "UPDATE dp3_incidents SET superseded_at=? "
                    "WHERE device_id=? AND target_id=? AND revision!=? "
                    "AND recovered_at IS NULL AND superseded_at IS NULL",
                    (now, device, target, revision))
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
                if observed == UNKNOWN and (
                    prev["observation"] != UNKNOWN or prev["streak"]):
                    # Lost freshness/gap invalidates a prior pending streak.
                    # It must not confirm an outage/recovery after reconnect.
                    db.execute(
                        "UPDATE dp3_states SET observation=?,candidate='',"
                        "streak=0,updated_at=? WHERE "
                        "device_id=? AND target_id=? AND revision=?",
                        (UNKNOWN, now, device, target, revision))
                continue
            candidate = observed if observed != UNKNOWN else ""
            # A skipped q, stale interval, reboot, or last UNKNOWN breaks
            # evidence continuity. Never combine one old and one new sample.
            consecutive = (prev["boot_id"] == latest["boot_id"] and
                           row["sequence"] == old_q + 1 and
                           0 <= row["received_at_ms"]-prev["last_received_at"] <= FRESH_MS and
                           prev["observation"] != UNKNOWN)
            streak = (prev["streak"] + 1 if candidate and consecutive and
                      prev["candidate"] == candidate else 1 if candidate else 0)
            effective = prev["effective"]
            incident = prev["open_incident"]
            # D0 is a *rapid observation warning*: one eligible signed
            # sample is enough. D1/D2 and recovery retain two independent
            # current-boot observations to prevent incorrect escalation.
            threshold = 1 if observed == D0 else CONFIRM
            if streak >= threshold:
                if observed in EVENT_TYPES:
                    confidence = (EARLY if observed == D0 and streak == 1
                                  else SUSPECTED)
                    if not incident:
                        incident = secrets.token_hex(12)
                        effective = observed
                        db.execute(
                            "INSERT INTO dp3_incidents "
                            "(id,device_id,target_id,revision,observed_class,confidence,"
                            "reason,opened_at,last_evidence_at,last_sequence) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (incident,device,target,revision,observed,confidence,detail,
                             now,now,row["sequence"]))
                        _transition(db, incident, "OPEN", observed, confidence,
                                    now, row["sequence"])
                        changed.append({"incident": incident, "kind": "OPEN"})
                    elif effective != observed:
                        effective = observed
                        db.execute(
                            "UPDATE dp3_incidents SET observed_class=?,confidence=?,reason=?,"
                            "last_evidence_at=?,last_sequence=? WHERE id=? AND recovered_at IS NULL",
                            (observed, confidence, detail, now, row["sequence"], incident))
                        _transition(db, incident, "CHANGE", observed, confidence,
                                    now, row["sequence"])
                        changed.append({"incident": incident, "kind": "CHANGE"})
                    else:
                        db.execute(
                            "UPDATE dp3_incidents SET confidence=?,last_evidence_at=?,last_sequence=? "
                            "WHERE id=? AND recovered_at IS NULL",
                            (confidence,now,row["sequence"],incident))
                elif observed == HEALTHY or (
                    observed == PREAUTH_REACHABLE and effective == D0
                ):
                    # A D0 TCP outage can be resolved by two fresh TCP/SSH
                    # preauth passes, but this says nothing about NPV traffic.
                    # Existing D1/D2 incidents require full Deep evidence.
                    if incident:
                        db.execute(
                            "UPDATE dp3_incidents SET recovered_at=?,last_evidence_at=?,"
                            "last_sequence=? WHERE id=? AND recovered_at IS NULL",
                            (now,now,row["sequence"],incident))
                        _transition(db, incident, "RECOVERED", RECOVERED,
                                    INCONCLUSIVE, now, row["sequence"])
                        changed.append({"incident": incident, "kind": "RECOVERED"})
                        incident = None
                    effective = observed
            db.execute(
                "UPDATE dp3_states SET boot_id=?,last_seq=?,candidate=?,streak=?,"
                "effective=?,observation=?,open_incident=?,last_received_at=?,"
                "last_control_at=?,updated_at=? WHERE device_id=? AND target_id=? AND revision=?",
                (latest["boot_id"],row["sequence"],candidate,streak,effective,
                 observed,incident,row["received_at_ms"],control_at,now,
                 device,target,revision))
        db.commit()
    return changed


def _live_probe(db: sqlite3.Connection, latest: sqlite3.Row, now: int) -> dict:
    """Current-boot signed evidence, not a tunnel-health verdict."""
    device, boot = latest["device_id"], latest["boot_id"]
    result = {
        "device_id": device, "target_id": None, "revision": None,
        "ssh_sequence": latest["ssh_sequence"],
        "https_sequence": latest["https_sequence"],
        "monitoring_gap": bool(latest["monitoring_gap"]),
        "last_received_at": 0, "ssh_fresh": False, "https_fresh": False,
        "tcp_code": None, "ssh_code": None, "wifi_code": None,
        "https_code": None, "https_received_at": None,
        "deep_route": None, "deep_code": None, "deep_fresh": False,
        "deep_first": None, "deep_second": None,
    }
    if latest["ssh_sequence"] is None:
        return result
    row = db.execute(
        "SELECT * FROM dpt2_events WHERE device_id=? AND boot_id=? "
        "AND sequence=? AND kind=1 AND history_only=0",
        (device, boot, latest["ssh_sequence"]),
    ).fetchone()
    if row is None:
        return result
    body = json.loads(row["raw_json"])
    last_completed = max(
        body["u"], body.get("c", {}).get("u", 0),
        body.get("z", {}).get("u", 0), body.get("h", {}).get("u", 0))
    ssh_age = int(row["sender_age_ms"]) + last_completed - body["u"]
    # A newer signed Wi-Fi-down observation invalidates a prior live result,
    # although it must never promote an outage or claim filtering.
    last_event = db.execute(
        "SELECT wifi_code,received_at_ms FROM dpt2_events "
        "WHERE device_id=? AND boot_id=? AND kind=1 "
        "ORDER BY sequence DESC LIMIT 1", (device, boot),
    ).fetchone()
    wifi_down = bool(
        last_event and last_event["wifi_code"] == 0 and
        0 <= now - last_event["received_at_ms"] <= FRESH_MS)
    fresh = (
        not latest["monitoring_gap"] and not wifi_down and
        body.get("w") == 1 and
        _fresh(now, int(row["received_at_ms"]), ssh_age, FRESH_MS)
    )
    result.update(
        target_id=row["target_id"], revision=row["target_revision"],
        last_received_at=row["received_at_ms"], ssh_fresh=fresh,
        wifi_code=0 if wifi_down else body.get("w"),
        tcp_code=body.get("c", {}).get("s") if fresh else None,
        ssh_code=body.get("s") if fresh else None,
    )
    # Route and Deep sample have an independent signed completion time.
    z = body.get("z")
    if isinstance(z, dict):
        deep_age = int(row["sender_age_ms"]) + last_completed - z["u"]
        deep_fresh = bool(fresh and _fresh(
            now, int(row["received_at_ms"]), deep_age, FRESH_MS))
        result.update(
            deep_route=z.get("rt"), deep_code=z.get("s") if deep_fresh else None,
            deep_fresh=deep_fresh,
            deep_first=z.get("f") if deep_fresh else None,
            deep_second=z.get("g") if deep_fresh else None,
        )
    if latest["https_sequence"] is None:
        return result
    control = db.execute(
        "SELECT raw_json,sender_age_ms,received_at_ms FROM dpt2_events "
        "WHERE device_id=? AND boot_id=? AND sequence=? "
        "AND kind=1 AND history_only=0",
        (device, boot, latest["https_sequence"]),
    ).fetchone()
    if control is None:
        return result
    control_body = json.loads(control["raw_json"])
    h = control_body.get("h")
    if not isinstance(h, dict) or "u" not in h:
        return result
    control_last = max(
        control_body["u"], control_body.get("c", {}).get("u", 0),
        control_body.get("z", {}).get("u", 0), h["u"])
    control_age = int(control["sender_age_ms"]) + control_last - h["u"]
    direct_fresh = _fresh(
        now, int(control["received_at_ms"]), control_age, HTTPS_FRESH_MS)
    result.update(
        https_fresh=direct_fresh,
        https_code=h.get("c") if direct_fresh else None,
        https_received_at=control["received_at_ms"],
    )
    return result


def read_dashboard(db_path: Path, *, now_ms: int | None = None) -> dict:
    """Read-only operator snapshot. Link freshness != full NPV health."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    uri = f"file:{Path(db_path).resolve()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
        db.row_factory = sqlite3.Row
        states = [dict(r) for r in db.execute(
            "SELECT s.* FROM dp3_states AS s "
            "JOIN (SELECT target_id,MAX(revision) AS revision FROM targets "
            "GROUP BY target_id) t ON t.target_id=s.target_id "
            "AND t.revision=s.revision ORDER BY s.updated_at DESC LIMIT 50")]
        history = [dict(r) for r in db.execute(
            "SELECT * FROM dp3_incidents ORDER BY opened_at DESC LIMIT 50")]
        active = [dict(r) for r in db.execute(
            "SELECT * FROM dp3_incidents WHERE recovered_at IS NULL "
            "AND superseded_at IS NULL ORDER BY opened_at DESC LIMIT 200")]
        seen = {i["id"] for i in history}
        incidents = history + [i for i in active if i["id"] not in seen]
        operators = {r["device_id"]: r["declared_operator"][:32]
                     for r in db.execute("SELECT * FROM dp3_operator_labels")}
        probes = [_live_probe(db, row, now) for row in db.execute(
            "SELECT * FROM dpt2_latest ORDER BY device_id LIMIT 50")]
        probe_by_key = {
            (p["device_id"], p["target_id"], p["revision"]): p
            for p in probes
        }
        samples = {}
        for state in states:
            key = (state["device_id"], state["target_id"], state["revision"])
            row = db.execute(
                "SELECT raw_json,received_at_ms FROM dpt2_events WHERE "
                "device_id=? AND boot_id=? AND sequence=? AND target_id=? "
                "AND target_revision=? AND history_only=0",
                (state["device_id"], state["boot_id"], state["last_seq"],
                 state["target_id"], state["revision"])).fetchone()
            if row:
                b = json.loads(row["raw_json"])
                z, c = b.get("z") or {}, b.get("c") or {}
                probe = probe_by_key.get(key, {})
                samples[key] = {
                    "tcp_code": c.get("s"), "tcp_ms": c.get("ms"),
                    "auth_ms": z.get("am"), "session_ms": z.get("sm"),
                    "deep_code": z.get("s"), "deep_route": z.get("rt"),
                    "first": z.get("f"),
                    "second": z.get("g"),
                    "direct_code": probe.get("https_code"),
                    "received_at": row["received_at_ms"],
                }
    # These counters are transport freshness, never a classifier verdict.
    fresh = sum(bool(p["ssh_fresh"]) for p in probes)
    return {"states": states, "incidents": incidents, "active": active,
            "fresh": fresh, "stale": len(probes) - fresh, "now": now,
            "probes": probes, "samples": samples, "operators": operators}
