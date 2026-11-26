"""Opt-in first-alert relay switching using the existing Quick Switch engine.

Read committed detector evidence, never Telegram delivery or historical messages.
No new route lock, DNS writer, user migration, or monitor policy.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from datetime import datetime
import json
import logging
from pathlib import Path
import secrets
import sqlite3
import time

from manual_quick_switch import QuickSwitchHold
from nvl_superadmin_access import is_revoked_principal

KEY = "manual_auto_relay"
MONITOR_DB = Path("/var/lib/nvl-network-alerts/state.sqlite3")
log = logging.getLogger(__name__)


def read_config(db):
    row = db.execute("SELECT value FROM settings WHERE key=?", (KEY,)).fetchone()
    try:
        value = json.loads(row[0]) if row else {}
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write(db, config):
    db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)",
               (KEY, json.dumps(config, sort_keys=True)))


def _admin(db, actor):
    return (type(actor) is int and actor > 0 and not is_revoked_principal(actor)
            and db.execute("SELECT 1 FROM bot_access WHERE telegram_id=? "
                           "AND role='super_admin' AND active=1 LIMIT 1",
                           (actor,)).fetchone() is not None)


def _timestamp(value):
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("naive timestamp")
    return dt.timestamp()


def read_event(path, armed_at, now):
    """One coherent read of the current incident and its first queued alert."""
    if not path.is_file():
        return None
    with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro",
                                 uri=True, timeout=1)) as db:
        db.execute("BEGIN")
        row = db.execute("SELECT v FROM kv WHERE k='detector'").fetchone()
        state = json.loads(row[0]) if row else {}
        incident = state.get("incident")
        if (not isinstance(incident, str) or not incident
                or state.get("incident_open") is not True
                or state.get("phase") not in ("SUSPECTED", "DEGRADED")
                or not state.get("last_sample")):
            return None
        # The detector already treats telemetry older than 300s as stale.
        if not 0 <= now - _timestamp(state["last_sample"]) <= 300:
            return None
        key = incident + ":SUSPECTED"
        event = db.execute("SELECT created_at FROM outbox WHERE event_key=?",
                           (key,)).fetchone()
        if event is None:
            return None
        stamp = _timestamp(event[0])
        if not armed_at < stamp <= now:
            return None
        return {"key": key, "created_at": stamp}


def reserve_auto(db, plan, actor, authorization, job):
    """Consume the exact opt-in in the existing route reservation transaction."""
    cfg = read_config(db)
    if (cfg != authorization.get("config") or cfg.get("enabled") is not True
            or cfg.get("actor") != actor or not _admin(db, actor)
            or cfg.get("source") != plan["source"]
            or cfg.get("target") != plan["target"]):
        raise QuickSwitchHold("AUTO_RELAY_AUTHORIZATION_CHANGED")
    event = authorization.get("event") or {}
    key = event.get("key")
    if (not isinstance(key, str) or not key.endswith(":SUSPECTED")
            or not isinstance(event.get("created_at"), (int, float))
            or event["created_at"] <= cfg["armed_at"]):
        raise QuickSwitchHold("AUTO_RELAY_EVENT_INVALID")
    # Re-read the same committed detector event after the final target
    # preflight, immediately before consuming the authorization. No additional
    # wait or route lock. A stale/recovered/replaced incident must not switch.
    revalidate = authorization.get("revalidate")
    if not callable(revalidate) or revalidate() != event:
        raise QuickSwitchHold("AUTO_RELAY_EVENT_CHANGED")
    # Same SQLite transaction as the existing DNS intent and 6G lease.
    # No separate lock or durable pre-write claim that can strand a transfer.
    _write(db, {**cfg, "enabled": False, "last_event": key, "last_job": job})
    return "AUTO_FIRST_ALERT:" + key


class AutoRelaySwitch:
    def __init__(self, *, db, engine, released, monitor_db=MONITOR_DB,
                 now=time.time):
        self.db = db
        self.engine = engine
        self.released = released
        self.monitor_db = Path(monitor_db)
        self.now = now
        self.stopping = False
        self.last_error = None
        self.effect_lock = None  # reuse the existing UI worker mutex if wired

    def status(self):
        with self.db() as db:
            return read_config(db)

    def arm(self, target, actor):
        if not self.released():
            raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not _admin(db, actor):
                raise QuickSwitchHold("AUTO_RELAY_AUTHORIZATION_CHANGED")
            sources = db.execute("SELECT host FROM host_pool "
                                 "WHERE active=1 AND is_default=1").fetchall()
            ready = db.execute(
                "SELECT h.host FROM host_pool h JOIN manual_edge_operations m "
                "ON m.ip=h.host WHERE h.host=? AND h.active=1 "
                "AND h.is_default=0 AND h.is_standby=1 AND h.provider='manual' "
                "AND h.provider_instance_id IS NULL AND m.status='STANDBY'",
                (target,)).fetchall()
            if len(sources) != 1 or ready != [(target,)]:
                raise QuickSwitchHold("MANUAL_STANDBY_NOT_READY")
            _write(db, {"enabled": True, "source": sources[0][0],
                        "target": target, "actor": actor,
                        "armed_at": self.now(), "nonce": secrets.token_hex(8)})

    def disarm(self, actor):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not _admin(db, actor):
                raise QuickSwitchHold("AUTO_RELAY_AUTHORIZATION_CHANGED")
            cfg = read_config(db)
            _write(db, {**cfg, "enabled": False})

    def tick(self):
        if self.stopping or not self.released():
            return None
        cfg = self.status()
        if cfg.get("enabled") is not True:
            return None
        with self.db() as db:
            if not _admin(db, cfg.get("actor")):
                return None
            if db.execute("SELECT host FROM host_pool WHERE active=1 "
                          "AND is_default=1").fetchall() != [(cfg.get("source"),)]:
                return None
        event = read_event(self.monitor_db, cfg["armed_at"], self.now())
        if event is None:
            return None
        # Keep synchronous DNS work and the engine's event loop in a worker,
        # just like the existing manual UI. The route engine remains the owner.
        async def execute():
            plan = await self.engine.preview(cfg["target"])
            if plan["source"] != cfg["source"] or self.stopping or not self.released():
                return None
            return await self.engine.start_auto(
                plan, actor=cfg["actor"],
                authorization={"config": cfg, "event": event,
                               "revalidate": lambda: (
                                   read_event(self.monitor_db, cfg["armed_at"], self.now())
                                   if not self.stopping and self.released() else None)})
        lock = self.effect_lock
        if lock is not None and not lock.acquire(blocking=False):
            return None
        try:
            return asyncio.run(execute())
        finally:
            if lock is not None:
                lock.release()

    async def loop(self):
        while not self.stopping:
            delay = 2
            try:
                job = await asyncio.to_thread(self.tick)
                if job:
                    log.info("AUTO_RELAY_DONE job=%s", job)
                self.last_error = None
            except Exception as exc:
                # A pre-reservation failure may be retried while the same
                # incident is open. An uncertain DNS write is never replayed:
                # the opt-in was consumed atomically with the route intent.
                reason = (str(exc) if isinstance(exc, QuickSwitchHold)
                          else type(exc).__name__)
                if not reason.isascii() or not reason.replace("_", "").isalnum():
                    reason = "AUTO_RELAY_FAILED"
                if reason != self.last_error:
                    log.warning("AUTO_RELAY_ERROR %s", reason)
                self.last_error = reason
                delay = 5
            if not self.stopping:
                await asyncio.sleep(delay)
