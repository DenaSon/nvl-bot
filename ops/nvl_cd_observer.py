"""NVL CD event history and group notifications; no production mutations."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request

if __package__:
    from . import nvl_cd_planner as p
    from . import nvl_cd_publisher as pub
else:
    import nvl_cd_planner as p
    import nvl_cd_publisher as pub

TOKEN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,100}")
GROUP = re.compile(r"-[1-9][0-9]{5,20}")
MAX_HISTORY = 1000
HISTORY_DAYS = 90
KEEP_BACKUPS = 5
BACKUP_DAYS = 14
MAX_RETRY = 3600


def target(env):
    token = env.get("BOT_TOKEN", "")
    group = env.get("MARZBAN_ALERT_CHAT_ID", "")
    if not TOKEN.fullmatch(token) or not GROUP.fullmatch(group):
        return None
    return token, group


def send(text, env=os.environ):
    configured = target(env)
    if not configured:
        return False
    token, group = configured
    req = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=urllib.parse.urlencode({"chat_id": group, "text": text,
                                     "disable_web_page_preview": "true"}).encode())
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), p.NoRedirect())
        with opener.open(req, timeout=8) as response:
            body = response.read(65537)
        return len(body) <= 65536 and json.loads(body).get("ok") is True
    except Exception:
        # Request URLs contain the bot token; never log the exception.
        return False


def event(state):
    """Only release outcomes and explicit actionable drift; no CI polling spam."""
    phase = state.get("phase")
    sha = state.get("candidate")
    if not isinstance(sha, str) or not p.SHA.fullmatch(sha):
        return None
    if phase in ("COMMITTED", "ROLLED_BACK", "HOLD"):
        key = "release:" + sha + ":" + phase
        labels = {"COMMITTED": "✅ استقرار موفق",
                  "ROLLED_BACK": "↩️ بازگشت به نسخه قبلی",
                  "HOLD": "⚠️ استقرار نیازمند بررسی"}
        msg = "NVL CI/CD\n" + labels[phase] + "\nSHA: " + sha[:12]
        deployed = state.get("deployed")
        if isinstance(deployed, str) and p.SHA.fullmatch(deployed):
            msg += "\nنسخه ثبت‌شده: " + deployed[:12]
        return key, msg
    if state.get("status") == "HOLD" and (state.get("drift") or state.get("manual")):
        # Only counts, never raw runtime paths or secret values.
        drift, manual = len(state.get("drift", [])), len(state.get("manual", []))
        return ("plan:" + sha + ":HOLD",
                "NVL CI/CD\n⚠️ برنامه استقرار نیازمند بررسی\nSHA: " + sha[:12] +
                "\nاختلاف محلی: " + str(drift) + "\nفایل نیازمند بررسی: " + str(manual))
    return None


def db_open(path):
    if os.path.lexists(path):
        p.trusted(path)
    con = sqlite3.connect(path, timeout=3)
    os.chmod(path, 0o600)
    con.execute("""CREATE TABLE IF NOT EXISTS events(
        event_key TEXT PRIMARY KEY, message TEXT NOT NULL, observed INTEGER NOT NULL,
        sent INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0
    )""")
    return con


def record(con, snapshot, now):
    item = event(snapshot)
    if item:
        con.execute("INSERT OR IGNORE INTO events(event_key,message,observed) VALUES(?,?,?)",
                    (*item, now))


def prune_history(con, now):
    # Preserve unsent events; do not silently drop failures during outages.
    con.execute("DELETE FROM events WHERE sent IS NOT NULL AND observed < ?",
                (now - HISTORY_DAYS * 86400,))
    con.execute("""DELETE FROM events WHERE sent IS NOT NULL AND event_key IN (
        SELECT event_key FROM events WHERE sent IS NOT NULL
        ORDER BY observed DESC,event_key DESC LIMIT -1 OFFSET ?
    )""", (MAX_HISTORY,))
    # Repeated observations of an ancient terminal checkpoint must not be
    # re-enqueued after pruning: the observer also stores its last snapshot.


def drain(con, now, sender=send):
    row = con.execute("""SELECT event_key,message,attempts FROM events
        WHERE sent IS NULL AND next_try <= ? ORDER BY observed,event_key LIMIT 1""",
                      (now,)).fetchone()
    if not row:
        return "IDLE"
    key, msg, attempts = row
    if sender(msg):
        con.execute("UPDATE events SET sent=? WHERE event_key=?", (now, key))
        return "SENT"
    delay = min(MAX_RETRY, 60 * (2 ** min(attempts, 6)))
    con.execute("UPDATE events SET attempts=attempts+1,next_try=? WHERE event_key=?",
                (now + delay, key))
    return "RETRY"


def current_plan(plan, checkpoint, plan_mtime, checkpoint_mtime):
    """A plan predating a release checkpoint cannot describe current drift."""
    if checkpoint is None:
        return True
    if checkpoint.get("phase") not in pub.FINAL:
        return False
    return (plan.get("baseline") == checkpoint.get("deployed")
            and plan_mtime > checkpoint_mtime)


def observe(state, env=os.environ, now=None, sender=None):
    now = int(time.time()) if now is None else now
    if sender is None:
        sender = lambda message: send(message, env)
    seenfile = state / "observer-seen.json"
    seen = p.load_json(seenfile) if seenfile.exists() else {}
    with contextlib.closing(db_open(state / "history.sqlite3")) as con:
        with con:
            release_path = state / "release-state.json"
            checkpoint = p.load_json(release_path) if release_path.exists() else None
            checkpoint_mtime = release_path.stat().st_mtime_ns if checkpoint is not None else 0
            for filename in ("release-state.json", "latest-plan.json"):
                path = state / filename
                if not path.exists():
                    continue
                snapshot = checkpoint if filename == "release-state.json" else p.load_json(path)
                if filename == "latest-plan.json" and not current_plan(
                        snapshot, checkpoint, path.stat().st_mtime_ns, checkpoint_mtime):
                    continue
                item = event(snapshot)
                if item and seen.get(filename) != item[0]:
                    record(con, snapshot, now)
                    seen[filename] = item[0]
        pub.durable_json(seenfile, seen)
        with con:
            result = drain(con, now, sender)
            prune_history(con, now)
            count = con.execute("SELECT COUNT(*) FROM events WHERE sent IS NULL").fetchone()[0]
        return {"notification": result, "pending": count}


def retention_candidates(backups, checkpoint, now):
    """Report eligible old verified backups only; no deletion in this phase."""
    p.trusted(backups, directory=True)
    if checkpoint.get("phase") not in pub.FINAL:
        return []
    protected = checkpoint.get("backup")
    paths = []
    for path in backups.iterdir():
        if not path.name.startswith("release-") or str(path) == protected:
            continue
        try:
            p.trusted(path, directory=True)
            manifest = path / "manifest.json"
            record = p.load_json(manifest)
            proof = {"backup": str(path), "manifest_sha256": pub.file_digest(manifest),
                     "deployed": record["baseline"], "candidate": record["candidate"]}
            pub.verified_manifest(pub.Host(backups=backups), proof)
            paths.append((manifest.stat().st_mtime, path.name))
        except (OSError, ValueError, TypeError, KeyError, p.Hold):
            continue
    paths.sort(reverse=True)
    return [name for stamp, name in paths[KEEP_BACKUPS:]
            if now - stamp >= BACKUP_DAYS * 86400]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retention-report", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        state = p.trusted(pub.STATE, directory=True)
        # Reuse the deploy lock; observer never blocks or edits bot operations.
        with pub.exclusive(state):
            if args.retention_report:
                saved = state / "release-state.json"
                checkpoint = p.load_json(saved) if saved.exists() else {}
                result = {"retention_candidates": retention_candidates(
                    pub.BACKUPS, checkpoint, int(time.time())), "deleted": 0}
            else:
                result = observe(state)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, p.Hold):
        print('{"status":"OBSERVER_DEFERRED"}')
        return 0


if __name__ == "__main__":
    sys.exit(main())
