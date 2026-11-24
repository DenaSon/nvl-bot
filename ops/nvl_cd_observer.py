"""NVL CD event history and group notifications; no production mutations."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request

if __package__:
    from . import nvl_cd_planner as p
    from . import nvl_cd_publisher as pub
    from . import nvl_cd_release_notes as notes
else:
    import nvl_cd_planner as p
    import nvl_cd_publisher as pub
    import nvl_cd_release_notes as notes

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


def bot_identity():
    raw = subprocess.check_output(
        ["/usr/bin/systemctl", "show", "nvlbot.service",
         "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "InvocationID"],
        text=True, timeout=5, stderr=subprocess.DEVNULL)
    info = dict(line.split("=", 1) for line in raw.splitlines())
    pid = int(info["MainPID"])
    invocation = info["InvocationID"]
    if (info["ActiveState"] != "active" or info["SubState"] != "running"
            or pid <= 1 or not re.fullmatch(r"[0-9a-f]{32}", invocation)
            or invocation == "0" * 32):
        return None
    return pid, invocation


def bot_environ(pid):
    with Path(f"/proc/{pid}/environ").open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        return {}
    values = {}
    keys = {b"BOT_TOKEN", b"MARZBAN_ALERT_CHAT_ID"}
    for entry in raw.split(b"\0"):
        key, sep, value = entry.partition(b"=")
        if sep and key in keys:
            name = key.decode("ascii")
            if name in values:
                return {}
            values[name] = value.decode("ascii")
    return values


def live_env(identity=bot_identity, read=bot_environ):
    """Use only the actual running nvlbot invocation, never another group."""
    try:
        first = identity()
        if first is None:
            return {}
        values = read(first[0])
        if identity() != first or not target(values):
            return {}
        return {name: values[name] for name in ("BOT_TOKEN", "MARZBAN_ALERT_CHAT_ID")}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return {}


def send(text, env=None):
    configured = target(live_env() if env is None else env)
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
        if phase == "COMMITTED" and state.get("restart_required") is False:
            labels[phase] = "✅ ثبت نسخه بدون نیاز به Restart"
        msg = "NVL CI/CD\n" + labels[phase] + "\nSHA: " + sha[:12]
        deployed = state.get("deployed")
        if isinstance(deployed, str) and p.SHA.fullmatch(deployed):
            msg += "\nنسخه ثبت‌شده: " + deployed[:12]
        if phase == "COMMITTED":
            count = state.get("file_count")
            if type(count) is int and count >= 0:
                msg += "\nفایل‌های منتشرشده: " + str(count)
            start, finish = state.get("started_at"), state.get("finished_at")
            if type(start) is int and type(finish) is int and 0 <= finish - start <= 86400:
                msg += "\nمدت استقرار: " + str(finish - start) + " ثانیه"
            if state.get("restart_required") is True:
                msg += ("\n\n✅ CI موفق | بکاپ تأیید شد"
                        "\n✅ Polling تلگرام و سلامت دیتابیس تأیید شد"
                        "\n🧪 تست عملیاتی مدیران: در انتظار انجام")
            elif state.get("restart_required") is False:
                msg += "\n✅ CI موفق | بدون انتشار فایل عملیاتی"
            msg += "\n" + notes.render(state)
        elif phase == "ROLLED_BACK":
            msg += "\nنسخه جدید قابل تست نیست؛ نسخه قبلی بازیابی شده است."
        else:
            msg += "\nاز تست نسخه جدید تا بررسی وضعیت خودداری کنید."
        # Telegram length is bounded conservatively in UTF-16 units.
        if len(msg.encode("utf-16-le")) // 2 > 3900:
            msg = msg.encode("utf-16-le")[:7600].decode("utf-16-le", errors="ignore") + "\n…"
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


def observe(state, env=None, now=None, sender=None):
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
            # Import archived terminal outcomes even if a newer release
            # completed before this observer tick. Remove only after DB commit.
            archive = state / "outcomes"
            consumed = []
            if archive.exists():
                p.trusted(archive, directory=True)
                for path in sorted(archive.glob("*.json")):
                    snapshot = p.load_json(path)
                    item = event(snapshot)
                    expected = snapshot.get("candidate", "") + "-" + snapshot.get("phase", "") + ".json"
                    if not item or path.name != expected or snapshot.get("phase") not in pub.FINAL | {"HOLD"}:
                        raise p.Hold("OUTCOME_INVALID")
                    if seen.get("release-state.json") != item[0]:
                        record(con, snapshot, snapshot.get("finished_at", now))
                    consumed.append(path)
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
        for path in consumed:
            path.unlink()
        if consumed:
            pub.sync_dir(archive)
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
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--retention-report", action="store_true")
    group.add_argument("--check-target", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.check_target:
            ready = target(live_env()) is not None
            print(json.dumps({"telegram_target": "READY" if ready else "UNAVAILABLE"}))
            return 0 if ready else 2
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
