"""CICD-04: explicitly invoked code-only publisher; no unattended activation."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

if __package__:
    from . import nvl_cd_planner as p
else:
    import nvl_cd_planner as p

SERVICE = "nvlbot.service"
RUNTIME = Path("/root")
STATE = Path("/var/lib/nvl-deploy")
BACKUPS = Path("/var/backups/nvl")
CONFIG = Path("/etc/nvl-deploy/config.json")
DB = RUNTIME / "master_bot.db"
ACTIVE = {
    "failover_operations": ("RUNNING",),
    "manual_quick_switch_jobs": ("DNS_INTENT", "DB_COMMITTED"),
    "manual_edge_operations": ("INSTALLING", "ROUTING"),
    "cloudzy_cz07_jobs": ("QUEUED", "ROUTING", "MIGRATING"),
    "cloudzy_cz04b_operations": ("PREPARING", "DNS_WRITE_INTENT",
                                "DNS_TARGET_CONFIRMED", "USERS_COMMITTING"),
}
FINAL = {"COMMITTED", "ROLLED_BACK"}


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_json(path, data):
    p.atomic_json(path, data)
    sync_dir(path.parent)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def atomic_bytes(path, raw, mode):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".nvl-cd-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


@contextlib.contextmanager
def read_db(path):
    p.trusted(path)
    deadline = time.monotonic() + 30
    con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)
    try:
        con.execute("PRAGMA query_only=ON")
        con.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        yield con
    finally:
        con.close()


def schema(con):
    rows = con.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    version = con.execute("PRAGMA user_version").fetchone()
    return digest(json.dumps([rows, version], ensure_ascii=False).encode())


def busy(con):
    for table, statuses in ACTIVE.items():
        exists = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                             (table,)).fetchone()
        if not exists:
            if table == "failover_operations":
                raise p.Hold("SHARED_LEASE_SCHEMA_MISSING")
            continue
        cols = {row[1] for row in con.execute("PRAGMA table_info(" + table + ")")}
        if "status" not in cols:
            raise p.Hold("OPERATION_SCHEMA_UNKNOWN")
        if con.execute("SELECT 1 FROM " + table + " WHERE status IN (" +
                       ",".join("?" for _ in statuses) + ") LIMIT 1",
                       statuses).fetchone():
            return True
    return False


class Host:
    def __init__(self, runtime=RUNTIME, db=DB, backups=BACKUPS):
        self.runtime, self.db, self.backups = runtime, db, backups

    def command(self, *args):
        return subprocess.check_output(args, stderr=subprocess.DEVNULL,
                                       timeout=90, text=True)

    def status(self):
        raw = self.command("/usr/bin/systemctl", "show", SERVICE,
                           "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
                           "-p", "NRestarts")
        return dict(line.split("=", 1) for line in raw.splitlines())

    def active(self):
        s = self.status()
        return s.get("ActiveState") == "active" and s.get("SubState") == "running"

    def stop(self):
        self.command("/usr/bin/systemctl", "stop", SERVICE)
        s = self.status()
        if s.get("ActiveState") != "inactive" or s.get("MainPID") != "0":
            raise p.Hold("BOT_NOT_STOPPED")

    def start(self):
        self.command("/usr/bin/systemctl", "start", SERVICE)

    def idle(self):
        with read_db(self.db) as con:
            return not busy(con)

    def schema(self):
        with read_db(self.db) as con:
            return schema(con)

    def healthy(self):
        # Process-level health only; application readiness still required
        # for unattended activation in CICD-06.
        first = self.status()
        pid = first.get("MainPID", "0")
        if not self.active() or pid == "0":
            raise p.Hold("BOT_HEALTH_FAILED")
        for _ in range(6):
            time.sleep(2)
            state = self.status()
            if (state.get("ActiveState") != "active"
                    or state.get("SubState") != "running"
                    or state.get("MainPID") != pid
                    or state.get("NRestarts") != first.get("NRestarts")):
                raise p.Hold("BOT_HEALTH_FAILED")
        with read_db(self.db) as con:
            if con.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise p.Hold("DB_HEALTH_FAILED")

    def snapshot_db(self, path):
        deadline = time.monotonic() + 90
        def progress(status, remaining, total):
            if time.monotonic() > deadline:
                raise p.Hold("BACKUP_TIMEOUT")
        with read_db(self.db) as src, contextlib.closing(sqlite3.connect(path)) as dst:
            src.backup(dst, pages=256, progress=progress, sleep=0.05)
            dst.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            if dst.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise p.Hold("BACKUP_INTEGRITY_FAILED")
            dst.commit()
        os.chmod(path, 0o600)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        return file_digest(path)

    def live(self, name):
        return p.live_blob(self.runtime, name)


def file_digest(path):
    with p.trusted(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stage(host, repo, baseline, candidate, updates, old, new):
    p.trusted(host.backups, directory=True)
    required = host.db.stat().st_size * 2 + 1024**3
    if shutil.disk_usage(host.backups).free < required:
        raise p.Hold("BACKUP_SPACE_LOW")
    directory = Path(tempfile.mkdtemp(prefix="release-", dir=host.backups))
    before, after = directory / "before", directory / "after"
    before.mkdir(mode=0o700)
    after.mkdir(mode=0o700)
    manifest = {}
    for name in updates:
        prior = old.get(name)
        expected = prior[2] if prior else "ABSENT"
        if host.live(name) != expected:
            raise p.Hold("RUNTIME_DRIFT")
        raw = p.git(repo, "cat-file", "blob", new[name][2])
        if len(raw) > p.MAX_BYTES or blob(raw) != new[name][2]:
            raise p.Hold("STAGE_HASH_MISMATCH")
        compile(raw, name, "exec")
        atomic_bytes(after / name, raw, 0o600)
        mode = 0o644
        previous = None
        if prior:
            path = p.trusted(host.runtime / name)
            original = path.read_bytes()
            if blob(original) != expected:
                raise p.Hold("RUNTIME_DRIFT")
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode not in (0o600, 0o640, 0o644):
                raise p.Hold("RUNTIME_MODE_UNSUPPORTED")
            atomic_bytes(before / name, original, 0o600)
            previous = digest(original)
        manifest[name] = {"old": expected, "new": new[name][2],
                          "old_sha256": previous, "new_sha256": digest(raw),
                          "mode": mode}
    db_sha = host.snapshot_db(directory / "database.sqlite3")
    record = {"baseline": baseline, "candidate": candidate,
              "files": manifest, "db_sha256": db_sha, "schema": host.schema()}
    durable_json(directory / "manifest.json", record)
    sync_dir(host.backups)
    return directory, record


def verified_manifest(host, checkpoint):
    directory = Path(checkpoint["backup"])
    if directory.parent != host.backups or not directory.name.startswith("release-"):
        raise p.Hold("BACKUP_PATH_INVALID")
    p.trusted(directory, directory=True)
    p.trusted(directory / "before", directory=True)
    p.trusted(directory / "after", directory=True)
    manifest_path = directory / "manifest.json"
    if file_digest(manifest_path) != checkpoint["manifest_sha256"]:
        raise p.Hold("BACKUP_MANIFEST_CHANGED")
    record = p.load_json(manifest_path)
    if record["baseline"] != checkpoint["deployed"] or record["candidate"] != checkpoint["candidate"]:
        raise p.Hold("BACKUP_IDENTITY_MISMATCH")
    if file_digest(directory / "database.sqlite3") != record["db_sha256"]:
        raise p.Hold("DATABASE_BACKUP_CHANGED")
    p.inventory_paths(list(record["files"]))
    for name, item in record["files"].items():
        for side, expected, oid in (("before", item["old_sha256"], item["old"]),
                                    ("after", item["new_sha256"], item["new"])):
            if expected is None and side == "before" and oid == "ABSENT":
                continue
            path = directory / side / name
            if file_digest(path) != expected or blob(path.read_bytes()) != oid:
                raise p.Hold("CODE_BACKUP_CHANGED")
        if item["mode"] not in (0o600, 0o640, 0o644):
            raise p.Hold("BACKUP_MODE_INVALID")
    return directory, record


def set_phase(state, checkpoint, phase, **fields):
    checkpoint = dict(checkpoint, phase=phase, **fields)
    durable_json(state / "release-state.json", checkpoint)
    return checkpoint


def restore(host, state, checkpoint):
    """Recover old code only, never rewind live SQLite or external effects."""
    directory, record = verified_manifest(host, checkpoint)
    if host.schema() != record["schema"]:
        raise p.Hold("SCHEMA_CHANGED_NO_AUTO_ROLLBACK")
    # Do not stop an already-running bot if it has begun a new sensitive job.
    if host.active() and not host.idle():
        raise p.Hold("ACTIVE_OPERATION_NO_AUTO_ROLLBACK")
    for name, item in record["files"].items():
        if host.live(name) not in (item["old"], item["new"]):
            raise p.Hold("UNKNOWN_RUNTIME_NO_AUTO_ROLLBACK")
    host.stop()
    if not host.idle() or host.schema() != record["schema"]:
        host.start()
        raise p.Hold("OPERATION_OR_SCHEMA_CHANGED")
    for name, item in record["files"].items():
        target = host.runtime / name
        if item["old"] == "ABSENT":
            if host.live(name) == item["new"]:
                target.unlink()
                sync_dir(target.parent)
        else:
            atomic_bytes(target, (directory / "before" / name).read_bytes(), item["mode"])
        if host.live(name) != item["old"]:
            raise p.Hold("ROLLBACK_HASH_FAILED")
    host.start()
    host.healthy()
    return set_phase(state, checkpoint, "ROLLED_BACK")


def publish(host, state, repo, baseline, candidate, updates, old, new, revalidate):
    if not host.active() or not host.idle():
        raise p.Hold("BOT_OR_OPERATION_BUSY")
    directory, record = stage(host, repo, baseline, candidate, updates, old, new)
    checkpoint = {"deployed": baseline, "candidate": candidate,
                  "backup": str(directory),
                  "manifest_sha256": file_digest(directory / "manifest.json")}
    verified_manifest(host, checkpoint)
    # Last read-only checks; no stale saved plan used as authority.
    revalidate()
    if not host.idle() or host.schema() != record["schema"]:
        raise p.Hold("OPERATION_OR_SCHEMA_CHANGED")
    for name, item in record["files"].items():
        if host.live(name) != item["old"]:
            raise p.Hold("RUNTIME_DRIFT")
    checkpoint = set_phase(state, checkpoint, "STOPPING")
    try:
        host.stop()
        if not host.idle() or host.schema() != record["schema"]:
            host.start()
            return set_phase(state, checkpoint, "ROLLED_BACK", reason="OPERATION_OR_SCHEMA_CHANGED")
        checkpoint = set_phase(state, checkpoint, "PUBLISHING")
        for name, item in record["files"].items():
            if host.live(name) != item["old"]:
                raise p.Hold("RUNTIME_DRIFT")
            atomic_bytes(host.runtime / name, (directory / "after" / name).read_bytes(), item["mode"])
            if host.live(name) != item["new"]:
                raise p.Hold("PUBLISH_HASH_FAILED")
        checkpoint = set_phase(state, checkpoint, "STARTING")
        host.start()
        host.healthy()
        # Successful but schema-changing start needs explicit review before
        # recording a reversible release. Do not undo database changes.
        if host.schema() != record["schema"]:
            return set_phase(state, checkpoint, "HOLD", reason="SCHEMA_CHANGED")
        return set_phase(state, checkpoint, "COMMITTED", deployed=candidate)
    except Exception:
        try:
            return restore(host, state, checkpoint)
        except Exception:
            return set_phase(state, checkpoint, "HOLD", reason="RECOVERY_REQUIRED")


@contextlib.contextmanager
def exclusive(state):
    fd = os.open(state / "poll.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise p.Hold("LOCK_UNTRUSTED")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def release(state, config, expected):
    saved = state / "release-state.json"
    previous = p.load_json(saved) if saved.exists() else None
    if previous and previous["phase"] not in FINAL:
        raise p.Hold("RECOVERY_REQUIRED")
    baseline = p.exact_sha(previous["deployed"] if previous else config["baseline"])
    candidate = p.exact_sha(expected)
    if previous and previous["phase"] == "ROLLED_BACK" and previous["candidate"] == candidate:
        raise p.Hold("FAILED_CANDIDATE_REQUIRES_REVIEW")
    if p.remote_head() != candidate:
        raise p.Hold("MASTER_MOVED")
    repo = p.trusted(state / "repository.git", directory=True)
    # Re-fetch and freshly validate CI; do not consume latest-plan.json.
    p.git(repo, "fetch", "--no-tags", "--no-recurse-submodules", p.REMOTE,
          "+refs/heads/master:refs/nvl/master")
    if p.git(repo, "rev-parse", "refs/nvl/master").decode().strip() != candidate:
        raise p.Hold("MASTER_MOVED")
    p.git(repo, "merge-base", "--is-ancestor", baseline, candidate)
    old, new = p.tree(repo, baseline), p.tree(repo, candidate)
    host = Host()
    inventory = p.inventory_paths(config["inventory"])
    plan = p.build_plan(old, new, inventory, host.live)
    if plan["status"] != "PLAN_READY":
        raise p.Hold("PLAN_NOT_READY")
    def revalidate():
        if p.remote_head() != candidate:
            raise p.Hold("MASTER_MOVED")
        p.check_gate(candidate)
        if p.remote_head() != candidate:
            raise p.Hold("MASTER_MOVED")
        if p.build_plan(old, new, inventory, host.live) != plan:
            raise p.Hold("PLAN_CHANGED")
    if not plan["updates"]:
        revalidate()
        return set_phase(state, {"candidate": candidate}, "COMMITTED", deployed=candidate)
    return publish(host, state, repo, baseline, candidate, plan["updates"], old, new, revalidate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apply", metavar="EXACT_MASTER_SHA")
    group.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise p.Hold("ROOT_REQUIRED")
        state = p.trusted(STATE, directory=True)
        with exclusive(state):
            # This marker is deliberately NOT shipped or created by a timer.
            # CICD-06 must verify real quiescence, readiness and rollback policy.
            marker = p.trusted(Path("/etc/nvl-deploy/operator-accepted"))
            if marker.read_text().strip() != "CICD-06-ACCEPTED":
                raise p.Hold("PRODUCTION_NOT_ACCEPTED")
            config = p.load_json(CONFIG)
            if set(config) != {"baseline", "inventory"}:
                raise p.Hold("CONFIG_SCOPE_INVALID")
            if args.recover:
                checkpoint = p.load_json(state / "release-state.json")
                if checkpoint["phase"] in FINAL:
                    raise p.Hold("NOTHING_TO_RECOVER")
                result = restore(Host(), state, checkpoint)
            else:
                result = release(state, config, args.apply)
            print(json.dumps({k: result.get(k) for k in
                              ("phase", "deployed", "candidate", "reason")}, sort_keys=True))
            return 0 if result["phase"] == "COMMITTED" else 2
    except (p.Hold, OSError, ValueError, KeyError, TypeError,
            sqlite3.Error, subprocess.SubprocessError):
        print('{"phase":"HOLD","reason":"RELEASE_NOT_AUTHORIZED_OR_FAILED"}')
        return 2


if __name__ == "__main__":
    sys.exit(main())
