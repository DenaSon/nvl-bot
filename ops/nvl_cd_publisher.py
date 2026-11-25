"""CICD-04: explicitly invoked code-only publisher; no unattended activation."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import traceback

if __package__:
    from . import nvl_cd_components as components
    from . import nvl_cd_planner as p
    from . import nvl_cd_release_notes as notes
else:
    import nvl_cd_components as components
    import nvl_cd_planner as p
    import nvl_cd_release_notes as notes

SERVICE = "nvlbot.service"
RUNTIME = Path("/root")
STATE = Path("/var/lib/nvl-deploy")
BACKUPS = Path("/var/backups/nvl")
CONFIG = Path("/etc/nvl-deploy/config.json")
ACCEPTED = Path("/etc/nvl-deploy/operator-accepted")
DB = RUNTIME / "master_bot.db"
ACTIVE = {
    "failover_operations": ("RUNNING",),
    "manual_quick_switch_jobs": ("DNS_INTENT", "DB_COMMITTED"),
    "manual_edge_operations": ("INSTALLING", "ROUTING"),
    "cloudzy_edge_operations": ("CREATING", "PROVISIONING"),
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
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.trusted(path.parent, directory=True)
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


def report_failure(stage, exc):
    """Log diagnostics without exception text, command arguments or locals."""
    event = {"event": "NVL_CD_FAILURE", "stage": stage,
             "error_type": type(exc).__name__}
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        event["errno"] = exc.errno
    if isinstance(exc, subprocess.CalledProcessError):
        event["returncode"] = exc.returncode
    # Hold messages are internal reason codes; never print arbitrary text.
    if isinstance(exc, p.Hold) and len(exc.args) == 1:
        reason = exc.args[0]
        if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z_]{2,79}", reason):
            event["reason"] = reason
    frames = traceback.extract_tb(exc.__traceback__)
    if frames:
        event["function"] = frames[-1].name
        event["line"] = frames[-1].lineno
    print(json.dumps(event, sort_keys=True), file=sys.stderr, flush=True)


def runtime_write_preflight(runtime, names=()):
    """Exercise atomic writes in every runtime directory before shutdown."""
    directories = {runtime}
    for name in names:
        parent = (runtime / name).parent
        while parent != runtime and runtime in parent.parents:
            directories.add(parent)
            parent = parent.parent
    for directory in list(directories):
        cache = directory / "__pycache__"
        if os.path.lexists(cache):
            directories.add(cache)
    directories = sorted(directories, key=lambda item: len(item.parts))
    try:
        for directory in directories:
            p.trusted(directory, directory=True)
            with tempfile.TemporaryDirectory(prefix=".nvl-cd-probe-", dir=directory) as tmp:
                probe = Path(tmp) / "probe"
                atomic_bytes(probe, b"old", 0o600)
                atomic_bytes(probe, b"new", 0o600)
                if probe.read_bytes() != b"new":
                    raise p.Hold("RUNTIME_WRITE_PROBE_MISMATCH")
            sync_dir(directory)
    except Exception as exc:
        report_failure("RUNTIME_WRITE_PREFLIGHT", exc)
        raise p.Hold("RUNTIME_WRITE_PREFLIGHT_FAILED") from exc


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
                                       timeout=120, text=True)

    def status(self):
        raw = self.command("/usr/bin/systemctl", "show", SERVICE,
                           "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
                           "-p", "NRestarts", "-p", "InvocationID",
                           "-p", "Result", "-p", "ExecMainCode", "-p", "ExecMainStatus")
        return dict(line.split("=", 1) for line in raw.splitlines())

    def active(self):
        s = self.status()
        return s.get("ActiveState") == "active" and s.get("SubState") == "running"

    def evidence(self, identity, message, since):
        invocation, pid = identity.get("InvocationID", ""), identity.get("MainPID", "")
        if (not re.fullmatch(r"[0-9a-f]{32}", invocation)
                or invocation == "0" * 32 or not pid.isdigit() or int(pid) <= 1):
            return False
        raw = self.command("/usr/bin/journalctl", "--no-pager", "--output=json",
                           "--lines=1", "--since=@" + str(int(since)),
                           "_SYSTEMD_UNIT=" + SERVICE,
                           "_SYSTEMD_INVOCATION_ID=" + invocation,
                           "_PID=" + pid, "MESSAGE=" + message)
        try:
            entry = json.loads(raw)
            observed = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
            return (entry.get("MESSAGE") == message
                    and entry.get("_SYSTEMD_UNIT") == SERVICE
                    and entry.get("_SYSTEMD_INVOCATION_ID") == invocation
                    and entry.get("_PID") == pid
                    and since <= observed <= time.time() + 2)
        except (ValueError, TypeError, KeyError):
            return False

    def stop(self):
        before = self.status()
        if before.get("ActiveState") == "inactive" and before.get("MainPID") == "0":
            # Recovery may start with an already stopped process. Never infer
            # a clean stop from a failed/killed unit.
            if (before.get("Result"), before.get("ExecMainCode"),
                    before.get("ExecMainStatus")) != ("success", "1", "0"):
                raise p.Hold("BOT_STOP_UNPROVEN")
            return
        if before.get("ActiveState") != "active" or before.get("SubState") != "running":
            raise p.Hold("BOT_STOP_UNPROVEN")
        started = time.time()
        self.command("/usr/bin/systemctl", "stop", SERVICE)
        s = self.status()
        if (s.get("ActiveState"), s.get("MainPID"), s.get("Result"),
                s.get("ExecMainCode"), s.get("ExecMainStatus")) != (
                    "inactive", "0", "success", "1", "0"):
            raise p.Hold("BOT_STOP_UNCLEAN")
        if not self.evidence(before, "NVL_CD_SHUTDOWN_CLEAN", started):
            raise p.Hold("BOT_DRAIN_UNPROVEN")

    def start(self):
        self.command("/usr/bin/systemctl", "start", SERVICE)

    def idle(self):
        with read_db(self.db) as con:
            return not busy(con)

    def schema(self):
        with read_db(self.db) as con:
            return schema(con)

    def healthy(self):
        first = self.status()
        pid = first.get("MainPID", "0")
        if (first.get("ActiveState") != "active" or first.get("SubState") != "running"
                or pid == "0"):
            raise p.Hold("BOT_HEALTH_FAILED")
        # Require real polling evidence from the same invocation, plus
        # at least 12 seconds of process stability. No extra getUpdates calls.
        started = time.monotonic()
        deadline = started + 60
        while True:
            state = self.status()
            if (state.get("ActiveState") != "active"
                    or state.get("SubState") != "running"
                    or state.get("MainPID") != pid
                    or state.get("InvocationID") != first.get("InvocationID")
                    or state.get("NRestarts") != first.get("NRestarts")):
                raise p.Hold("BOT_HEALTH_FAILED")
            if (time.monotonic() - started >= 12
                    and self.evidence(state, "NVL_CD_POLL_OK", time.time() - 45)):
                break
            if time.monotonic() >= deadline:
                raise p.Hold("BOT_POLL_UNPROVEN")
            time.sleep(2)
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
            backup_schema = schema(dst)
            dst.commit()
        os.chmod(path, 0o600)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        return file_digest(path), backup_schema

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
        runtime_parent = (host.runtime / name).parent
        runtime_parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        p.trusted(runtime_parent, directory=True)
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
    db_sha, backup_schema = host.snapshot_db(directory / "database.sqlite3")
    if host.schema() != backup_schema:
        raise p.Hold("SCHEMA_CHANGED_DURING_BACKUP")
    record = {"baseline": baseline, "candidate": candidate,
              "files": manifest, "db_sha256": db_sha, "schema": backup_schema}
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


def archive_outcome(state, checkpoint):
    """Preserve the outcome before another release can replace its checkpoint."""
    if checkpoint.get("phase") not in FINAL | {"HOLD"}:
        return
    candidate = p.exact_sha(checkpoint["candidate"])
    directory = state / "outcomes"
    if not directory.exists():
        directory.mkdir(mode=0o700)
        sync_dir(state)
    p.trusted(directory, directory=True)
    durable_json(directory / (candidate + "-" + checkpoint["phase"] + ".json"),
                 checkpoint)


def set_phase(state, checkpoint, phase, **fields):
    previous = state / "release-state.json"
    if previous.exists():
        # Recover the archive even if an earlier process died after saving
        # its terminal checkpoint but before the next write below.
        archive_outcome(state, p.load_json(previous))
    checkpoint = dict(checkpoint, phase=phase, **fields)
    if phase in FINAL | {"HOLD"}:
        checkpoint["finished_at"] = int(time.time())
    durable_json(previous, checkpoint)
    return checkpoint



def invalidate_bytecode(runtime, names):
    # CPython can otherwise reuse a timestamp/size-matched .pyc after an
    # atomic replacement, including rollback within the same second.
    directory = runtime / "__pycache__"
    if os.path.lexists(directory):
        p.trusted(directory, directory=True)
    else:
        return
    stems = {Path(name).stem for name in names}
    for path in directory.iterdir():
        if path.suffix == ".pyc" and any(
                path.name.startswith(stem + ".") for stem in stems):
            p.trusted(path)
            path.unlink()
    sync_dir(directory)


def resume_unchanged(host, state, checkpoint, *, allow_running=True,
                     reason="STOP_UNPROVEN_BASELINE_RESUMED"):
    """Restore availability of verified unchanged code without rewriting it."""
    _, record = verified_manifest(host, checkpoint)
    if host.schema() != record["schema"] or not host.idle():
        raise p.Hold("OPERATION_OR_SCHEMA_CHANGED")
    if any(host.live(name) != item["old"] for name, item in record["files"].items()):
        raise p.Hold("BASELINE_NOT_UNCHANGED")
    status = host.status()
    if allow_running and (status.get("ActiveState"), status.get("SubState")) == ("active", "running"):
        # Stop may have failed without stopping the service.
        pass
    elif (status.get("ActiveState"), status.get("SubState"), status.get("MainPID")) == (
            "inactive", "dead", "0"):
        # Never send a second stop or publish code; start the verified
        # unchanged baseline only after systemd confirms it is fully stopped.
        host.start()
    else:
        raise p.Hold("STOP_STATE_UNCERTAIN")
    host.healthy()
    return set_phase(state, checkpoint, "ROLLED_BACK",
                     reason=reason)


def restore(host, state, checkpoint):
    """Recover old code only, never rewind live SQLite or external effects."""
    if checkpoint.get("reason") == "STOP_UNPROVEN" or checkpoint.get("phase") == "STOPPING":
        return resume_unchanged(host, state, checkpoint)
    directory, record = verified_manifest(host, checkpoint)
    if host.schema() != record["schema"]:
        raise p.Hold("SCHEMA_CHANGED_NO_AUTO_ROLLBACK")
    # Do not stop an already-running bot if it has begun a new sensitive job.
    if not host.idle():
        raise p.Hold("ACTIVE_OPERATION_NO_AUTO_ROLLBACK")
    for name, item in record["files"].items():
        if host.live(name) not in (item["old"], item["new"]):
            raise p.Hold("UNKNOWN_RUNTIME_NO_AUTO_ROLLBACK")
    all_old = all(host.live(n) == i["old"] for n, i in record["files"].items())
    status = host.status()
    # PUBLISHING is persisted only after a proven clean shutdown, and
    # STARTING is persisted before any candidate start. If publication failed
    # before changing any file, no writes (or second stop) are necessary.
    # An active process or unknown historical HOLD is not proof of generation.
    phase = checkpoint.get("phase")
    if phase == "HOLD":
        phase = checkpoint.get("failure_phase")
    if (phase == "PUBLISHING" and all_old
            and (status.get("ActiveState"), status.get("SubState"), status.get("MainPID"))
            == ("inactive", "dead", "0")):
        return resume_unchanged(host, state, checkpoint, allow_running=False,
                                reason="PUBLISH_FAILED_BASELINE_RESUMED")
    # A rollback that requires writes must not stop a running service if
    # its sandbox cannot write. Recheck after the clean stop as usual.
    runtime_write_preflight(host.runtime, record["files"])
    was_active = host.active()
    uniform = (all_old
               or all(host.live(n) == i["new"] for n, i in record["files"].items()))
    host.stop()
    if not host.idle() or host.schema() != record["schema"]:
        # Never start a half-published generation during recovery.
        if was_active and uniform:
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
    invalidate_bytecode(host.runtime, record["files"])
    host.start()
    host.healthy()
    return set_phase(state, checkpoint, "ROLLED_BACK")


def publish(host, state, repo, baseline, candidate, updates, old, new, revalidate,
            release_notes=None, component_result=None):
    if not host.active() or not host.idle():
        raise p.Hold("BOT_OR_OPERATION_BUSY")
    started_at = int(time.time())
    directory, record = stage(host, repo, baseline, candidate, updates, old, new)
    component_result = component_result or {}
    component_count = int(component_result.get("updated", 0))
    checkpoint = {"deployed": baseline, "candidate": candidate,
                  "backup": str(directory),
                  "manifest_sha256": file_digest(directory / "manifest.json"),
                  "started_at": started_at, "restart_required": True,
                  "file_count": len(updates) + component_count,
                  "bot_file_count": len(updates),
                  "component_count": component_count,
                  "components": component_result.get("components", []),
                  "component_backup": component_result.get("backup"),
                  "release_notes": release_notes or {}}
    verified_manifest(host, checkpoint)
    # Last read-only checks; no stale saved plan used as authority.
    revalidate()
    if not host.idle() or host.schema() != record["schema"]:
        raise p.Hold("OPERATION_OR_SCHEMA_CHANGED")
    for name, item in record["files"].items():
        if host.live(name) != item["old"]:
            raise p.Hold("RUNTIME_DRIFT")
    runtime_write_preflight(host.runtime, updates)
    checkpoint = set_phase(state, checkpoint, "STOPPING")
    try:
        host.stop()
    except Exception as exc:
        report_failure("STOPPING", exc)
        # Never publish or send a second stop after uncertain shutdown.
        # If the exact old code is intact, resume its service instead of
        # leaving a confirmed inactive bot offline.
        try:
            return resume_unchanged(host, state, checkpoint)
        except Exception as exc:
            report_failure("STOP_RECOVERY", exc)
            return set_phase(state, checkpoint, "HOLD", reason="STOP_UNPROVEN",
                             failure_phase="STOPPING")
    try:
        if not host.idle() or host.schema() != record["schema"]:
            host.start()
            host.healthy()
            return set_phase(state, checkpoint, "ROLLED_BACK", reason="OPERATION_OR_SCHEMA_CHANGED")
        checkpoint = set_phase(state, checkpoint, "PUBLISHING")
        for name, item in record["files"].items():
            if host.live(name) != item["old"]:
                raise p.Hold("RUNTIME_DRIFT")
            atomic_bytes(host.runtime / name, (directory / "after" / name).read_bytes(), item["mode"])
            if host.live(name) != item["new"]:
                raise p.Hold("PUBLISH_HASH_FAILED")
        invalidate_bytecode(host.runtime, record["files"])
        checkpoint = set_phase(state, checkpoint, "STARTING")
        host.start()
        host.healthy()
        # Successful but schema-changing start needs explicit review before
        # recording a reversible release. Do not undo database changes.
        if host.schema() != record["schema"]:
            return set_phase(state, checkpoint, "HOLD", reason="SCHEMA_CHANGED")
        return set_phase(state, checkpoint, "COMMITTED", deployed=candidate,
                         previous_deployed=baseline)
    except Exception as exc:
        report_failure(checkpoint["phase"], exc)
        try:
            return restore(host, state, checkpoint)
        except Exception as recovery_exc:
            report_failure("RECOVERY", recovery_exc)
            return set_phase(state, checkpoint, "HOLD", reason="RECOVERY_REQUIRED",
                             failure_phase=checkpoint["phase"])


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
    if baseline == candidate:
        raise p.Hold("ALREADY_DEPLOYED")
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
    read_component_blob = lambda oid: p.git(repo, "cat-file", "blob", oid)
    build = lambda: p.build_plan(
        old, new, inventory, host.live, p.control_plane_blob,
        read_component_blob, components.live_blob,
    )
    plan = build()
    if plan["status"] != "PLAN_READY":
        raise p.Hold("PLAN_NOT_READY")

    # Component targets are published independently of nvlbot. Existing live
    # candidate hashes are reconciled as already deployed; only old->new files
    # are written. Component state/telemetry databases are never replaced.
    p.check_gate(candidate)
    try:
        component_result = components.apply_updates(
            repo, plan["component_updates"], candidate, read_component_blob,
            backup_root=BACKUPS, affected=plan["components"],
        )
    except components.ComponentApplyError as exc:
        report_failure("COMPONENT_DEPLOY", exc)
        raise p.Hold(
            "COMPONENT_ROLLBACK_FAILED" if not exc.rolled_back
            else "COMPONENT_DEPLOY_RETRY"
        ) from exc

    plan = build()
    if plan["status"] != "PLAN_READY" or plan["component_updates"]:
        raise p.Hold("COMPONENT_POSTCHECK_FAILED")

    def revalidate():
        if p.remote_head() != candidate:
            raise p.Hold("MASTER_MOVED")
        p.check_gate(candidate)
        if p.remote_head() != candidate:
            raise p.Hold("MASTER_MOVED")
        if build() != plan:
            raise p.Hold("PLAN_CHANGED")

    # Metadata is advisory, fetched before cutover and never part of the gate.
    release_notes = notes.collect(repo, baseline, candidate)
    component_count = int(component_result.get("updated", 0))
    total_files = len(plan["updates"]) + component_count
    if not plan["updates"]:
        revalidate()
        return set_phase(state, {
            "candidate": candidate, "restart_required": False,
            "started_at": int(time.time()), "file_count": total_files,
            "bot_file_count": 0, "component_count": component_count,
            "components": component_result.get("components", plan["components"]),
            "component_backup": component_result.get("backup"),
            "previous_deployed": baseline, "release_notes": release_notes,
        }, "COMMITTED", deployed=candidate)

    # The rollback baseline must already implement the polling contract.
    host.healthy()
    return publish(
        host, state, repo, baseline, candidate, plan["updates"], old, new,
        revalidate, release_notes=release_notes,
        component_result=component_result,
    )


def accepted_config():
    marker = p.trusted(ACCEPTED)
    if marker.read_text().strip() != "CICD-06-ACCEPTED":
        raise p.Hold("PRODUCTION_NOT_ACCEPTED")
    config = p.load_json(CONFIG)
    if set(config) != {"baseline", "inventory"}:
        raise p.Hold("CONFIG_SCOPE_INVALID")
    p.exact_sha(config["baseline"])
    p.inventory_paths(config["inventory"])
    return config


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
            config = accepted_config()
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
            sqlite3.Error, subprocess.SubprocessError) as exc:
        report_failure("MANUAL_RECOVERY" if args.recover else "MANUAL_APPLY", exc)
        print('{"phase":"HOLD","reason":"RELEASE_NOT_AUTHORIZED_OR_FAILED"}')
        return 2


if __name__ == "__main__":
    sys.exit(main())
