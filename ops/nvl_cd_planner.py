"""NVL CD discovery and dry-run planner. No production publisher."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

if __package__:
    from . import nvl_cd_components as components
else:
    import nvl_cd_components as components

REPO = "DenaSon/nvl-bot"
REMOTE = "https://github.com/" + REPO + ".git"
API = "https://api.github.com/repos/" + REPO
WORKFLOW = ".github/workflows/python-checks.yml"
REQUIRED = {"syntax-and-unit-tests", "Release manifest and root safety",
            "Clean runtime preflight", "NVL Release Gate"}
SHA = re.compile(r"[0-9a-f]{40}")
API_INTERVAL = 300
MAX_BYTES = 32 * 1024 * 1024
# Only these reviewed deployer modules may be reconciled against their
# already-installed /opt/nvl-deploy copies. They are never runtime updates.
CONTROL_PLANE_PATH = re.compile(r"ops/nvl_cd_[a-z0-9_]+\.py\Z")
APPLY_UNIT_TEMPLATE = "systemd/nvl-deploy-apply.service.example"
APPLY_UNIT = Path("/etc/systemd/system/nvl-deploy-apply.service")

# Explicitly reviewed repository-only transitions from UI-02. Match both
# Git tree entries, not merely a filename. Future edits, re-additions,
# mode changes and unreviewed removals remain manual HOLD. Inventory
# entries are evaluated first and cannot be bypassed by this policy.
REVIEWED_NONRUNTIME_TRANSITIONS = {
    "cloudzy_phase8_matrix.py": (
        ("100644", "blob", "da4d245ddd7b3def54eda31a7f345524146f5f5a"),
        None,
    ),
    "ops/denaprobe_r3_stage_bot.py": (
        ("100644", "blob", "9251cbe62214539ea7dec74e6889c3d5f91cf391"),
        ("100644", "blob", "5044a4c67c27e7d6b65814c3cc1c30fa38418dad"),
    ),
}


class Hold(RuntimeError):
    pass


def exact_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Hold("INVALID_SHA")
    return value


def trusted(path, directory=False):
    if not path.is_absolute():
        raise Hold("ABSOLUTE_PATH_REQUIRED")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise Hold("UNTRUSTED_PARENT")
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022):
        raise Hold("UNTRUSTED_PATH")
    return path


def atomic_json(path, obj):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".plan-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def load_json(path):
    return json.loads(trusted(path).read_text(encoding="utf-8"))


def git(repo, *args):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
    cmd = ["git", "-c", "core.hooksPath=/dev/null",
           "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "http.sslVerify=true", "-c", "http.followRedirects=false",
           "-c", "credential.helper=", "-c", "fetch.fsckObjects=true",
           "-c", "gc.auto=0"]
    if repo is not None:
        cmd += ["--git-dir", str(repo)]
    return subprocess.check_output(cmd + list(args), env=env, cwd="/",
                                   stderr=subprocess.DEVNULL, timeout=90)


def remote_head():
    rows = git(None, "ls-remote", "--exit-code", REMOTE,
               "refs/heads/master").decode("ascii").splitlines()
    if len(rows) != 1:
        raise Hold("REMOTE_HEAD_AMBIGUOUS")
    sha, ref = rows[0].split("\t")
    if ref != "refs/heads/master":
        raise Hold("REMOTE_REF_MISMATCH")
    return exact_sha(sha)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_json(path, timeout=15):
    req = urllib.request.Request(API + path, headers={
        "User-Agent": "NVL-CD/1", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=timeout) as res:
        raw = res.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES or 'rel="next"' in res.headers.get("Link", ""):
            raise Hold("API_RESPONSE_INCOMPLETE")
        return json.loads(raw)


def select_run(data, sha):
    runs = data["workflow_runs"]
    if not isinstance(runs, list) or data["total_count"] != len(runs):
        raise Hold("RUN_LIST_INCOMPLETE")
    if not runs:
        raise Hold("CI_NOT_FOUND")
    for run in runs:
        if (run["head_sha"] != sha or run["head_branch"] != "master"
                or run["event"] != "push" or run["path"] != WORKFLOW
                or run["head_repository"]["full_name"].lower() != REPO.lower()
                or run["repository"]["full_name"].lower() != REPO.lower()):
            raise Hold("CI_RUN_IDENTITY_MISMATCH")
        if (type(run["id"]) is not int or type(run["run_attempt"]) is not int
                or run["id"] <= 0 or run["run_attempt"] <= 0):
            raise Hold("CI_RUN_ID_INVALID")
    run = max(runs, key=lambda x: (x["id"], x["run_attempt"]))
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise Hold("CI_NOT_SUCCESSFUL")
    return run


def verify_jobs(data, run):
    jobs = data["jobs"]
    if not isinstance(jobs, list) or data["total_count"] != len(jobs):
        raise Hold("JOB_LIST_INCOMPLETE")
    names = set()
    for job in jobs:
        if (job["run_id"] != run["id"] or job["head_sha"] != run["head_sha"]
                or job["run_attempt"] != run["run_attempt"]):
            raise Hold("CI_JOB_IDENTITY_MISMATCH")
        if job["name"] in names:
            raise Hold("CI_JOB_DUPLICATE")
        names.add(job["name"])
        if job["status"] != "completed" or job["conclusion"] != "success":
            raise Hold("CI_JOB_NOT_SUCCESSFUL")
    if not REQUIRED <= names:
        raise Hold("CI_REQUIRED_JOB_MISSING")


def check_gate(sha):
    query = urllib.parse.urlencode({"branch": "master", "event": "push",
                                    "head_sha": sha, "per_page": 100})
    run = select_run(api_json("/actions/workflows/python-checks.yml/runs?" + query), sha)
    verify_jobs(api_json("/actions/runs/{}/attempts/{}/jobs?per_page=100".format(
        run["id"], run["run_attempt"])), run)
    return {"run_id": run["id"], "attempt": run["run_attempt"]}


def tree(repo, sha):
    result = {}
    for record in git(repo, "ls-tree", "-rz", "--full-tree", sha).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        path = name.decode("utf-8")
        p = PurePosixPath(path)
        if (p.is_absolute() or ".." in p.parts or str(p) != path
                or path in result or any(ord(c) < 32 for c in path)):
            raise Hold("TREE_PATH_INVALID")
        result[path] = (mode, kind, exact_sha(oid))
    return result


def inventory_paths(paths):
    if not isinstance(paths, list) or not paths:
        raise Hold("INVENTORY_REQUIRED")
    valid = set()
    for name in paths:
        if not isinstance(name, str) or name in valid:
            raise Hold("INVENTORY_PATH_INVALID")
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or str(path) != name
                or not path.parts or path.suffix != ".py"
                or any(part.startswith(".") for part in path.parts)
                or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part)
                       for part in path.parts[:-1])
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.py", path.name)):
            raise Hold("INVENTORY_PATH_INVALID")
        valid.add(name)
    return valid


def nonruntime(name):
    return (
        name in {
            "README.md", "LICENSE", ".gitignore", "AGENTS.md",
            "ops/k2_release_bundle.py",
            ".github/workflows/core-auto-deploy.yml",
        }
        or name.startswith(("docs/", "tests/"))
        or components.is_edge_sync_path(name)
    )


def build_plan(old, new, inventory, live_hash, control_plane_hash=None,
               component_read=None, component_live_hash=None):
    drift, updates, manual = [], [], []
    for name in sorted(inventory):
        a, b = old.get(name), new.get(name)
        if a is None and b is not None:
            if b[:2] != ("100644", "blob"):
                manual.append(name)
                continue
            current = live_hash(name)
            if current == b[2]:
                continue
            if current != "ABSENT":
                drift.append(name)
            else:
                updates.append(name)
            continue
        if (a is None or b is None or a[:2] != ("100644", "blob")
                or b[:2] != ("100644", "blob")):
            manual.append(name)
            continue
        current = live_hash(name)
        if a == b:
            if current != a[2]:
                drift.append(name)
            continue
        # Reconcile files that were already published outside CD. A live
        # candidate hash is current, not drift and not another update.
        if current == b[2]:
            continue
        if current != a[2]:
            drift.append(name)
        else:
            updates.append(name)

    component_updates, component_drift, component_managed = [], [], set()
    if component_read is not None:
        component_plan = components.plan_updates(
            old, new, component_read, component_read,
            component_live_hash or components.live_blob,
            inventory,
        )
        component_updates = component_plan["updates"]
        component_drift = component_plan["drift"]
        component_managed = component_plan["managed"]
        drift.extend(component_drift)

    for name in sorted(old.keys() | new.keys()):
        if old.get(name) == new.get(name) or name in inventory or name in component_managed:
            continue
        if nonruntime(name):
            continue
        if REVIEWED_NONRUNTIME_TRANSITIONS.get(name) == (old.get(name), new.get(name)):
            continue
        if CONTROL_PLANE_PATH.fullmatch(name) or name == APPLY_UNIT_TEMPLATE:
            candidate = new.get(name)
            # The runner bootstraps only the trusted CD control-plane modules
            # from the exact CI-approved master commit before invoking Apply.
            if (candidate is not None and candidate[:2] == ("100644", "blob")
                    and control_plane_hash is not None
                    and control_plane_hash(name) == candidate[2]):
                continue
        manual.append(name)

    return {
        "drift": sorted(set(drift)),
        "updates": updates,
        "component_updates": component_updates,
        "component_drift": component_drift,
        "components": component_plan["components"] if component_read is not None else [],
        "component_post_actions": component_plan["post_components"] if component_read is not None else [],
        "component_post_sources": component_plan["post_sources"] if component_read is not None else [],
        "manual": sorted(set(manual)),
        "restart_required": bool(updates),
        "status": "HOLD" if drift or manual else "PLAN_READY",
    }


def live_blob(runtime, name):
    path = runtime / name
    try:
        trusted(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                return None
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) > MAX_BYTES or len(raw) != before.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or path.lstat().st_ino != after.st_ino):
            return None
        return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    except FileNotFoundError:
        # Only a genuinely absent entry can be admitted as a new file.
        return "ABSENT" if not os.path.lexists(path) else None
    except (OSError, Hold):
        return None


def apply_unit_blob():
    """Accept only the exact manually installed, reloaded apply unit."""
    oid = live_blob(APPLY_UNIT.parent, APPLY_UNIT.name)
    if oid in (None, "ABSENT"):
        return None
    expected = {"FragmentPath": str(APPLY_UNIT), "DropInPaths": "",
                "NeedDaemonReload": "no", "ProtectHome": "no",
                "ProtectSystem": "strict", "PrivateTmp": "yes",
                "NoNewPrivileges": "yes"}
    try:
        raw = subprocess.check_output(
            ["/usr/bin/systemctl", "show", APPLY_UNIT.name,
             *["-p" + key for key in expected], "-pReadWritePaths"],
            text=True, stderr=subprocess.DEVNULL, timeout=10)
        status = dict(line.split("=", 1) for line in raw.splitlines())
        if any(status.get(key) != value for key, value in expected.items()):
            return None
        if set(status.get("ReadWritePaths", "").split()) != {
                "/root", "/var/lib/nvl-deploy", "/var/backups/nvl",
                "/opt/nvl-network-alerts", "/etc/systemd/system"}:
            return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    # Re-read the fragment to reject a change during inspection.
    return oid if live_blob(APPLY_UNIT.parent, APPLY_UNIT.name) == oid else None


def control_plane_blob(name):
    """Reconcile installed deployer modules and one explicit apply unit."""
    if name == APPLY_UNIT_TEMPLATE:
        return apply_unit_blob()
    if not isinstance(name, str) or not CONTROL_PLANE_PATH.fullmatch(name):
        return None
    return live_blob(Path("/opt/nvl-deploy"), PurePosixPath(name).name)


def poll(config, state, now=time.time):
    baseline = exact_sha(config["baseline"])
    checkpoint = state / "release-state.json"
    if checkpoint.exists():
        saved = load_json(checkpoint)
        if saved["phase"] not in ("COMMITTED", "ROLLED_BACK"):
            raise Hold("RELEASE_RECOVERY_REQUIRED")
        baseline = exact_sha(saved["deployed"])
    inventory = inventory_paths(config["inventory"])
    repo = trusted(state / "repository.git", directory=True)
    runtime = trusted(Path("/root"), directory=True)
    candidate = remote_head()
    if candidate == baseline:
        old = tree(repo, baseline)
        reader = lambda oid: git(repo, "cat-file", "blob", oid)
        inventory = inventory_paths(sorted(components.effective_inventory(old, old, inventory, reader)))
        plan = build_plan(
            old, old, inventory, lambda n: live_blob(runtime, n),
            control_plane_blob, reader, components.live_blob,
        )
        if plan["status"] == "PLAN_READY":
            plan["status"] = "NO_NEW_COMMIT"
        return dict(plan, baseline=baseline, candidate=candidate)
    cooldown = state / "api-cooldown.json"
    current = int(now())
    if cooldown.exists():
        last = load_json(cooldown)["last"]
        if type(last) is not int or current - last < API_INTERVAL:
            return {"status": "API_BACKOFF", "candidate": candidate}
    atomic_json(cooldown, {"last": current})
    proof = check_gate(candidate)
    git(repo, "fetch", "--no-tags", "--no-recurse-submodules", REMOTE,
        "+refs/heads/master:refs/nvl/master")
    fetched = exact_sha(git(repo, "rev-parse", "refs/nvl/master").decode().strip())
    if fetched != candidate or remote_head() != candidate:
        raise Hold("MASTER_MOVED")
    git(repo, "merge-base", "--is-ancestor", baseline, candidate)
    old, new = tree(repo, baseline), tree(repo, candidate)
    reader = lambda oid: git(repo, "cat-file", "blob", oid)
    inventory = inventory_paths(sorted(components.effective_inventory(old, new, inventory, reader)))
    plan = build_plan(
        old, new, inventory, lambda n: live_blob(runtime, n),
        control_plane_blob, reader, components.live_blob,
    )
    return dict(plan, baseline=baseline, candidate=candidate, ci=proof)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/nvl-deploy/config.json"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/nvl-deploy"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        state = trusted(args.state, directory=True)
        config = load_json(args.config)
        if set(config) != {"baseline", "inventory"}:
            raise Hold("CONFIG_SCOPE_INVALID")
        fd = os.open(state / "poll.lock", os.O_CREAT | os.O_RDWR |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise Hold("LOCK_UNTRUSTED")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print('{"status":"POLL_BUSY","apply_enabled":false}')
                return 0
            try:
                result = poll(config, state)
            except Hold as exc:
                result = {"status": "HOLD", "reason": str(exc)}
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                result = {"status": "HOLD", "reason": "PROBE_FAILED"}
            result.update(mode="DRY_RUN", apply_enabled=False, observed_at=int(time.time()))
            atomic_json(state / "latest-plan.json", result)
            print(json.dumps(result, sort_keys=True))
            return 0
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print('{"status":"HOLD","reason":"LOCAL_CONFIGURATION_ERROR","apply_enabled":false}')
        return 2


if __name__ == "__main__":
    sys.exit(main())
