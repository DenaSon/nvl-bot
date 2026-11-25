"""Core component catalog and transactional publisher for NVL CD-07.

The catalog discovers Python dependencies from trusted service entrypoints.
It does not execute candidate source while planning. Only the Core bot,
Network Alerts, and the two independent AWG Core services are managed here.
Edge Sync is deliberately outside this deployer.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time


COMPONENT_ENTRYPOINTS = {
    "network-alerts": ("ops/nvl_network_live_alerts.py",),
    "awg-core-routes": ("nvl_awg_core_routes.py",),
    "awg-witness-refresh": ("nvl_awg_witness_refresh.py",),
}

FIXED_TARGETS = {
    "systemd/nvl-network-sampler.timer.d/90-nvl-cadence.conf.example":
        ("/etc/systemd/system/nvl-network-sampler.timer.d/90-nvl-cadence.conf",
         "network-alerts", 0o644),
    "systemd/nvl-network-alerts.timer.d/90-nvl-cadence.conf.example":
        ("/etc/systemd/system/nvl-network-alerts.timer.d/90-nvl-cadence.conf",
         "network-alerts", 0o644),
    "systemd/nvl-network-alerts.service.example":
        ("/etc/systemd/system/nvl-network-alerts.service",
         "network-alerts", 0o644),
    "systemd/nvl-network-alerts.timer.example":
        ("/etc/systemd/system/nvl-network-alerts.timer",
         "network-alerts", 0o644),
    "nvl-awg-core-routes.service":
        ("/etc/systemd/system/nvl-awg-core-routes.service",
         "awg-core-routes", 0o644),
    "nvl-awg-witness-refresh.service":
        ("/etc/systemd/system/nvl-awg-witness-refresh.service",
         "awg-witness-refresh", 0o644),
    "nvl-awg-witness-refresh.timer":
        ("/etc/systemd/system/nvl-awg-witness-refresh.timer",
         "awg-witness-refresh", 0o644),
}

EDGE_SYNC_RE = re.compile(
    r"(^|/)(?:edge[_-]sync|nvl[_-]edge[_-]sync)(?:/|\.|$)", re.I
)
MAX_FILE_BYTES = 32 * 1024 * 1024
ABSENT = "ABSENT"


class ComponentApplyError(RuntimeError):
    def __init__(self, reason: str, rolled_back: bool):
        super().__init__(reason)
        self.reason = reason
        self.rolled_back = rolled_back


def is_edge_sync_path(name: str) -> bool:
    return bool(EDGE_SYNC_RE.search(name))


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def _valid_python_tree(tree):
    return {
        name: entry[2]
        for name, entry in tree.items()
        if name.endswith(".py") and entry[:2] == ("100644", "blob")
    }


def static_imports(source: bytes, filename: str, tracked: set[str]) -> set[str]:
    """Resolve literal Python imports without importing or executing code."""
    try:
        syntax = ast.parse(source, filename=filename)
    except (SyntaxError, UnicodeError) as exc:
        raise ValueError("COMPONENT_SOURCE_SYNTAX_INVALID") from exc

    package = filename.split("/")[:-1]
    found = set()

    def add(parts):
        if not parts:
            return
        prefix = "/".join(parts)
        for candidate in (prefix + ".py", prefix + "/__init__.py"):
            if candidate in tracked:
                found.add(candidate)

    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > len(package):
                    continue
                base = package[:len(package) - node.level + 1]
            else:
                base = []
            parts = base + (node.module.split(".") if node.module else [])
            add(parts)
            for alias in node.names:
                if alias.name != "*":
                    add(parts + alias.name.split("."))
        elif isinstance(node, ast.Call):
            fn = node.func
            literal_import = (
                isinstance(fn, ast.Name) and fn.id in ("__import__", "import_module")
            ) or (
                isinstance(fn, ast.Attribute) and fn.attr == "import_module"
            )
            if literal_import and node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str) and not value.startswith("."):
                    add(value.split("."))
    return found


def dependency_closure(entrypoints, tree, read_blob) -> set[str]:
    tracked = set(_valid_python_tree(tree))
    found, pending = set(), list(entrypoints)
    while pending:
        name = pending.pop()
        if name in found or name not in tracked:
            continue
        found.add(name)
        entry = tree[name]
        raw = read_blob(entry[2])
        if not isinstance(raw, bytes) or len(raw) > MAX_FILE_BYTES:
            raise ValueError("COMPONENT_SOURCE_INVALID")
        pending.extend(static_imports(raw, name, tracked) - found)
    return found


def component_targets(tree, read_blob) -> dict[tuple[str, str], dict]:
    """Map source blobs to fixed, reviewed Core runtime destinations."""
    result = {}
    for component, entrypoints in COMPONENT_ENTRYPOINTS.items():
        for source in sorted(dependency_closure(entrypoints, tree, read_blob)):
            if component == "network-alerts":
                destination = "/opt/nvl-network-alerts/" + PurePosixPath(source).name
                mode = 0o700
            else:
                destination = str(Path("/root") / source)
                mode = 0o700
            key = (source, destination)
            item = result.setdefault(key, {
                "source": source, "destination": destination,
                "components": set(), "mode": mode,
            })
            item["components"].add(component)

    for source, (destination, component, mode) in FIXED_TARGETS.items():
        if source not in tree:
            continue
        key = (source, destination)
        item = result.setdefault(key, {
            "source": source, "destination": destination,
            "components": set(), "mode": mode,
        })
        item["components"].add(component)
        item["mode"] = mode

    for item in result.values():
        item["components"] = sorted(item["components"])
    return result


def plan_updates(old_tree, new_tree, read_old, read_new, live_hash):
    old_targets = component_targets(old_tree, read_old)
    new_targets = component_targets(new_tree, read_new)
    keys = old_targets.keys() | new_targets.keys()
    updates, drift, managed = [], [], set()

    for key in sorted(keys):
        old_item = old_targets.get(key)
        new_item = new_targets.get(key)
        item = new_item or old_item
        source, destination = key
        managed.add(source)
        old_entry = old_tree.get(source)
        new_entry = new_tree.get(source)

        if old_entry is not None and old_entry[:2] != ("100644", "blob"):
            drift.append(source)
            continue
        if new_entry is not None and new_entry[:2] != ("100644", "blob"):
            drift.append(source)
            continue

        old_oid = old_entry[2] if old_entry else ABSENT
        new_oid = new_entry[2] if new_entry else ABSENT
        current = live_hash(destination)

        if old_oid == new_oid:
            if current != old_oid:
                drift.append(source)
            continue

        if current == new_oid:
            # A previously manual/partial deployment already matches this SHA.
            continue
        if current != old_oid:
            drift.append(source)
            continue

        components = sorted(
            set((old_item or {}).get("components", []))
            | set((new_item or {}).get("components", []))
        )
        updates.append({
            "source": source,
            "destination": destination,
            "components": components,
            "old_oid": old_oid,
            "new_oid": new_oid,
            "mode": (new_item or old_item)["mode"],
            "action": "delete" if new_oid == ABSENT else "write",
        })

    return {
        "updates": updates,
        "drift": sorted(set(drift)),
        "managed": managed,
    }


def _trusted_directory(path: Path):
    if not path.is_absolute():
        raise ComponentApplyError("COMPONENT_PATH_INVALID", False)
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise ComponentApplyError("COMPONENT_PARENT_UNTRUSTED", False)


def live_blob(destination: str) -> str | None:
    path = Path(destination)
    try:
        _trusted_directory(path)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            return None
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            return None
        return git_blob(raw)
    except FileNotFoundError:
        return ABSENT if not os.path.lexists(path) else None
    except OSError:
        return None


def _ensure_parent(parent: Path):
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    _trusted_directory(parent)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise ComponentApplyError("COMPONENT_PARENT_UNTRUSTED", False)


def _sync_dir(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, raw: bytes, mode: int):
    _ensure_parent(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=".nvl-component-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        _sync_dir(path.parent)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _run(args, timeout=60):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ComponentApplyError("COMPONENT_COMMAND_FAILED", False) from exc
    if result.returncode != 0:
        raise ComponentApplyError("COMPONENT_COMMAND_FAILED", False)
    return result.stdout.strip()


def _systemd_props(unit):
    raw = _run([
        "/usr/bin/systemctl", "show", unit,
        "-p", "Result", "-p", "ExecMainStatus",
    ])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def _health(component, changed):
    names = {item["source"] for item in changed}
    if component == "network-alerts":
        systemd_changed = any(
            name.startswith("systemd/nvl-network-") for name in names
        )
        timer_changed = any(".timer" in name for name in names)
        if systemd_changed:
            _run(["/usr/bin/systemctl", "daemon-reload"])
        if timer_changed:
            _run(["/usr/bin/systemctl", "restart",
                  "nvl-network-sampler.timer", "nvl-network-alerts.timer"])
        for unit in ("nvl-network-sampler.timer", "nvl-network-alerts.timer"):
            _run(["/usr/bin/systemctl", "is-active", "--quiet", unit])
        status = _run([
            "/usr/bin/python3", "-B",
            "/opt/nvl-network-alerts/nvl_network_live_alerts.py", "status",
        ])
        data = json.loads(status)
        if data.get("baseline_quality") != "NORMAL_VERIFIED":
            raise ComponentApplyError("NETWORK_ALERTS_BASELINE_UNHEALTHY", False)

    elif component == "awg-core-routes":
        if any(name == "nvl-awg-core-routes.service" for name in names):
            _run(["/usr/bin/systemctl", "daemon-reload"])
        if any(name.endswith(".py") or name == "nvl-awg-core-routes.service"
               for name in names):
            _run(["/usr/bin/systemctl", "restart", "nvl-awg-core-routes.service"])
            props = _systemd_props("nvl-awg-core-routes.service")
            if props.get("Result") != "success" or props.get("ExecMainStatus") != "0":
                raise ComponentApplyError("AWG_CORE_ROUTES_UNHEALTHY", False)

    elif component == "awg-witness-refresh":
        unit_changed = any(
            name in ("nvl-awg-witness-refresh.service",
                     "nvl-awg-witness-refresh.timer") for name in names
        )
        if unit_changed:
            _run(["/usr/bin/systemctl", "daemon-reload"])
        if unit_changed or any(name.endswith(".py") for name in names):
            _run(["/usr/bin/systemctl", "is-active", "--quiet",
                  "nvl-awg-witness-refresh.timer"])
            if unit_changed:
                _run(["/usr/bin/systemctl", "restart",
                      "nvl-awg-witness-refresh.timer"])
        _run(["/usr/bin/systemctl", "is-active", "--quiet",
              "nvl-awg-witness-refresh.timer"])


def _manifest_write(path: Path, data):
    _ensure_parent(path.parent)
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    _atomic_write(path, raw, 0o600)


def apply_updates(repo, updates, candidate, read_blob, backup_root=Path("/var/backups/nvl")):
    """Apply independent component files with per-release backup and rollback."""
    if not updates:
        return {"updated": 0, "components": [], "backup": None}

    candidate = str(candidate)
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ComponentApplyError("COMPONENT_SHA_INVALID", False)

    components = sorted({name for item in updates for name in item["components"]})
    backup = backup_root / ("components-" + candidate)
    _ensure_parent(backup_root)
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    _trusted_directory(backup)
    before = backup / "before"
    before.mkdir(mode=0o700, exist_ok=True)
    _trusted_directory(before)

    changed, saved = [], {}
    try:
        for index, item in enumerate(updates):
            destination = Path(item["destination"])
            current = live_blob(item["destination"])
            if current == item["new_oid"]:
                continue
            if current != item["old_oid"]:
                raise ComponentApplyError("COMPONENT_RUNTIME_DRIFT", False)

            old_raw = None
            old_mode = None
            if current != ABSENT:
                _trusted_directory(destination)
                old_raw = destination.read_bytes()
                old_mode = stat.S_IMODE(destination.stat().st_mode)
                saved[item["destination"]] = {
                    "raw": old_raw, "mode": old_mode,
                }
                backup_file = before / (str(index) + ".bin")
                _atomic_write(backup_file, old_raw, 0o600)

            new_raw = None
            if item["new_oid"] != ABSENT:
                new_raw = read_blob(item["new_oid"])
                if (not isinstance(new_raw, bytes) or len(new_raw) > MAX_FILE_BYTES
                        or git_blob(new_raw) != item["new_oid"]):
                    raise ComponentApplyError("COMPONENT_BLOB_MISMATCH", False)
                if item["source"].endswith(".py"):
                    try:
                        compile(new_raw, item["source"], "exec")
                    except (SyntaxError, ValueError) as exc:
                        raise ComponentApplyError("COMPONENT_PYTHON_SYNTAX", False) from exc
                mode = old_mode if old_mode is not None else item["mode"]
                _atomic_write(destination, new_raw, mode)
            else:
                destination.unlink()
                _sync_dir(destination.parent)

            if live_blob(item["destination"]) != item["new_oid"]:
                raise ComponentApplyError("COMPONENT_PUBLISH_HASH_FAILED", False)
            changed.append(item)

        _manifest_write(backup / "manifest.json", {
            "candidate": candidate,
            "components": components,
            "files": [{
                "source": item["source"],
                "destination": item["destination"],
                "old_oid": item["old_oid"],
                "new_oid": item["new_oid"],
                "components": item["components"],
            } for item in changed],
        })

        for component in components:
            selected = [item for item in changed if component in item["components"]]
            if selected:
                _health(component, selected)

        return {
            "updated": len(changed),
            "components": components,
            "backup": str(backup),
        }

    except Exception as exc:
        rollback_ok = True
        for item in reversed(changed):
            destination = Path(item["destination"])
            previous = saved.get(item["destination"])
            try:
                if previous is None:
                    if os.path.lexists(destination):
                        destination.unlink()
                        _sync_dir(destination.parent)
                else:
                    _atomic_write(destination, previous["raw"], previous["mode"])
                if live_blob(item["destination"]) != item["old_oid"]:
                    rollback_ok = False
            except Exception:
                rollback_ok = False

        if rollback_ok:
            for component in components:
                selected = [item for item in changed if component in item["components"]]
                if selected:
                    try:
                        _health(component, selected)
                    except Exception:
                        rollback_ok = False
        reason = (exc.reason if isinstance(exc, ComponentApplyError)
                  else "COMPONENT_APPLY_FAILED")
        raise ComponentApplyError(
            reason if rollback_ok else "COMPONENT_ROLLBACK_FAILED",
            rollback_ok,
        ) from exc
