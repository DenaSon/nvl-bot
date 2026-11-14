"""AWG-04: independent root-only runtime limiter witness for guarded cutover.

Source-only tool: never installs/restarts a service, changes firewall/NAT, or
writes the database. A root-owned systemd timer (operator opt-in) may renew one
short-lived /32 marker only while every production check stays green.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from nvl_tunnel_backend import lookup_binding, probe_binding


class LimiterWitnessHold(RuntimeError):
    pass


MARKER = Path("/run/nvl-awg-limiter-ready")
LIMITER = Path("/root/ip_limiter.py")
PROMOTER = Path("/root/promote_edge_to_core.sh")
DB = Path("/root/master_bot.db")
SERVICE = "ssh-limiter.service"
PAYLOAD_START = "cat << 'EOF' > /root/ip_limiter.py\n"


def _run(args, *, timeout=8):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 or len(result.stdout) > 131072:
        raise LimiterWitnessHold("RUNTIME_COMMAND_UNVERIFIED")
    return result.stdout.strip()


def _trusted_file(path):
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise LimiterWitnessHold("RUNTIME_FILE_UNTRUSTED")
        return path.read_bytes(), st
    except OSError as exc:
        raise LimiterWitnessHold("RUNTIME_FILE_UNAVAILABLE") from exc


def _approved_source(limiter=LIMITER, promoter=PROMOTER):
    """Require exact installed bytes from the separately reviewed promoter."""
    actual, st = _trusted_file(limiter)
    generated, _ = _trusted_file(promoter)
    try:
        payload = generated.decode("utf-8").split(PAYLOAD_START, 1)[1]
        payload = payload.split("\nEOF\n", 1)[0] + "\n"
    except (IndexError, UnicodeError) as exc:
        raise LimiterWitnessHold("PROMOTER_LIMITER_TEMPLATE_MISSING") from exc
    if hashlib.sha256(actual).digest() != hashlib.sha256(
            payload.encode("utf-8")).digest():
        raise LimiterWitnessHold("RUNNING_LIMITER_SOURCE_MISMATCH")
    return st


def _pid_started_at(pid):
    """Unix process start from Linux procfs, not its mutable directory mtime."""
    raw = Path(f"/proc/{pid}/stat").read_text()
    suffix = raw[raw.rfind(")") + 2:].split()
    ticks = int(suffix[19])  # field 22, suffix begins with field 3
    boot = next(int(line.split()[1]) for line in
                Path("/proc/stat").read_text().splitlines()
                if line.startswith("btime "))
    return boot + ticks / os.sysconf("SC_CLK_TCK")


def _live_service_matches_script(st, *, limiter=LIMITER):
    props = dict(
        line.split("=", 1) for line in
        _run(["systemctl", "show", SERVICE, "--property=ActiveState",
              "--property=MainPID"]).splitlines()
        if "=" in line
    )
    if props.get("ActiveState") != "active":
        raise LimiterWitnessHold("LIMITER_SERVICE_NOT_ACTIVE")
    try:
        pid = int(props["MainPID"])
        if pid <= 1:
            raise ValueError("invalid PID")
        proc = Path(f"/proc/{pid}")
        if proc.stat().st_uid != 0:
            raise LimiterWitnessHold("LIMITER_PROCESS_NOT_ROOT")
        cmd = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        if cmd != [b"/usr/bin/python3", os.fsencode(str(limiter))]:
            raise LimiterWitnessHold("LIMITER_PROCESS_IMAGE_MISMATCH")
        if _pid_started_at(pid) + 1 < st.st_mtime:
            raise LimiterWitnessHold("LIMITER_SOURCE_CHANGED_AFTER_START")
    except (KeyError, ValueError, OSError) as exc:
        raise LimiterWitnessHold("LIMITER_PROCESS_UNVERIFIED") from exc


def _functional_test(ip, *, limiter=LIMITER):
    """Load the exact approved limiter in a short-lived isolated interpreter.

    Its real shared-IP classifier must exempt the registered /32, while a
    negative public-IP control must not be exempt. Intercept any attempted
    ipset add during apply_cooldown; no customer connection is affected.
    """
    program = (
        "import importlib.util,sys\n"
        "sys.path.insert(0,'/root')\n"
        "spec=importlib.util.spec_from_file_location('nvl_ip_limiter_probe',sys.argv[1])\n"
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
        "assert m.is_shared_edge_ip(sys.argv[2]), 'EDGE_NOT_EXEMPT'\n"
        "assert not m.is_shared_edge_ip('198.51.100.42'), 'PUBLIC_FALSE_POSITIVE'\n"
        "def forbidden(*a,**kw): raise AssertionError('IPSET_WRITE_ATTEMPT')\n"
        "m.subprocess.run=forbidden\n"
        "m.apply_cooldown(sys.argv[2])\n"
        "print('SHARED_IP_BEHAVIOR=PASS')\n"
    )
    return _run(["/usr/bin/python3", "-I", "-c", program,
                 str(limiter), ip], timeout=15) == "SHARED_IP_BEHAVIOR=PASS"


def _unblocked(ip):
    """Do not attest a source currently present in the SSH penalty ipset."""
    result = subprocess.run(
        ["ipset", "test", "ssh_penalty", ip],
        capture_output=True, text=True, timeout=5,
    )
    msg = result.stdout + result.stderr
    return result.returncode == 1 and "is NOT in set" in msg


def _registered_binding(host, db=DB):
    host = str(ipaddress.IPv4Address(host))
    if not db.is_file() or db.is_symlink():
        raise LimiterWitnessHold("CORE_DB_MISSING")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
    try:
        binding = lookup_binding(con, host)
        if binding is None or binding.backend != "amneziawg" or binding.interface != "awg0":
            raise LimiterWitnessHold("AWG_TARGET_BINDING_NOT_VERIFIED")
        row = con.execute(
            "SELECT m.status,h.active,h.is_default,h.is_standby "
            "FROM manual_edge_operations m JOIN host_pool h ON h.host=m.ip "
            "WHERE m.ip=? AND m.tunnel_backend='amneziawg'", (host,)
        ).fetchall()
        if len(row) != 1 or row[0] not in (
                ("STANDBY", 1, 0, 1),
                ("ROUTING", 1, 0, 1),
                ("ACTIVE", 1, 1, 0),
        ):
            raise LimiterWitnessHold("AWG_TARGET_NOT_IN_MANAGED_LIFECYCLE")
        return binding
    finally:
        con.close()


def _write_marker(source, path=MARKER):
    # Create privately within /run, then replace atomically. Never follow
    # any old marker symlink. Readers reject anything not root:0600.
    fd, tmp = tempfile.mkstemp(prefix=".nvl-awg-witness-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(f"NVL_AWG_LIMITER_READY {source}\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def attest(host, *, marker=MARKER):
    if os.geteuid() != 0:
        raise LimiterWitnessHold("ROOT_REQUIRED")
    # An unavailable witness must never leave a previous permission active.
    # A newer independent run may re-attest after the failure is resolved.
    if os.path.lexists(marker):
        marker.unlink()
    binding = _registered_binding(host)
    proof = probe_binding(binding)
    if proof.get("wg_peer_ok") is not True or proof.get("core_path_ok") is not True:
        raise LimiterWitnessHold("CORE_AWG_PATH_UNVERIFIED")
    st = _approved_source()
    _live_service_matches_script(st)
    if not _functional_test(binding.edge_tunnel_ip):
        raise LimiterWitnessHold("LIMITER_BEHAVIOR_UNVERIFIED")
    if not _unblocked(binding.edge_tunnel_ip):
        raise LimiterWitnessHold("EDGE_SOURCE_ALREADY_BANNED")
    _write_marker(binding.edge_tunnel_ip, marker)
    return binding.edge_tunnel_ip


def main():
    parser = argparse.ArgumentParser(description="AWG Core SSH limiter witness; read-only prechecks")
    parser.add_argument("--host", required=True, help="registered AWG Edge public IPv4")
    args = parser.parse_args()
    try:
        source = attest(args.host)
    except Exception as exc:
        code = str(exc) if isinstance(exc, LimiterWitnessHold) else "WITNESS_UNVERIFIED"
        print("AWG_LIMITER_WITNESS=HOLD " + code, file=sys.stderr)
        return 2
    print("AWG_LIMITER_WITNESS=READY " + source)
    return 0


if __name__ == "__main__":
    sys.exit(main())
