#!/usr/bin/env python3
"""D1-D2D: explicit stg1 SSH canary; no customer UID routing or bot imports.

Prepare creates exactly one OS test user (password unusable), an isolated
sshd config, and new disposable keypairs. Start runs ONLY that sshd inside
the already active Core staging netns. No system sshd reload, wg0, db, routes,
iptables, 6G journal or systemd changes. Operator must separately approve
each phase. Never invoke this on Standby or outside the verified stg1 Core.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import pwd
import signal
import time
import shutil
import stat
import subprocess
import sys

NS = "nvl-egress-stg1"
USERNAME = "nvlstg1"
LISTEN_IP = "10.78.111.2"
CORE_VETH_IP = "10.78.111.1"
EXPECTED_EDGE = "216.126.229.12"
CORE_IP = "209.200.246.198"
PORT = 22282
DIR = Path("/var/lib/nvl-egress-stg1-sshd")
CLIENT_KEY = Path("/root/.ssh/nvl_stg1_canary")
CLIENT_KNOWN = Path("/root/.ssh/nvl_stg1_canary_known_hosts")
HOST_KEY = DIR / "host_ed25519"
CONFIG = DIR / "sshd_config"
PID = DIR / "sshd.pid"
PROOF = DIR / "egress-proof.sh"
AUTHORIZED = DIR / "authorized_keys"


class Unsafe(ValueError):
    pass


def cmd(*argv: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, text=True, capture_output=True,
                            timeout=12, check=False)
    if check and result.returncode:
        raise Unsafe("CHECK_FAILED:" + argv[0].rsplit("/", 1)[-1])
    return result


def is_root_owned(path: Path, mode: int) -> bool:
    if path.is_symlink() or not path.exists():
        return False
    info = path.stat()
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode


def ssh_config() -> str:
    return (
        "# D1-D2D isolated test-only sshd, never installed into /etc/ssh.\n"
        "Port 22282\n"
        "ListenAddress 10.78.111.2\n"
        "AddressFamily inet\n"
        "HostKey /var/lib/nvl-egress-stg1-sshd/host_ed25519\n"
        "PidFile /var/lib/nvl-egress-stg1-sshd/sshd.pid\n"
        "AuthorizedKeysFile /var/lib/nvl-egress-stg1-sshd/authorized_keys\n"
        "AllowUsers nvlstg1\n"
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "AuthenticationMethods publickey\n"
        "UsePAM yes\n"
        "DisableForwarding yes\n"
        "AllowTcpForwarding no\n"
        "AllowAgentForwarding no\n"
        "X11Forwarding no\n"
        "PermitTTY no\n"
        "PermitTunnel no\n"
        "PermitUserEnvironment no\n"
        "AllowUserRC no\n"
        "PermitOpen none\n"
        "AllowStreamLocalForwarding no\n"
        "ForceCommand /var/lib/nvl-egress-stg1-sshd/egress-proof.sh\n"
        "LogLevel ERROR\n"
    )


def proof_script() -> str:
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        '[ "$(id -un)" = "nvlstg1" ] || exit 70\n'
        'echo "SSH_CANARY_AUTH=PASS"\n'
        'echo "SSH_CANARY_USER=$(id -un)"\n'
        'echo "SSH_CANARY_UID=$(id -u)"\n'
        'IP="$(curl -4 --noproxy \'*\' --connect-timeout 5 --max-time 15 -fsS https://api.ipify.org)" || exit 71\n'
        'echo "SSH_CANARY_EGRESS=$IP"\n'
        '[ "$IP" = "216.126.229.12" ] || exit 72\n'
        'echo "SSH_CANARY_EGRESS=PASS"\n'
    )


def preflight() -> dict:
    """Read-only checks only; no result authorizes production UID routing."""
    issues = []
    for tool in ("/usr/sbin/sshd", "ip", "ssh-keygen", "useradd", "curl"):
        if not (Path(tool).is_file() if tool.startswith("/") else shutil.which(tool)):
            issues.append("MISSING_TOOL:" + tool)
    if os.geteuid() != 0:
        issues.append("NOT_ROOT")
    if cmd("ip", "netns", "list").stdout.splitlines() and NS not in {
        line.split()[0] for line in cmd("ip", "netns", "list").stdout.splitlines() if line.strip()
    }:
        issues.append("NAMESPACE_MISSING")
    elif NS not in {line.split()[0] for line in cmd("ip", "netns", "list").stdout.splitlines() if line.strip()}:
        issues.append("NAMESPACE_MISSING")
    for iface, expected in (("vnh-stg1", CORE_VETH_IP),):
        out = cmd("ip", "-j", "-4", "addr", "show", "dev", iface, check=False)
        if out.returncode != 0 or expected not in out.stdout:
            issues.append("CORE_STAGING_VETH_MISSING")
    nsaddr = cmd("ip", "netns", "exec", NS, "ip", "-4", "addr", "show", "dev", "vnn-stg1", check=False)
    if nsaddr.returncode != 0 or LISTEN_IP not in nsaddr.stdout:
        issues.append("NAMESPACE_VETH_MISSING")
    nsif = cmd("ip", "netns", "exec", NS, "wg", "show", "interfaces", check=False)
    if nsif.returncode != 0 or "wg-nvl-stg1" not in nsif.stdout.split():
        issues.append("ISOLATED_WG_MISSING")
    hostroute = cmd("ip", "-4", "route", "get", EXPECTED_EDGE, check=False)
    if hostroute.returncode != 0 or CORE_IP not in hostroute.stdout or " dev eth0 " not in hostroute.stdout:
        issues.append("CORE_PUBLIC_ROUTE_CHANGED")
    if cmd("systemctl", "is-active", "nvlbot", check=False).stdout.strip() != "active":
        issues.append("PRODUCTION_BOT_INACTIVE")
    if cmd("systemctl", "is-active", "ssh", check=False).stdout.strip() != "active":
        issues.append("PRODUCTION_SSH_INACTIVE")
    if cmd("ip", "netns", "exec", NS, "ss", "-H", "-ltn", check=False).stdout.find(":" + str(PORT) + " ") != -1:
        issues.append("SSH_TEST_PORT_BUSY")
    return {"mode": "READ_ONLY", "issues": sorted(set(issues)),
            "stg1_namespace_present": "NAMESPACE_MISSING" not in issues,
            "activation_authorized": False}


def _create_file(path: Path, content: str, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def prepare() -> None:
    check = preflight()
    if check["issues"]:
        raise Unsafe("PREFLIGHT_BLOCKED:" + ",".join(check["issues"]))
    for p in (DIR, CLIENT_KEY, Path(str(CLIENT_KEY) + ".pub"), CLIENT_KNOWN):
        if p.exists() or p.is_symlink():
            raise Unsafe("STAGING_ASSET_ALREADY_EXISTS:" + p.name)
    try:
        pwd.getpwnam(USERNAME)
    except KeyError:
        pass
    else:
        raise Unsafe("STAGING_ACCOUNT_ALREADY_EXISTS")
    if cmd("getent", "group", USERNAME, check=False).returncode == 0:
        raise Unsafe("STAGING_GROUP_ALREADY_EXISTS")
    if not is_root_owned(Path("/root/.ssh"), 0o700):
        raise Unsafe("ROOT_SSH_DIR_NOT_OWNED_700")

    # One host-global NSS addition: a password-disabled system user with
    # no writable home or sudo; default production sshd sees no public key.
    cmd("useradd", "--system", "--user-group", "--no-create-home",
        "--home-dir", "/nonexistent", "--shell", "/bin/sh", "-p", "*", USERNAME)
    DIR.mkdir(mode=0o755)
    # Explicit chmod: the root shell uses umask 077, which masks mkdir 0755
    # down to 0700, preventing sshd from reading the dedicated user key.
    DIR.chmod(0o755)
    _create_file(CONFIG, ssh_config(), 0o600)
    _create_file(PROOF, proof_script(), 0o755)
    cmd("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(HOST_KEY))
    cmd("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(CLIENT_KEY))
    os.chmod(HOST_KEY, 0o600)
    os.chmod(CLIENT_KEY, 0o600)
    pub = Path(str(CLIENT_KEY) + ".pub").read_text().strip()
    pieces = pub.split()
    if len(pieces) < 2 or pieces[0] != "ssh-ed25519":
        raise Unsafe("INVALID_CANARY_PUBLIC_KEY")
    _create_file(AUTHORIZED,
        f'from="{CORE_VETH_IP}",restrict ' + pieces[0] + " " + pieces[1] + "\n", 0o644)
    hostpub = Path(str(HOST_KEY) + ".pub").read_text().split()
    _create_file(CLIENT_KNOWN, f"[{LISTEN_IP}]:{PORT} {hostpub[0]} {hostpub[1]}\n", 0o600)
    cmd("/usr/sbin/sshd", "-t", "-f", str(CONFIG))
    print("SSH_CANARY_PREPARED_ONLY")
    print("CANARY_USER=" + USERNAME)
    print("SSH_LISTEN_IP=" + LISTEN_IP)
    print("SSH_PORT=" + str(PORT))
    print("NO_NETWORK_OR_SSH_SERVICE_CHANGES")


def assert_prepared() -> None:
    for file, mode in ((CONFIG, 0o600), (HOST_KEY, 0o600),
                       (PROOF, 0o755), (AUTHORIZED, 0o644),
                       (CLIENT_KEY, 0o600), (CLIENT_KNOWN, 0o600)):
        if not is_root_owned(file, mode):
            raise Unsafe("CANARY_OWNERSHIP_OR_MODE_BAD:" + file.name)
    if not is_root_owned(DIR, 0o755):
        raise Unsafe("CANARY_DIR_OWNERSHIP_OR_MODE_BAD")
    if CONFIG.read_text() != ssh_config() or PROOF.read_text() != proof_script():
        raise Unsafe("CANARY_CONFIG_CHANGED")
    acct = pwd.getpwnam(USERNAME)
    if acct.pw_dir != "/nonexistent" or acct.pw_shell != "/bin/sh" or acct.pw_uid == 0:
        raise Unsafe("CANARY_USER_IDENTITY_CHANGED")


def start() -> None:
    assert_prepared()
    check = preflight()
    if check["issues"]:
        raise Unsafe("START_BLOCKED:" + ",".join(check["issues"]))
    if PID.exists() or PID.is_symlink():
        raise Unsafe("CANARY_PIDFILE_ALREADY_EXISTS")
    cmd("/usr/sbin/sshd", "-t", "-f", str(CONFIG))
    # Process inherits only the existing Staging netns, not root namespace.
    cmd("ip", "netns", "exec", NS, "/usr/sbin/sshd", "-f", str(CONFIG), "-E", str(DIR / "sshd.log"))
    print("SSH_CANARY_STARTED")
    print("TEST_SSH_LISTEN=" + LISTEN_IP + ":" + str(PORT))
    print("PRODUCTION_SSH_SERVICE_UNTOUCHED")


def probe() -> None:
    assert_prepared()
    if not PID.is_file() or PID.is_symlink():
        raise Unsafe("CANARY_NOT_RUNNING")
    ssh = ("ssh", "-T", "-p", str(PORT), "-i", str(CLIENT_KEY),
           "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=" + str(CLIENT_KNOWN),
           "-o", "ConnectTimeout=6", USERNAME + "@" + LISTEN_IP)
    result = subprocess.run(ssh + ("ignored-by-forced-command",),
                            capture_output=True, text=True, timeout=27)
    if result.returncode != 0:
        # Do not print unexpected server data/logs, secrets or untrusted output.
        raise Unsafe("SSH_CANARY_AUTH_OR_EGRESS_FAILED")
    values = result.stdout.splitlines()
    if ("SSH_CANARY_AUTH=PASS" not in values or
        "SSH_CANARY_EGRESS=" + EXPECTED_EDGE not in values or
        "SSH_CANARY_EGRESS=PASS" not in values):
        raise Unsafe("SSH_CANARY_OUTPUT_INVALID")
    print("SSH_CANARY_AUTH=PASS")
    print("SSH_CANARY_EGRESS_IP=" + EXPECTED_EDGE)
    print("SSH_CANARY_PROOF=PASS_NOT_UID_POLICY")


def stop() -> None:
    """Stop ONLY the uniquely identified stg1 sshd within the existing netns.

    Do not stop system sshd, kill-by-name, or delete NSS/users/other resources.
    If exact identity cannot be established, hold for operator reconciliation.
    """
    assert_prepared()
    if PID.is_symlink():
        raise Unsafe("UNSAFE_CANARY_PID_SYMLINK")
    if not PID.exists():
        print("SSH_CANARY_ALREADY_STOPPED")
        return
    s = PID.stat()
    if not PID.is_file() or s.st_uid != 0 or s.st_mode & 0o022:
        raise Unsafe("UNSAFE_CANARY_PID_OWNERSHIP")
    raw = PID.read_text().strip()
    if not raw.isdecimal() or not (2 <= int(raw) < 1_000_000_000):
        raise Unsafe("INVALID_CANARY_PID")
    pid = int(raw)
    process = Path("/proc") / str(pid)
    if not process.exists():
        raise Unsafe("STALE_CANARY_PID_REQUIRES_REVIEW")
    try:
        argv = (process / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
            "utf-8", "replace"
        )
        netns_inode = (process / "ns/net").stat().st_ino
        expected_inode = (Path("/run/netns") / NS).stat().st_ino
    except OSError as exc:
        raise Unsafe("CANARY_PROCESS_IDENTITY_UNAVAILABLE") from exc
    if "sshd" not in argv or str(CONFIG) not in argv or netns_inode != expected_inode:
        raise Unsafe("CANARY_PROCESS_IDENTITY_MISMATCH")
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        if not process.exists():
            break
        time.sleep(0.1)
    else:
        raise Unsafe("CANARY_STOP_UNCERTAIN")
    if PID.exists() and not PID.is_symlink():
        PID.unlink()
    print("SSH_CANARY_STOPPED_SCOPE_ONLY")
    print("PRODUCTION_SSH_SERVICE_UNTOUCHED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "prepare", "start", "probe", "stop"))
    args = parser.parse_args()
    try:
        if args.action == "preflight":
            result = preflight()
            print(result)
            return 0 if not result["issues"] else 3
        if args.action == "prepare":
            prepare()
        elif args.action == "start":
            start()
        elif args.action == "stop":
            stop()
        else:
            probe()
    except (Unsafe, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if isinstance(exc, Unsafe) else type(exc).__name__
        print("STOP:" + reason[:200], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
