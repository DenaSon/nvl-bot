"""Phase 2 safe Edge retirement: guarded metadata-only delete, never kernel cleanup.

Runtime transport, attached UID, staged material or wg0 peer => HOLD. The
Phase-3 guarded executor must detach those resources before this can run.
No remote VPS, DNS, wg0, IP rules, firewall or SSH accounts are mutated here.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from typing import Callable

from edge_egress_v1_ingress import REGISTRY, load_registry, render_registry
from edge_egress_v1_console import edge_id_checked

BACKUP_ROOT = Path("/root/nvl-backups")
STAGE_ROOT = Path("/root/nvl-egress-v1")
LOCK_NAME = ".v1-ingress-peers.lock"
TOKEN_TTL = 120


class RetireHold(ValueError):
    pass


@dataclass(frozen=True)
class RetirePlan:
    edge_id: str
    edge_ipv4: str
    fingerprint: str
    blockers: tuple[str, ...]
    pool_row: bool

    @property
    def allowed(self) -> bool:
        return not self.blockers


@dataclass(frozen=True)
class RetireTicket:
    actor_id: int
    chat_id: int
    edge_id: str
    fingerprint: str
    nonce: str
    expiry: float


def _read(conn, statement, args=()):
    return conn.execute(statement, args).fetchall()


def _table(conn, name):
    return bool(_read(conn, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)))


def _run(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RetireHold("RUNTIME_AUDIT_UNAVAILABLE") from exc


def _checked(*args):
    result = _run(*args)
    if result.returncode:
        raise RetireHold("RUNTIME_AUDIT_UNAVAILABLE")
    return result.stdout


def kernel_blockers(edge_id: str, ingress_ipv4: str, wg_public_key: str) -> tuple[str, ...]:
    """Fail closed unless *all* dedicated kernel and wg0 references are absent."""
    n = int(edge_id[1:])
    table = str(20000 + n)
    ns = "nvl-egress-" + edge_id
    names = ("wg-nvl-" + edge_id, "vnh-" + edge_id, "vnn-" + edge_id)
    issues = []
    if any(line.split()[0] == ns for line in _checked("ip", "netns", "list").splitlines()):
        issues.append("NAMESPACE_PRESENT")
    links = _checked("ip", "-o", "link", "show")
    if any(re.search(r": " + re.escape(name) + r"(?:@|:)", links)
           for name in names):
        issues.append("EGRESS_LINK_PRESENT")
    rules = _checked("ip", "-4", "rule", "show")
    if re.search(r"\blookup\s+" + re.escape(table) + r"\b", rules):
        issues.append("EGRESS_POLICY_RULE_PRESENT")
    routes = _checked("ip", "-j", "-4", "route", "show", "table", "all")
    try:
        items = json.loads(routes)
        if not isinstance(items, list):
            raise ValueError("invalid routing inventory")
    except (ValueError, TypeError) as exc:
        raise RetireHold("ROUTE_AUDIT_INVALID") from exc
    if any(str(r.get("table", "main")) == table for r in items):
        issues.append("EGRESS_ROUTE_TABLE_PRESENT")
    wg = _checked("wg", "show", "wg0", "allowed-ips")
    if any(len(words := line.split()) >= 2 and
           ingress_ipv4 + "/32" in words[1].split(",")
           for line in wg.splitlines()):
        issues.append("WG0_INGRESS_PEER_PRESENT")
    # Verify exact peer key, not only /32 ownership. A peer can retain a
    # different AllowedIPs set and become reachable again on reload.
    if wg_public_key in _checked("wg", "show", "wg0", "peers").splitlines():
        issues.append("WG0_PEER_KEY_PRESENT")
    wg0_config = Path("/etc/wireguard/wg0.conf")
    try:
        statbuf = wg0_config.lstat()
        if not stat.S_ISREG(statbuf.st_mode) or statbuf.st_uid != 0:
            raise OSError("untrusted wg0 config")
        if wg_public_key in wg0_config.read_text(encoding="utf-8"):
            issues.append("WG0_PERSISTENT_PEER_PRESENT")
    except (OSError, UnicodeError) as exc:
        raise RetireHold("WG0_PERSISTENCE_AUDIT_UNAVAILABLE") from exc
    for cmd in (
        ("systemctl", "list-units", "--all", "--no-legend", "--plain", "--no-pager"),
        ("systemctl", "list-unit-files", "--no-legend", "--plain", "--no-pager"),
    ):
        units = _checked(*cmd)
        if any(re.search(r"(^|[^a-z0-9])nvl-egress-" +
                         re.escape(edge_id) + r"(?:[.\s@-]|$)", line)
               for line in units.splitlines()):
            issues.append("EGRESS_SYSTEMD_REFERENCE_PRESENT")
    for cmd in (("iptables", "-S"), ("iptables", "-t", "nat", "-S"),
                ("ip6tables", "-S")):
        rules = _checked(*cmd)
        if any(tag in rules for tag in (ns, "vnh-" + edge_id,
                                        "wg-nvl-" + edge_id)):
            issues.append("EGRESS_FIREWALL_REFERENCE_PRESENT")
    return tuple(sorted(set(issues)))


def _plan(conn: sqlite3.Connection, edge_id: str, *, peers,
          runtime_probe: Callable = kernel_blockers,
          stage_root: Path = STAGE_ROOT, registry_bytes: bytes) -> RetirePlan:
    edge_id_checked(edge_id)
    matches = [p for p in peers if p.edge_id == edge_id]
    if len(matches) != 1:
        raise RetireHold("EDGE_NOT_IN_TRUSTED_REGISTRY")
    peer = matches[0]
    ipaddress.IPv4Address(peer.edge_ipv4)
    issues = []
    for name in ("host_pool", "ssh_accounts", "settings", "failover_operations",
                 "edge_egress_f3_ingress_candidates", "edge_egress_allocations",
                 "edge_egress_readiness", "edge_egress_uid_bindings",
                 "edge_egress_uid_runtime"):
        if not _table(conn, name):
            issues.append("REQUIRED_TABLE_MISSING")
    if issues:
        return RetirePlan(edge_id, peer.edge_ipv4, "", tuple(sorted(set(issues))), False)

    pool = _read(conn, "SELECT active,is_default FROM host_pool WHERE host=?",
                 (peer.edge_ipv4,))
    if len(pool) > 1 or (pool and pool[0] != (0, 0)):
        issues.append("HOST_POOL_ACTIVE_OR_DEFAULT")
    if _read(conn, "SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",
             (peer.edge_ipv4,)):
        issues.append("SSH_ACCOUNT_DEPENDENCY")
    if _read(conn, "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"):
        issues.append("6G_RUNNING")
    mode = _read(conn, "SELECT value FROM settings WHERE key='edge_egress_protected_mode'")
    if mode and mode != [("0",)]:
        issues.append("PROTECTED_MODE_NOT_LEGACY")
    if _read(conn, "SELECT value FROM settings WHERE key='dns_current_ip'") == [(peer.edge_ipv4,)]:
        issues.append("EDGE_IS_PUBLIC_DNS")
    candidates = _read(conn, "SELECT state FROM edge_egress_f3_ingress_candidates WHERE edge_ipv4=?",
                       (peer.edge_ipv4,))
    if candidates not in ([], [("INGRESS_ONLY",)]):
        issues.append("F3_CANDIDATE_CONFLICT")
    for table in ("edge_egress_allocations", "edge_egress_readiness",
                  "edge_egress_uid_bindings", "edge_egress_uid_runtime"):
        if _read(conn, f"SELECT 1 FROM {table} WHERE edge_id=? LIMIT 1", (edge_id,)):
            issues.append(table.upper() + "_DEPENDENCY")
    if (stage_root / ("core-" + edge_id)).exists() or (
            stage_root / ("core-" + edge_id)).is_symlink():
        issues.append("LOCAL_STAGE_PRESENT")
    try:
        issues.extend(runtime_probe(edge_id, peer.ingress_ipv4, peer.wg_public_key))
    except (RetireHold, ValueError, OSError):
        issues.append("KERNEL_AUDIT_HOLD")

    snapshot = {
        "registry_sha256": sha256(registry_bytes).hexdigest(),
        "edge_id": edge_id, "ip": peer.edge_ipv4,
        "pool": pool, "candidate": candidates,
        "issues": sorted(set(issues)),
        "stage_pin": _read(conn, "SELECT value FROM settings WHERE key=?",
                           ("edge_egress_v1_stage_sha256_" + edge_id,)),
    }
    digest = sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":")).encode()).hexdigest()
    return RetirePlan(edge_id, peer.edge_ipv4, digest,
                      tuple(snapshot["issues"]), bool(pool))


def plan_retirement(db_conn: Callable, edge_id: str, *,
                    registry_path: Path = REGISTRY, registry_loader=load_registry,
                    runtime_probe=kernel_blockers, stage_root: Path = STAGE_ROOT) -> RetirePlan:
    """Safe read-only preview for the existing Telegram Egress detail page."""
    edge_id_checked(edge_id)
    peers = registry_loader()
    content = registry_path.read_bytes()
    with db_conn() as conn:
        return _plan(conn, edge_id, peers=peers, registry_bytes=content,
                     runtime_probe=runtime_probe, stage_root=stage_root)


def issue_ticket(plan: RetirePlan, actor_id: int, chat_id: int, *,
                 now=time.time) -> RetireTicket:
    if not plan.allowed or type(actor_id) is not int or actor_id <= 0 or (
            type(chat_id) is not int):
        raise RetireHold("RETIRE_NOT_AUTHORIZED")
    return RetireTicket(actor_id, chat_id, plan.edge_id,
                        plan.fingerprint, secrets.token_hex(16), now() + TOKEN_TTL)


def legacy_delete_managed(db_conn: Callable, host: str,
                          *, registry_loader=load_registry) -> bool:
    """Block old host-pool delete on registered K2 Egress, regardless of mode."""
    ipaddress.IPv4Address(host)
    if any(p.edge_ipv4 == host for p in registry_loader()):
        return True
    with db_conn() as conn:
        for table, column in (
            ("edge_egress_f3_ingress_candidates", "edge_ipv4"),
            ("edge_egress_allocations", "edge_public_ipv4"),
            ("edge_egress_readiness", "edge_ipv4"),
            ("edge_egress_uid_bindings", "edge_ipv4"),
            ("edge_egress_uid_runtime", "edge_ipv4"),
        ):
            if not _table(conn, table):
                raise RetireHold("REQUIRED_TABLE_MISSING")
            if _read(conn, f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1", (host,)):
                return True
    return False


def retire_metadata(db_conn: Callable, ticket: RetireTicket, *, actor_id: int,
                    chat_id: int, edge_id: str, now=time.time,
                    registry_path: Path = REGISTRY, registry_loader=load_registry,
                    runtime_probe=kernel_blockers, stage_root: Path = STAGE_ROOT,
                    backup_root: Path = BACKUP_ROOT, geteuid=os.geteuid) -> str:
    """One-shot, backup-first CAS. Refuses ANY live Edge/UID/network reference.

    No user, wg0, namespace, routing, firewall, DNS or remote object is touched.
    """
    edge_id_checked(edge_id)
    if not isinstance(ticket, RetireTicket) or (
            ticket.actor_id != actor_id or ticket.chat_id != chat_id or
            ticket.edge_id != edge_id or not ticket.nonce or
            now() >= ticket.expiry or geteuid() != 0):
        raise RetireHold("RETIRE_TICKET_INVALID_OR_EXPIRED")
    if registry_path != REGISTRY and registry_loader is load_registry:
        raise RetireHold("REGISTRY_PATH_NOT_FIXED")
    root_st = backup_root.stat()
    if (not stat.S_ISDIR(root_st.st_mode) or root_st.st_uid != 0
            or stat.S_IMODE(root_st.st_mode) & 0o077):
        raise RetireHold("BACKUP_ROOT_UNTRUSTED")
    lock = registry_path.parent / LOCK_NAME
    if lock.is_symlink():
        raise RetireHold("REGISTRY_LOCK_SYMLINK")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    conn = None
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
            raise RetireHold("REGISTRY_LOCK_PERMISSIONS")
        fcntl.flock(fd, fcntl.LOCK_EX)
        conn = db_conn()
        conn.execute("BEGIN IMMEDIATE")
        old = registry_path.read_bytes()
        plan = _plan(conn, edge_id, peers=registry_loader(), registry_bytes=old,
                     runtime_probe=runtime_probe, stage_root=stage_root)
        if not plan.allowed or not compare_digest(plan.fingerprint, ticket.fingerprint):
            raise RetireHold("RETIRE_PLAN_CHANGED_OR_HOLD")
        # Backup before the first mutation. Use a separate connection for
        # SQLite backup to avoid backing up a write transaction on itself.
        bdir = Path(tempfile.mkdtemp(prefix="k2-retire-" + edge_id + "-",
                                     dir=str(backup_root)))
        os.chmod(bdir, 0o700)
        (bdir / "ingress-registry.json").write_bytes(old)
        os.chmod(bdir / "ingress-registry.json", 0o600)
        with sqlite3.connect("file:/root/master_bot.db?mode=ro", uri=True) as source:
            with sqlite3.connect(str(bdir / "master_bot.db")) as copy:
                source.backup(copy)
        os.chmod(bdir / "master_bot.db", 0o600)
        new = render_registry([p for p in registry_loader()
                               if p.edge_id != edge_id]).encode()
        tmp = None
        published = False
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=registry_path.parent,
                                             prefix=".k2-retire-", delete=False) as f:
                tmp = f.name
                os.fchmod(f.fileno(), 0o600)
                f.write(new)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, registry_path)
            tmp = None
            published = True
            conn.execute("DELETE FROM edge_egress_f3_ingress_candidates "
                         "WHERE edge_ipv4=?", (plan.edge_ipv4,))
            if plan.pool_row:
                cur = conn.execute("DELETE FROM host_pool "
                                   "WHERE host=? AND active=0 AND is_default=0",
                                   (plan.edge_ipv4,))
                if cur.rowcount != 1:
                    raise RetireHold("HOST_POOL_CAS_FAILED")
            conn.execute("DELETE FROM settings WHERE key=?",
                         ("edge_egress_v1_stage_sha256_" + edge_id,))
            conn.commit()
        except BaseException:
            conn.rollback()
            if published:
                with tempfile.NamedTemporaryFile(mode="wb", dir=registry_path.parent,
                                                 prefix=".k2-restore-", delete=False) as f:
                    tmp = f.name
                    os.fchmod(f.fileno(), 0o600)
                    f.write(old)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, registry_path)
                tmp = None
            raise
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        return str(bdir)
    finally:
        if conn is not None:
            if conn.in_transaction:
                conn.rollback()
            conn.close()
        os.close(fd)


def plan_html(plan: RetirePlan) -> str:
    from html import escape
    lines = ["🗑 <b>حذف ایمن Edge</b>",
             f"شناسه: <code>{escape(plan.edge_id)}</code>",
             f"IP: <code>{escape(plan.edge_ipv4)}</code>", ""]
    if plan.blockers:
        lines.extend(["⛔ <b>HOLD — ابتدا وابستگی‌ها را ایمن پاکسازی کنید.</b>"])
        lines.extend(f"• <code>{escape(item)}</code>" for item in plan.blockers[:12])
    else:
        lines.extend(["✅ <b>قابل حذف از رجیستری NVL</b>",
                      "فقط اطلاعات ثبت‌شده حذف می‌شود؛ خود VPS یا منابع شبکه تغییر نمی‌کنند.",
                      "⚠️ این مجوز تنها زمانی صادر شده که هیچ منبع Egress باقی نمانده است."])
    return "\n".join(lines)
