"""Root-owned AWG Limiter witness renewal for managed STANDBY Edges.

Run only from a root systemd timer. This observer NEVER changes DNS, routes,
iptables/ipset, AWG peers, customer records, or starts a cutover.
Each STANDBY /32 gets an independent 120-second marker. Failed checks revoke
only that candidate's marker. The bot only reads markers; it never invokes
this privileged script.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import sqlite3
import stat
import sys

from nvl_awg_limiter_witness import LimiterWitnessHold, attest

DB = Path("/root/master_bot.db")
MARKER_DIR = Path("/run/nvl-awg-limiter-ready.d")


class WitnessRefreshHold(RuntimeError):
    pass


def _private_directory(directory: Path) -> None:
    if directory.is_symlink():
        raise WitnessRefreshHold("WITNESS_DIRECTORY_UNTRUSTED")
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
    except OSError:
        raise WitnessRefreshHold("WITNESS_DIRECTORY_UNAVAILABLE") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WitnessRefreshHold("WITNESS_DIRECTORY_UNTRUSTED")


def _candidates(db_path: Path) -> list[tuple[str, str]]:
    if db_path.is_symlink() or not db_path.is_file():
        raise WitnessRefreshHold("WITNESS_DATABASE_UNAVAILABLE")
    try:
        with sqlite3.connect("file:" + str(db_path) + "?mode=ro",
                             uri=True, timeout=4) as db:
            rows = db.execute(
                "SELECT m.ip,b.edge_tunnel_ip "
                "FROM manual_edge_operations m "
                "JOIN host_pool h ON h.host=m.ip "
                "JOIN edge_tunnel_bindings b ON b.host=m.ip "
                "WHERE m.status='STANDBY' AND m.archived_at IS NULL "
                "AND m.tunnel_backend='amneziawg' "
                "AND h.active=1 AND h.is_standby=1 AND h.is_default=0 "
                "AND h.provider='manual' AND h.provider_instance_id IS NULL "
                "AND b.backend='amneziawg' AND b.interface='awg0' "
                "AND b.state='VERIFIED' "
                "ORDER BY m.ip"
            ).fetchall()
    except sqlite3.Error:
        raise WitnessRefreshHold("WITNESS_DATABASE_UNAVAILABLE") from None
    seen_host, seen_ip = set(), set()
    result = []
    for host, tunnel in rows:
        try:
            host = str(ipaddress.IPv4Address(host))
            tunnel = str(ipaddress.IPv4Address(tunnel))
        except (ValueError, TypeError):
            raise WitnessRefreshHold("WITNESS_CANDIDATE_INVALID") from None
        if host in seen_host or tunnel in seen_ip:
            raise WitnessRefreshHold("WITNESS_CANDIDATE_AMBIGUOUS")
        seen_host.add(host)
        seen_ip.add(tunnel)
        result.append((host, tunnel))
    return result


def _prune_retired(directory: Path, eligible: set[str]) -> None:
    """Only prune owned IPv4-named marker entries in a private root directory."""
    for entry in directory.iterdir():
        if entry.name in eligible:
            continue
        try:
            if str(ipaddress.IPv4Address(entry.name)) != entry.name:
                continue
        except ValueError:
            continue
        # unlink does not follow symlinks; never touch unrelated files.
        if entry.is_symlink() or entry.is_file():
            entry.unlink()


def refresh(*, db_path=DB, marker_dir=MARKER_DIR,
            attest_fn=attest, root_check=os.geteuid) -> tuple[int, int]:
    if root_check() != 0:
        raise WitnessRefreshHold("WITNESS_ROOT_REQUIRED")
    directory = Path(marker_dir)
    _private_directory(directory)
    candidates = _candidates(Path(db_path))
    # Scan eligibility before any marker writes; never select an arbitrary
    # 'latest' Edge. Multiple STANDBYs each get an independent marker.
    valid_names = {tunnel for _host, tunnel in candidates}
    _prune_retired(directory, valid_names)
    success = 0
    failure = 0
    for host, tunnel in candidates:
        marker = directory / tunnel
        try:
            # Reuses the full, root-only existing witness: peer path/route,
            # installed limiter source, PID/image, exemption and ipset proof.
            observed = attest_fn(host, marker=marker)
            if observed != tunnel:
                raise WitnessRefreshHold("WITNESS_TARGET_MISMATCH")
            success += 1
        except Exception as exc:
            # Revoke stale approval for a failed candidate. The future
            # runtime cutover gate also enforces a 120-second TTL.
            marker.unlink(missing_ok=True)
            failure += 1
            # Journal a safe, per-Edge reason. Never print arbitrary exception
            # text because transport libraries may include sensitive details.
            reason = (str(exc) if isinstance(
                exc, (LimiterWitnessHold, WitnessRefreshHold)
            ) else type(exc).__name__)
            if (not reason or len(reason) > 96
                    or not all(ch.isupper() or ch.isdigit() or ch == "_"
                               for ch in reason)):
                reason = type(exc).__name__
            print(
                f"AWG_WITNESS_EDGE=HOLD host={host} tunnel={tunnel} reason={reason}",
                file=sys.stderr, flush=True,
            )
    return success, failure


def main() -> int:
    parser = argparse.ArgumentParser(description="Root-only standby witness refresh")
    parser.add_argument("--refresh-standby", action="store_true", required=True)
    parser.parse_args()
    try:
        ready, failed = refresh()
    except WitnessRefreshHold as exc:
        print("AWG_WITNESS_REFRESH=HOLD " + str(exc), file=sys.stderr)
        return 2
    except Exception:
        print("AWG_WITNESS_REFRESH=HOLD UNEXPECTED_FAILURE", file=sys.stderr)
        return 2
    if failed:
        print(f"AWG_WITNESS_REFRESH=PARTIAL ready={ready} failed={failed}",
              file=sys.stderr)
        return 2
    print(f"AWG_WITNESS_REFRESH=READY count={ready}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
