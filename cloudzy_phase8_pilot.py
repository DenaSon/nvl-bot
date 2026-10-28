"""Phase 8 — safe LIVE pilot preflight and postcutover verification.

Reads existing SQLite with mode=ro/query_only and optionally makes only
Cloudflare GETs. It never purchases, installs, switches DNS/default, modifies
accounts, releases 6G, or marks a business test accepted.

Intended usage: run this between *operator-driven* native bot steps. A
successful preflight is evidence to continue testing, NOT authority for a
mutating step. All native CZ03/04B/07 CAS/6G/provider safeguards remain in force.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from cloudzy_route_snapshot import inspect_route


@dataclass(frozen=True)
class PilotReport:
    phase: str
    verdict: str
    source: str
    target: str
    cohort: int
    blockers: tuple[str, ...]
    next_checks: tuple[str, ...]
    facts: tuple[str, ...]

    def to_dict(self):
        return asdict(self)


class PilotAuditError(ValueError):
    pass


def _exists(db, table):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _running(db, table, where, params=()):
    if not _exists(db, table):
        return 0
    return int(db.execute("SELECT COUNT(*) FROM " + table +
                          " WHERE " + where, params).fetchone()[0])


def _ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except ValueError:
        return ""


def _candidate(db):
    if not all(_exists(db, t) for t in (
        "cloudzy_cz06_runs", "cloudzy_edge_operations", "host_pool"
    )):
        return None
    return db.execute("""
        SELECT e.public_ipv4,e.provider_server_id,c.operation_id,
               c.actor_id,c.chat_id
        FROM cloudzy_cz06_runs c
        JOIN cloudzy_edge_operations e ON e.id=c.operation_id
        JOIN host_pool h ON h.host=e.public_ipv4
          AND h.provider='cloudzy'
          AND h.provider_instance_id=e.provider_server_id
        WHERE c.stage='READY' AND e.status='EDGE_READY'
          AND h.active=1 AND h.is_standby=1 AND h.is_default=0
        ORDER BY c.updated_at DESC,c.operation_id DESC LIMIT 1
    """).fetchone()


def evaluate_pilot(db, *, phase, expected_target=None,
                   max_accounts=5, live_dns=None,
                   client_witness=None):
    """Read-only live assessment; client witness must be independent callback.

    client_witness is a trusted observer invoked with (source, target);
    operator text / saved file / a URL is NOT an independent witness.
    """
    if phase not in ("purchase", "cutover", "final"):
        raise PilotAuditError("INVALID_PHASE")
    if type(max_accounts) is not int or not 0 <= max_accounts <= 100000:
        raise PilotAuditError("INVALID_MAX_ACCOUNTS")
    if expected_target is not None and not _ip(expected_target):
        raise PilotAuditError("INVALID_TARGET")
    required = ("settings", "host_pool", "ssh_accounts")
    missing = tuple(t for t in required if not _exists(db, t))
    if missing:
        return PilotReport(
            phase, "INSPECT_SCHEMA", "", "", 0,
            ("CORE_SCHEMA_UNAVAILABLE",), ("INSPECT_CORE_SCHEMA",), missing)
    snapshot = inspect_route(db)
    source = snapshot.default_hosts[0] if len(snapshot.default_hosts) == 1 else ""
    source = _ip(source)
    counts = dict(snapshot.active_assignments)
    cohort = int(sum(v for _, v in snapshot.active_assignments))
    blocks = [x.code for x in snapshot.issues if x.severity == "ERROR"]
    next_checks = []
    facts = [f"SALE_GATE:{snapshot.sale_gate_code}",
             f"ACTIVE_SSH:{cohort}",
             f"ROUTE_DEFAULTS:{len(snapshot.default_hosts)}"]
    if source and counts.get(source, 0) != cohort:
        blocks.append("ACTIVE_CUSTOMERS_ON_OTHER_RELAY")
    if phase == "purchase":
        # An unrelated ended/verified Cloudzy order must not freeze purchases.
        # Unsettled financial effects are never assumed absent after timeout.
        pending = _running(
            db, "cloudzy_edge_operations",
            "status NOT IN ('EDGE_READY','REJECTED','CANCELLED')")
        if pending:
            blocks.append("UNSETTLED_CLOUDZY_PURCHASE")
        facts.append(f"UNSETTLED_CLOUDZY_PURCHASES:{pending}")
        if not blocks:
            next_checks.extend(("VERIFY_LIVE_STOCK_AND_TOTAL_COST",
                                "AUTHORIZE_ONE_CHARGEABLE_CZ03_ORDER"))
        verdict = "BLOCKED" if blocks else "READY_FOR_PURCHASE_TEST"
        return PilotReport(
            phase, verdict, source, "", cohort, tuple(sorted(set(blocks))),
            tuple(next_checks), tuple(facts))
    # Only a CZ06 READY target with exact provider/host_pool match is a
    # candidate. No inferred manual standby and no IP-only correlation.
    chosen = _candidate(db)
    target = _ip(chosen[0]) if chosen else ""
    if not target:
        blocks.append("NO_VERIFIED_CZ06_STANDBY")
    if expected_target is not None and target != expected_target:
        blocks.append("TARGET_PROVIDER_IDENTITY_MISMATCH")
    if chosen:
        facts.append(f"PROVIDER_REFERENCE_PRESENT:{bool(chosen[1])}")
    # These checks must not bypass the original 6G or CZ04A/CZ04B fences.
    if _running(db, "failover_operations", "status='RUNNING'"):
        blocks.append("ORIGINAL_6G_LEASE_BUSY")
    if _running(db, "cloudzy_cz04a_actions",
                "status NOT IN ('DONE','REJECTED')"):
        blocks.append("CZ04A_UNRESOLVED")
    if _running(db, "cloudzy_cz04b_operations",
                "status NOT IN ('READY','DONE','ABORTED')"):
        blocks.append("CZ04B_UNRESOLVED")
    if _running(db, "cloudzy_cz07_jobs",
                "status NOT IN ('DONE','ABORTED')") and phase == "cutover":
        blocks.append("CZ07_UNRESOLVED")
    if phase == "cutover" and cohort > max_accounts:
        blocks.append("PILOT_COHORT_EXCEEDS_EXPLICIT_LIMIT")
    if live_dns is None:
        next_checks.append("RUN_CLOUDFLARE_LIVE_GET")
    else:
        # These snapshots come from an independent GET, not settings cache.
        if not isinstance(live_dns, list) or not live_dns:
            blocks.append("LIVE_DNS_UNVERIFIED")
        elif (not source or any(not isinstance(rec, dict) or
                _ip(rec.get("ip")) != source or not rec.get("id") or
                not rec.get("name") for rec in live_dns)):
            if phase == "cutover":
                blocks.append("LIVE_DNS_SOURCE_CHANGED")
            else:
                # Final stage expects current new default instead.
                if not target or any(
                        not isinstance(rec, dict) or _ip(rec.get("ip")) != target
                        for rec in live_dns):
                    blocks.append("LIVE_DNS_FINAL_TARGET_MISMATCH")
        facts.append("LIVE_DNS_GET_OBSERVED")
    if phase == "cutover":
        witness = False
        if not blocks and callable(client_witness):
            try:
                witness = client_witness(source, target) is True
            except Exception:
                witness = False
        if not witness:
            next_checks.append("VERIFY_REAL_CLIENT_FROM_AFFECTED_ISP")
        if "RUN_CLOUDFLARE_LIVE_GET" in next_checks:
            verdict = "READY_FOR_LIVE_DNS_TEST" if not blocks else "BLOCKED"
        else:
            verdict = ("READY_FOR_CONTROLLED_CUTOVER" if witness and not blocks
                       else "READY_FOR_CLIENT_TEST" if not blocks
                       else "BLOCKED")
    else:
        # A postcutover audit uses the native, immutable CZ07 result.
        # The standby candidate may have been promoted and is no longer
        # marked standby; instead verify the exact accepted job as authority.
        if not _exists(db, "cloudzy_cz07_jobs"):
            blocks.append("CZ07_JOURNAL_UNAVAILABLE")
        else:
            row = db.execute(
                "SELECT id,status,source,target,moved,total,actor "
                "FROM cloudzy_cz07_jobs ORDER BY started_at DESC,id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                blocks.append("CZ07_JOB_MISSING")
            else:
                _job, state, _old, final_target, moved, total, actor = row
                facts.extend((f"CZ07_STATUS:{state}",f"CZ07_MOVED:{moved}",
                              f"CZ07_TOTAL:{total}"))
                if state != "DONE" or moved != total:
                    blocks.append("CZ07_NOT_BUSINESS_ACCEPTED")
                if source != _ip(final_target):
                    blocks.append("FINAL_DEFAULT_TARGET_MISMATCH")
                if _exists(db, "cloudzy_cz07_acceptance"):
                    accepted = db.execute(
                        "SELECT create_ref,renew_ref,client_ref FROM "
                        "cloudzy_cz07_acceptance WHERE job_id=? AND actor=?",
                        (_job, actor)
                    ).fetchone()
                    if not accepted or any(not value for value in accepted):
                        blocks.append("INDEPENDENT_CREATE_RENEW_CLIENT_PROOF_MISSING")
                else:
                    blocks.append("CZ07_ACCEPTANCE_JOURNAL_MISSING")
        if live_dns is None:
            verdict = "READY_FOR_LIVE_DNS_TEST" if not blocks else "BLOCKED"
        else:
            verdict = "FINAL_AUDIT_PASS" if not blocks else "BLOCKED"
    return PilotReport(
        phase, verdict, source, target, cohort,
        tuple(sorted(set(blocks))), tuple(next_checks), tuple(facts))


def open_core_readonly(path):
    db_path = Path(path).expanduser().resolve(strict=True)
    if not db_path.is_file():
        raise PilotAuditError("CORE_DB_INVALID")
    db = sqlite3.connect(
        "file:" + quote(str(db_path), safe="/") + "?mode=ro",
        uri=True, timeout=5)
    db.execute("PRAGMA query_only=ON")
    return db


def live_cloudflare_get():
    """Optional exact Cloudflare DNS GET; never loads or logs raw API token."""
    names = ("NVL_PHASE8_CF_ZONE", "NVL_PHASE8_CF_TOKEN",
             "NVL_PHASE8_CF_PUBLIC_DOMAIN")
    values = [os.environ.get(name, "") for name in names]
    if any(not v for v in values):
        raise PilotAuditError("PHASE8_CLOUDFLARE_GET_CONFIG_MISSING")
    from cloudzy_cz04b_dns import CloudflareExactDNS
    cfg = {
        "zone": values[0], "token": values[1], "public_domain": values[2],
        "tls_domain": os.environ.get("NVL_PHASE8_CF_TLS_DOMAIN", ""),
        "tls_passthrough": os.environ.get("NVL_PHASE8_CF_TLS_PASSTHROUGH", "0"),
        "email": os.environ.get("NVL_PHASE8_CF_EMAIL", ""),
    }
    # This call invokes only snapshot(); set_all/PUT is never referenced.
    return CloudflareExactDNS(lambda: cfg).snapshot()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="NVL Phase-8 read-only pilot readiness (no provider POST/DNS PUT)")
    parser.add_argument("--db", default="/root/master_bot.db")
    parser.add_argument("--phase", required=True,
                        choices=("purchase", "cutover", "final"))
    parser.add_argument("--expected-target")
    parser.add_argument("--max-accounts", type=int, default=5)
    parser.add_argument("--cloudflare-get", action="store_true",
                        help="Explicitly use configured Cloudflare read-only GET")
    args = parser.parse_args(argv)
    db = None
    try:
        db = open_core_readonly(args.db)
        snapshot = live_cloudflare_get() if args.cloudflare_get else None
        report = evaluate_pilot(
            db, phase=args.phase, expected_target=args.expected_target,
            max_accounts=args.max_accounts, live_dns=snapshot)
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        # Missing human client proof is an expected next test, not a forced
        # business rollback, global lock or fake final completion.
        return 1 if report.blockers else 0
    except (PilotAuditError, sqlite3.Error, OSError, ValueError):
        print(json.dumps({"verdict": "INSPECTION_ERROR",
                          "code": "PHASE8_READONLY_EVIDENCE_UNAVAILABLE"}))
        return 2
    finally:
        if db is not None:
            db.close()


if __name__ == "__main__":
    raise SystemExit(main())
