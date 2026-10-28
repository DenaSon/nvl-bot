"""Safe Legacy SSH host-list projection shared by old Telegram controls.

A Legacy host list is a CUSTOMER endpoint list, not a complete host_pool
inventory. This module does not change DNS, defaults, accounts or host_pool.
Unknown/stale external Cloudflare is NOT certified by cached DNS here.
"""
from __future__ import annotations
from dataclasses import dataclass

class LegacyRouteHold(RuntimeError):
    """Stable diagnostic reason; no secrets in error messages."""

@dataclass(frozen=True)
class CustomerHostPlan:
    default: str
    before: str
    after: str
    excluded_standby: tuple[str, ...]

def project_customer_hosts(conn, *, add_host=None):
    """Fail closed if route authority is incoherent; avoid new host promotion.

    Only keep existing member IPs which are active, non-Standby and non-Core.
    An explicitly reactivated host may be included after its host_pool checks.
    Existing customer assignments are never edited.
    """
    settings = dict(conn.execute(
        "SELECT key,value FROM settings WHERE key IN "
        "('hosts','dns_current_ip','core_wg_public_ip')"
    ).fetchall())
    rows = conn.execute(
        "SELECT host,active,is_default,is_standby FROM host_pool"
    ).fetchall()
    if not rows or len({r[0] for r in rows}) != len(rows):
        raise LegacyRouteHold("HOST_POOL_IDENTITY_AMBIGUOUS")
    pool = {str(h): (bool(active), bool(default), bool(standby))
            for h,active,default,standby in rows}
    default_rows = [h for h,active,default,standby in rows if default]
    if len(default_rows) != 1:
        raise LegacyRouteHold("DEFAULT_NOT_UNIQUE")
    default = str(default_rows[0])
    if pool[default] != (True, True, False):
        raise LegacyRouteHold("DEFAULT_NOT_CUSTOMER_ELIGIBLE")
    if (settings.get("dns_current_ip") != default
            or not settings.get("core_wg_public_ip")
            or settings["core_wg_public_ip"] == default):
        raise LegacyRouteHold("CACHED_DNS_OR_CORE_MISMATCH")
    before = settings.get("hosts") or ""
    if not isinstance(before, str) or not before:
        raise LegacyRouteHold("LEGACY_HOSTS_EMPTY")
    listed = [x.strip() for x in before.split(",")]
    if any(not x for x in listed) or len(set(listed)) != len(listed):
        raise LegacyRouteHold("LEGACY_HOSTS_MALFORMED")
    if settings["core_wg_public_ip"] in listed:
        raise LegacyRouteHold("CORE_IN_CUSTOMER_HOSTS")
    if any(h not in pool for h in listed):
        raise LegacyRouteHold("UNKNOWN_HOST_IN_LEGACY_LIST")
    foreign = conn.execute(
        "SELECT COUNT(*) FROM ssh_accounts "
        "WHERE service_type='ssh' AND status LIKE '%فعال%' "
        "AND status NOT LIKE '%غیر%' AND "
        "COALESCE(NULLIF(TRIM(host),''),?) != ?",
        (default,default)
    ).fetchone()[0]
    if foreign:
        raise LegacyRouteHold("ACTIVE_CUSTOMERS_NOT_ON_DEFAULT")

    if add_host is not None:
        if add_host not in pool or pool[add_host] != (True, False, False):
            raise LegacyRouteHold("EXPLICIT_HOST_NOT_ELIGIBLE")
        if add_host == settings["core_wg_public_ip"]:
            raise LegacyRouteHold("CORE_NOT_CUSTOMER_HOST")
    excluded = tuple(x for x in listed if pool[x][2])
    # Preserve existing customer membership and order; never import ALL active
    # host_pool rows (which can be unrelated/untested inventory).
    cleaned = [h for h in listed if pool[h][0] and not pool[h][2] and h != default]
    if add_host is not None and add_host not in cleaned and add_host != default:
        cleaned.append(add_host)
    after = ",".join((default, *cleaned))
    return CustomerHostPlan(default, before, after, excluded)

def repair_local_metadata(conn, *, expected_before, expected_default):
    """Operator-only compare-and-swap; caller must prove live DNS separately.

    No authorization to invoke this automatically during normal browsing.
    Operates in the caller's existing BEGIN IMMEDIATE transaction.
    """
    plan = project_customer_hosts(conn)
    if plan.before != expected_before or plan.default != expected_default:
        raise LegacyRouteHold("OPERATOR_PREVIEW_STALE")
    if conn.execute(
        "UPDATE settings SET value=? WHERE key='hosts' AND value=?",
        (plan.after, expected_before)
    ).rowcount != 1:
        raise LegacyRouteHold("HOSTS_CAS_FAILED")
    return plan
