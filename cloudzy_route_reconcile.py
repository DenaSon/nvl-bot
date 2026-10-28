"""P5 route/Cloudflare evidence is read-only; it never modifies route state."""
from dataclasses import dataclass
import ipaddress

class RouteProjectionHold(RuntimeError):
    pass

@dataclass(frozen=True)
class RouteEvidence:
    db_route: str
    dns_route: str
    disposition: str
    next_action: str

def _ip(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except (TypeError, ValueError):
        raise RouteProjectionHold("ROUTE_INVALID_IP") from None

def require_customer_route_projection(conn, *, source=None, target=None):
    """Strict Legacy route listing: only verified current customer endpoints."""
    settings = dict(conn.execute(
        "SELECT key,value FROM settings WHERE key IN "
        "('hosts','dns_current_ip','core_wg_public_ip')"
    ).fetchall())
    defaults = conn.execute(
        "SELECT host,active FROM host_pool WHERE is_default=1"
    ).fetchall()
    if len(defaults) != 1 or int(defaults[0][1] or 0) != 1:
        raise RouteProjectionHold("ROUTE_DEFAULT_AMBIGUOUS")
    current = _ip(defaults[0][0])
    if _ip(settings.get("dns_current_ip")) != current:
        raise RouteProjectionHold("ROUTE_CACHED_DNS_DEFAULT_DRIFT")
    core = _ip(settings.get("core_wg_public_ip"))
    if current == core:
        raise RouteProjectionHold("ROUTE_DEFAULT_IS_CORE")
    raw = settings.get("hosts")
    if not isinstance(raw, str) or not raw:
        raise RouteProjectionHold("ROUTE_HOSTS_UNSET")
    parts = [s.strip() for s in raw.split(",")]
    if any(not s for s in parts):
        raise RouteProjectionHold("ROUTE_HOSTS_INVALID")
    hosts = tuple(_ip(s) for s in parts)
    if len(hosts) != len(set(hosts)):
        raise RouteProjectionHold("ROUTE_HOSTS_DUPLICATE")
    if not hosts or hosts[0] != current:
        raise RouteProjectionHold("LEGACY_HOSTS_ORDER_MISMATCH")
    if core in hosts:
        raise RouteProjectionHold("ROUTE_CORE_IN_CUSTOMER_HOSTS")
    known = {}
    for host, active, standby, default in conn.execute(
            "SELECT host,active,is_standby,is_default FROM host_pool"):
        if host in known:
            raise RouteProjectionHold("ROUTE_HOST_IDENTITY_AMBIGUOUS")
        known[host] = (bool(active), bool(standby), bool(default))
    for host in hosts:
        flags = known.get(host)
        if not flags or not flags[0] or flags[1]:
            raise RouteProjectionHold("ROUTE_HOST_NOT_CUSTOMER_ELIGIBLE")
        if host != current and flags[2]:
            raise RouteProjectionHold("ROUTE_EXTRA_DEFAULT")
    if source is not None and current != _ip(source):
        raise RouteProjectionHold("ROUTE_SOURCE_CHANGED")
    if target is not None:
        dst = _ip(target)
        if dst in hosts or dst == core or known.get(dst) != (True, True, False):
            raise RouteProjectionHold("ROUTE_TARGET_NOT_ISOLATED_STANDBY")
    return (current, tuple(hosts))

def classify_db_route(conn, *, source, target):
    src, dst = _ip(source), _ip(target)
    defaults = conn.execute(
        "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
    ).fetchall()
    settings = dict(conn.execute(
        "SELECT key,value FROM settings WHERE key IN ('hosts','dns_current_ip')"
    ).fetchall())
    hosts = [h.strip() for h in (settings.get("hosts") or "").split(",") if h.strip()]
    if len(defaults) != 1 or not hosts or len(hosts) != len(set(hosts)):
        return "UNVERIFIED"
    triple = (defaults[0][0], settings.get("dns_current_ip"), hosts[0])
    if all(v == src for v in triple):
        return "SOURCE"
    if all(v == dst for v in triple):
        return "TARGET"
    return "MIXED_OR_OTHER"


def classify_dns_records(records, *, source, target):
    """Strict exact-record snapshot; missing IDs/TTL or duplicates deny proof."""
    src, dst = _ip(source), _ip(target)
    if not isinstance(records, list) or not records:
        return "UNVERIFIED"
    names, ids, ips = set(), set(), set()
    for record in records:
        if not isinstance(record, dict):
            return "UNVERIFIED"
        name, rid, ttl = record.get("name"), record.get("id"), record.get("ttl")
        if (not isinstance(name, str) or not name
                or not isinstance(rid, str) or not rid
                or type(ttl) is not int or ttl < 1
                or name in names or rid in ids
                or record.get("proxied") is True):
            return "UNVERIFIED"
        names.add(name)
        ids.add(rid)
        try:
            ips.add(_ip(record.get("ip")))
        except RouteProjectionHold:
            return "UNVERIFIED"
    if ips == {src}:
        return "SOURCE"
    if ips == {dst}:
        return "TARGET"
    return "MIXED_OR_OTHER"

def reconcile_evidence(*, db_route, dns_route, shared_lock_running):
    """Classification only: even both SOURCE requires proof old worker stopped."""
    permitted = ("SOURCE", "TARGET", "MIXED_OR_OTHER", "UNVERIFIED")
    if db_route not in permitted or dns_route not in permitted:
        raise RouteProjectionHold("ROUTE_CLASSIFICATION_INVALID")
    if type(shared_lock_running) is not bool:
        raise RouteProjectionHold("SHARED_LOCK_EVIDENCE_INVALID")
    if not shared_lock_running:
        code = "SHARED_6G_OWNERSHIP_UNVERIFIED"
        action = "INSPECT_ORIGINAL_6G_JOURNAL"
    elif db_route == dns_route == "SOURCE":
        code = "SOURCE_CONSISTENT_UNRELEASED"
        action = "VERIFY_WORKER_QUIESCENT_BEFORE_MANUAL_CLOSE"
    elif db_route == dns_route == "TARGET":
        code = "TARGET_CONSISTENT_UNACCEPTED"
        action = "VERIFY_PROVIDER_SSH_WG_AND_6G_BEFORE_ACCEPTANCE"
    else:
        code = "RECONCILE_REQUIRED"
        action = "DO_NOT_REPLAY_DNS_OR_REVERSE_DEFAULT"
    return RouteEvidence(db_route, dns_route, code, action)
