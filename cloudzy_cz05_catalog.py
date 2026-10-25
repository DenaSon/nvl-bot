"""CZ-05: deterministic, fail-closed Cloudzy hourly Regular CPU catalog policy.

The public pricing catalog is NOT an inventory source. Only a fresh, live,
per-plan /plan-availability response for the exact region can authorize listing.
This module performs no network requests or paid actions.
"""
from datetime import datetime, timezone
import re

PREFERRED_REGIONS = (
    "DE-Frankfurt", "NL-Amsterdam-DC2", "NL-Amsterdam",
    "UK-London", "CH-Switzerland", "DTX", "US-Utah",
    "SG-Singapore-DC2", "SG-Singapore",
)
STANDARD_VPS_SLUG = re.compile(r"vps-(?:512|[1-9][0-9]*gb)\\Z", re.I)
AVAILABILITY_MAX_AGE_SECONDS = 90


class CatalogHold(ValueError):
    """Non-chargeable, explicit catalog/stock validation failure."""


def preferred_regions(regions):
    """Only operator-approved locations, in deterministic preference order."""
    by_id = {}
    for region in regions if isinstance(regions, list) else []:
        if not isinstance(region, dict):
            continue
        key = region.get("id")
        if (key in PREFERRED_REGIONS and region.get("isActive") is True
                and region.get("isHidden") is not True
                and region.get("isOutOfStock") is not True):
            by_id[key] = (key, str(region.get("name") or key))
    return [by_id[key] for key in PREFERRED_REGIONS if key in by_id]


def _fresh_checked_at(value, *, now=None):
    if not isinstance(value, str) or not value:
        raise CatalogHold("AVAILABILITY_TIMESTAMP_MISSING")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("naive datetime")
        age = (datetime.now(timezone.utc).timestamp() if now is None else now) - stamp.timestamp()
    except (ValueError, OverflowError, TypeError):
        raise CatalogHold("AVAILABILITY_TIMESTAMP_INVALID") from None
    if age < -30 or age > AVAILABILITY_MAX_AGE_SECONDS:
        raise CatalogHold("AVAILABILITY_STALE")


def eligible_offers(catalog, availability, *, region, now=None):
    """Join exact regional hourly prices to live per-plan availability by planId.

    Output tuples: (plan_id, display_name, cents_per_hour, scope, label).
    Missing/unknown stock and generic/monthly-equivalent prices fail closed.
    """
    if not isinstance(catalog, dict) or catalog.get("region") != region or catalog.get("billingCycle") != "hourly":
        raise CatalogHold("CATALOG_REGION_OR_CYCLE_INVALID")
    if not isinstance(availability, dict) or availability.get("region") != region:
        raise CatalogHold("AVAILABILITY_REGION_MISMATCH")
    _fresh_checked_at(availability.get("checkedAt"), now=now)
    stocks = availability.get("plans")
    if not isinstance(stocks, list):
        raise CatalogHold("AVAILABILITY_PLANS_MISSING")
    valid = {}
    for stock in stocks:
        if not isinstance(stock, dict) or not isinstance(stock.get("planId"), str):
            continue
        pid = stock["planId"]
        if pid in valid:
            raise CatalogHold("AVAILABILITY_DUPLICATE_PLAN")
        valid[pid] = stock
    results = []
    for plan in catalog.get("plans", []) if isinstance(catalog.get("plans"), list) else []:
        if not isinstance(plan, dict) or plan.get("instanceType") != "default":
            continue
        slug = plan.get("slug")
        pid = plan.get("id")
        if not isinstance(slug, str) or not STANDARD_VPS_SLUG.fullmatch(slug) or not isinstance(pid, str):
            continue
        stock = valid.get(pid)
        if not stock or stock.get("available") is not True or stock.get("source") != "live":
            continue
        fits = stock.get("fitsOnNodes")
        if type(fits) is not int or fits <= 0:
            continue
        if plan.get("priceScope") != "regional_catalog_base":
            continue
        price = plan.get("price")
        if not isinstance(price, dict) or price.get("regionId") != region or price.get("billingCycle") != "hourly":
            continue
        cents = price.get("amount")
        if type(cents) is not int or cents <= 0 or price.get("currency") != "USD":
            continue
        results.append((pid, str(plan.get("name") or slug)[:34], cents,
                        "regional_catalog_base", "ساعتی"))
    return results
