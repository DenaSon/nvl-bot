# Manual Edge: Live Role Display and Safe List Removal

## Incident confirmed (2026-10-30)

The operator's local database shows two operations with historical `ACTIVE` status, but only one active default in `host_pool`:

| IP | Journal status | active | is_default | is_standby |
|---|---|---:|---:|---:|
| 45.59.126.73 | ACTIVE | 1 | 0 | 0 |
| 144.172.69.30 | ACTIVE | 1 | 1 | 0 |
| 104.194.141.86 | EDGE_READY | no matching row | — | — |

The old listing used the journal status as the operational role. This caused the former relay to appear active. The journal is intentionally an immutable-ish lifecycle history and must not be retroactively rewritten solely to style a list.

## Display contract

- Show **رله اصلی** only for the unique, active `host_pool.is_default=1` manual host when `settings.hosts` and `settings.dns_current_ip` equal that host and journal status is `ACTIVE`.
- Show **رله سابق** for journal `ACTIVE` entries registered as non-default, non-standby manual hosts.
- Show **آماده‌به‌کار** only when journal and pool both prove Standby.
- Show **ثبت سرور ناقص** for `EDGE_READY` without an inventory row.
- For any contradictory default/pool configuration, show **ناسازگاری مسیر؛ بررسی لازم**, never a second apparently active relay.
- Live DNS from Cloudflare and end-user connectivity still require independent verification. The list represents a coherent Core snapshot, not proof of customer reachability.

## Removal contract

The admin may select **حذف از فهرست (بایگانی)** on retired former relays or inactive `EDGE_READY` cards. A second explicit confirmation is required. In the same SQLite transaction, the operation must still be owned by the admin, not the default/standby route or listed in DNS/hosts, have **zero** assigned accounts (including disabled/expired), and have no relevant unresolved Quick Switch, CZ07 or running failover operation. Uncertain identities fail closed.

- Only `archived_at` is set and `REMOVED_FROM_EDGE_LIST` is appended to the audit journal.
- No VPS destruction, WireGuard peer removal, `host_pool` row change, DNS call, customer transfer, or lifecycle status rewrite.
- Original IP identity stays reserved; this is **not** permission to reinstall a possibly already provisioned Edge.
- Prepared operational Standby, default relay, in-flight route and any host with attached accounts cannot be hidden.
- This action is list organization, **not decommissioning**. Full host/service decommission requires a separately reviewed lifecycle with customer, WireGuard, DNS and provider safeguards.

## Rollout

Source PR and CI success do not constitute a Production deployment. Back up live SQLite, verify staged source and installed SHA against the intended baseline, then deploy only through a pinned release. Test the admin Rich list for exactly one default, one former relay and the broken `EDGE_READY` record; try the archive preview but only confirm once all guards are green. Preserve existing users and DNS.
