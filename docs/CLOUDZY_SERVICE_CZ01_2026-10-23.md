> **Integration decision — 2026-10-23 (documentation only):** The proposed next Cloudzy UI will be a **separate first-page admin shortcut** reusing the existing Legacy Edge installer while preserving the original manual UI and callback behavior. Ubuntu 24.04 is fixed and hidden in the new flow. K2 protected customer Egress is **not operationally released/accepted** and is out of scope. No Telegram integration is implemented by this note. See [Cloudzy Legacy quick-Edge design and safety plan](CLOUDZY_LEGACY_QUICK_EDGE_PLAN_2026-10-23.md).

# NVL CloudzyService — CZ-01 (service only)

## Scope and source

Standalone Python client: `cloudzy_service.py`. **No Telegram handler,
existing SSH/WireGuard workflow, database migration, job, server provisioning
or production deployment is changed by this feature.**

Contract source: the official Cloudzy CLI `CloudzyVPS/cli`,
`src/api/ops.rs` and `src/api/client.rs`, as checked on 2026-10-23.
Use the **new** `https://dash.cloudzy.com/api/v1` with
`Authorization: Bearer <developer-token>`, not the older
`https://api.cloudzy.com/developers` API-Token interface.

## Exactly the 20 owner-selected capabilities

| ID | CloudzyService method | API |
| --- | --- | --- |
| 01 | `list_regions()` | GET /regions |
| 02 | `list_plans(region=, billing_cycle=)` | GET /pricing/catalog |
| 06 | `create_server(..., confirm=True)` | POST /services |
| 07 | `list_servers()` | GET /services |
| 08 | `get_server(server_id)` | GET /services/{id} |
| 09 | `get_server_status(server_id)` | GET /services/{id}/status |
| 10 | `wait_for_ready(server_id)` | polls GET /services/{id} |
| 11 | `rename_server(server_id, hostname)` | PATCH /services/{id} |
| 12 | `power_on(server_id)` | POST /services/{id}/power action=start |
| 13 | `power_off(server_id)` | POST /services/{id}/power action=stop |
| 14 | `restart_server(server_id)` | POST /services/{id}/power action=reboot |
| 16 | `rebuild_server(server_id, os_template_id=, confirm=True)` | POST /services/{id}/rebuild |
| 17 | `reset_server_password(server_id, confirm=True)` | POST /services/{id}/reset-password |
| 18 | `get_server_usage(server_id)` | GET /services/{id}/usage |
| 20 | `delete_server(server_id, confirm=True)` | DELETE /services/{id} |
| 21 | `list_ssh_keys()` | GET /ssh-keys |
| 22 | `add_ssh_key(name, public_key)` | POST /ssh-keys |
| 23 | `delete_ssh_key(key_id, confirm=True)` | DELETE /ssh-keys/{id} |
| 41 | `whoami()` | GET /auth/me |
| 42 | `get_balance()` | GET /billing/summary |

All other Cloudzy actions (Resize, snapshots, IPs, firewall, activity,
invoices, OS-template listing, app marketplace, ledger) are deliberately
out of scope. `os_template_id` is supplied by the caller for create/rebuild;
there is no additional OS-listing endpoint inside this service.

## Security and operational limits

- Token comes from `CLOUDZY_TOKEN` or an explicit constructor argument; it
  must never be committed or printed. Create a scoped, expiring developer token.
- No SDK/package installation is needed: HTTPS requests use Python's standard-library `urllib`.
- Creation is chargeable; `confirm=True` must follow an actual operator
  decision elsewhere. Rebuild destroys the disk, password reset invalidates
  old credentials, and delete destroys the VPS. The library checks the explicit
  flag but **does not implement operator authorization**.
- `create_server` takes **plan ID**, region ID and optional
  `os_template_id`, `billing_cycle`, public SSH key lines, cloud-init
  `user_data`, and `ip_version`. No SSH private key is accepted.
- `list_plans` combines plan catalog data and matching region/cycle pricing;
  where regional pricing is absent it explicitly labels the general catalog
  fallback. All monetary amounts remain in the provider's original **cents**.
  These prices are *base prices*, not full server quotes: IPv4 fees/extras may
  change the actual charge. The provider still decides final stock/capacity.
- A create request sends an `Idempotency-Key`. Supply the **same** key if
  manually reconciling/retrying an uncertain create operation. The service
  never silently retries chargeable or destructive operations.
- Any write connection timeout, bad response body, or HTTP 5xx is treated as
  **CloudzyUncertainError**: first reconcile provider state, then decide whether
  to retry. Never assume an uncertain delete/rebuild/reset did not happen.
- `wait_for_ready` polls Cloudzy until server `state == active`; this is
  **provider-level** readiness only. It is not proof of SSH reachability,
  a working WireGuard tunnel, an activated Edge or a successful customer
  IP migration.
- Successful password-reset and rebuild responses may contain a one-time
  root password. Callers must not log or persist the returned plaintext
  without a separate approved credentials-handling policy.

## Example (read-only)

```python
from cloudzy_service import CloudzyService

cloudzy = CloudzyService()  # reads CLOUDZY_TOKEN from the environment
print(cloudzy.list_regions())
print(cloudzy.list_plans(region="fra"))
print(cloudzy.list_servers())
# Balance values are cents, not dollars.
print(cloudzy.get_balance())
```

## Tests

```bash
python3 -m unittest tests.test_cloudzy_service -v
```

The test suite uses an injected fake HTTP session. It covers the selected
routes, payloads, confirmation fences, token redaction, no mutation auto-retry,
idempotency handoff and readiness polling. It does **not** prove that the
account's token scopes, prices, server stock or live API are working.
Before operational use, run approved read-only checks (`whoami`,
`list_regions`, `list_servers` and `get_balance`) with an actual token.
No live create, rebuild, password reset or delete has been attempted here.
