# NVL — Super Admin registry authority and legacy ID revocation (2026-11-10)

## Decision and Production evidence

This security fix supersedes the legacy `SUPER_ADMIN_ID` single-account permission model **without** changing ordinary legacy admin sales/SSH/V2Ray workflows. Operator's Nov 10 read-only Core verification:

- `bot_access` exists with `telegram_id, role, active, label, created_at, updated_at`.
- Exactly these three requested Super Admin users have `role='super_admin'`, `active=1`: `5981086716`, `75610890`, `1252512320`.
- Revoked historical ID `1947045855` has **no `bot_access` row** but is still listed in `settings.admin_chat_ids` and `historical_admin_ids`.
- Two current Super Admin identities also appear in `agents.telegram_id`; do not infer their permissions from agent records.
- Previous source ignored `bot_access` and used the revoked hardcoded principal for exclusive menus, critical notifications, and Finance V1. Legacy admin IDs remained broadcast recipients.

## Security contract

1. New `nvl_superadmin_access.py` reads existing `bot_access` using SQLite `mode=ro` plus `PRAGMA query_only=ON`. Only `role='super_admin' AND active=1` counts. Missing table/database fails **closed** for all Super Admin surfaces.
2. `SUPER_ADMIN_ID=5981086716` exists ONLY as a compatibility argument to the legacy critical notice API; it is **not an authorization grant**. All privileged callbacks and menus use the active registry, role `admin`, Telegram user identity, and own **private** chat identity on each request.
3. All three active Super Admins auto-login on `/start` and see the `👑 تنظیمات سوپر ادمین` menu, including text-only `💰 گزارش حسابداری` when `NVL_SUPERADMIN_ACCOUNTING_REPORT_ENABLED=1`. Existing report module and calculations are unchanged.
4. The revoked legacy principal is explicitly denied in an early `TypeHandler(Update,...)` (group -2), before all command, text, photo and callback routes, regardless of stored login state or shared admin password. Its persisted `user_data` is cleared on attempted access. This user cannot re-register itself through the bot.
5. `_db_get_admin_chat_ids` removes the revoked ID even while it remains in old `settings.admin_chat_ids` and includes current authorized Super Admin IDs. Ordinary existing admins retain their historical receipt/alert distribution behavior.
6. Direct high-priority Super Admin notices fan out to all active registry Super Admins. `critical_operation_notice` uses an explicit registry allowlist, ignoring stale `NVL_CRITICAL_SUPERADMIN_IDS`, primary and legacy fallback; the revoked ID is excluded in all modes.
7. `historical_admin_ids` is retained as immutable historical evidence. The existing management display can still show old historical principals without granting active access.

## Scope and tests

Changed: `bot_final_v49-2.py`, `nvl_superadmin_access.py`, `critical_operation_notice.py`, `tests/test_nvl_superadmin_access_registry.py`, this document. Existing financial tables, balances, receipt flows, Core networking and database schema are not changed.

Isolated tests:

```bash
python3 -B -m unittest discover -s tests -p 'test_nvl_superadmin_access_registry.py' -v
python3 -B -m py_compile bot_final_v49-2.py nvl_superadmin_access.py critical_operation_notice.py
```

Required full checks on exact PR head: Python checks, Legacy Core Migration Safety, DenaProbe, Edge stage-only safety. No master merge without green CI.

## Gated Core deploy (not performed by a GitHub merge)

Core previously showed bot `/root/bot_final_v49-2.py`, Python `/root/venv/bin/python3`, DB `/root/master_bot.db`, service `nvlbot`, Git checkout `/root/nvl-release`. Operator might have **manually changed** the live single Super Admin ID before this PR: the live file may not be byte-identical to the old GitHub base. **Never overwrite the live bot with a broad Git copy before a real host-side diff and reviewed exact allowlist.**

Stage the exact release SHA in an immutable directory and verify full Python/CI. Review all live vs staged differences in the bot source, including deployed earlier modules. Back up old bot and notice module (if present), stage `nvl_superadmin_access.py`, then atomically publish the three compatible Python files with a prepared rollback and ONE controlled `nvlbot` restart. Preserve `/root/master_bot.db`, `/root/accounting.db`, `bot_persistence.pickle`, settings, all SSH/WG/Edge files and secrets. The existing Accounting Report V1 module stays unchanged, and its feature flag stays as explicitly configured in the live service.

**Post-deploy live security acceptance:**

- `/start` from all three active IDs shows automatic Super Admin login.
- All three see `👑 تنظیمات سوپر ادمین` and the Accounting Report V1 menu.
- Inactive or ordinary admins do not see it and cannot invoke old callback buttons.
- The revoked ID cannot log in, press old buttons, create orders or receive notifications (verify with controlled non-sensitive test, not by sharing credentials).
- `nvlbot` stays active; no regressions in ordinary admin/reseller tasks or customer connections.
- On changes to `bot_access.active`, new Super Admin callbacks lose access without restarting.

## Optional Core cleanup of legacy settings (separate operator-controlled action)

After a successful code rollout and SQLite backup, remove revoked ID **only** from the `settings.admin_chat_ids` list using a parameterized, CAS-guarded SQLite transaction. Do not delete `historical_admin_ids`. This cleanup is defense-in-depth; the new code already forbids the old principal and excludes it from notifications. Do not run write SQL against the live database during in-progress financial transactions. Never erase historical audit evidence to hide an incident.

## Security limit

If someone previously knew the shared `MASTER_PASS`, revoking their Telegram account ID does not invalidate that password elsewhere. Rotate shared credentials by a separate controlled, tested process if compromise is suspected. This patch makes the exact revoked Telegram identity unable to use the bot; it is not a general authentication-system redesign.
