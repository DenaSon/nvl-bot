# NVL Edge — AWG-first operator UI and retired provider

## Product contract

The active **SuperAdmin > Programs > Edge Management** route now shows an AWG-first installation wizard. **AWG** is the only displayed name for new installations. Customer/manager messages use concise stage copy, not internal engineering language.

- `NVL_AWG_NEW_EDGE_ENABLED=1`: permit new AWG Edge setup via `apps_edge_manual_new_awg`.
- `NVL_LEGACY_WG_UI_ENABLED=0` (**default**): do not show old WireGuard install controls or legacy operation list/details; deny stale Telegram callbacks that create or act on a legacy WG manual Edge; deny selecting/confirming legacy WG quick-switch targets.
- `NVL_LEGACY_WG_UI_ENABLED=1`: explicitly restore manual legacy WG creation, relevant operation management and Quick Switch controls **without restoring Cloudzy**.
- `NVL_AWG_CUTOVER_ENABLED=1`: AWG cutover still requires an independently renewed, per-Edge root-owned runtime limiter marker and all existing guarded route checks.

The flags are independent. Turning ON the legacy WG UI flag never bypasses original Core/6G/WG safety preflights.

## Cloudzy retirement

Old Cloudzy menu callbacks and Rich callbacks from historic Telegram messages redirect to the active provider-independent Edge home without executing purchases, VPS provisioning, Cloudzy standby handling or obsolete DNS actions. Cloudzy paid QuickEdge wizard and admin UI startup bindings are removed from the main bot runtime. All Cloudzy/provider purchasing UI is removed from the active navigation.

**Do not physically delete shared historical migration modules yet.** `cloudzy_cz04a`, `cloudzy_cz04b_guarded`, `cloudzy_cz07_queue`, `cloudzy_cz04b_dns` and their associated recovery data structures are still called by manual Edge verification and provider-independent Cloudflare/6G cutover; deleting or renaming them without an audited substitute would regress existing customer routes and recovery. Retiring the **provider and provider UI** is distinct from deleting the shared migration implementation. That replacement must be a separately tested refactor.

The historical provider records are retained in SQLite for audit/recovery; this patch does not delete tables, customers, credentials or route journals.

## Canary acceptance

1. Deploy pinned source separately from merging Git. Leave AWG and legacy flags controlled in Core environment.
2. With legacy UI OFF, test new Edge home, AWG Wizard, old `apps_edge_manual_new` callback, previously issued legacy operation callbacks, legacy QuickSwitch select/confirm, and stale Cloudzy menu callbacks. No legacy/provider UI or action should be reachable.
3. With legacy UI ON in a controlled staging process, verify original manual WG intake remains reachable; turn OFF afterwards. No Cloudzy purchase UI should reappear.
4. Test AWG fresh Ubuntu 24.04 install, pinned SSH, NAT persisted after reboot, safe Standby, real off-platform NPV client, limiter readiness, authorized Quick Switch, recovery and former rearm.
5. Full Python checks and release safety jobs must pass before merging. No deployment or network mutation is implied by this PR.
