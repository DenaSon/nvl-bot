# NVL — AWG-first Edge Management UI (2026-11-14)

Scope: bot-side UI, intake authorization and historical callback routing. No production deployment, provider API calls, DNS writes, customer migration or Core service restart.

## Operator workflow

SuperAdmin private chat → برنامه‌ها → 🌐 مدیریت Edge → 🖥 سرورها و ساخت Edge → ➕ افزودن Edge با AWG.

The AWG wizard asks for a fresh Ubuntu 24.04 Edge IPv4, independent SSH host-key verification, and Root password in private chat. The Telegram password message must be deleted before it is consumed. Existing Core AWG provisioning and journalled EDGE_READY → STANDBY → Manual Quick Switch flows remain guarded.

The UI uses **AWG**, never the full protocol name, and displays three setup steps followed by installation and Standby verification. Development-stage concepts and retired provider workflows are not advertised.

## Feature flags

- NVL_AWG_NEW_EDGE_ENABLED=1 admits the AWG new-edge wizard when its Core dependencies are installed; default OFF.
- NVL_LEGACY_EDGE_UI_ENABLED=1 restores legacy WG new-edge creation button and callbacks; default OFF. With OFF, no legacy creation in the menu, host-key step, password prompt, pending message intake or installer.
- NVL_AWG_CUTOVER_ENABLED=1 enables the existing separately verified AWG Cutover gate only after its Runtime Limiter witness; default OFF.
- NVL_MANUAL_QUICK_SWITCH_ENABLED controls independent Manual Quick Switch release; unchanged and default OFF.

The legacy flag restricts **new WG creation**. It does not remove existing WG Edge inventory, read-only history, or permitted recovery/Standby management.

## Retired provider UI

The old Cloudzy administration panel is no longer imported or instantiated. Historical provider action callbacks (apps_cz* and u7:) are routed only to the authenticated Edge-management hub; they cannot trigger provider purchases, VPS management, provider quick relay or historical migration actions.

Do not delete internal cloudzy_cz04/cz07 adapters or historical database records during UI retirement. The live provider-independent Manual Quick Switch/Cloudflare DNS, 6G conflict guards, and recovery still use these components. A complete internal-code removal requires a separate provider-neutral adapter migration and historical-data review.

## Validation and release

- Both creation flags OFF: no Add Edge option, but existing inventory and navigation remain.
- AWG ON, legacy OFF: exactly one new Edge option («➕ افزودن Edge با AWG»); old callbacks and pending credentials cannot start legacy setup.
- Legacy ON: old creation may be deliberately restored without modifying existing Edges.
- Old provider callbacks cannot reach any paid or effectful provider handler.
- Cutover remains gated by the Runtime Limiter witness, independent client connectivity evidence and Quick Switch authorization.

Run Python and privileged CI and deploy through the pinned release worktree with DB backup, controlled bot restart, and private-chat UI smoke tests. A GitHub merge is not a Core deployment.
