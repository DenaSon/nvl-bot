# NVL K2 — Telegram new-Edge port type hotfix (2026-10-14)

## Evidence and scope

On the deployed code-only K2 release `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a`, the existing Telegram `EDGE_NEW_PORT` handler stores `text.strip()` as a string (e.g. `"2252"`). The integrated K2 admission gate requires an integer `customer_port`, so it rejected the new disposable VPS **before remote provisioning** with a generic K2 HOLD message. A second working VPS reproduced the same refusal; successful root SSH alone does not prove the rest of K2 onboarding.

## Fix

- A strict, fail-closed decimal-string/int normalizer executes only in the K2 opt-in branch.
- The **same integer** is sent to both pre- and post-provisioning K2 admission checks and into the original immutable `StagePin.customer_port` at onboarding.
- Invalid, out-of-range, boolean, float, whitespace-padded and non-ASCII port values HOLD before host mutation.
- The unchanged legacy `_provision_new_edge_sync` input remains the original type. Legacy's optional Stage path retains its prior default `customer_port=0`.
- No changes to wg0, customer assignment, UID/PAM, failover, public DNS, shared 6G, or root infrastructure from this source change.

## Verification and acceptance

- Tests: `python3 -m unittest tests.test_edge_egress_k2_phase1_wizard -v`; full Python checks and Edge stage-only checks on the exact PR HEAD must PASS before merge.
- Green source CI is **not** VPS acceptance. After controlled *code-only* Production deploy, test **one new, unused VPS** through the Telegram wizard.
- Confirm root-pinned SSH key, Ingress wg0 peer /32, Stage/registry identity, and stored StagePin customer port `2252` without printing secrets.
- Retest independent dedicated Edge namespace IPv4 and finally real client SSH/SOCKS traffic only after separate F4/PAM/boot/fail-closed review; **do not move customers automatically**.
- If a previous VPS may have been partly provisioned, reconcile Core/Edge wg0 and Stage/registry first. Never repeat that same wizard blindly.

## Deployment constraints

Use the canonical K2 code-release runbook for exact SHA pin, staging/compile/tests, SQLite and code backup, deployed-file hash verification, service restart, post-restart smoke and rollback. This fix is not permission to enable protected customer transfer or any unsafe K2 feature flag.
