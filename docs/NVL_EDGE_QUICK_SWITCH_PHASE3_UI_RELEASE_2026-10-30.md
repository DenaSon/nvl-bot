# NVL — Phase 3: Edge operator UI / Quick Switch

**Status:** Source-only until CI, PR review and separate Core publication. Active customer Edge `45.59.126.73` and the 446 active SSH accounts are not changed by this PR.

## Scope
- Admin Programs now links to **🌐 مدیریت Edge**. Cloudzy purchase, credits, provider inventory, CZ07 batch and old Rich Cloudzy navigation are hidden from newly rendered menus. Their modules, existing journals and legacy callback handlers are retained for historical compatibility.
- Rich-only Edge UI: active Edge and account count, manual standby choices, real independent NPV client witness, one-use confirmation, status/recovery, explicit DNS retry confirmation, previous 2026-10-29 emergency attestation.
- Manual Edge standby button now points to Quick Switch. Old manual review/GO buttons on preexisting messages are redirected to the safe new UI, rather than scheduling a CZ07 batch.
- Engine is wired to existing CloudflareExactDNS and pinned NAT/WG/SSH probes with provider API verification excluded. Existing 6G + K2 protected mutation guard is supplied explicitly. No SSH account recreation or password changes.

## Release flag (OFF by default)

`NVL_MANUAL_QUICK_SWITCH_ENABLED=0` (default): operator can see Edge UI, diagnostics and preview, but cannot execute cutover, DNS retry or external attestation. For activation only after isolated manual Standby acceptance, set to 1 and restart the service via a separate approved deployment. Keep OFF during first Core code-only deployment.

## Validation
1. Run all Python and Root stage tests in PR.
2. Deploy code-only with backup and SHA verification; read only route, DNS, WireGuard and current account roster. Confirm Cloudzy buttons absent and target source remains unchanged; flag OFF blocks confirmation.
3. Independently create and validate a **new disposable, unused manual Edge**. Test pinned SSH management, customer 2252, NAT, WG and real NPV client ISP acceptance without moving current production users.
4. Only on explicitly approved staging/testing topology, set flag ON and exercise Quick Switch preview, confirmation, Cloudflare exact record change, single SQLite CAS, and actual CREATE/RENEW/NPV client traffic. Test partial DNS, callback duplicate, timeout and resume.
5. Do not blindly switch current default or re-run previous emergency cutover just to test. Old CZ07 HOLD remains historical and untouched; the new Quick Switch does not depend on that queue.
6. The previous manual rescue receipt is an independent, append-only attestation, not a fabricated CZ07 DONE. Only permit with the original emergency event and exact roster count.

**Deployment boundaries:** GitHub merge is not Core deploy. Without isolated field validation, the feature flag must stay OFF. Keep backups and route postcheck available before enabling.
