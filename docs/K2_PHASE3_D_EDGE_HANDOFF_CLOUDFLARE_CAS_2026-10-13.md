# K2 P3-D — Guarded Edge Handoff and Cloudflare CAS

**State:** GitHub source-only; disabled by default; no production SSH,
WireGuard, DNS or Cloudflare writes. F4 disposable release remains open #106.

## Separate two distinct handoffs

1. **Egress-only 6G/6H**: `run_guarded_6g6h_handoff()` is the
   source for protected UID Egress routing changes. It is **not** a public
   DNS/SSH ingress migration. It calls `assert_public_ingress_dns_unchanged`
   and only protected-mapping CAS; never the legacy SSH-account rebuilder
   or DNS cutover. Automatic 6H additionally requires a fresh independent
   incident and is NOT wired/enabled in the bot.
2. **Ingress+Egress migration**: `Existing6GProtectedHandoffAdapter`
   provides the full candidate→F4→PAM admission fence→drain→UID REJECT→
   repin→proof→frozen mapping CAS→public Cloudflare A record updates→
   verify→release saga. An immutable `HandoffSnapshot` is captured
   under the existing 6G lock. **No Core as target or fallback**.

## P3-D additions

- `ProtectedCloudflareDNS.preview_edge_to_edge` binds the same zone,
  exact public domains and single DNS-only A-record IDs, source contents,
  TTL and modified_on fingerprints, and refuses an AAAA record. Complete
  first-page record-list evidence must be proved (no pagination drift).
- The record writer checks the original pinned identity before its first
  write, then rechecks that individual record again immediately before
  each PATCH, verifies the provider response and re-reads it. It requires
  a supplied `guard()` before every mutation. The existing live driver
  now injects its `_lease` guard into each provider step.
- `GuardedIngressCloudflarePort` adds the **source-only** stricter proof:
  exactly one `failover_operations` RUNNING record with correct operation,
  source and target, correct protected-ingress DNS phase/kind,
  `edge_egress_protected_mode=1`, unchanged default host/DNS source,
  F4-admissible STAGED target not equal to Core, complete active-account
  set, exact FROZEN runtime target mappings with still-PROTECTED permanent
  bindings, and an independently injected admission/Ingress/UID proof
  before every provider write. No live `IndependentHandoffProof`
  registration is present. This port is not yet connected to Telegram.
- Existing handoff source now handles async CancelledError/SystemExit/
  KeyboardInterrupt at candidate or customer-routing boundaries:
  attempt single-UID freeze, retain protected RUNNING journal and
  re-raise. Unknown provider writes remain an operator-only HOLD.

## Critical Cloudflare limitation

Cloudflare's per-record REST PATCH plus pre-write fingerprint checking is
**not a server-enforced atomic compare-and-swap**. A concurrent outside
actor may still race between our final GET and PATCH; two or more DNS
records also cannot be updated atomically. Therefore this is a
*best-effort application-level CAS with fail-closed reconciliation*.
The operational release additionally requires exclusive provider-side
change governance, independent reread/propagation proof and operator
acceptance. Any timeout, partial response, record-identity drift,
unconfirmed DNS propagation or lost 6G lock => leave UIDs FROZEN,
journal RUNNING/RECOVERY_REQUIRED and manually reconcile; never rewrite
public DNS to Core or auto-unfreeze subscribers.

## Acceptance and blocked release

Offline tests in `tests/test_edge_egress_p3_dns_cutover.py` and
`tests/test_edge_egress_p3_handoff_cancel.py` simulate:
multi-domain cutover, incomplete snapshot, AAAA, unsolicited DNS edits,
lease loss after first write, 6H Egress-only no-DNS, UID mapping drift,
F4 rejection and abrupt asyncio cancellation. No real provider/API used.
Do not claim actual packet-level IPv4/DNS/IPv6 proof from fake ports.

- Flag `P3D_INGRESS_DNS_EXECUTOR_ENABLED=False`. No default privileged
  port, no Telegram execute hook, no P3-F release and no automatic 6H.
- P3-E closes orphan/owned resource teardown, P3-F wires reviewed
  administrator UI; F4 lab issue #106 must pass first before any
  production protected release.
- Original 6G lock & Journal, cloudflare zone config, host_pool, SSH
  and per-UID runtime schemas are reused; no new DB migration.
- Core remains at previously pinned production source; no deployed file
  or live network configuration is changed by this PR.
