# K2 P3-F — Telegram Integration & Final UX

## Source-only delivery
P3-F uses the **existing** NVL admin-only `hpeg_*` handlers (no new bot,
bot token, session store or parallel menu), with `edge_egress_p3_telegram.py`
as a pure, bounded display layer. The shared Core/WireGuard/SSH runtime and
existing Phase2 registry/6G proof functions remain unchanged. UI language
is concise Persian for operators: no phases, CAS/UID/PAM, code details or
internal HOLD identifiers in the chat.

- **Dashboard:** exactly two Edge buttons per row, paging based on
  the existing `read_egress_dashboard` snapshot; basic status/default.
  `➕ افزودن سرور`, `🧹 پاکسازی`, Refresh, Help and Back.
- **Edge details:** two-column buttons preserve every existing action:
  connection inspection, eligible live-IP read-only probe, protected-user
  selection, current readiness, pinned local-stage inspection, prepare
  operator review, safe metadata deletion, refresh and back. On unknown
  stage states, the message never claims a live protected route.
- **Protected user:** keeps original read-only
  `edge_egress_phase2_console.preview_uid_html` eligibility checks and
  one-shot actor/chat-bound selection for `UID_ATTACH` / `UID_FREEZE`
  reviews. These reviews remain acknowledgment-only; no kernel call.
- **Retire (metadata-only):** retains real `plan_retirement`,
  actor/chat/expiry-bound `issue_ticket` and
  `retire_metadata` backup-first CAS. Confirmation explicitly says
  removal is from the list only, not VPS destruction; failed/stale
  confirmation remains safe and user-readable. The old generic
  `hpdelyes_` path retains its K2 fence.
- **Orphans:** `hpeg_orphans` is an *admin-only read-only stage-directory
  listing*, with root-owned, private path checks and no claim that the
  folder proves orphanhood. It does not invoke P3-E root worker, remove
  netns/WG/VETH/REJECT, modify DB or reveal SHA/pins.
- **New Edge wizard:** reuses exact existing
  `staged_edge_result` success validation before displaying a short
  confirmation; one per-user step of the old wizard is unchanged.

## Security boundary
P3-A through P3-E remain **disabled for live execution** in this
source release. P3-F does not issue or consume their executable tickets,
register a privileged host implementation, call Cloudflare PATCH,
auto-accept F4 or restart SSH/WG. The only mutating button retained is
the *already existing and reviewed* Phase2 **metadata-only** delete
on an Edge with no kernel or protected UID dependencies.

`P3F_LIVE_EXECUTION_ENABLED=False` is explicit. A true protected
provision/attach/cutover/retire executor must wait for the independent
live disposable F4 (#106): PAM account/direct-tcpip, BootGuard ordering,
UID routing, IPv4/IPv6/DNS/DoH leak tests, real SSH/SOCKS, tunnel loss
and reboot evidence, independent rescue, and a separately reviewed
root-only pinned HostSafety/Worker adapter. Operator approval for a
preview is never promoted to host-privileged permission.

## Tests
`tests/test_edge_egress_p3_telegram.py` checks two-column callbacks,
paging, escaped HTML, no internal UI strings, read-only orphan listing
even for symlink/untrusted paths, one-shot review/retire wiring and
deny-first admin-only callback. Existing CI, Telegram integration and
Phase2 retire tests must remain green before any merge.

After merge, **no Core production code is deployed**. Issue #108 remains
open through lab approval and controlled pinning/deploy; #106 remains
open until independently attested real F4 acceptance. The historic e7
Core kernel remnants and UID1644 IPv6 proof are unresolved.
