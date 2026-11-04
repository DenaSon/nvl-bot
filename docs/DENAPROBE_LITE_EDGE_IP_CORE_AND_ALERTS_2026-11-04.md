# DenaProbe Lite — signed Edge DNS IP in Core and Telegram
Date: 2026-11-04
Status: source PR; **no live deployment or ESP32 flash implied**.

## Definition
Target hostname + port are read from Core's existing versioned `targets`
registry (`target_id`, `revision`); the board supplies the **IPv4 actually
returned by DNS for the Edge hostname in the same probe cycle**. The IP is
reused by the ESP32 TCP preflight and SSH session. It is not Core's IP,
and a DNS lookup performed by Core later is **not** interchangeable.

Optional, signed DPT/2 root field:
```json
{"ei":"198.51.100.22"}
```
Example address above is documentation-only. The board never sends `ei`
after Edge DNS failure. Absence is displayed as unknown; a prior IP must
not be reused as the current observation.

Only `esp32dev_lite_wire_compile` adds `ei` to the signed packet.
The older Lite profile emits none of the new `j`, `ei`, or `z.rt=2`
evidence and remains compatible with the currently deployed Core.

## Core validation and storage
DPT/2 only; DPT/1 is unchanged. `ei` must be a canonical dotted IPv4,
not a URL, hostname, IPv6, port or arbitrary display string. The value
may be an RFC1918/reserved address: DNS anomalies themselves are important,
and no inference that the resolved address is publicly routed is made.
The sender HMAC authenticates the complete JSON including `ei`.
The existing `dpt2_events.raw_json` persists it atomically under
(device,boot,sequence); **no SQLite migration** is needed.

Also accepts Phase 2 Lite `j={u,s,ms}` for password login and `z.rt=2`
for an 8KiB/8KiB controlled-public-target witness. Route=1 still denotes
Core loopback only. The new route remains a limited transfer observation,
never an unqualified VPN-health or censorship declaration.

## Display semantics and safety
- Dashboard: registered Edge hostname and port (same target revision),
  plus fresh signed sample's `ei` or “unknown”.
- Incident detail: the last known eligible sample for that incident/target,
  explicitly labeled as the last witness.
- Telegram OPEN/CHANGE/RECOVERED: `ei` is taken from the **original
  transition evidence sequence**, constrained to a recent matching
  receive-time and exact target revision. On absent or ambiguous matching
  evidence it is omitted / marked unknown, never copied from a newer DNS
  observation. This protects old incident history from DNS IP drift.
- Do not put passwords, account identities, DNS resolver, internal Core IP,
  or SSH private keys in any Rich message.

The existing RBAC/superadmin recipient selection, anti-duplicate delivery
intent and cooldown remain unchanged. A failed authenticated transfer on
one controlled public destination may indicate an SSH/target/path problem;
it does not establish that every NPV destination is unavailable. Password
rejection, Wi-Fi failure and SSH host-key mismatch remain UNKNOWN for
filtering attribution.

## Deployment order
1. Merge and deploy this **Core** source after CI passes, with the current
   Core services, HMAC keys, DB, Telegram roles and target revision retained.
2. Verify DPT/2 old boot and legacy Core-loopback samples remain accepted.
3. Merge the matching **board** source for `ei`, then provision and flash
   the **wire** profile only after the Core update and the approved public
   responder / per-account Forwarding checks.
4. Verify serial real SSH/Auth/8KiB sample results, signed telemetry HTTP200,
   row's stored raw_json `ei`, fresh Dashboard hostname/IP/port and an
   opt-in supervised test notification. Avoid sending artificial incident
   alerts to production admins until this gate passes.
5. Rollback: restore previous Core source; before doing so flash the board's
   older wire-compatible profile. No destructive DB cleanup is required.

This is source compatibility/UX completion; field acceptance and actual
notifications remain to be verified on real MCI data.
