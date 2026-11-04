# DenaProbe Lite: route 3 public HTTP over SSH — Core rollout (2026-11-04)

## Scope
This is a small additive upgrade to the existing DPT/2 Collector, DP3 Detector
and Telegram Rich Admin. No DB migration, new bot, dedicated responder,
second VPS or new public DNS name.

Signed \`z.rt=3\` records two 8192-byte HTTP BODY downloads from
\`speedtest.tele2.net:80\`, \`GET /1MB.zip\`, \`Range: bytes=0-8191\`,
on separate channels in one pinned/password-authenticated SSH session.
Signed \`j\` gives login evidence and \`ei\` gives the real Edge IPv4
resolved by the ESP32 before TCP/SSH. Hostname and port of the Edge itself
remain versioned in the existing Core target registry.

Route 1 remains private Core-loopback and route 2 remains historical
fixed-payload public responder evidence. Route 3 must not be reinterpreted
as either of those types. All values are observational and do not prove
the complete NPV client pathway.

## Alerts
- Two fresh route3 successes: tested HTTP-over-SSH path observed healthy.
- Two fresh, continuous \`z.s=40\` body/read timeouts: \`D2\` suspected
  downstream HTTP data unavailability. This may be Tele2 service failure.
- Redirect/HTTP status errors, partial/early EOF, setup/write/forwarding
  errors and rejected account credentials: UNKNOWN or diagnostic only,
  not a claim that MCI is filtering an NPV tunnel.
- SSH transport loss and independent TCP failures retain separate
  existing source-bound failure classes.
- Rich messages report the fixed HTTP witness, the Edge DNS IPv4
  from the *triggering* signed measurement, and the registered Edge domain
  and port. Existing superadmin recipient/opt-in and dedup controls stay.

## Required operator steps
1. Deploy the Core release containing PR #282 before flashing Board PR #22.
   GitHub merge alone does not deploy Core.
2. Preserve current HMAC keys, database, target revision, admin roles and bot
   feature gates. Do not reset telemetry/history.
3. On SSH terminator, verify \`curl -4 -I --max-time 10
   http://speedtest.tele2.net/1MB.zip\` and that test account has
   *restricted* local TCP forwarding to \`speedtest.tele2.net:80\`.
4. Enable only \`esp32dev_lite_wire_compile\` after its local ignored
   private header is set to the fixed test destination (Board runbook 025)
   and the Core version is confirmed live.
5. Observe signed \`rt=3\` telemetry HTTP 200 ACK, recent sample
   Edge \`ei\`, Rich admin dashboard, and one supervised incident/recovery
   scenario if available. Otherwise don't claim field acceptance.

Rollback board wire profile first if Core must be downgraded.
No standalone static responder is used by route3; leave the old
127.0.0.1:18180 Core service untouched for historical experiments.
