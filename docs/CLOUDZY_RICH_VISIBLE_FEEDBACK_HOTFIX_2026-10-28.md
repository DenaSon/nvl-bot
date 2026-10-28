# NVL Phase 7 hotfix — visible Rich UI feedback (2026-10-28)

## Symptom and evidence

An active NVL admin tapped «Unified Edge | داشبورد Rich» and saw no apparent response. The callback handler acknowledged the Telegram query, but the Rich bridge silently returned `DENIED`, `HOLD`, or `UNCHANGED` without posting any visible feedback. The provided SQLite excerpt only queried `cloudzy_rich_delivery_outbox WHERE status != 'SENT'`; `NO_RECORDS` there **does not rule out already acknowledged SENT rows** or a prior empty-card attempt.

The same Core contains a new CZ03/CZ06 receipt for `144.172.119.190` at `EDGE_READY/READY`, with UO at `CLIENT_E2E/NEEDS_ATTESTATION`. Separately, a CZ07 job `97ae84fa...` for `45.61.180.119 → 104.194.141.63` is `VERIFYING`, moved 485 of 485, not independently business-accepted. These facts are independent of the Rich UI rendering problem.

## Narrow patch

- On private admin click, show an ordinary diagnostic Telegram message for Rich `DENIED`, `HOLD`, and `UNCHANGED`. It is *not* a replacement Rich-card render or general HTML fallback. The original `sendRichMessage`, durable outbox, and no-auto-replay constraints remain unchanged.
- Map known delivery/ownership codes to limited Persian error text; unknown and unexpected exceptions never expose raw DB values, credentials, body, or Telegram token.
- Never send diagnostic feedback to a group/channel or to another user's chat.
- No change to provider purchase, DNS, installer, WireGuard, 6G, CZ07, migration, SSH, or the Unified coordinator. No restart/deploy on production by this PR.

## Server-side read-only verification

Inspect Rich delivery outcomes in the actual database rather than filtering out SENT rows:

```sql
SELECT kind, substr(operation_id,1,12) AS op,
       status, reason, method, version, message_id
FROM cloudzy_rich_delivery_outbox
ORDER BY updated_at DESC, attempt DESC LIMIT 10;
```

Do not log/paste Telegram bot tokens. Verify provider-safe business journal separately.

**Release:** CI green, then deploy only `cloudzy_rich_bridge.py` and associated tests if needed via pinned commit and backed-up file, restarting only `nvlbot`. After release, tap the dashboard and inspect visible Persian feedback; if a known Telegram Rich HTTP 400 is reported, compare the message payload with the official Bot API 10.3 schema in a separate transport/render patch.
