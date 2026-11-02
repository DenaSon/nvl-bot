# DenaProbe R3 Phase 2 — source-only DPT/2 Collector and relay witness
**Approved staged release model:** implement three phases in GitHub first, **then** deploy Core, flash ESP32 and run real field tests. This PR must not start, configure or restart anything.

## Source
- Opt-in Collector `--enable-v2` defaults OFF. Adds `POST /api/dpt/v2/telemetry` on the existing loopback-only `denaprobe-collector` HTTP service, **not** a new public listener or bot endpoint.
- Fresh DPT/1 still uses `/api/dpt/v1/telemetry` and its original SHA/HMAC domain, 1KiB limit, schema, DB and ACK. v2 cannot turn old v1 pre-auth success into Data Plane PASS.
- `denaprobe_ingest/dpt2.py` validates the DPT2 domain `DPT2\nPOST\n/api/dpt/v2/telemetry...`, independent key-ID namespace **`v2-`**, raw body HMAC, strict numeric types, nested independent `c` TCP and `z` SSH session/two samples; uses existing DPT/1 validation for legacy fields. Supports exact duplicates and 409 conflicting same boot+q.
- v2 evidence persisted in separate `dpt2_events`, `dpt2_boots`, `dpt2_latest` tables within the same isolated SQLite database; never modifies bot/user data. Raw signed payload stored, target ID + server-owned revision linked, sender-age + server receipt recorded, unknown/stale/history-only never promoted to current state. Two eligible sequential SSH measurements are required to clear v2 monitoring gap, independent from v1.
- Read-only Phase 3 classifier remains **not implemented** here. No notifications, actions, DNS, NPV or GOST integration. No administrator read endpoint for telemetry. Versioned sender and Collector flags require separate operator activation.
- `ops/denaprobe_static_responder.py` is a separately operated relay-local, loopback-only TCP responder. It sends exactly N bytes `0x5A` and closes, up to four concurrent clients; its deployment is **deferred**. Restrict SSH account with authenticated key, no shell, no customer identity and `PermitOpen 127.0.0.1:18180`; reject a public listener or unrestricted forwarding.

## Acceptance before future production activation
- Run `python -m py_compile denaprobe_ingest/collector.py denaprobe_ingest/dpt2.py` and `python -m unittest discover -s tests -p 'test_denaprobe*.py' -v`, plus DPT/1 regression.
- DPT/2 signed fixture golden matches `DenaProbe/contracts/dpt/v2/hmac-test-vectors.json` exactly, including path+version; wrong key ID, cross-protocol signatures and duplicate headers 403.
- Unauthenticated POST 403, version-disabled route 404, valid signed ACK 200 with `v=2`, exact duplicate r=1, modified same identity conflict 409; malformed nested values 422.
- Simulate D0 TCP timeout with no z, D1 first full + second timeout, good two full, unmeasurable local conditions, stale and unknown codes history-only, v1 coexistence.
- Physical E2E and live rollout are deferred until all phases done: operator first takes SQLite **online backup** and previous Collector SHA, confirms existing secure v1 service and active key rotation, stages code, and after explicit approval enables v2. Never put secrets or copied keys into Git.
- Existing DPT/1 sender/collector and NVLBot/GOST remain unaffected. On regression disable `--enable-v2` and restore only the isolated Collector; never delete DB/event history.

**Source-only acceptance != deployed/field accepted.** Admin Rich Message dashboard is exclusively Phase 3 per approved UX contract.
