# Change Server — Phase 5: Cloudflare Cutover + External Verification + Rollback

Phase 5 owns the external cutover after Phase 4 has completed the final database
synchronization and started/verified the destination.

It intentionally does not modify Marzban data. Its mutable scope is limited to
the exact Cloudflare A record selected by zone + hostname, plus service-state
recovery if the post-cutover verification fails.

## Inputs

Required:

- source SSH credentials
- destination SSH credentials
- migration job ID
- Cloudflare zone name
- exact hostname
- scoped Cloudflare API token

The token is never accepted as a normal CLI argument. The normal path reads it
automatically from the server environment variable:

    NVL_CLOUDFLARE_API_TOKEN

For the production bot, systemd injects that variable from the root-only
EnvironmentFile. No Cloudflare token is sent through Telegram, stored in the
bot database, printed in logs, or placed in subprocess arguments.

A hidden token prompt exists only as an explicit manual/emergency fallback via
`--prompt-cloudflare-token`.

Recommended token permissions:

- Zone / DNS / Edit
- scoped only to the exact zone used by the migration

## PLAN_ONLY mode

PLAN_ONLY is read-only.

It verifies:

- source/destination identity
- exact Cloudflare zone
- exactly one A record for the requested hostname
- current A record content
- current proxied state
- Phase 4 FINAL_SYNC_COMPLETE marker, when present
- source runtime state
- destination runtime state
- direct destination API reachability with the real hostname as TLS SNI/Host
- direct destination TCP reachability for the configured Xray ports

Before Phase 4 FINALIZE, PLAN_ONLY is expected to report the Phase 4 marker as a
blocker. This is useful because Cloudflare token, zone and record selection can
be validated before downtime starts.

## CUTOVER mode

CUTOVER requires the exact confirmation phrase:

    CUTOVER

It also requires:

- Phase 4 FINAL_SYNC_COMPLETE
- source stopped
- destination running
- direct destination API precheck passing
- all configured destination Xray TCP ports reachable from NVL
- Cloudflare A record still pointing to the old/source IP
- proxied=true by default

This prevents stale or unexpected DNS state from being overwritten.

## Cloudflare mutation

Phase 5 resolves the exact active zone and exact A record, then uses a partial
PATCH that changes only:

    content = NEW_IP

The existing proxy state and other record properties are preserved.

After PATCH, Phase 5 reads the record again and requires the API-visible content
to converge to the destination IP.

## Verification after cutover

Phase 5 verifies:

1. Cloudflare API reports the A record pointing to NEW_IP.
2. The public hostname responds on the Marzban API port through Cloudflare.
3. The destination IP accepts TCP connections on every configured Xray port.

The public hostname verification uses normal TLS validation because the request
terminates at Cloudflare.

The direct origin precheck performed before cutover preserves the hostname as
TLS SNI and HTTP Host. Certificate verification is intentionally disabled for
that direct probe because a Cloudflare Origin CA certificate may not exist in a
normal public trust store.

## Automatic rollback

If Cloudflare was already changed and a post-cutover verification fails, the
default recovery sequence is:

1. PATCH the exact Cloudflare A record back to OLD_IP.
2. Verify the Cloudflare API reports OLD_IP again.
3. Stop the destination runtime.
4. Restart and locally health-check the source if it is stopped.
5. Write CUTOVER_ROLLBACK_COMPLETE with recovery status.

Important: any rollback after external cutover can lose writes that reached the
destination before rollback. The marker records this warning explicitly.

Automatic rollback can be disabled for controlled debugging, but it should stay
enabled in the normal bot workflow.

## Locks

CUTOVER obtains an exclusive migration lock on both source and destination:

    /root/nvl-migrations/.cutover-lock

This prevents concurrent cutover operations.

## Completion marker

Successful cutover writes:

    /root/nvl-migrations/<job-id>/CUTOVER_COMPLETE

It records:

- old/new IP
- zone + hostname
- DNS record ID
- proxied state
- Cloudflare record verification
- hostname API verification
- direct destination ports
- rollback_performed=false

## CLI

Read-only Cloudflare/cutover preflight:

    python3 -m server_migration.phase5_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --hostname gate.example.com \
      --zone example.com \
      --plan-only

Actual cutover:

    python3 -m server_migration.phase5_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --hostname gate.example.com \
      --zone example.com \
      --cutover \
      --confirm CUTOVER

Normal execution requires no token flag when
`NVL_CLOUDFLARE_API_TOKEN` is already present in the process environment:

    python3 -m server_migration.phase5_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --hostname gate.example.com \
      --zone example.com \
      --plan-only

To use a differently named environment variable, override only the variable
name:

    --cloudflare-token-env MY_SCOPED_CF_TOKEN

For controlled manual recovery only, an operator may explicitly request a
hidden prompt:

    --prompt-cloudflare-token

The CLI never falls back to an interactive Cloudflare-token prompt implicitly.
Do not place the token itself in shell history.

## Phase chain

    Phase 1  Detector / Preflight
      ->
    Phase 2  Backup / Transfer
      ->
    Phase 3  Restore / Offline validation
      ->
    Phase 4  Final Sync / IP Rewrite / Start / Local Verify
      ->
    Phase 5  Cloudflare Cutover / External Verify / Immediate Rollback

The bot UX should ultimately execute Phase 4 FINALIZE and Phase 5 CUTOVER as a
closely chained operation to keep the source-stop-to-cutover interval short.
