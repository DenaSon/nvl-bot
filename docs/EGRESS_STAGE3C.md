# NVL Stage 3C — Egress intent control plane (PLAN_ONLY)

Status: **implementation in a draft stacked PR**. This phase does not expose a public SSH port, change live connections or switch a customer's Egress IP.

## Why this is NOT the existing Edge migration

- \`ssh_accounts.host\` remains the **Ingress/endpoint** metadata used by the existing Core/Edge architecture.
- The Phase 6G/6H failover engine changes Edge/Standby ownership and public DNS; it is not an Egress routing engine.
- Stage 3B locally demonstrated that an isolated SSHD with forwarding can reach the public internet via Edge \`216.126.229.12\` and fail closed when its WG interface is administratively lowered.
- Those tests do **not** prove safe public listener exposure, per-user steering, UDPGW behavior, all link-failure modes, or automatic switching.

## What's implemented

- \`egress_manager.py\`: additive \`ssh_egress_targets\` metadata table and \`ssh_egress_intents\` journal.
- The journal supports \`PLANNED\` and \`CANCELLED\` only; **there is no APPLY or DONE transition**.
- A single pending plan per username, SQLite \`BEGIN IMMEDIATE\` write lock and parameterized queries; conflicts with an active Phase 6G \`failover_operations\` are rejected.
- Existing active SSH accounts only; admin role and valid Telegram actor ID are mandatory for any write.
- Admin-only, feature-flagged Telegram entry in SSH user detail; options record/cancel a *proposal*, not an actual cutover.
- Never writes \`ssh_accounts.host\`, \`host_pool\`, settings, firewall, systemd, DNS, WireGuard or production SSH files.
- \`NVL_EGRESS_INTENTS_UI=0\` by default. No notification loops or automatically triggered actions.

## Register one DRAFT target (future deliberate operation, NOT part of a code deploy)

Only after verifying that this exact namespace, IP, and local port are valid **on the running Core**, and after DB backup:

\`\`\`bash
python3 egress_manager.py --db /root/master_bot.db register-draft \
  --target-id edgea \
  --edge-public-ip 216.126.229.12 \
  --namespace nvl-egress-stg1 \
  --internal-ip 10.78.111.2 \
  --local-port 22284 \
  --confirm-no-route-change

python3 egress_manager.py --db /root/master_bot.db list
\`\`\`

The command records *metadata only*. These examples are **not** a recommendation to run on Production before a release/DB backup and review. Do not paste real credentials into commands or GitHub.

## Telegram navigation

When explicitly enabled in the service environment and \`nvlbot\` is deployed/restarted in a controlled release:

Admin → SSH account detail → \`درخواست Egress (آزمایشی)\` → choose DRAFT target → \`PLANNED\` journal. Optional cancel.

The panel explicitly states no IP/route changed. Non-admin and disabled-state forged callbacks are rejected server-side.

## Limitations / required next work

**Stage 3D (not implemented here)** needs explicit edge-specific listening endpoints, reliable public ingress transport, credential validation (the tested pilot uses password/PAM), confirmed client configuration delivery or per-user traffic steering, strict PermitOpen/forwarding restrictions, verified fail-closed policies under more failure modes, and an evidence-backed apply/rollback journal. Existing SSH sessions may need reconnecting.

Do not expose the Stage 3B \`127.0.0.1:22284\` proxy publicly, or infer that an intent changes a customer's external IP.

Existing Stage 3A PR \`#81\` is a prerequisite: this PR should be reviewed as a stacked change and rebased after #81 merges.

## Verification

\`\`\`bash
python3 -m py_compile egress_manager.py bot_final_v49-2.py
python3 -m unittest discover -s tests -p 'test_egress_intents.py' -v
python3 -m unittest discover -s tests -p 'test_egress_pilot.py' -v
\`\`\`

All tests use throwaway SQLite databases, and no production route is exercised by tests.
