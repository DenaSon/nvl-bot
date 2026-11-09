# NVL P1 — Manual Core SSH limiter safety rollout (2026-11-09)

**Scope:** Prevent shared Legacy Edge addresses in `10.77.0.0/24` from being added to `ssh_penalty` or selected for `SIGKILL` by the Core limiter. This does **not** implement accurate per-device IP limits behind Edge SNAT.

## Source and prerequisites

- Fix source: PR [#286](https://github.com/DenaSon/nvl-bot/pull/286), merged at `8312b14edad72a2638af6719f156bc8609c368f3`.
- Deployment utility: `ops/nvl_p1_edge_limiter_hotfix.sh` (root-only; explicit `--apply` required).
- Baseline promotion source is pinned to `38a635fd296a2893cf92bce2957ce2050463c7bb`.
- On the live Core, the current `/root/ip_limiter.py` must byte-match the embedded original baseline. If not, the utility **HOLDs without deploying**.
- No need to run `promote_edge_to_core.sh`; **never run that migration script for this hotfix**.
- Nothing in the source merge constitutes deployment to the live Core.

## Manual procedure — only on the authorized Core

First fetch and inspect the merged utility; this is not an instruction to deploy immediately:

```bash
curl -fsSL --connect-timeout 10 --max-time 45 \
  https://raw.githubusercontent.com/DenaSon/nvl-bot/master/ops/nvl_p1_edge_limiter_hotfix.sh \
  -o /root/nvl_p1_edge_limiter_hotfix.sh
bash -n /root/nvl_p1_edge_limiter_hotfix.sh
sha256sum /root/nvl_p1_edge_limiter_hotfix.sh
```

For the initially reviewed utility, expected SHA-256 is:
`956119c4ba2b44c27b26793171922bf361530e1dbec04a4964a8b9f6bf50b4a2`.
If it differs, inspect the current source and **do not assume** the existing review still applies.

Read-only **live-configuration preflight** (downloads pinned source to temporary files but neither replaces `/root/ip_limiter.py` nor restarts the service):

```bash
bash /root/nvl_p1_edge_limiter_hotfix.sh --check
```

Expected when the live limiter matches the original baseline:
`P1_PRECHECK=READY`, `MATCHES_BASELINE=YES`, `FIXED_SOURCE_VALID=YES`, `NO_FILES_CHANGED=YES`.

- `HOLD` / exit 2: the live file differs from the reference. Stop and manually review the differences before deciding on any rollout; **do not force**.
- `ALREADY_PATCHED`: live limiter already equals the pinned fixed version; no restart is needed.
- Any other error: stop, investigate; do not use `--apply`.

Only after an explicit operator review and a READY preflight, controlled production deployment is:

```bash
bash /root/nvl_p1_edge_limiter_hotfix.sh --apply
```

`--apply` rechecks the same preconditions, makes a timestamp-independent unique backup of `/root/ip_limiter.py`, atomically replaces only that file, then restarts **only** `ssh-limiter.service`. It does not restart WireGuard, SSHD, GOST or change iptables configuration. On restart/health-check failure it attempts to restore the prior file and restart the limiter, reporting `ROLLBACK`. The backup path is printed on successful deployment.

## Post-deploy verification

```bash
systemctl is-active ssh-limiter.service
systemctl show ssh-limiter.service -p MainPID -p NRestarts --no-pager
grep -nE 'SHARED_EDGE_NETWORK|is_shared_edge_ip' /root/ip_limiter.py
ipset test ssh_penalty 10.77.0.175
```

The last command should say the Edge IP is **NOT** in the penalty set; a nonzero exit code for that negative membership test is expected. Confirm real customer connection behavior separately. **Do not add Edge IPs to `ipset` as a test.**

## Safety and limitations

- Current Legacy ingress DNAT/SNAT and WireGuard/MTU/ports stay unchanged.
- Non-shared/direct client IPs retain the existing limiter behavior.
- This fixes the group-blocking risk from the limiter's own code; independently configured firewall/security tools are outside this scope.
- Root execution, host state matching, an explicit apply decision and operator observation are mandatory for the real deploy.
