# K2 legacy ingress compatibility and actual release checkpoint

## Owner-confirmed Core state, 2026-10-16

Production application `df52db715c4042b8b2bbe2817b5d12b4bf8e36c0` was
published successfully on CloudVPS121849 (`209.200.246.198`): 13 replacements,
59 additions, stable bot PID `4133554`, code backup
`/root/nvl-k2-predeploy-df52-zvwttvmd`. The owner independently confirmed
installed source verification, DB quick check, zero running operations and
working Programs → Manage output, navigation and wizard UI. Do not redeploy
that publisher or treat older pending-deploy notes as current.

The new isolated Edge `e12` (`144.172.84.112`) completed the existing wizard,
original P1 transport activation and a separate Telegram re-probe returning
the exact expected public IPv4. Allocation and readiness remain STAGED.
No account has been transferred and no customer IP fix is accepted yet.
P1 transport activation does not prove persistent customer boot/PAM safety.

Single, native operations and Batch are OFF; no field qualification is
installed and the new PAM hook is absent. The owner authorized their
test account `nvl0555`, UID `1636`, for the first customer trial. It has no
active processes, F2 runtime/binding rows or reported IPv4/IPv6 UID rules.
Its historical host is `172.86.111.69`, port 2252. The root registry lacks
that host; live wg0 endpoint inspection found one candidate `10.77.0.8`.
The fully specified SSHD connection check returned UsePAM, password auth and
TCP forwarding enabled. Bare `sshd -T` failed because Match LocalPort requires
lport; it was not an SSH configuration fault. These observations alone do
not authenticate the user's current ingress.

## Source correction

PR #155 merged at `febcc45c505e5bdc6a712745651dd8f87c2e1f91` after
2,492 full source tests, 2,492 extracted-root tests and 1,745 stage tests on
each supported Python version. This source is not installed on Core yet.
The separately reviewed `ops/k2_core_code_publish_febcc.py` handles the exact
one-time df52 → febcc code delta; adding that helper does not change the
application release SHA. Its execution and runtime enablement remain unconfirmed.

The existing native review now recognizes an unregistered legacy candidate
without requiring the manager to run a Core command or edit JSON. It requires
one active DB listener, exact live wg0 endpoint/key/32 ownership, no overlapping
peer, no reused registry/allocation/stage-pin identity, and the same OS UID.
An existing unique source allocation keeps its original Edge ID; discovery
does not create a second identity for the same public IP.
These facts select a candidate only. The existing pinned SSH/SOCKS client must
actually authenticate the selected account through that public listener.

A fresh journald cursor bounds an independently read Core sshd acceptance
record: exact username and observed wg0 peer, trusted root UID/executable,
same boot and exactly one matching login. Missing, ambiguous, spoofed or changed
observations hold before publication. journald is a Core release dependency;
neither an Edge-reported address nor historical DB host is source authority.
The existing atomic registry append rechecks this identity under its original
file lock and preserves every other peer. An exact concurrent append is safe
to reuse; conflicting identities are never overwritten. The original source
journal is then refreshed through its existing CAS path.

This writes ingress identity metadata only. It never changes wg0, UID routes,
account host/password, DNS/default, F3 readiness, release profiles or a 6G lease.
No extra bot, worker, process, transfer engine or execution journal is added.
The transport/migration release gates remain unchanged. The bot transfer entry
states when Core setup is incomplete instead of offering a ready-looking menu.

## Validation and remaining acceptance

Focused regression tests cover
automatic discovery through real disposable SQLite, trusted Core SSH observation,
authentication failure, wrong/duplicate/missing acceptance, wrong boot or log
producer, WG drift, identity reuse and atomic append drift/idempotence. They are
not live SSH, kernel, reboot or external-device acceptance.

The first CI head found one old source-refresh fixture that implicitly depended
on the runner being root. Its intended root observation is now explicit, with
a separate regression proving a genuinely nonroot process cannot discover or
register a source. Production root checks are unchanged. Exact final-head CI
results belong in the pull request.

The source correction is not installed on Core merely by committing/merging it.
One-time release/Core field qualification and runtime enablement remain pending;
never fabricate that report or READY to enable buttons. First/Nth UID PAM and
guard setup already run automatically inside the original P3/6G operation once
the native runtime is legitimately released. Normal manager operations must be
entirely in Telegram, with no per-account CLI or witness-file work.

Next: review the exact fix and CI, publish the source once through the owner's
manual SSH deployment workflow, complete release qualification and Single
enablement, then transfer `nvl0555` from the bot and independently observe
its real external IP. Batch/all/active-egress remain subsequent tests.
