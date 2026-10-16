# NVL K2 — Package A2 host boundary and sealed root daemon (2026-10-15)

**Scope:** incremental source-only implementation on draft PR #148, stacked on M1/M2/M3. **NO** master merge, production deployment, root service activation, real UID movement, WireGuard/PAM/systemd/DNS modification.

## Concrete code delivered

1. `edge_egress_k2_a_host_factory.py` adds `ReviewedM2P3HostFactory` and immutable `ReviewedUIDHostSnapshot`. M4 root assembly accepts only this typed host factory, with identical authoritative original DB and OS UID/root callbacks; arbitrary `port_factory=lambda ...` is denied.
2. For `UID_ENROLL_SOURCE` **only** (source and target exactly same trusted Edge), the factory rechecks real M1/M2 source/session/F4 inventory, target identity and one selected UID before requesting any root host plan. It requires a typed `GuardBootstrap` with real M2 first-UID `GuardInstallPlan` and `RootFilePort`, or next-UID `MultiUIDAppendPlan` and `CASRootRosterPort`. Mixed-Legacy direct `UID_ATTACH` remains HOLD.
3. Actual existing M2 bootstrap is deferred until **original P3/6G INTENT** is durably committed. After bootstrap, source constructs the **original** `review_protected_uid`, `SameEdge6GUIDRuntimeStore`, `LocalLinuxProtectedRuntimeKernel`, `GuardedProtectedUIDPort` and `GuardedVerifiedIngressUIDPort`. It never creates a second 6G or an alternate kernel path, and does not accept forged root-host objects / missing packet or neighbour witness providers.
4. `ops/k2_m4_root_daemon.py` now provides `serve_reviewed_assembly`, guarded by a **separate default-OFF** root daemon flag. It checks the root-worker flag, the reviewed assembly's nonroot bot UID/socket transport and exact source manifest SHA before delegating to the existing `RootWorkerService.serve`. Its standalone `main()` deliberately **still exits 78**, since no physically approved trusted live HostReviewedPorts or service identity exists; it cannot auto-enable from env vars.
5. The root-worker exact pinned source set includes the new privileged factory. Regression tests block unsafe host payload, wrong UID, wrong Edge, unsafe source, forged plans, old daemon auto-activation, SHA drift, fake factory in root assembly.

**All release flags remain OFF**. Release acceptance requires independent review of root-owned `read_root_snapshot` (cannot write during planning), actual first/Nth-M2 file inputs and PAM-last gate, immutable kernel config, admin live role authority and signed off-host F4.

## Critical unresolved engineering and physical dependencies

### A3 — production root adapter / privilege split (code + field)
- Construct a **concrete reviewed on-host** read-only snapshot provider that reads the real first/Nth M2 plan, exact existing roster, pinned module/sshd/PAM source, exact owned paths and positive independent safety callbacks. This factory cannot safely invent missing Core/Edge files.
- Implement audited privilege boundary for **every** pre-existing root bot feature, before changing `nvlbot.service User` to nonroot. The root bot currently runs as root; changing its UID without a feature-by-feature permission inventory would break older functions. Preserve a single Telegram polling owner.
- Bind live admin actor/chat to current authenticated session (not historic `settings.admin_chat_ids`) and root-owned allowlist. Issue short-lived scoped approvals only once genuinely authorized.

### A4 — independent external witness (code + physical)
- Deploy a signer/service **off Core** that measures real client SSH/SOCKS IPv4, UDP/TCP DNS, NSS, IPv6, source PAM/WG sessions, no Core egress, neighbour isolation, rescue, boot and WG-loss. Its private signing key stays off Core; root owns only public key and report copy. The existing strict signed-evidence verification is **not** a source of physical observations.
- An honest `UNKNOWN/FAIL` must HOLD, not fabricate `checks=true`, infer sessions=0 from absent PIDs or promote DB F4 to physical READY.

### M5–M7 — next acceptance
- M5: disposable Core/Edge field acceptance of one UID including reboot/WG loss and leak capture; no production canary before signoff.
- M6: adversarial recovery, manual reconciliation, mixed legacy isolation, capacity and staging freeze.
- M7: independently authorize <=10 UID batches, capacity checks, operator confirmation and cross-feature UI polish, then explicit controlled merge/deploy if authorized.

## Classification

`M4.1–M4.5` and Package A adapters are source/CI deliverables, not operational release. **Package A overall remains HOLD** until A3 and A4 prove the installed host and identity. A real root daemon, live signed physical observer and safe bot privilege split cannot be honestly marked implemented from Github-only access.


### Nonroot privilege-audit hardening

`assert_nonroot_bot_identity` additionally requires rootless *kernel* evidence from `/proc/MainPID/status`: identical real/effective/saved/fs GIDs, the reviewed IPC GID in actual `Groups`, **zero CapInh/CapPrm/CapEff/CapAmb** (not just `Uid != 0`), and `NoNewPrivs: 1`. A user configured as nonroot in systemd but carrying `CAP_NET_ADMIN`, ambient capabilities or no IPC supplementary group is HOLD. This is intentionally *stricter* than the current root-running production bot. No credentials, unit or group is modified in this change.
