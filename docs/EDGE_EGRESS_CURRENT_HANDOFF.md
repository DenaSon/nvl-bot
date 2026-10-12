# NVL — Edge Egress: مرجع ادامه کار و وضعیت قطعی

**آخرین بازبینی: 2026-10-12 | مرجع پیش‌فرض چت‌ها و توسعه‌های بعدی**

> **اول این فایل را بخوانید؛ فازهای F1–F4، تست‌های CI و آزمایش SSHD ایزوله را از صفر تکرار نکنید.** این سند خلاصه وضعیت است؛ برای Runbook عملی و شواهد دقیق، فایل‌های مرتبط در انتهای سند را ببینید. اگر شواهد جدید VPS با این فایل مغایرت داشتند، مشاهده جدید را ثبت و این فایل را اصلاح کنید.

## 1. هدف دقیق و وضعیت فعلی

**هدف:** اتصال SSH مشتری از Edge ورودی به Core (احراز هویت)، سپس خروج اینترنت **همان UID** از تونل WireGuard اختصاصی Egress به IP عمومی Edge؛ در صورت خرابی Edge، خروجی **قطع شود** و هرگز به مسیر پیش‌فرض/Core برنگردد (Fail-Closed).

**وضعیت امروز:** کدهای F1–F4 و ابزارهای آزمون/کنترل در GitHub ادغام شده‌اند؛ **Egress محافظت‌شده برای SSH معمولی مشتریان در Production راه‌اندازی نشده است.** تعریف Edge جدید یا انتقال کاربر در بات، فعلاً مدیریت **Ingress/Ownership** است و **به‌تنهایی IP خروجی اینترنت SSH را تغییر نمی‌دهد**. بخش پیش‌نمایش تخصیص کاربر **Read-only** است؛ Runtime واقعی و PAM/Boot روی VPS هنوز به تأیید/یکپارچه‌سازی نیاز دارند.

**شرط پایان:** ورود از SSH معمولی مشتری، خروج از IP دقیق Edge، قطع کامل هنگام از‌دست‌رفتن Edge بدون نشت Core/DNS/IPv6، بازیابی کنترل‌شده پس از Reboot، بدون اختلال برای سایر کاربران و سرویس‌های Core، سپس اتصال این چرخه به Wizard افزودن/تعویض Edge در بات.

## 2. توپولوژیِ گزارش‌شده (نه تأیید لحظه‌ای)

| نقش | شناسه/آدرس | توضیح |
|---|---|---|
| Core | `209.200.246.198` | اجرای بات، SSH اصلی، احراز هویت، `wg0` موجود |
| Edge ورودی قدیمی | `172.86.94.174` | Edge Relay / ورودی؛ با «خروج اینترنت» اشتباه نشود |
| Edge مورد آزمون Egress | `216.126.229.12` | IP خروجی تأییدشده در **namespace آزمایشی** |
| کاربر Canary | `nvl0557`، UID `1644` | فقط پس از عبور از Release Gate، نه انتقال خودکار |
| مسیر آزمایش | `nvl-egress-stg1` و `wg-nvl-stg1` | تونل مجزا؛ نه `wg0` تولیدی |
| SSHD آزمایشگاهی | `127.0.0.1:22284`؛ SOCKS `127.0.0.1:31884` | **loopback و مجزا از SSH عمومی**؛ وضعیت فعلی فعالیت آن را باید Read-only بازبینی کرد |

این شناسه‌ها براساس خروجی‌های ارائه‌شده در آزمایش‌های **2026-10-11** هستند؛ قبل از هر تغییر، وضعیت زنده و مالکیت واقعی سرورها/جدول Route باید دوباره **فقط خوانده** شود.

## 3. چه چیزی واقعاً اثبات شده است؟

- **آزمایش روی Core موجود با SSHD جداگانه و loopback-only:** احراز هویت واقعی رمزدار برای `nvl0557`، SOCKS و مشاهده IPv4 خروجی `216.126.229.12` از تونل اختصاصی؛ خاموش‌کردن لینک WG در namespace باعث شکست درخواست آزمایشی شد و پس از بازیابی لینک، همان IP Edge بازگشت. نتیجه محدود به **همین مسیر و درخواست آزمایشی** است، نه SSH عادی و نه تمام انواع ترافیک.
- **CI روی GitHub:** آخرین Commit ادغام‌شده F1–F4 و اصلاح CI، `589625073e5b191529485bd9dc3d1bbbd2119cea`، دارای Python Unit/Integration **1069 PASS**، Stage-only روی Python 3.11 **330 PASS** و 3.12 **330 PASS**، و Kernel Lab **PASS** شامل UID routing، WireGuard، DNS UDP/TCP، IPv6 guard، outage/blackhole و recovery در محیط ایزوله. GitHub Actions سبز است.
- **اثبات‌نشده:** خروج IP Edge از **SSH عمومی فعلی** برای `nvl0557`؛ نصب واقعی PAM session/account gate، بقای Guard پس از Reboot، تمام forwardingها و اتصال‌های طولانی، عدم نشت با packet capture روی Core واقعی، BadVPN/UDP، عدم تداخل multi-user و خودکارشدن تخصیص Edge جدید.

**هشدار تفسیر:** شکست `curl` به‌تنهایی گواه نبودِ نشت نیست؛ تست Fail-Closed جدید ابتدا SOCKS سالم و IP Edge را اثبات می‌کند و سپس در محیط disposable خرابی را تزریق می‌کند. `STAGED` یا `VERIFIED_LAB` به‌معنای `READY` نیست.

## 4. وضعیت کد / تصمیم معماری

- ریپو: `DenaSon/nvl-bot`؛ شاخه اصلی `master`.
- PRهای ادغام‌شده: [F1 #84](https://github.com/DenaSon/nvl-bot/pull/84)، [F2 #85](https://github.com/DenaSon/nvl-bot/pull/85)، [F3 #86](https://github.com/DenaSon/nvl-bot/pull/86)، [F4 #87](https://github.com/DenaSon/nvl-bot/pull/87)، [CI fix #89](https://github.com/DenaSon/nvl-bot/pull/89).
- F1: UID route + blackhole، DNS/IPv6 guard، boot policy، جلوگیری از برخورد Ruleها و Legacy mutation.
- F2: store/controller با وضعیت‌های `BLOCKED / ROUTED_UNVERIFIED / PROTECTED / FROZEN / HOLD` و قفل و Journal **مشترک 6G**؛ اجرای Kernel **opt-in و پیش‌فرض خاموش**؛ PAM hook هنوز در مسیر SSH اصلی نصب نشده.
- F3: ثبت `INGRESS_ONLY` هنگام Wizard (در صورت Migration صریح)، stage و شاهد `VERIFIED_LAB`، پنل وضعیت/پیش‌نمایش تخصیص Read-only؛ هنوز جایگزین Production-ready نیست.
- F4: Preflight، ممیزی PAM و SHA-256، ابزار تست SSH SOCKS خارجی، ممیزی Kernel، چک‌لیست Release؛ **هیچ ابزار F4 به‌تنهایی مجوز READY یا Cutover صادر نمی‌کند.**
- **تصمیم:** Core محل SSH و احراز هویت می‌ماند؛ Edge برای ingress و public egress. Egress با **WireGuard اختصاصی** و Route برای UID انجام شود، نه تغییر main default route یا `wg0`. فقط **یک منبع حقیقت** برای Egress و Failover: مدل `edge_egress_uid_*` با lock/journal فعلی **6G/6H**. ساخت کنترلر و دیتابیس موازی ممنوع.

## 5. دقیقاً چه کارهایی باقی مانده؟ (به ترتیب، بدون فاز جدید)

1. **Live Read-only inventory، یک‌بار:** وضعیت دو VPS، SSH/PAM، سرویس‌ها، `wg show` بدون کلید، `ip rule`، جدول‌های Route، DB schema/6G lock، unitهای تستی و Shadow namespace؛ بدون تغییر شبکه. از خروجی‌ها یک Snapshot وضعیت بسازید. اگر آزمایش روز قبل هنوز فعال است، **بدون ممیزی آن را حذف یا دوباره نصب نکنید**.
2. **R1–R3، بستن اتصال واقعی:** Runtime پایدار و root-owned برای Egress اختصاصی Core↔Edge + راه‌اندازی و Freeze/Recovery بعد از Reboot، پشت lock/journal فعلی؛ PAM دقیق و مؤثر برای ورود SSH و `direct-tcpip / SOCKS` و جلوگیری از Session قبلی. ابتدا روی VPS **ایزوله/قابل‌بازیابی با کنسول مستقل**؛ `ssh.service` سراسری را به گارد UID وابسته نکنید.
3. **R4–R6، فقط آزمایش‌های باقی‌مانده:** از **کلاینت خارجی** SSH عادی، SOCKS/IP، قطع Edge بدون Core fallback، DNS UDP/TCP و NSS، IPv6، BadVPN/UDP، نشست قدیمی، Reboot، root/non-root admin recovery، Restore از Backup، اثر روی کاربران دیگر. نتیجه را با شواهد host/زمان/packet capture ثبت کنید.
4. **Canary تک‌کاربره:** فقط پس از PASS مرحله 3 و تأیید صریح اپراتور، `nvl0557` را روی مسیر public SSH واقعی محافظت کنید؛ تست IP خروجی و Rollback/Fail-Closed و سلامتی `nvlbot`، SSH سایر کاربران و `wg0`. هنگام شکست، HOLD/FROZEN، **نه fallback به Core**.
5. **ادغام با بات:** وقتی Canary واقعی پذیرفته شد، «افزودن Edge» و «انتقال کاربر» فقط با Edge `READY` و Journal قفل‌شده مسیر خروجی را مدیریت کنند؛ تا آن زمان نمایش وضعیت Read-only و مسیر ingress قبلی حفظ شود.

**Release blocker مرجع:** [Issue #88](https://github.com/DenaSon/nvl-bot/issues/88). دستورالعمل مفصل: [F4 Release Acceptance](EDGE_EGRESS_F4_RELEASE_ACCEPTANCE.md).

## 6. مواردی که نباید دوباره انجام دهیم

- تکرار ساخت F1–F4، همان 1069 تست CI، یا اثبات SOCKS در SSHD جداگانه به‌عنوان «پیش‌نیاز تازه». تنها با تغییر کد یا محیط، تست مرتبط را مجدداً اجرا کنید.
- فرض اینکه با `ssh_accounts.host`، افزودن Edge، DNS عمومی یا 6G/6H قدیمی، **خروج اینترنت** کاربر به Edge تغییر می‌کند.
- استفاده از `setup_edge_datapath.sh` (معماری Edge-terminates-SSH) به‌جای معماری Core-terminated SSH فعلی.
- کپی مستقل Draft PRهای قدیمی #80/#81/#82 یا ساخت `ssh_egress_intents`/lock دوم؛ یافته‌های آن‌ها در اسناد قدیمی موجود است، نه مجوز ساخت مسیر موازی.
- روشن‌کردن `edge_egress_protected_mode`، نصب PAM روی Production، اجرای guard `--enforce`، ریستارت SSH، Flush کردن iptables یا تغییر `wg0` بدون snapshot/console، تست ایزوله و تأیید صریح.
- اعتباردادن `READY` به صرف Unit Test، `VERIFIED_LAB`، IP نمونه، JSON چک‌لیست دستی یا خطای نامشخص Curl.
- تغییر Domainهای عمومی/Marzban یا جریان دیگر کاربران برای حل موضوعی که مختص **Egress SSH** است.

## 7. نحوه ادامه در چت‌های آینده

**دستور شروع:** «سند `docs/EDGE_EGRESS_CURRENT_HANDOFF.md` در ریپو `DenaSon/nvl-bot` را از GitHub بخوان؛ از مرحله 5 ادامه بده. کارهای ثبت‌شده را دوباره انجام نده؛ ابتدا وضعیت VPS را Read-only بازبینی کن.»

در آغاز هر نشست: 1) سند حاضر را بخوان، 2) `master` و Issue #88 را بررسی کن، 3) فقط شکاف بین **شواهد جدید واقعی** و **Release Gate باز** را هدف بگیر، 4) پس از هر تست معتبر، همین سند را با تاریخ، نتیجه و شواهد به‌روزرسانی کن.

### مراجع تکمیلی
- [آزمایش واقعی SSHD ایزوله، 2026-10-11](EDGE_EGRESS_STG3B_RUNTIME_EVIDENCE.md)
- [Runbook Release F4](EDGE_EGRESS_F4_RELEASE_ACCEPTANCE.md)
- [مدل F2 Runtime](EDGE_EGRESS_F2_PROTECTED_RUNTIME.md)
- [مدل F3 Onboarding](EDGE_EGRESS_F3_ONBOARDING.md)
- [Runbook عمومی و قدیمی‌تر NVL](NVL_PROJECT_MEMORY.md) — بخش نسخه V115.2 تاریخی است؛ نسخه فعلی Production را از سرور بخوانید، نه از آن عنوان.
- [Release blockers](https://github.com/DenaSon/nvl-bot/issues/88)

**مرز اعتماد:** متن GitHub وضعیت کد را مستند می‌کند، نه وضعیت لحظه‌ای سیستم‌عامل VPS؛ هیچ عملیات Production با اتکا به این سند به‌تنهایی مجاز نیست.

## 8. Live VPS audit — 2026-10-12 (operator terminal evidence; not independent attestation)

**Scope:** Read-only inventory of actual Production Core `209.200.246.198` and Frankfurt Egress Edge `216.126.229.12`. No route, PAM, SSH, database, `wg0`, firewall, systemd or user assignment mutations. Times and packet counters below are snapshots, **not fresh health guarantees**. R1–R6 remain open; `customer_ready=false`.

### Core facts

- `ssh` and `nvlbot` were active. Normal SSH listeners on ports `22` and `2252`; isolated pilot proxy listener only on `127.0.0.1:22284`. Pilot `nvl-egress-pilot-{sshd,proxy}.service` and `nvl-egress-pilot-proxy.socket` were active; their unit files are marked **static**. **Static does not prove boot activation or absence thereof** — dependency/socket wiring requires separate evidence.
- Effective `sshd -T -C` for `nvl0557`, using explicit `laddr=209.200.246.198,lport=22` and separately `lport=2252`: `usepam yes`, password/public-key/keyboard-interactive enabled, `allowtcpforwarding yes`, `disableforwarding no`, `permitopen any`. Earlier omission of `lport` gave `Match LocalPort ... 'lport' not in connection test specification`; **that command failure was not evidence that SSH had bad configuration**. These are effective checks with a localhost source address, not an exhaustive customer-source `Match` audit.
- `ip -4 route get 1.1.1.1 uid 1644` returned `dev eth0 src 209.200.246.198`: Canary `nvl0557` **still egresses via Core** under the observed host UID routing. A user-owned `sshd` process was observed (started 2026-10-12 02:05:58 local host time); session ownership/forwarding activity has **not** been established. Do not interrupt it.
- Existing root-namespace `wg0` and separate `nvl-egress-stg1` namespace with `wg-nvl-stg1`, veth and namespace default route over dedicated WG; recent handshake observed. `wg-quick@wg-nvl-stg1.service` is inactive/disabled, **not proof that the shadow tunnel is down**. No `/opt/nvl-egress` installed, and no Egress `pam_exec` account hook observed in `/etc/pam.d/sshd` output.
- SQLite query-only inventory: `ssh_accounts`, `host_pool`, `settings`, `failover_operations`, `edge_egress_allocations` present; `edge_egress_readiness`, `edge_egress_uid_runtime`, `edge_egress_uid_bindings` absent. `edge_egress_protected_mode=0`, `RUNNING` shared 6G operations = 0. `nvl0557` ingress owner remains `172.86.94.174` and account active. **Do not migrate DB tables as an implicit preflight step.**
- `nvl-edge-sync.service` showed `ActiveState=activating, SubState=start, Result=success` at observation; diagnose independently if required, without assuming it manages Egress persistence.

### Edge facts

- Ubuntu kernel `6.8.0-90-generic`; `eth0=216.126.229.12`, original `wg0=10.77.0.6/24`, dedicated `wg-nvl-stg1=10.78.110.1/30`, listening UDP `51842` and recent handshake; `net.ipv4.ip_forward=1`.
- `wg-quick@wg-nvl-stg1.service` inactive/disabled, no `/etc/wireguard/wg-nvl-stg1.conf`, no matching dedicated systemd unit file discovered. WG interface **exists and is up nevertheless**: current creator/credential ownership and restart/reboot behavior remain unverified. Never copy private keys into Git or print them in evidence.
- `iptables v1.8.10 (nf_tables)`. `POSTROUTING` rule 1 is unconditional `MASQUERADE` (12,643 packets) and rule 2 is tagged `nvl-egress-stg1` source `10.78.110.2/32` → `eth0` (zero packets). Forward counters on staged path were nonzero (191 outbound, 148 return). The earlier broad NAT rule likely shadows the tagged NAT rule; **do not reorder or remove it** before owner/legacy dependency review. NAT counters are not a packet-capture leak proof.
- Edge has a public IPv6 default route but `net.ipv6.conf.all.forwarding=0`. That does not itself prove protected Core-UID IPv6 policy, DNS safety or leak absence.

### Decision / next permissible work

1. **Inventory completed for the two current hosts.** Preserve running `stg1`, public SSH ports, BadVPN and original `wg0`; do not recreate namespace, NAT or pilot SSHD just to repeat the 2026-10-11 proof.
2. **R1 implementation, not activation:** create a dedicated root-owned, version-pinned Core/Edge transport lifecycle with independent systemd/reconcile and fail-closed recovery, integrating the existing F2 bridge and sole shared 6G journal; include a non-destructive adoption/refusal rule for the *already existing* shadow resources and a legacy NAT owner check. No second controller/DB or global SSH dependency.
3. **R2–R3 blockers remain:** audited PAM account enforcement on actual forwarding paths, independent root/non-root rescue access, socket-activated SSH and crash/reboot of a **disposable** full-system VPS. No deployment of PAM/BootGuard or protected-mode setting on these production hosts.
4. **R4–R6 remain unproven:** external normal SSH + SOCKS IP proof, DNS/NSS UDP/TCP/IPv6 and BadVPN packet captures, Edge-loss leak proof, active-session drain, multi-user/shared-table behavior, offsite restore and signed acceptance. Only then a single-UID `nvl0557` canary following explicit operator approval.

**Evidence quality:** Operator-copied real terminal outputs; not independently signed or recorded as kernel packet captures. This section supersedes historical assumptions about stage service persistence, but does **not** change Issue #88 release status.

### Supplemental Core legacy-rule inventory — 2026-10-12 (read-only)

Operator-provided follow-up confirmed that previously used experimental priority `7681`, routes in table `178`, and `veth-nvl-h` are **absent** from the Core snapshot. No `uidrange` selector or protected table `1790` appeared in the filtered report. Thus the removal of that legacy route does **not** contradict the successful `nvl-egress-stg1` isolated SSHD/SOCKS proof: the normal `uid 1644` host-path still selecting Core `eth0` is the expected current unprotected production configuration.

Old, **separate** policy remains: `7700: from all fwmark 0x77 lookup 77`, table `77` has `default dev wg0`; the Core `iptables -t mangle -S OUTPUT` lists **two identical** `--uid-owner 1658 -j MARK --set-xmark 0x77/0xffffffff` entries; and `iptables -t nat -S POSTROUTING` lists **two identical** `-o wg0 -m mark --mark 0x77 -j MASQUERADE` entries. UID `1658` is the historical test UID, distinct from Canary `nvl0557` UID `1644`. No current evidence shows that these old explicit UID rules redirect UID `1644`. Their present ownership, persistence, active sessions, rule counters and impact of any removal remain **unverified**. **Do not delete/reorder** those rules or touch `wg0` as part of R1. Duplicate lines are evidence of redundant installed entries, not authorization for live firewall mutation.

Next: focus on the missing dedicated transport lifecycle/reconcile, PAM/boot acceptance and shared 6G bridge; legacy-rule cleanup is a separately owned, deliberately scoped maintenance decision and not a prerequisite to re-running prior staging tests.

## 9. R1 development checkpoint — 2026-10-12 (Draft PR #92)

**Code-only work in progress**, not an accepted R1 release. [Draft PR #92](https://github.com/DenaSon/nvl-bot/pull/92) adds `edge_egress_r1_transport.py`, focused tests and [R1 technical contract](EDGE_EGRESS_R1_PERSISTENT_TRANSPORT.md). The new logic is deliberately **opt-in/disposable-only** and never starts on import, runs an installer or changes the existing Core/Edge. It refuses to adopt the running `stg1` shadow implicitly, refuses unreviewed broad-then-tagged Edge NAT, requires root-owned SHA-256-pinned stage/unit files and checks dedicated WG peer/addresses/routes/forwarding without printing private keys.

The `GuardedR1ShadowPort` is an optional injected F2 bridge collaborator and requires externally verified same **existing 6G** lease and independently attested UID guard before and between Edge/Core starts. Any uncertain partial start results in an error for the F2 coordinator to HOLD/freeze; it never cleans up live legacy resources blindly. `MANAGED_RUNNING` describes transport observation only and always keeps `customer_ready=false`.

**R1 is NOT complete:** approved durable systemd installation, actual Core/Edge host launchers, startup/freeze/reconcile on a disposable full VPS and post-reboot evidence remain outstanding. R2–R6 and Issue #88 are unchanged. Existing successful Stage 3B tests must not be repeated solely to validate this code change. Never promote `READY`, enable protected mode, migrate DB or change live production `wg0`/SSH/PAM/NAT from this draft.
