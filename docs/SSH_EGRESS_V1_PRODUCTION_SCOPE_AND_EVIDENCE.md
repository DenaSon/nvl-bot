# NVL — SSH Egress V1 | محدوده اجرایی و شواهد معتبر

> **مرجع اصلی ادامه این موضوع — 2026-10-12**
>
> **تصمیم:** اولویت فعلی فقط **اصلاح IP خروجی ترافیک SSH/SOCKS روی Production** است. توسعه جدید 6G/6H، F4/READY، معماری HA، UI بات و توسعه R1 متوقف/موکول شده‌اند. این سند «برنامه و حافظه شواهد» است، **نه مجوز دست‌کاری Production**.
>
> **شروع گفتگوهای بعدی:** این فایل را از `master` بخوان، وضعیت جاری GitHub و سرورها را از شواهد تازه (ابتدا Read-only) تطبیق بده، و فقط از «گام بعدی» بخش 10 پیش برو. تست‌های اثبات‌شده قبلی را بی‌دلیل تکرار نکن.

## 1) مسئله و معیار موفقیت، بدون ابهام

معماری عملیاتی NVL، **Core-terminated SSH / Edge Relay** است: اتصال SSH مشتری از Edge وارد می‌شود، از طریق WireGuard ورودی (`wg0`) به Core می‌رسد، و SSHD/احراز هویت/کاربران و Bot روی Core هستند. در مدل فعلی، خروج اینترنت پردازش SSH کاربر عموماً از IPv4 عمومی **Core** انجام می‌شود.

**خروجی مورد نیاز V1:** برای یک حساب کنترل‌شده که به Edge **A** وارد شده، ترافیک IPv4/TCP ناشی از همان Session SSH/SOCKS باید با **IP عمومی دقیقاً همان Edge A** به مقصد برسد، نه IP Core، نه یک Edge دیگر.

```text
Client -> Ingress Edge A -> existing wg0 -> Core:sshd(UID test)
                                      Core:UID-owned egress route
                                               |
                                     dedicated Egress WireGuard
                                               |
                                      Edge A -> SNAT -> Internet
                                      observed IPv4 == Edge A IPv4
```

**نکته تعیین‌کننده:** «خروج از یک Edge» کافی نیست؛ **Ingress Edge و Egress Edge باید برای همین حساب یکی باشند.** `ssh_accounts.host` در بات Endpoint/Ingress است، نه الزاماً مقصد Routing در Linux.

در خرابی Egress مسیر متعلق به UID باید **Fail-Closed** بماند: blackhole/unreachable، **بدون fallback به `eth0` یا IP Core**. حفظ سرویس سایر کاربران و SSH مدیریتی الزام است.

### تفکیک مسئولیت

- **Root cause مستقیم:** Linux routing / WireGuard egress / Edge SNAT / مسیر برگشت، نه منطق فروش یا Telegram Bot.
- **نقش آینده بات:** منبع نگاشت واقعی `username / UID / ingress Edge` و اعمال lifecycle برای ایجاد/غیرفعال‌سازی/حذف/تغییر Edge، **پس از** اثبات مسیر شبکه.
- **6G/6H موجود:** حذف یا خاموش نمی‌شود؛ در V1 هیچ تغییر توسعه‌ای به آن نمی‌دهیم. پیش از هر اعمال شبکه‌ای، برخورد با وضعیت‌های فعلی 6G و فنس‌های `edge_egress_legacy_fence` **Read-only بررسی** می‌شود. **هیچ دورزدن lock/fence موجود مجاز نیست**؛ در تعارض، توقف و تصمیم جداگانه.

## 2) محیط‌ها را قاطی نکنید

| محیط | واقعیت/شناسه | وضعیت شاهد |
|---|---|---|
| **Production Core** | `209.200.246.198`، بات/DB/SSHD واقعی | دسترسی زنده از این سند اثبات نمی‌شود |
| **Production Ingress برای شاهد قدیمی nvl0557** | `172.86.94.174` طبق `ssh_accounts.host` در Snapshot 2026-10-12 | Snapshot تاریخی؛ قبل از تغییر بازبینی شود |
| **Frankfurt Edge آزمایش خروج** | `216.126.229.12`، WG اختصاصی `wg-nvl-stg1` در آزمایش قدیمی | خروج این IP اثبات شده، نه «برابر با Ingress nvl0557» |
| **Production Core shadow آزمایشی قدیمی** | namespace `nvl-egress-stg1`، WG `10.78.110.0/30`، loopback SSHD `127.0.0.1:22284`، SOCKS `127.0.0.1:31884` | تست محدود؛ برخلاف SSH عمومی Production |
| **LAB Core مستقل آمستردام** | `107.189.16.36`، UID `nvlr1test=1555`، جدول `1791`، WG `10.78.120.0/30` | جدا از Core واقعی Production؛ روی آن Bot عملیاتی نیست |
| **LAB Egress طرف مقابل** | همان IP Frankfurt `216.126.229.12` در سناریوی LAB R1 | اشتراک IP بین شواهد محیطی را به‌معنی ایزوله‌بودن کل Edge فرض نکنید |

**اشتباه ممنوع:** آزمایش `nvl0557` با Ingress قدیمی `172.86.94.174` و مشاهده Egress `216.126.229.12` **به هدف «همان Edge» نمی‌رسد**. در فاز صفر، Edge ورودی واقعی *حساب Canary جدید* و مالکیت آن باید تثبیت شود؛ IP هدف خروج فقط پس از آن انتخاب می‌شود.

## 3) شواهد اثبات‌شده پیشین — چه کاری را تکرار نکنیم؟

### 3.1 Production Core و Frankfurt / آزمون 2026-10-11 تا 12

- `ip -4 route get 1.1.1.1 uid 1644` برای `nvl0557` در Snapshot، `dev eth0 src 209.200.246.198` داد. **علت مستقیم IP خروجی Core در مسیر عادی UID** همین انتخاب Route بود.
- در **SSHD جداگانه و loopback-only** روی Production Core، احراز هویت رمزدار، SOCKS و خروج IPv4 برابر **`216.126.229.12`** از WG مجزای آزمایشی مشاهده شد. با قطع کنترل‌شده لینک WG **داخل همان namespace آزمایشی**، درخواست شکست خورد؛ پس از بازگشت لینک، همان IP برگشت. این تست نه SSH عمومی مشتری را اثبات می‌کند نه نبود همه نشت‌ها را.
- Snapshot Production: سرویس‌های `ssh` و `nvlbot` فعال؛ SSH عمومی روی `22` و `2252`؛ `wg0` اصلی موجود؛ namespace `nvl-egress-stg1` با تونل مجزا حاضر؛ `wg-quick@wg-nvl-stg1` غیرفعال/disabled با وجود Interface فعال. **مالک Startup/Reboot نامعلوم است**.
- `nvl0557` در DB فعال و یک فرایند `sshd` به UID او منسوب مشاهده شده بود. ماهیت Session قطعی نشده؛ **کاربر فعلی را کورکورانه Canary نکنید، Session را قطع نکنید.**
- Snapshot Production DB: `ssh_accounts`، `host_pool`، `settings`، `failover_operations` و `edge_egress_allocations` موجود؛ `edge_egress_readiness`، `edge_egress_uid_runtime` و `edge_egress_uid_bindings` غایب؛ `edge_egress_protected_mode=0`؛ 6G `RUNNING=0`. وضعیت کنونی نیازمند بازبینی Read-only است.
- Snapshot Frankfurt: `wg0=10.77.0.6/24`، WG اختصاصی `wg-nvl-stg1=10.78.110.1/30`، UDP `51842` و `net.ipv4.ip_forward=1`؛ `POSTROUTING` یک MASQUERADE عمومی **قبل** از SNAT/MASQUERADE اختصاصی `nvl-egress-stg1` داشت. شمارنده Rule عمومی بیشتر بود و Rule اختصاصی صفر؛ احتمال Shadow شدن وجود دارد، **نه اجازه جابه‌جایی Rule**.
- روی Core ردیف‌های قدیمی و مستقل `fwmark 0x77`، جدول `77`، priority `7700` و قواعد تکراری `uid-owner 1658` دیده شدند. **این UID با `1644` فرق دارد**؛ هیچ Rule قدیمی را Cleanup، Flush یا Reorder نکنید.
- اولویت/Route آزمایشگاهی قدیمی `7681/178` و `veth-nvl-h` طبق ممیزی بعدی غایب بود. آن آزمایش را با مسیر فعال `stg1` یکی نگیرید.

### 3.2 LAB مستقل R1 / دستاوردهای واقعی 2026-10-12

- Core آمستردام و Edge فرانکفورت تونل اختصاصی `lab1` را بالا آوردند؛ خروج از namespace با **IP فرانکفورت** دیده شد.
- تخصیص موقت Route به UID **1555**، مشاهده Edge IPv4 و بازگشت به **blackhole** پس از Detach روی LAB مشاهده شد. این دلیل بر کنترل همه Sessionها، BadVPN یا پایداری پس از Reboot نیست.
- BootGuard برای LAB Core در Systemd نصب، فعال و enabled گزارش شد؛ **ترتیب نسبت به SSH در Reboot واقعی آزمایش نشده**.
- SQLite مستقل `/root/master_bot.db` روی **LAB آمستردام** با جدول‌های خالی F1–F3 و Journal اصلی 6G ایجاد شد؛ ثبت واقعی Edge در 6G با `SUCCEEDED` پایان یافت اما Edge فقط `STAGED` است، نه `READY`. **این Bot عملیاتی Production یا دیتابیس Production نیست**.
- PAM LAB Core نصب شد، test UID `nvlr1test` همچنان password-locked و `/usr/sbin/nologin` است. پس از PAM، یک **SSH تازه از PowerShell** برای Root موفق بود (`ADMIN_SSH_NEW_SESSION_PASS`، UID `0`). این **صرفاً ورود مدیریتی** را اثبات می‌کند، نه ورود SSH مشتری.
- هنوز اولین Canary E2E، Edge واقعی Outage، DNS/IPv6/BadVPN packet capture و Reboot LAB تکمیل **نشده‌اند**. اسکریپت PAM روی مسیر PAM همه SSHهای آن LAB قرار دارد؛ بدون بازیابی Console مستقل و ممیزی، دست‌کاری نکنید.

### 3.3 CI و GitHub

- PRهای زیر روی `master` ادغام شده‌اند: F1 [#84](https://github.com/DenaSon/nvl-bot/pull/84)، F2 [#85](https://github.com/DenaSon/nvl-bot/pull/85)، F3 [#86](https://github.com/DenaSon/nvl-bot/pull/86)، F4 [#87](https://github.com/DenaSon/nvl-bot/pull/87).
- تست‌های CI و Kernel ایزوله برای این فازها قبلاً PASS شده‌اند؛ **CI معادل پذیرش public SSH Production نیست**.
- PR [#92](https://github.com/DenaSon/nvl-bot/pull/92) برای R1، هنگام بازبینی 2026-10-12، **Open / Draft / Not merged** بود: **97 Commit، 32 فایل، +5390 خط**؛ بیشتر فایل‌های جدید آن ابزارهای LAB/Transport/6G/PAM هستند. **طبق تصمیم فعلی: Freeze، بدون Merge و بدون توسعه جدید.** تنها تغییر مستقیم در کد Runtime موجود آن PR، استثنای خاص Core-as-Ingress برای LAB است؛ فایل اصلی Bot در PR #92 تغییر نکرد.
- این شواهد از خروجی‌های ارائه‌شده اپراتور، کد GitHub و مستندات ممیزی هستند؛ **Telemetry و Snapshot هم‌زمان زنده یا امضای مستقل** نیستند.

## 4) آنچه قطعاً هنوز اثبات نشده است

- خروج IPv4 از **همان Edge ورودی** در یک Session **SSH عمومی فعلی** روی Production.
- پایداری Route/Guard و عدم بازگشت به Core در **قطع واقعی و کنترل‌شده** مسیر اختصاصی و پس از Reboot.
- جلوگیری از نشت DNS/NSS و IPv6 در انواع مسیرهای واقعی، با مشاهده Packet و تست منفی.
- یکسان‌بودن IP خروجی برای BadVPN/UDPGW یا فرایندهای Gost/Resolver با UIDهای دیگر.
- عدم تداخل با کاربران، SSH مدیریتی، NAT قدیمی و سرویس‌های Bot تحت شرایط خطا.
- خودکار شدن نگاشت کاربر به Edge در چرخه ایجاد/تمدید/تغییر Edge از بات.
- صحت فعلی Production در لحظه گفت‌وگو؛ **اطلاعات بخش 3 فقط Snapshot تاریخی هستند**.

## 5) Scope کنترل‌شده V1 — چه چیزی داخل است؟

**یک سناریوی محدود، نه یک پلتفرم جدید:**

1. **یک حساب آزمایشی اختصاصی و قابل جمع‌آوری در Production**؛ نه کاربر فعال مشتری و نه تغییر گروهی UIDها. انتخاب Edge **A** بعد از بازبینی واقعی Ingress و مالکیت آن حساب.
2. حفظ Core به‌عنوان محل اجرای `sshd` و Bot؛ مسیر ورودی Edge و `wg0` عملیاتی تغییر نکند.
3. یک مسیر **اختصاصی Egress** از Core به همان Edge A، با استفاده از زیرساخت موجود *اگر واقعاً قابل انتساب/استفاده باشد*؛ بدون WireGuard موازی اضافی تا زمانی که ضرورتش اثبات نشده.
4. یک Rule **مختص UID آزمایشی** + جدول Route مختص/تأییدشده، terminal blackhole؛ **بدون تغییر default route کل Core** و بدون استفاده از `fwmark 0x77`/table `77`.
5. NAT/SNAT خروجی روی Edge A و مسیر برگشت؛ اصلاح فقط Rule مالکیت‌دارِ مورد نیاز، بدون flush/reorder سراسری.
6. اثبات **public SSH + SOCKS** از یک دستگاه خارجی، خروج IPv4 دقیق Edge A، تست منفی عدم Core fallback؛ قید عدم نشت IPv6/DNS در مسیرهای پشتیبانی‌شده.
7. مکانیسم توقف امن، کنترل Session موجود، Backup و Rollback با حفظ deny-only تا قطع/حذف امن حساب آزمایشی. هر مرحله بعدی تنها پس از PASS و مجوز جداگانه.

**مرز پایانی V1:** یک Canary واقعی که در مسیر عمومی Production از Edge A وارد می‌شود و با IPv4 دقیق Edge A خارج می‌شود، با guard معتبر و عدم اختلال سایر کاربران. **فعال‌سازی همه مشتریان جزو V1 نیست.**

## 6) صراحتاً خارج از Scope این راند

- بازطراحی، توسعه یا ادغام جدید 6G/6H، HA و جابه‌جایی خودکار Edge. **6G فعلی روشن می‌ماند؛ فقط توسعه آن موکول است.**
- Merge یا گسترش PR #92، ساخت کنترلر/DB/Journaling موازی یا ادامه نصب R1/PAM LAB بی‌هدف.
- افزودن Edge، تغییر default host، تغییر DNS عمومی، Cloudflare، Marzban، Xray، Wallet، قیمت‌گذاری یا UI جدید بات.
- بازنویسی SSH lifecycle یا اصلاح هم‌زمان محدودیت اتصال/تمدید/حسابداری.
- تغییر PAM سراسری Production، سرویس‌های SSH عمومی، `wg0`، Routing کل سیستم، یا Cleanup Ruleهای آزمایشی تاریخی بدون مالکیت.
- ادعای پشتیبانی همه پروتکل‌ها (BadVPN UDP، Gost یا IPv6 خروجی) بدون برنامه پذیرش جداگانه.
- Reboot بدون زمان نگهداری، Cloud Console، Snapshot و رضایت مجزا؛ Power-cycle/قطع واقعی Edge دارای کاربران فعال هم **خارج** است.

## 7) فازهای کوچک با شرط توقف و معیار خاتمه

### P0 — فقط تشخیص Production / Read-only

**هدف:** بگوییم مشکل روی این سناریو دقیقاً Route است، NAT است، Tunnel است، یا ترکیبی.

- بازبینی فقط موارد لازم: `ssh_accounts.host` و UID حساب کاندید، `ip rule` و `ip route get ... uid`، مسیر `stg1` موجود، WireGuard handshakes، NAT و counters، SSH/PAM/Session، DNS/IPv6 مسیر آزمایشی، مالکیت Edge A و تعارض احتمالی با 6G.
- از شواهد قبلی استفاده کن؛ تنها مقادیر **تغییرپذیر و تعیین‌کننده** را تازه‌سازی کن. **هرگز کاربر فعال `nvl0557` را خودکار کاندید قرار نده.**
- **خروجی لازم:** (الف) Ingress واقعی حساب A و IP Edge A، (ب) Root cause، (ج) حداقل Delta عملیاتی لازم، (د) اثر روی کاربران دیگر، (هـ) آماده‌سازی Backup و Plan بازگشت.
- **Stop:** ابهام در مالکیت Route/NAT/WG، نبود Console یا Backup معتبر، سرویس زنده نامعلوم، برخورد با Rule/Lock موجود.

### P1 — یک تغییر حداقلی و محدود به UID

- فقط پس از **تأیید صریح** تغییرات مشخص روی Production، Snapshot/Backup و دسترسی Console.
- Route/iptables/WG ایزوله و reversible، با rule دقیق UID، deny-only fallback و بدون تماس با default system route.
- **Stop فوری:** هر نشانه خروج Core برای UID محافظت‌شده، برخورد اولویت Rule، وابستگی به NAT ناشناس، ناپایداری SSH مدیر یا تغییر وضعیت دیگر کاربران. **No auto Core fallback**.

### P2 — شواهد واقعی پذیرش

- ابتدا baseline سالم از کلاینت خارجی: Public SSH با SOCKS؛ **observed IPv4 == Ingress Edge A**. اگر برابر نیست، FAIL.
- Packet-path هم‌زمان برای مسیرهای ضروری، عدم نشت Core/DNS/IPv6 و عدم اثر روی کاربر دیگر.
- قطع کنترل‌شده **مسیر Egress اختصاصی همان Canary** به‌جای خاموش‌کردن سرور Edge مشترک؛ انتظار: Deny/Timeout و **صفر مسیر موفق از Core**. پس از بازیابی، تکرار IP Edge A.
- پایداری پس از Reboot ابتدا با روش ایزوله/شواهد BootGuard بررسی می‌شود؛ Reboot واقعی **Production جداگانه** و تنها با پنجره نگهداری مجاز است. تا آن زمان ادعای boot-safe Production نکن.
- **پایان فاز:** گزارش PASS/FAIL با تاریخ، host، UID، Edge A، IP مشاهده‌شده، نوع Test و حدود اعتبار؛ هیچ `READY` ساختگی.

### P3 — پس از پایان فنی V1 (فاز جداگانه، با تصمیم جدید)

تنها پس از پذیرش واقعی شبکه، یک integration بسیار کوچک با lifecycle بات برای نگاشت `UID ↔ Edge` و Provisioning/Deprovisioning تعریف کن؛ ساخت/تمدید/تغییر/حذف باید بررسی سازگاری با 6G/6H موجود داشته باشد. **در این راند P3 پیاده‌سازی نمی‌شود**؛ تغییرات 6G همچنان خارج از Scope هستند.

## 8) قوانین توقف و Rollback

- **هیچ دستور Mutating بدون Change Plan و تأیید صریح:** دقیقاً UID، host، Rule/Interface، فرمان‌های verify، اثر جانبی و روش بازگشت.
- **نه به جعل وضعیت:** دست‌کاری دستی `READY`، `RUNNING`، `ssh_accounts.host`، `dns_current_ip` یا ثبت fictitious host به‌جای Evidence ممنوع.
- **Rollback محافظت‌شده:** بازگشت کور به مسیر Core برای یک Session محافظت‌شده مجاز نیست. ابتدا کاربر آزمایشی قطع/غیرفعال و Sessionها تخلیه شوند، سپس Routeهای دارای مالکیت مشخص جمع شوند. در خطا، حساب موقت deny-only بماند.
- **هر بار فقط یک فاز:** اگر تشخیص P0 نشان داد اصلاً فقط NAT یا UID Rule ناقص است، همان را اصلاح کن؛ به بهانه «ایمنی بیشتر» معماری جدید نساز.
- شواهد شامل رمزها، private key، SSH host secrets، DB مشتریان و dump حساس در GitHub/چت قرار نگیرند.

## 9) خطرها / نکات باز که نباید فراموش شوند

| موضوع | ریسک / نتیجه |
|---|---|
| `ssh_accounts.host` ورودی ≠ Egress | قبل از تغییر، IP Edge A را از رکورد واقعی حساب و dataplane استخراج کن |
| shared Core processes / SSH UID | یک UID Route الزاماً UDP BadVPN یا helperهای UID دیگر را شامل نمی‌شود |
| `wg0` و Rules تاریخی `1658/0x77/77` | دست‌نخوردنی تا بررسی مالکیت؛ با تست Canary قاطی نشوند |
| `stg1` فعال ولی unit غیرفعال | شواهد Running ≠ اثبات restart/reboot |
| PAM نصب‌شده روی **LAB آمستردام** | بعد از نصب Root تازه PASS، ولی Reboot و خرابی dependency اثبات‌نشده؛ بدون تغییر اضافی |
| F2/F4 circular readiness | به `READY` قبل از اولین SSH نیاز دارد و SSH proof را برای READY می‌خواهد؛ با fake row حل نکن. **در V1 وارد بازطراحی F4 نمی‌شویم**؛ اگر راه آزمایش مستقل و ایمن وجود نداشت Stop |
| Edge فرانکفورت ممکن است مشترک باشد | از روی عنوان «LAB» فرض نکن Power-off/stop Edge برای Production بی‌خطر است |
| CI PASS | تست کد است، نه public SSH acceptance |

## 10) وضعیت پروژه و «دقیقاً از کجا ادامه بدهیم؟»

**Checkpoint در لحظه ثبت (2026-10-12):**
- GitHub `master`: F1–F4 قبلاً Merge شده‌اند؛ برای SSH عمومی Production، IP خروجی هنوز اصلاح‌شده و پذیرفته‌شده نیست.
- R1 PR #92: Draft، **Freeze / No merge**. روی LAB مستقل فقط bootstrap، registration، PAM و دسترسی تازه مدیریتی بررسی شده‌اند؛ customer E2E باز است.
- Production: نتیجه معتبر قدیمی `nvl0557 uid=1644` خروج از Core است؛ آزمون SOCKS جداگانه خروج از فرانکفورت را نشان داده، نه هدف «همان Edge ورودی» را.
- **فاز فعال بعدی فقط P0 است.** هیچ اسکریپت شبکه/DB/PAM/6G تغییر داده نشود.

**پیام پیشنهادی در چت بعدی:**
> «ریپو `DenaSon/nvl-bot` را بخوان، مخصوصاً `docs/SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md`. اسکوپ جدید V1 را رعایت کن، توسعه 6G و PR #92 را ادامه نده. از P0 فقط با ممیزی Read-only واقعی Production آغاز کن، یافته‌های تست‌های قبلی را تکرار نکن. اول Root Cause و حداقل Delta را گزارش بده؛ بعد از تأیید من برای هر Mutation اقدام کن.»

## 11) منابع و وضعیت مرجع

- معماری واقعی: [ARCHITECTURE_CONTEXT_MAP](ARCHITECTURE_CONTEXT_MAP.md)
- جزئیات Snapshot و اصل تست‌ها: [EDGE_EGRESS_CURRENT_HANDOFF](EDGE_EGRESS_CURRENT_HANDOFF.md)
- ایزوله SSHD/SOCKS: [EDGE_EGRESS_STG3B_RUNTIME_EVIDENCE](EDGE_EGRESS_STG3B_RUNTIME_EVIDENCE.md)
- خطرهای Production و Backup: [EDGE_EGRESS_PRODUCTION_REVIEW](EDGE_EGRESS_PRODUCTION_REVIEW.md)
- پذیرش امنیتی قبلی (مرجع فنی، نه برنامه اجرایی جاری): [EDGE_EGRESS_F4_RELEASE_ACCEPTANCE](EDGE_EGRESS_F4_RELEASE_ACCEPTANCE.md)
- [PR #92 — R1 توقف‌شده](https://github.com/DenaSon/nvl-bot/pull/92)
- [Issue #88 — بدهی فاز کامل Production](https://github.com/DenaSon/nvl-bot/issues/88)

**قاعده تقدم:** برای **اولویت توسعه و Scope فعلی** این سند مقدم بر برنامه‌های قدیمی R1–R6 و handoff قبلی است؛ اسناد قبلی برای **شواهد تاریخی و قیود ایمنی** همچنان معتبرند. ادعاهای محیطی تا زمان تأیید Read-only تازه، تاریخی محسوب می‌شوند.


## 12) بازبینی واقعی Workflow بات: «افزودن Edge» و «رله فعال» — 2026-10-12

**منبع بررسی:** `bot_final_v49-2.py` و `setup_edge_relay.sh` از `master`؛ شرح رفتار **کد موجود** است، نه ادعای یکسان‌بودن نسخه نصب‌شده یا مقدار فعلی Production. هیچ کد/DB/شبکه در این بازبینی تغییر نکرده است.

### 12.1 تفکیک چهار مفهوم موجود (از نو نسازید)

| مفهوم | وضعیت واقعی در کد | آیا IP خروجی کاربر را تعیین می‌کند؟ |
|---|---|---|
| «➕ افزودن IP جدید به استخر» (`hp_add`, `HOSTPOOL_ADD_INPUT`) | فقط `settings.hosts` و `host_pool` را ثبت/فعال می‌کند؛ **VPS را provision نمی‌کند** | **خیر** |
| «🚀 افزودن Edge جدید» (`hp_addedge`, `EDGE_NEW_*`, `_provision_new_edge`) | VPS موجود را از طریق SSH به **Ingress Relay** تبدیل می‌کند؛ Edge `wg0`، ثبت Peer روی Core `wg0`، DNAT پورت SSH/TLS، NAT، ثبت `host_pool` و `settings.hosts` و `record_ingress_candidate(...)` | **خیر**؛ F3 فقط `INGRESS_ONLY`، نه Egress `READY` |
| «⭐ پیش‌فرض کل سیستم» (`hpdef_*`) | پس از TCP service reachability، `host_pool.is_default` را برای یک Host تنظیم می‌کند؛ Host حساب‌های **قبلی** را فقط با دکمه مستقل `hpdefmig_yes_*` منتقل می‌کند | **خیر**؛ پیش‌فرض نمایش/Endpoint است، نه Route برای UID |
| «🎯 رله فعال» در «وضعیت و نقش سرورها» (`srv_mkactive_*`) | پیش‌فرض را تغییر می‌دهد، `tls_passthrough=1`، Cloudflare A-record(s)، `dns_current_ip` و DNAT پورت TLS روی Edge را تنظیم می‌کند | **خیر**؛ صرفاً Ingress/domain و تنظیم پورت |

**واژگان داده‌ای مرتبط:** `host_pool.active` عضویت فعال در استخر است؛ `host_pool.is_default` پیش‌فرض سیستم است؛ `settings.dns_current_ip` آخرین مقصد ثبت‌شده دامنه است؛ `ssh_accounts.host` Endpoint/Ingress منتسب به آن حساب است. **هیچ‌کدام به‌تنهایی Policy Routing یک UID را روی Linux نمی‌سازند.**

**تفاوت دو دکمه:** `hpdef_*` قبل از تغییر پیش‌فرض، TCP Reachability پورت سرویس را چک می‌کند و درباره انتقال حساب‌های قبلی سؤال می‌پرسد. اما `srv_mkactive_*` در مسیر بررسی‌شده، قبل از تغییر `is_default` چک معادل ندارد؛ `is_default` **قبل** از درخواست Cloudflare تغییر می‌کند؛ شکست Cloudflare می‌تواند Default و DNS را ناهماهنگ بگذارد. این یک **ریسک کد موجود** است، نه مجوز تعمیر آن در V1. هر دو مسیر می‌توانند دسترسی ورودی مشتریان را تحت تأثیر قرار دهند؛ برای P0 **هیچ دکمه تغییر رله/پیش‌فرض/دامنه را نزنید**.

**نکته UI:** در `_render_server_status_panel` اگر `host == dns_current_ip OR host == default_host` باشد برچسب «🎯 رله فعال — متصل به دامنه» ظاهر می‌شود؛ پس ممکن است هنگام واگرایی دو مقدار، **بیش از یک Edge** همین برچسب را داشته باشد. عنوان UI، اثبات مالکیت یک Session یا سلامت DNS نیست.

### 12.2 افزودن Edge از قبل وجود دارد، اما فقط Ingress

مسیر ویزارد `hp_addedge` → `EDGE_NEW_IP` → `EDGE_NEW_ROOTPASS` → `EDGE_NEW_PORT` → `_provision_new_edge_sync`:

1. IP/رمز Root/پورت مشتری را دریافت می‌کند؛ اسکریپت `/root/setup_edge_relay.sh` را از Core به Edge می‌فرستد (منبع اسکریپت: `setup_edge_relay.sh` در ریپو).
2. روی Edge، `wg0` را برای `10.77.0.0/24` می‌سازد، آن را برای بوت enable می‌کند، `ip_forward=1` و DNAT `PREROUTING` برای SSH و TLS → `10.77.0.1` می‌گذارد. اسکریپت فعلی یک `iptables -t nat -A POSTROUTING -j MASQUERADE` **عمومی** هم اضافه می‌کند؛ **به‌تنهایی Egress از Edge برای Core SSH نمی‌سازد** و می‌تواند با Rule اختصاصی Egress هم‌پوشانی/Shadow داشته باشد.
3. کلید **عمومی** Peer را به تنظیمات Core `wg0` اضافه و با `wg syncconf` همگام می‌کند؛ عضویت استخر فعال می‌شود؛ دکمه «⭐ پیش‌فرض» جداگانه نمایش می‌یابد. صرف ثبت در استخر، Edge را Default/رله دامنه نمی‌کند.
4. در بخش `record_ingress_candidate` فقط کاندید `INGRESS_ONLY` ثبت می‌شود. این مرحله **تونل اختصاصی Egress، UID rule، table blackhole یا SNAT اختصاصی را برای مشتری فعال نمی‌کند**.
5. ویزارد ورود مدیریتی SSH به VPS مقصد و پیکربندی آن را واقعاً تغییر می‌دهد؛ صرفاً یک رکورد دیتابیس نیست. پس **برای تشخیص P0 مجدداً اجرا نشود**.

**نتیجه طراحی:** وظیفه Ingress Provisioning بات از قبل موجود است و **نباید بازنویسی شود**. کمبود فعلی، اتصال **مسیر خروجی همان UID → همان Edge ورودی حساب** در Data Plane است. افزودن Rule باید فقط پس از تعیین Edge واقعی حساب از داده‌های Production باشد؛ Default عمومی، گزینه «رله فعال» یا DNS عمومی به تنهایی دلیل تعیین Egress مقصد نیست.

**منابع دقیق در master:**
- `bot_final_v49-2.py`: `_provision_new_edge_sync` حدود خطوط 3582–3743؛ `_provision_new_edge` حدود 3746–3833؛ ویزارد `EDGE_NEW_*` حدود 12771–12824.
- `bot_final_v49-2.py`: پنل `_render_host_pool_panel` حدود 13437–13612؛ `_render_server_status_panel` حدود 14165–14257؛ `srv_mkactive_*` حدود 20896–20954؛ `hpdef_*` و `hpdefmig_yes_*` حدود 23882–23951.
- `bot_final_v49-2.py`: `_db_set_default_host` حدود 3436–3445؛ `_cf_update_dns_record_sync` حدود 3968–4034.
- `setup_edge_relay.sh`: سازوکار WireGuard ورودی، DNAT و MASQUERADE حدود 63–94.
- `docs/EDGE_EGRESS_CURRENT_HANDOFF.md`: Snapshot تولید، UID1644 و مسیر `stg1`.
- مسیر قدیمی `setup_edge_datapath.sh` معماری متناقض **Edge-terminates-SSH** است؛ **برای V1 اجرا نشود**.

### 12.3 چگونه ابهام «این Edge واقعاً برای Egress آماده است؟» را رفع کنیم؟

**P0 = Read-only و دو گام؛ هیچ «راه‌اندازی»، افزودن Edge، تغییر DNS، انتخاب رله یا تغییر 6G نداریم.**

**الف) فقط Production Core `209.200.246.198`:**
- از دیتابیس واقعی صرفاً **سطر حساب شناخته‌شده** (`nvl0557` به‌عنوان شاهد تاریخی، *نه Canary مجاز برای تغییر*)، `host_pool` فعال و `is_default`، و کلیدهای تنظیمات **غیرمحرمانه** (`dns_current_ip`, `tls_passthrough`, `edge_egress_protected_mode`, `phase6h_auto_failover_enabled`) را بخوان؛ هیچ Token یا Password چاپ نشود.
- `id -u nvl0557`، `ip -4 route get 1.1.1.1 uid 1644` (عدد را با UID واقعی تطبیق بده)، `ip -4 rule show`، فقط جدول‌های Route موردنیاز، `ip netns list`، نام Interfaceهای WG و Routeهای namespace Egress موجود را بخوان.
- تطبیق `ssh_accounts.host` با **public IP همان Edge ورودی** و `host_pool`، و بررسی زنده‌بودن تونل اختصاصی موجود، بدون افشای کلیدهای WireGuard؛ از Source/Targetهای تاریخی بدون ممیزی جدید نتیجه نگیر.

**ب) فقط Edge متعلق به همان حساب، پس از تعیین IP در (الف):**
- `ip -4 -br addr`, `ip -4 route show`, `ip -4 rule show`، `wg show interfaces` و فقط Rules مربوط `iptables -t nat -S PREROUTING`, `POSTROUTING` و `iptables -S FORWARD` را **Read-only** ببین؛ از پرینت کردن full `wg show`/config و هر private key خودداری کن.
- مشخص کن آیا Edge انتخاب‌شده **هم‌اکنون تونل Egress اختصاصی از Core**، Forwarding و SNAT scoped دارد یا فقط Ingress `wg0`/DNAT دارد. **اگر Ingress حساب مثلاً `172.86.94.174` باشد، موفقیت قبلی روی Frankfurt `216.126.229.12` برای شرط Same-Edge معتبر نیست**.

**خروجی P0 لازم، پیش از هر Mutation:**

```text
Production Core confirmed?                  YES / NO / UNKNOWN
Candidate account / UID / ingress Edge IP:  ... (NO customer changes)
Active relay / default / public DNS match?  YES / NO / DIVERGED / UNKNOWN
Regular UID IPv4 route currently via:        Core / Edge / Other
Dedicated egress tunnel to SAME Edge exists? YES / NO / UNKNOWN
SAME Edge forward+scoped SNAT proven?         YES / NO / UNKNOWN
Exact missing delta:                         routing / tunnel / SNAT / combination
Legacy wg0/NAT/UID1658/6G collision:          NONE / FOUND / UNKNOWN
Admin rescue/snapshot/read-only baseline:    VERIFIED / NOT VERIFIED
Decision:                                    P0 HOLD or propose ONE-UID change
```

**توقف:** تا وقتی Edge واقعی کاربر مشخص و مسیر Egress *همان* Edge تأیید نشده، **هیچ Rule** اعمال نشود. هیچ اسکریپت Stage یا 6G رجیستری دوباره اجرا نشود. نسخه در حال اجرای Production را فقط در حالت Read-only با منبع کد `master` تطبیق بده.

### 12.4 تعریف Stop برای V1

بعد از ارائه P0 و تأیید جداگانه اپراتور، تنها تغییرات شبکه **یک Canary ایزوله Production** قابل بررسی‌اند؛ هیچ Wizard، انتقال دسته‌جمعی کاربران، تغییر Default/DNS، Mer​ge PR #92 یا اتصال 6G جزو این فاز نیست. حتی مشاهده Egress IPv4 صحیح از namespace یا loopback SSHD، به‌تنهایی Feature-Complete نیست. پذیرش واقعی باید از **SSH عمومی** و برای **همان Edge حساب** باشد.
