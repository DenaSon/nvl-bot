# NVL — SSH Egress V1 | محدوده اجرایی و شواهد معتبر

> **مرجع اصلی ادامه این موضوع — 2026-10-12**
>
> **تصمیم:** اولویت فعلی فقط **اصلاح IP خروجی ترافیک SSH/SOCKS روی Production** است. توسعه جدید 6G/6H، F4/READY، معماری HA، UI بات و توسعه R1 متوقف/موکول شده‌اند. این سند «برنامه و حافظه شواهد» است، **نه مجوز دست‌کاری Production**.
>
> **شروع گفتگوهای بعدی:** این فایل را از `master` بخوان، وضعیت جاری GitHub و سرورها را از شواهد تازه (ابتدا Read-only) تطبیق بده، و فقط از «گام بعدی» بخش 10 پیش برو. تست‌های اثبات‌شده قبلی را بی‌دلیل تکرار نکن.


> **وضعیت جدید اجرایی در Production (2026-10-12):** مراحل P1-A تا P1-E برای یک Canary مستقل روی Miami موفق بوده‌اند: هم IP خروجی `144.172.84.76` از طریق SSH/SOCKS عمومی واقعی دیده شد و هم Fail-Closed با حذف Route آزمایش شد. **جزئیات و تنها نقطه صحیح ادامه در `14 است**؛ عبارت‌های تاریخی `P0 HOLD` و «SSH عمومی اثبات نشده» مربوط به قبل از این آزمایش هستند.
> **هدف مرحله بعد:** آماده‌سازی Persistence/Boot Guard و مسیر امن چندکاربره پیش از انتقال کاربران واقعی. هیچ مشتری منتقل نشده و هیچ پذیرش کلی امنیتی صادر نشده است. به‌روزرسانی سند فقط با درخواست صریح اپراتور.

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

**Checkpoint تاریخی، قبل از اجرای P1 (آخرین شواهد §14):**
- GitHub `master`: F1–F4 قبلاً Merge شده‌اند؛ برای SSH عمومی Production، IP خروجی هنوز اصلاح‌شده و پذیرفته‌شده نیست.
- R1 PR #92: Draft، **Freeze / No merge**. روی LAB مستقل فقط bootstrap، registration، PAM و دسترسی تازه مدیریتی بررسی شده‌اند؛ customer E2E باز است.
- Production: نتیجه معتبر قدیمی `nvl0557 uid=1644` خروج از Core است؛ آزمون SOCKS جداگانه خروج از فرانکفورت را نشان داده، نه هدف «همان Edge ورودی» را.
- **این تصمیم تاریخیِ قبل از P1 است؛ برای وضعیت فعلی و ادامه به §14 رجوع شود.**

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


## 13) P0 — شواهد تازه Core و تغییر IPهای Edge (2026-10-12؛ 14:20:49 UTC)

**منبع:** خروجی ترمینال Read-only ارائه‌شده اپراتور از Core با hostname `CloudVPS121849.s8rkc3`؛ وضعیت ثبت‌شده در این بخش Snapshot است، نه اثبات زنده مداوم یا مالکیت دیتاپلین. هیچ Mutation روی Production انجام نشد. `nvl0557` صرفاً شاهد Read-only است؛ Canary مجاز تغییر نیست.

- **تغییر کلیدی مالکیت حساب:** `ssh_accounts(username=nvl0557)` اکنون `host=104.194.144.195` و `status=🟢 فعال` نشان می‌دهد. **این مقدار با Snapshot تاریخی `172.86.94.174` متفاوت است.** `id -u nvl0557 = 1644`.
- **Default و DNS همچنان قدیمی‌اند:** تنها نتیجه Query هدفمند `host_pool WHERE is_default=1 OR host='104.194.144.195'`، سطر `172.86.94.174 / active=1 / is_default=1` بود؛ هیچ سطر تطبیقی برای `104.194.144.195` در همین Query برنگشت. `settings.dns_current_ip=172.86.94.174`، `tls_passthrough=1`. این اختلاف لزوماً خرابی نیست؛ ثبت حساب، default و DNS وظایف متفاوت دارند؛ فهرست کامل Edgeهای فعلی هنوز ممیزی نشده است.
- **مسیر UID هنوز Core است:** `ip -4 route get 1.1.1.1 uid 1644`، `via 148.113.199.41 dev eth0 src 209.200.246.198` داد. `ip -4 rule show` فقط `local`، `fwmark 0x77 -> table 77 (priority 7700)`، `main`، `default` داشت؛ Rule اختصاصی UID1644 دیده نشد. `table 77` همچنان `default dev wg0` دارد؛ دو MARK تکراری برای UID1658 و دو MASQUERADE تکراری mark 0x77 روی `wg0` باقی‌اند؛ به آن‌ها دست نزنید.
- **مسیر Egress فعلی، Same-Edge نیست:** namespace `nvl-egress-stg1` و interface `wg-nvl-stg1=10.78.110.2/30` فعال دیده شدند؛ namespace `default dev wg-nvl-stg1` و `allowed-ips=0.0.0.0/0` دارد، اما Endpoint ثبت‌شده تونل اختصاصی همچنان `216.126.229.12:51842` است، نه host فعلی حساب `104.194.144.195`. `wg-quick@wg-nvl-stg1` inactive/disabled است؛ مالکیت Startup/Reboot همچنان نامعلوم. `wg show interfaces` در root فقط `wg0` را نشان داد.
- **وضعیت عمومی:** `ssh` و `nvlbot` active؛ یک پردازش `sshd` متعلق به UID1644 گزارش شد، بدون اثبات نوع Session؛ هیچ دست‌کاری Session مجاز نیست. `ip -6 route get ... uid 1644` برای مقصد آزمایشی `Network is unreachable` بود، نه اثبات جامع عدم نشت IPv6. `iptables v1.8.10 (nf_tables)`.
- **سازگاری و Lock:** `edge_egress_allocations` حاضر؛ `edge_egress_readiness`، `edge_egress_uid_runtime`، `edge_egress_uid_bindings` و جدول به نام `edge_egress_legacy_fence` غایب‌اند (عدم وجود جدول به تنهایی به معنی نبود فنس خارج از DB نیست). `edge_egress_protected_mode=0`؛ `phase6h_auto_failover_enabled=1`. Query گروه‌بندی عملیات `failover_operations` سطری برنگرداند؛ از این خروجی نمی‌توان ایمنی تغییر را استنتاج کرد.

**تفسیر محدود:** نداشتن policy routing اختصاصی برای UID1644 و انتخاب Core `eth0` تأیید شد. اختلاف IP حساب، Default و Endpoint آزمایشی ثابت می‌کند که قبل از طراحی Delta، نگاشت **IPهای فعلی Edgeها، وضعیت واقعی Host Pool، مالکیت Peer ورودی و public IP سرور Edge حساب** باید Read-only روشن شود. دیتابیس نشان‌دهنده `configured ingress host` است، نه اثبات یک Session عبوری از آن Edge. هنوز نمی‌دانیم برای `104.194.144.195` تونل Egress اختصاصی و NAT مناسب از پیش نصب شده است یا نه.

**گام بعدی فقط P0:** روی همین Core، Query خواندنی محدود برای همه سطرهای `host_pool` با ستون‌های `host,active,is_default`، تعداد حساب‌های SSH به تفکیک `host` (بدون نام کاربری)، فقط `settings.hosts` در صورت بی‌خطر بودن مقدار، و خلاصه امن Peers WireGuard `wg0` (بدون private/public key)؛ سپس **فقط همان Edge واقعیِ مشخص‌شده** با فرمان‌های Read-only برای IP عمومی رابط، NAT، forward و WG بررسی شود. هیچ تغییر Default/DNS، SSH Session، `wg0`، 6G/6H، NAT یا Route انجام نشود. **Decision: P0 HOLD؛ Minimum Delta هنوز قابل تعیین دقیق نیست.**


### P0 Core follow-up — account distribution and wg0 endpoints (2026-10-12)

**Source:** operator-copied read-only output; dynamic handshake ages are a point-in-time snapshot, not a service availability attestation. No Production mutation.

- `ssh_accounts` aggregated by `host`: `104.194.144.195 = 1017` accounts; `172.86.94.174 = 1`; `144.172.84.72 = 1` (total 1019 records). Counts are DB rows, **not online users or live ingress observation**.
- `settings.hosts` IPv4 extraction: `144.172.84.76`, `144.172.84.82`, `172.86.94.174`. The `104.194.144.195` account host does not appear in this list. The `HOST POOL` block from this follow-up command was **not included in the supplied message**; full current pool membership must not be inferred.
- `wg0` peer endpoints (public key deliberately suppressed): `10.77.0.3/32 → 172.86.94.174:39370` (1 min since handshake); `10.77.0.9/32 → 144.172.111.51:58288` (32 min); `10.77.0.7/32 → 144.172.84.82:53398` (1 min); `10.77.0.8/32 → 144.172.84.76:60170` (0 min). Additional peer AllowedIPs `10.77.0.2/32`, `.5/32`, `.4/32` had endpoint `(none)` and handshake `never`. Endpoint addresses alone may differ from a peer's configured advertised host due to NAT; these observations do **not** establish which Edge currently receives any given customer's ingress.
- **Key mismatch:** `nvl0557` is configured on `104.194.144.195` (Section 13); that address appears in neither supplied `settings.hosts` nor observed `wg0` endpoints. The current default/DNS last seen is `172.86.94.174`; the dedicated staging egress endpoint is `216.126.229.12`. Do not substitute default/DNS or Frankfurt egress for a proven same-edge ingress.
- **Next gate (P0 only):** recover the omitted `HOST POOL` output (or re-query only `host,active,is_default`), establish authoritative current Edge public-IP ownership and intended account endpoint vs actual ingress using minimally scoped, credential-free Core/Edge evidence, then inspect NAT/forward/WG only on the confirmed relevant Edge. Keep live `nvl0557` read-only; no mass host migration or DNS edits. **P0 HOLD**; minimum specific route/tunnel/NAT delta unresolved.


### P0 Core follow-up — full host_pool snapshot (2026-10-12)

**Evidence:** operator-supplied read-only SQLite query of `host_pool` (timestamp of the newest capture not included):

| host | active | is_default |
|---|---:|---:|
| `144.172.84.76` | 1 | 1 |
| `144.172.111.51` | 0 | 0 |
| `144.172.84.82` | 1 | 0 |
| `172.86.94.174` | 1 | 0 |

**Changed default:** earlier P0 filtered query returned `172.86.94.174 / is_default=1`; newest full query instead reports `144.172.84.76 / is_default=1`. These are distinct read-only snapshots, not an attestation of what caused the transition. Earlier `phase6h_auto_failover_enabled=1` makes automation a possibility, not proof of causality. Do not change defaults, auto-failover or DNS.

**Unresolved identity:** `104.194.144.195` (1017 `ssh_accounts.host` rows including witness `nvl0557`) does not appear in this host pool, the earlier `settings.hosts` IPv4 list, or observed `wg0` endpoints. This does not itself prove SSH downtime: configured host is not proven live ingress. Last-seen `dns_current_ip=172.86.94.174` predates latest host_pool snapshot, so current DNS/default agreement is UNKNOWN.

**P0 next gate:** one narrow, read-only simultaneous Core snapshot of default and `dns_current_ip`, relevant non-secret 6H operation states (without PII), then non-invasive verification of actual public ingress/ownership for the account and, only after identification, read-only NAT/WG/forwarding inspection of that Edge. No live customer/session modifications, no mass migration, no routing/NAT/WG/Cloudflare changes. Status remains P0 HOLD; exact same-edge delta unknown.


### P0 Core follow-up — active relay UI and synchronized DNS/default (2026-10-12T14:30:29Z)

**Evidence:** operator-supplied read-only SQLite snapshot at `2026-10-12T14:30:29.036574+00:00` plus operator's report of role labels currently shown by the bot. Production remains unchanged.

- `host_pool`: `144.172.84.76 (active=1,is_default=1)`, `144.172.111.51 (active=0,is_default=0)`, `144.172.84.82 (active=1,is_default=0)`, `172.86.94.174 (active=1,is_default=0)`.
- `settings.dns_current_ip=144.172.84.76`, now **equal** to DB default; previous DNS/default values in earlier snapshot were point-in-time. `edge_egress_protected_mode=0`, `phase6h_auto_failover_enabled=1`.
- Operator reports bot UI: `144.172.84.76` is active relay; `144.172.84.82` and `172.86.94.174` are standby; `144.172.111.51` disabled. These are UI/operator role observations, not data-plane proof. Grouping query on `failover_operations` returned no rows; cannot establish what caused previous default transition.
- **Unresolved:** `ssh_accounts.host=104.194.144.195` for 1017 records including read-only witness `nvl0557` remains outside observed current host pool and wg0 endpoint list. Neither UI active relay nor DB default proves live ingress Edge of that existing SSH session. Do not treat `144.172.84.76` as its same-edge egress destination without verifying ingress.

**Next minimal P0:** inspect only the existing user-owned `sshd` process ancestry and corresponding established Core socket (with redaction of external client IPs) to determine which `10.77.0.x` WireGuard peer carried it, if an active SSH socket exists. Match that internal peer to the known `wg0` endpoint mapping. If no attributable socket exists, label live ingress UNKNOWN and do not infer it from default/DNS. Then inspect only the confirmed Edge read-only (WG/forward/NAT), without changing any customer account/session, WireGuard, network rules, bot, DNS or 6G. P0 HOLD.

## 14) P1-A تا P1-E — مسیر واقعی Miami (شواهد اپراتور، 2026-10-12)

**اعتبار:** خروجی‌های واقعی Core و Miami و Windows PowerShell که اپراتور در همین دور گزارش کرده است. این‌ها داده‌های نقطه‌ای هستند، نه تضمین سلامت دائمی یا سند امضاشده. این بخش بر وضعیت‌های قدیمی `P0 HOLD` مقدم است. هیچ دستور تغییر کد GitHub، مهاجرت کاربران واقعی، تغییر DNS/Cloudflare یا ویرایش `wg0` در این عملیات گزارش نشده است.

### 14.1 انتخاب Edge و اندازه عملیاتی

- Production Core: `209.200.246.198` (hostname: `CloudVPS121849`). Active Ingress Relay: Miami `144.172.84.76` (hostname: `ubuntu-Miami-1gb`)، `eth0=144.172.84.76/24` و `wg0=10.77.0.8/24`، خروج مستقیم Edge به اینترنت از `eth0` با IP خودش.
- Miami پیش از تغییر: `wg show interfaces` فقط `wg0`؛ بدون netns؛ `net.ipv4.ip_forward=1`؛ DNAT ورودی TCP `2252` و `2088` به `10.77.0.1`؛ `POSTROUTING -j MASQUERADE` عمومی؛ `FORWARD ACCEPT`. وجود MASQUERADE عمومی به معنی آمادگی کامل Egress چندکاربره نیست.
- وضعیت bot UI در Snapshot: Miami فعال، `144.172.84.82` و `172.86.94.174` standby و `144.172.111.51` disabled. در Core شمارش `ss`: **113 اتصال TCP established** از peer `10.77.0.8` روی پورت محلی `2252`. رادار بات جداگانه **540 فروش کل، 419 کاربر فعال SSH، 114 آنلاین، 118 اتصال مستقیم، صفر TLS/Gost** اعلام کرد. اختلاف روش/زمان شمارش‌ها را خرابی ندانید؛ 1019 سطر قدیمی `ssh_accounts` با 419 کاربر فعال برابر نیست.
- گزارش آزمایش قبلی و مجزا از اپراتور: UID 1636 (`nvl0555`) با Rule موقت و AllowedIPs سراسری روی `wg0` قدیمی از Edge `107.189.22.144` خارج شد، ولی بازنویسی `wg0.conf` آن را شکست. **این تجربه مجوز افزودن `0.0.0.0/0` به peer مشترک wg0 و تعمیم ناامن آن به چند Edge نیست.**

### 14.2 P1-A/P1-B — Backup، Stage و تونل اختصاصی

- طبق تصمیم اپراتور، **فقط Core بکاپ کامل گرفت**: `/root/nvl-egress-backups/core-20261012-153159-0MgVNi`، حدود **41M**. خروجی: `BACKUP_OK`، `DATABASE_INTEGRITY=OK`، `ARCHIVE_VERIFIED=OK`، تطبیق SHA256 دیتابیس/آرشیو/iptables. شامل `master_bot.db` با `PRAGMA integrity_check=ok`، تنظیمات Core، وضعیت Route/Firewall و فایل‌های موجود مرحله قبل. **بکاپ محلی است؛ Snapshot مستقل VPS، کپی Offsite و تست Restore گزارش نشده‌اند.** Miami بکاپ کامل ندارد؛ جایگزینی Edge لزوماً نشست‌های فعال را حفظ نمی‌کند.
- Provisioner موجود `ops/edge_egress_provision.py` با Git blob تأییدشده `9a5a193888f9f2f3d3b87ad996df361265061685` استفاده شد؛ کلیدهای **خصوصی** WG در سرورها باقی ماندند و نباید در سند/chat قرار گیرند. خروجی `CORE_STAGE_OK`، `TRANSFER_OK`، `MIAMI_STAGE_OK`؛ هر دو Preflight `ok=true,issues=[]`.
- منابع: `edge_id=mia1`، `wg-nvl-mia1`، UDP Edge `51843`، تونل `10.78.130.0/30` (Miami `.1`، Core `.2`)، Core namespace `nvl-egress-mia1`، veth `10.78.131.0/30` (Core root `vnh-mia1=10.78.131.1`، ns peer `10.78.131.2`)، routing table `1781`. مسیر مستقل قدیمی `nvl-egress-stg1`، `wg0` اصلی و جدول legacy `77` حفظ شدند.
- اپراتور `up.sh` ساخته‌شده را ابتدا در Miami سپس Core اجرا کرد: `MIAMI_EGRESS_UP` و `CORE_EGRESS_UP`، اینترفیس‌های متناظر و Route پیش‌فرض **فقط در namespace** تأیید شدند؛ `ssh` و `nvlbot` در Core هر دو `active`. هیچ `systemctl enable` یا Reboot آزمایشی برای Egress گزارش نشده است.
- تست `curl -4` داخل namespace Core با IP مقصد از پیش Resolve‌شده: `OBSERVED_PUBLIC_IP=144.172.84.76`، `SAME_EDGE_EGRESS=PASS` و handshake اختصاصی WG. این فقط مسیر TCP از namespace را ثابت می‌کند.

### 14.3 P1-C/P1-D/P1-E — Canary عمومی موفق

- حساب آزمایشی **`nvl-egc1` / UID 1690 / GID 1690** تازه ایجاد شد. `passwd -S` وضعیت **`L`** (رمز عبور قفل) را نشان می‌دهد، **اما کلید عمومی SSH مجاز نصب شد و ورود با کلید واقعاً موفق بود**؛ password-locked بودن به معنی ممنوعیت همه SSH loginها نیست. حساب مشتری واقعی تغییر نکرد.
- قواعد دستی و **غیرپایدار** مخصوص این UID: `ip rule pref 1781 uidrange 1690-1690 lookup 1781`؛ table `1781` دارای `default via 10.78.131.2 dev vnh-mia1 src 10.78.131.1 metric 100`، `blackhole default metric 4096` و `10.77.0.0/24 dev wg0 src 10.77.0.1` برای برگشت به Ingress؛ ip6tables owner reject و iptables owner DNS UDP/TCP 53 به `127.0.0.0/8`. Legacy `7700 fwmark 0x77→table 77` دست‌نخورده ماند.
- `ip route get 1.1.1.1 uid 1690` مسیر `vnh-mia1` را نشان داد، `runuser -u nvl-egc1 curl -4` بازگشت `144.172.84.76`: **`CANARY_EGRESS=PASS`**.
- P1-D: اسکریپت نخست قبل از تغییر Route در preflight متوقف شد؛ نسخه اصلاح‌شده `PREFLIGHT_PASS` و baseline IP صحیح داد. سپس فقط default متعلق به Miami در table 1781 حذف شد؛ با باقی‌ماندن blackhole، `ip route get` و probe اینترنت UID شکست خوردند: **`FAIL_CLOSED=PASS`**. Route بازسازی شد و IP Miami برگشت: `ROUTE_RESTORED`، **`EGRESS_RECOVERY=PASS`**، `P1_D_COMPLETE`. این **فقط یک آزمایش حذف Route** بود، نه اثبات قطع واقعی/rekey WG، packet capture یا همه نشت‌ها.
- P1-E: از **Windows PowerShell**، SSH/SOCKS واقعی روی Ingress عمومی Miami `144.172.84.76:2252` برای `nvl-egc1`، با dynamic forwarding محلی `127.0.0.1:31884` برقرار شد. `curl.exe -4 --socks5-hostname 127.0.0.1:31884 https://api.ipify.org` پاسخ **`144.172.84.76`** داد. **هدف Same-Edge برای یک SSH/SOCKS واقعی روی Production اثبات شد.** برای سایر UIDها، BadVPN/UDPGW، Gost، IPv6 یا DNS/NSS چنین اثباتی نداریم.
- جدیدترین خروجی کوتاه اپراتور: `id nvl-egc1` برابر UID/GID 1690، `passwd -S` برابر `L` و `systemctl is-active ssh nvlbot` هر دو `active`. بخش‌های `systemctl is-enabled`، واحدهای Egress، `sshd -T` و Route تازه در این پیام **ارائه نشده‌اند**؛ علامت `COMPLETE` معادل Boot Readiness نیست.

### 14.4 مرز عملیاتی و دقیقاً از کجا ادامه دهیم

**Checkpoint فعلی:** Dedicated Miami Egress و اتصال UID 1690 پس از P1-D طبق آخرین شواهد اپراتور برقرارند؛ اما ابزارهای اجرایی `up.sh` دستی و Ruleهای دستی UID **پس از reboot تضمین ندارند**. Canary اکنون authorized key دارد؛ با حذف selector UID پس از reboot، ممکن است به Route اصلی Core و IP `209.200.246.198` برگردد. **وجود blackhole در جدول غیرمنتخب محافظت نمی‌کند. از reboot کورکورانه یا migration قبل از BootGuard/admission deny-before-allow خودداری کنید.**

**باز/حل‌نشده:** (1) Persistent systemd ordering و Runtime/PAM admission واقعی، admin console rescue و restore rehearsal؛ (2) قطع واقعی dedicated WG/Edge و اثبات نبود fallback، DNS/NSS/IPv6/BadVPN/packet capture؛ (3) ناسازگاری فعلی F2/F4 برای چند UID روی Edge مشترک: shared table freeze و runtime-store که ثبت دومین protected UID را منع می‌کند؛ (4) نگاشت واقعی حساب/Session به Edge و چالش یک UID با Sessionهای هم‌زمان از چند Edge؛ (5) حفظ 6G lock/journal و سازگاری با 6H؛ (6) هیچ مشتری منتقل نشده، **419 فقط Snapshot کاربران فعال** نه فهرست آماده Cutover.

**گام بعد:** ابتدا **فقط Read-only** وضعیت Systemd/Boot، قواعد فعلی UID 1690، PAM/SSH و 6G lock را بررسی کنید. سپس Persistence همراه deny-first و rollback امن را در VPS ایزوله دارای Console تست و طراحی کنید؛ وضعیت shared-table چندکاربره را قبل از اضافه‌کردن UID دوم اصلاح و تست کنید؛ بعد از تست WG outage، DNS/IPv6 و rescue/restore، به‌صورت batch کوچک کاربران Miami را منتقل کنید و برای Edgeهای دیگر تونل و نگاشت جدا بسازید. برای Sessionهای هم‌زمان یک UID روی چند Edge، UID-only route به‌تنهایی Same-Edge per-session را تضمین نمی‌کند. **از همان تست‌های موفق namespace، UID curl، route-loss و SOCKS بدون علت تکرار نکنید.**

**مسیرهای محلی حساس، فقط برای Operator:** Core Backup `/root/nvl-egress-backups/core-20261012-153159-0MgVNi`؛ prep `/root/nvl-egress-mia1-prep`؛ Core stage `/root/nvl-egress-mia1-core-stage`؛ Edge prep `/root/nvl-egress-mia1-prep`؛ Edge stage `/root/nvl-egress-mia1-edge-stage`. **فایل‌های حاوی Private Key یا credential منتشر نشوند.** اجرای `down.sh` ساده بعد از اتصال UID به Route، rollback امن نیست؛ ابتدا Loginهای جدید deny، Sessionها مدیریت و Fail-Closed حفظ شود.

**تغییر مستندات فقط با درخواست صریح اپراتور.**


## 15) Dynamic Egress V1 implementation kickoff — 2026-10-12

**User-approved development scope:** Complete Dynamic SSH Egress V1 code first; only after code delivery and a short CI suite, deploy once under a controlled operator-led procedure, then validate by provisioning **one NEW Edge** rather than repeating an unbounded set of historical experiments. Preserve Core SSHD, legacy `wg0`, 6G/6H implementation and current customer sessions. Update context and essential development documents after each stage. This §15 and [the delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md) supersede earlier development-priority wording, but DO NOT supersede the safety evidence or production approval boundary.

**F1 completed on branch, not deployed:** New `ops/edge_egress_v1_transport.py` is an idempotent dedicated Egress transport supervisor for any Edge ID, with SHA-pinned root-only stage files and conservative HOLD on resource collision/partial state. It renders only an optional systemd unit, does not install/enable it or touch customer UID, SSH/PAM, `wg0`, default route or bot. Six lightweight pure Python unit tests are checked in. **This alone does not fix the reboot fail-open issue** and is not customer-ready. No real production change in this stage.

**Next:** F2 persistent deny-first UID guard and admission; G shared Edge multi-UID; H true ingress/session binding; I Egress in existing Edge onboarding; J 6H integration; K one gated deployment followed by NEW-Edge end-to-end acceptance. Full details and per-stage progress tracking: `docs/SSH_EGRESS_DYNAMIC_V1_DELIVERY.md`.

**F1 post-merge verification (2026-10-12):** [PR #93](https://github.com/DenaSon/nvl-bot/pull/93) merged to `master` (`0e9d976129cccbd47cb3ab6f9d14f93de468a64d`); Python checks and stage-only checks on final PR head passed. Code-only transport supervisor is present; UID boot guard, full Dynamic Egress, release and all customer onboarding remain **NOT DONE**. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md).

## 16) Dynamic V1 F2 code-only checkpoint (2026-10-12)

F2 development adds durable root-only protected UID roster, fail-closed PAM account policy using the existing DB/6G/readiness/kernel guard, and an opt-in precise `10.77.0.0/24 dev wg0 src 10.77.0.1` SSH ingress-return route installed by BootGuard before UID selection. Root recovery is an exception. Offline per-user Systemd/PAM renderers perform no installation. Seven focused source tests were added. **No Production modifications, no customer migration, no reboot**. This does NOT by itself solve multi-UID shared table, alive/dead WireGuard peer, legacy sessions, or multi-Edge 6H switching. Delivery details in [Dynamic V1 delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **F2 GitHub result:** [PR #94](https://github.com/DenaSon/nvl-bot/pull/94) merged to `master` with commit `29e66d7390c469b330e87eb06c7e741ece6b0b0e` after Python, staging and existing kernel-lab checks PASS on the final head. This remains code-only: no Production guard installation or permanent fail-closed claim. **Next stage is G (non-disruptive shared-Edge multi-UID).**

## 17) Dynamic V1 G source checkpoint (2026-10-12)

G adds shared-table / multiple-UID runtime code and a root-only protected roster for multiple users on the same Edge: freeze/boot arms owner-scoped IPv4 deny for only the selected UID instead of deleting shared table default, preserving other users' routes. Existing 6G transaction/CAS retained. Explicit opt-in and coherent new `shared_edge` manifests are required; no automatic adoption of old boot manifests. **No Production modifications or customer migrations.** This is not proof of simultaneous multi-Edge ingress, actual WireGuard loss, SSH boot safety or new Edge deployment. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **G result:** [PR #95](https://github.com/DenaSon/nvl-bot/pull/95) merged to `master` as `222a782da9b4a6bbbb5c17aee248260540918a6d`, final-head Python checks, stage-only (3.11/3.12), and existing kernel lab checks all PASS. **Next H session/actual ingress Edge binding**, then I/J and one K deployment. No actual protected-customer cutover or reboot has occurred.

## 18) Dynamic V1 H source checkpoint — 2026-10-12

H branch adds fail-closed *new SSH login* binding to the actual Core-observed ingress `wg0` peer; root-owned registry mapping (Edge ID, public Edge IPv4, `10.77.0.x/32`, WireGuard **public** key), live `wg show wg0 allowed-ips` check and PAM `PAM_RHOST` (`PAM_SERVICE=sshd`). Account must match its **existing protected UID Edge**; unknown or conflicting relay denied even if global active/default DNS points elsewhere. Sticky UID-to-one-Edge routing is deliberate: no unsafe UID switch during old sessions. **NOT** a per-socket multi-Edge system, not a production PAM attestation, and not a fix for live-session routing by itself. I must populate registry on Edge provisioning, J manage drain/6H failover, K verify public SSH/SOCKS on a NEW Edge. No Production mutation or user migration while code is developed. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **H GitHub result:** [PR #96](https://github.com/DenaSon/nvl-bot/pull/96) merged to `master` as `e40d812c4a11ceacd3edd8211f923563fa7080e4`; final-head Python and Stage-only checks PASS. **Next I** integrates an authoritative wg0 ingress-peer registry into the existing Edge wizard, then J/6H and the only controlled K new-Edge deployment/test. No claim of live PAM protection or public SSH proof for newly added Edges.

## 19) Dynamic Egress V1 I development (2026-10-12)

Proposed `hp_addedge` integration is behind default-OFF `edge_egress_v1_onboard_enabled` flag. After existing wg0 ingress provision it validates actual internal /32/public key with live wg0 AllowedIPs, stages the independent Egress tunnel on Core and new Edge, then atomically registers its H ingress identity. Stage-only result **STAGED_NOT_READY** is never equivalent to a real customer-safe Egress; incomplete stages HOLD (no host_pool success). No Production changes in source phase. Pre-existing `legacy_new_edge_gate` remains for protected mode until J/K guarded lifecycle and 6G are implemented. Scope and next gating: [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **I result:** [PR #97](https://github.com/DenaSon/nvl-bot/pull/97) merged `185cba018f1de7c1fc00d1e85daa6eba62b8467d`; final-head Python and Stage-only checks PASS. **Next J**: guarded 6H integration and actual Egress readiness/drain, then K deployment/new Edge E2E. Source completion is NOT production acceptance.

## 20) Dynamic SSH Egress V1 J — protected 6H source safety gate (2026-10-12)

J integrates a **read-only** F4 readiness + sticky-UID decision into existing manual 6G preflight, automatic Phase 6H evaluation before any failover start and protected manual default/bulk callback HOLD messages. Target ingress identity must be registered; STAGED/LAB/expired/non-F4 READY is denied. A pinned protected UID (including nonsettled/unknown state) prevents global DNS-to-another-Edge, and even an empty binding set does NOT open the legacy DNS→Core fallback. **Not yet a working guarded per-UID repin**: the injected `edge_egress_handoff` coordinator still needs a live 6G-journaled adapter, current session drain, trusted new-Edge readiness and tested Edge→Edge only DNS recovery. K must resolve this to enable protected active relay switching. No change to Production, sessions or IP. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **J safety gate result:** [PR #98](https://github.com/DenaSon/nvl-bot/pull/98) merged to `master` (`f0df4fd01410e1cc03989f5b2ff80bd1de8941ea`) with final-head Python and Stage-only 3.11/3.12 checks PASS. This is ONLY the fail-closed switch guard, NOT automatic protected Edge-to-Edge handoff. A real 6G-locked drain/repin/target-evidence adapter remains a release blocker before K customer migration; no Production changes.

## 21) J2 Positive Protected Handoff Adapter — 2026-10-12 code checkpoint

New code (PR #99) supplies a guarded **existing 6G lock/journal** adapter with: durable PAM FROZEN before session drain, per-UID fail-closed freeze, staged new dedicated Edge observation, UID repin and external IPv4 checks, same-transaction protected runtime/binding + drained-account-host CAS, direct Edge→Edge public DNS change followed by default/DNS setting CAS, final re-verification and UID release. Every partial operation after admission/candidate mutation leaves shared 6G RUNNING/HOLD, never DNS→Core. **This has only the application/SQLite side plus required audited HostActions interface; no production/live host driver is installed or enabled, no real new Edge test, no customer switched.** **J2 GitHub result:** [PR #99](https://github.com/DenaSon/nvl-bot/pull/99) merged to `master` (`d62d54a348aa8ec1bdb00cbe57b57fd73cccefc7`) after final-head Python and Stage-only 3.11/3.12 checks PASS. The source-only adapter remains disabled and needs a K-audited live HostActions driver. K must implement and attest real SSH session drain, root-owned manifest+roster persistence, Linux UID rule/transport handling, remote Edge and direct DNS proofs before protected failover may be enabled. Details: [Dynamic V1 delivery](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md).

## 22) K1 live SSH / Kernel / DNS driver — source-only checkpoint (2026-10-12)

The J2 HostActions implementation is staged in GitHub: bounded pinned Paramiko Edge transport; Core owner-only F2 roster/BootGuard and G per-UID REJECT + exact selector repin; conservative SSH/UID idle scan; per-UID external public IP probe with REJECT rearmed; Cloudflare Edge→Edge exact record read/CAS/verify with no Core fallback. Only usable via existing J2 adapter with current RUNNING 6G lock, explicit K opt-in, and root; the bot does **not** call this live path and **no server/DNS/DB changes are made by source development**. Stage hashes, host keys, dedicated transport boot persistence, PAM gate, F4 acceptance, real process/socket proof and packet-level IPv6/DNS-leak tests must be accepted on one NEW Edge under K2 before live migration. Current J2 global snapshot is all-protected only and may not be applied to the mixed current customer base; legacy 6H remains untouched. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). **K1 GitHub result:** [PR #100](https://github.com/DenaSon/nvl-bot/pull/100) merged to `master` (`dabea657de901b7eb851eaf64f3add4eab0007a1`) after final-head Python and Stage-only 3.11/3.12 PASS. Fixed Paramiko SSH key blob parsing, checked live PAM before F2 admission freeze, migrated per-UID DoH systemd Unit alongside route, and exempted only attested DoH MainPID from idle scan. No Production changes. Next K2 ONE new Edge controlled install/acceptance; global protected 6H remains HOLD for mixed users.


## 23) K2 Telegram Egress UI source checkpoint — 2026-10-12

Admin Edge pool → Egress Management now exposes registered Edge status, F4 evidence/expiry, optional signed-stage Core namespace IPv4 trace, existing Edge onboarding and the five K2 activation prerequisites. This is read-only except the pre-existing `hp_addedge` wizard, which still follows its own existing legacy fences and default-OFF dedicated Egress opt-in. The IP probe requires an operator-attested root-owned stage SHA256 and an already-running dedicated namespace; it only reports IP equality, never marks READY. NO one-button enable/reboot, customer route/DNS mutation or claim that a protected 6H switch is already ready. Initial Core/PAM boot installation and a new Edge E2E acceptance remain to be performed under K2 with rescue. See [delivery ledger](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md).


**K2 UI merge evidence (2026-10-12):** [PR #101](https://github.com/DenaSon/nvl-bot/pull/101) merged to `master` (`7c3218116974974ae124ef44e995c9e9fa3ecb4d`), final-head Python + Stage-only CI PASS. Admin-only UI is code-complete but NOT deployed on Production, and it cannot enable protected accounts, PAM/Boot or 6H. One NEW Edge SSH/SOCKS egress/DNS/IPv6/WG-loss and rescue acceptance is pending.
