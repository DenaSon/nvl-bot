#!/bin/bash
# ============================================================================
# collect_core_migration_files.sh — ساختِ خودکارِ پکیجِ کاملِ مهاجرت (Phase 1 تکمیلی)
# ----------------------------------------------------------------------------
# این اسکریپت را روی Core فعلی اجرا می‌کنید (دستی، یا خودکار توسط sync_bot_to_edges.sh).
# هر بار اجرا می‌شود، /root/core_migration/ را از صفر و تازه می‌سازد؛ شاملِ همهٔ چیزهایی
# که promote_edge_to_core.sh برای ترفیعِ یک Edge به Core جدید لازم دارد:
#   core_private.key, wg0.conf.peers, master_bot.db, gost_config.yaml,
#   letsencrypt.tar.gz, cf_certs.tar.gz (اگر باشد), gost_bin
#
# نتیجه: دیگر هیچ‌وقت لازم نیست قبل از هر Promote، دستی این ۷ فایل را جمع کنید —
# اگر این اسکریپت را به‌صورت دوره‌ای (مثل sync_bot_to_edges.sh) اجرا کنید، همیشه یک
# نسخهٔ تازه آماده و منتظر است.
# ============================================================================
set -uo pipefail

BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"
OUT_DIR="${MIGRATION_OUT_DIR:-/root/core_migration}"
WG_CONF="/etc/wireguard/wg0.conf"
CORE_PRIV_KEY="/etc/wireguard/core_private.key"
GOST_CONF="/etc/gost/config.yaml"
GOST_BIN="/usr/local/bin/gost"
BADVPN_UDPGW_BIN="/usr/local/bin/badvpn-udpgw"
LETSENCRYPT_DIR="/etc/letsencrypt"
CF_CERTS_DIR="/etc/ssl/cf"
DB_PATH="${BOT_DIR}/master_bot.db"
# 🆕 وضعیتِ لاگینِ ادمین/نماینده‌ها (python-telegram-bot persistence) — بدون این، بعد از هر
# Promote/فیل‌اوور همه باید دوباره لاگین کنند، حتی اگر لاگینشان همان لحظه هنوز معتبر بود.
BOT_PERSISTENCE="${BOT_DIR}/bot_persistence.pickle"
# 🆕 کلید دائمیِ SSH که خودِ ربات برای اتصال خودکار به همهٔ Edgeها استفاده می‌کند (هم در
# sync_bot_to_edges.sh و هم در عملیات‌های داخلی خودِ ربات، مثل DO_SSH_KEY_PATH). قبلاً این
# فایل اصلاً جزو پکیجِ مهاجرت نبود — نتیجه‌اش این بود که بعد از هر Promote، ربات روی Core
# جدید با «کلید SSH پیدا نشد» شکست می‌خورد و کسی مجبور بود دستی با scp منتقلش کند.
EDGE_SSH_KEY_PRIV="/root/.ssh/edge_provision_ed25519"
EDGE_SSH_KEY_PUB="/root/.ssh/edge_provision_ed25519.pub"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*"; }

mkdir -p "$OUT_DIR"
MISSING=()

# ۱) کلید خصوصیِ Core
if [ -f "$CORE_PRIV_KEY" ]; then
    cp "$CORE_PRIV_KEY" "${OUT_DIR}/core_private.key"
else
    MISSING+=("core_private.key (این سرور اصلاً Core نیست یا کلیدش گم شده)")
fi

# ۲) بلاک‌های [Peer] از wg0.conf
if [ -f "$WG_CONF" ]; then
    awk '/^\[Peer\]/{f=1} f' "$WG_CONF" > "${OUT_DIR}/wg0.conf.peers"
else
    MISSING+=("wg0.conf.peers (wg0.conf پیدا نشد)")
fi

# ۳) دیتابیس ربات
if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "${OUT_DIR}/master_bot.db"
else
    MISSING+=("master_bot.db")
fi

# ۴) کانفیگ gost
if [ -f "$GOST_CONF" ]; then
    cp "$GOST_CONF" "${OUT_DIR}/gost_config.yaml"
else
    MISSING+=("gost_config.yaml (اختیاری — یعنی TLS/WSS روی Core جدید هم غیرفعال می‌ماند)")
fi

# ۵) خودِ باینریِ gost — 🆕 همان چیزی که دیشب فراموش شده بود و باعث ۲۳ ساعت crash-loop شد
if [ -x "$GOST_BIN" ]; then
    cp "$GOST_BIN" "${OUT_DIR}/gost_bin"
else
    MISSING+=("gost_bin (باینریِ /usr/local/bin/gost پیدا نشد)")
fi

# ۵.۵) 🆕 خودِ باینریِ badvpn-udpgw — چون این از سورس کامپایل می‌شود (نه apt)، اگر این‌جا کپی نشود،
# Core جدید اصلاً باینری‌اش را ندارد و سرویسِ UDPGW بالا نمی‌آید.
if [ -x "$BADVPN_UDPGW_BIN" ]; then
    cp "$BADVPN_UDPGW_BIN" "${OUT_DIR}/badvpn_udpgw_bin"
else
    MISSING+=("badvpn_udpgw_bin (باینریِ /usr/local/bin/badvpn-udpgw پیدا نشد)")
fi

# ۶) گواهی‌های Let's Encrypt
if [ -d "$LETSENCRYPT_DIR" ] && [ -n "$(ls -A "$LETSENCRYPT_DIR" 2>/dev/null)" ]; then
    tar -czf "${OUT_DIR}/letsencrypt.tar.gz" -C /etc letsencrypt
else
    MISSING+=("letsencrypt.tar.gz (پوشهٔ /etc/letsencrypt خالی یا وجود ندارد)")
fi

# ۷) گواهی‌های Cloudflare (اختیاری)
if [ -d "$CF_CERTS_DIR" ] && [ -n "$(ls -A "$CF_CERTS_DIR" 2>/dev/null)" ]; then
    tar -czf "${OUT_DIR}/cf_certs.tar.gz" -C /etc ssl/cf
fi

# ۸) 🆕 کلید دائمیِ SSH — الزامی؛ بدونش ربات روی Core جدید نمی‌تواند به هیچ Edgeای وصل شود
if [ -f "$EDGE_SSH_KEY_PRIV" ]; then
    cp "$EDGE_SSH_KEY_PRIV" "${OUT_DIR}/edge_provision_ed25519"
    chmod 600 "${OUT_DIR}/edge_provision_ed25519"
    [ -f "$EDGE_SSH_KEY_PUB" ] && cp "$EDGE_SSH_KEY_PUB" "${OUT_DIR}/edge_provision_ed25519.pub"
else
    MISSING+=("edge_provision_ed25519 (کلید دائمیِ SSH پیدا نشد — ربات روی Core جدید نمی‌تواند به Edgeها وصل شود)")
fi

# ۹) 🆕 وضعیتِ لاگینِ ادمین/نماینده‌ها — تا بعد از Promote/فیل‌اوور نیازی به لاگینِ مجدد نباشد.
if [ -f "$BOT_PERSISTENCE" ]; then
    cp "$BOT_PERSISTENCE" "${OUT_DIR}/bot_persistence.pickle"
else
    MISSING+=("bot_persistence.pickle (اختیاری — یعنی همهٔ ادمین/نماینده‌ها بعد از Promote باید دوباره لاگین کنند)")
fi

# ۱۰) 🆕 اسنپ‌شاتِ کاملِ محیط: هر فایل/اسکریپت/یادداشتی که دستی توی BOT_DIR اضافه/ادیت شده،
# نه فقط لیستِ ثابتِ بالا. master_bot.db*, bot_persistence.pickle عمداً کنار گذاشته می‌شوند
# چون بالاتر با روشِ اختصاصی‌شان منتقل شدند؛ venv/nvlbot_standby/core_migration هم عمداً کنار
# گذاشته می‌شوند چون حجیم‌اند و از مسیرهای دیگری (sync_bot_to_edges.sh / خودِ Promote) منتقل
# می‌شوند — اینجا فقط برای فایل‌های «یتیم»ی است که هیچ مسیرِ دیگری برای انتقالشان وجود ندارد.
echo "۱۰) ساختِ اسنپ‌شاتِ کاملِ محیط (root_full_snapshot.tar.gz)..."
# 🐛🔧 فیکس: tar وقتی پوشهٔ «زنده»ای (که پروسهٔ ربات هم‌زمان داخلش می‌نویسد، مثل
# bot_operations.log) را آرشیو می‌کند، اگر فایلی وسطِ خواندن تغییر کند، exit code 1
# برمی‌گرداند (فقط هشدار: «یک فایل حین کپی تغییر کرد»)، نه یک شکستِ واقعی. exit code
# واقعیِ خطا 2 یا بیشتر است. قبلاً هر خروجیِ غیرصفری (شاملِ همین ۱ی بی‌خطر) را «شکست»
# حساب می‌کردیم و همین باعث می‌شد پکیجِ کاملاً سالم، غلط به‌عنوانِ MISSING گزارش شود.
tar -czf "${OUT_DIR}/root_full_snapshot.tar.gz" -C "$(dirname "$BOT_DIR")" "$(basename "$BOT_DIR")" \
    --exclude="$(basename "$BOT_DIR")/venv" \
    --exclude="$(basename "$BOT_DIR")/venv.bak.*" \
    --exclude="$(basename "$BOT_DIR")/nvlbot_standby" \
    --exclude="$(basename "$BOT_DIR")/core_migration" \
    --exclude="$(basename "$BOT_DIR")/master_bot.db*" \
    --exclude="$(basename "$BOT_DIR")/bot_persistence.pickle*" \
    --exclude="$(basename "$BOT_DIR")/.migration_export_*" \
    2>/dev/null
TAR_RC=$?
if [ "$TAR_RC" -le 1 ]; then
    log "   ✅ root_full_snapshot.tar.gz ساخته شد ($(du -h "${OUT_DIR}/root_full_snapshot.tar.gz" 2>/dev/null | cut -f1))."
else
    MISSING+=("root_full_snapshot.tar.gz (ساختِ اسنپ‌شاتِ محیط شکست خورد — کدِ خروجیِ تار: ${TAR_RC})")
fi

# ============================================================================
# ۱۱) 🆕 اسنپ‌شاتِ سطح-سیستم: پکیج‌هایی که دستی نصب کردی، کرون‌جاب‌ها، و سرویس‌های
# systemd سفارشی‌ای که خودت ساختی — چیزهایی که بیرون از BOT_DIR هستند ولی جزو «کارهایی که
# روی این Core انجام دادی» محسوب می‌شوند. عمداً /etc را کامل کپی نمی‌کنیم (چون شاملِ چیزهای
# مخصوصِ همین سرور مثل hostname/machine-id/کلیدهای host SSH است که کپیِ کورکورانه‌شان می‌تواند
# سرور جدید را خراب کند) — فقط لیستِ فایل‌های /etc که دستی تغییر کرده‌اند را می‌سازیم تا خودت
# دستی مرورش کنی.
# ============================================================================
echo "۱۱) اسنپ‌شاتِ سطح-سیستم (پکیج‌ها، کرون، سرویس‌های سفارشی، لیستِ /etc تغییریافته)..."

# ۱۱.۱) پکیج‌هایی که دستی نصب کرده‌ای (نه وابستگی‌های خودکار)
if command -v apt-mark >/dev/null 2>&1; then
    apt-mark showmanual > "${OUT_DIR}/manually_installed_packages.txt" 2>/dev/null || true
    log "   ✅ manually_installed_packages.txt ساخته شد ($(wc -l < "${OUT_DIR}/manually_installed_packages.txt" 2>/dev/null || echo 0) پکیج)."
fi

# ۱۱.۲) کرون‌جاب‌های root + /etc/cron.d
crontab -l -u root > "${OUT_DIR}/root_crontab.txt" 2>/dev/null || : > "${OUT_DIR}/root_crontab.txt"
if [ -d /etc/cron.d ] && [ -n "$(ls -A /etc/cron.d 2>/dev/null)" ]; then
    mkdir -p "${OUT_DIR}/cron_d"
    cp /etc/cron.d/* "${OUT_DIR}/cron_d/" 2>/dev/null || true
fi
log "   ✅ کرون‌جاب‌ها ذخیره شدند."

# ۱۱.۳) سرویس‌های systemd سفارشی (نه چیزهایی که خودِ Promote/setup_edge_relay می‌سازد)
KNOWN_UNITS=(gost.service badvpn-udpgw.service nvl-edge-sync.service nvl-edge-sync.timer
             wg-quick@wg0.service ssh.socket ssh.service sshd.service)
mkdir -p "${OUT_DIR}/custom_systemd_units"
: > "${OUT_DIR}/custom_systemd_units_enabled.txt"
for unit_path in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.socket; do
    [ -f "$unit_path" ] || continue
    unit_name="$(basename "$unit_path")"
    skip=0
    for k in "${KNOWN_UNITS[@]}"; do [ "$unit_name" = "$k" ] && skip=1 && break; done
    [ "$skip" = "1" ] && continue
    cp "$unit_path" "${OUT_DIR}/custom_systemd_units/${unit_name}"
    if systemctl is-enabled --quiet "$unit_name" 2>/dev/null; then
        echo "$unit_name" >> "${OUT_DIR}/custom_systemd_units_enabled.txt"
    fi
done
CUSTOM_UNIT_COUNT=$(find "${OUT_DIR}/custom_systemd_units" -type f 2>/dev/null | wc -l)
log "   ✅ ${CUSTOM_UNIT_COUNT} سرویسِ systemd سفارشی ذخیره شد."

# ۱۱.۴) فقط لیست (نه محتوا) فایل‌های /etc که دستی تغییر کرده‌اند — امن‌تر از کپیِ کورکورانه
if command -v dpkg >/dev/null 2>&1; then
    timeout 30 dpkg -V 2>/dev/null | awk '$1 ~ /^..5/ {print $2}' | grep '^/etc/' \
        > "${OUT_DIR}/modified_etc_conffiles.txt" 2>/dev/null || : > "${OUT_DIR}/modified_etc_conffiles.txt"
    timeout 30 bash -c '
        find /etc -type f 2>/dev/null | while read -r f; do
            dpkg -S "$f" >/dev/null 2>&1 || echo "$f"
        done
    ' > "${OUT_DIR}/untracked_etc_files.txt" 2>/dev/null || : > "${OUT_DIR}/untracked_etc_files.txt"
    log "   ✅ لیستِ فایل‌های /etc تغییریافته/دستی ساخته شد ($(wc -l < "${OUT_DIR}/modified_etc_conffiles.txt") تغییریافته + $(wc -l < "${OUT_DIR}/untracked_etc_files.txt") دستی)."
fi

date '+%Y-%m-%d %H:%M:%S' > "${OUT_DIR}/.last_collected"

echo ""
if [ "${#MISSING[@]}" -eq 0 ]; then
    log "✅ پکیجِ مهاجرت کامل ساخته شد در ${OUT_DIR} — همه‌چیز آماده."
else
    log "⚠️ پکیج ساخته شد ولی این موارد کم بودند/رد شدند:"
    for m in "${MISSING[@]}"; do echo "   - $m"; done
fi
ls -la "$OUT_DIR"