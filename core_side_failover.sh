#!/bin/bash
# ============================================================================
# core_side_failover.sh — اجرا روی Core فعلی؛ کل مسیر Failover را یک‌دستوری می‌کند
# ----------------------------------------------------------------------------
# جایگزینِ کاملِ کارِ دستیِ MobaXterm/لپ‌تاپ. این اسکریپت:
#   ۱) تمام فایل‌های لازم (کلید WireGuard، peers، دیتابیس، TLS، gost) را خودش
#      از روی همین Core جمع می‌کند — نه چیزی دانلود روی لپ‌تاپ، نه آپلود دستی.
#   ۲) آن‌ها را + خودِ promote_edge_to_core.sh را با rsync به سرور Edgeِ مقصد می‌فرستد.
#   ۳) از طریق همان اتصال SSH، promote_edge_to_core.sh را روی Edge اجرا می‌کند —
#      و OLD_CORE_IP را خودکار به IP همین سرور ست می‌کند تا محافظِ Split-Brain
#      (مرحلهٔ ۱۰ در promote_edge_to_core.sh) بدون نیاز به وارد کردنِ دستیِ آن کار کند.
#
# پیش‌نیازِ یک‌بارهٔ اجرا (فقط همین یک بار، نه هر بار Failover):
#   - promote_edge_to_core.sh باید همین‌جا روی Core، در مسیر PROMOTE_SCRIPT_PATH
#     (پیش‌فرض: /root/promote_edge_to_core.sh) موجود باشد.
#
# نحوهٔ اجرا:
#   sudo bash core_side_failover.sh <TARGET_EDGE_IP> <CUSTOMER_SSH_PORT>
# مثال:
#   sudo bash core_side_failover.sh 104.194.134.158 8443
# ============================================================================
set -uo pipefail   # عمداً بدون -e: می‌خواهیم پیام خطای دقیق خودمان را بدهیم، نه توقف خام

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi
if [ "$#" -ne 2 ]; then
    echo "استفاده: sudo bash $0 <TARGET_EDGE_IP> <CUSTOMER_SSH_PORT>"
    exit 1
fi

TARGET_EDGE="$1"
CUSTOMER_SSH_PORT="$2"

BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"
DB_PATH="${BOT_DIR}/master_bot.db"
PROMOTE_SCRIPT_PATH="${PROMOTE_SCRIPT_PATH:-/root/promote_edge_to_core.sh}"
EDGE_SSH_KEY="/root/.ssh/edge_provision_ed25519"
REMOTE_MIGRATION_DIR="/root/core_migration"
EXPORT_DIR="/root/.migration_export_$(date +%s)"

for f in "$DB_PATH" "$PROMOTE_SCRIPT_PATH" "$EDGE_SSH_KEY"; do
    if [ ! -f "$f" ]; then
        echo "❌ پیش‌نیاز پیدا نشد: ${f}"
        exit 1
    fi
done

echo "🔹 ۱) تشخیصِ IP عمومیِ همین Core (برای OLD_CORE_IP خودکار)..."
SELF_IP=""
if [ -n "${SELF_IP_OVERRIDE:-}" ]; then
    SELF_IP="$SELF_IP_OVERRIDE"
else
    for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://checkip.amazonaws.com"; do
        CAND="$(curl -4 -s --max-time 6 "$svc" 2>/dev/null | tr -d '[:space:]')"
        if [[ "$CAND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            SELF_IP="$CAND"
            break
        fi
    done
fi
if [ -z "$SELF_IP" ]; then
    echo "❌ نتوانستیم IP عمومیِ همین سرور را تشخیص دهیم — بدون این، محافظِ Split-Brain"
    echo "   خودکار کار نمی‌کند. با متغیر SELF_IP_OVERRIDE دستی بدهید و دوباره اجرا کنید."
    exit 1
fi
echo "   ✅ IP این Core: ${SELF_IP}"

echo "🔹 ۲) پیدا کردن پورتِ SSH بازِ Edgeِ مقصد (${TARGET_EDGE})..."
DEFAULT_CUSTOMER_PORT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='port';" 2>/dev/null)
DEFAULT_CUSTOMER_PORT="${DEFAULT_CUSTOMER_PORT:-8443}"
EDGE_PORT=""
for p in 22 "$DEFAULT_CUSTOMER_PORT" "$CUSTOMER_SSH_PORT"; do
    if ssh -i "$EDGE_SSH_KEY" -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${TARGET_EDGE}" "true" 2>/dev/null; then
        EDGE_PORT="$p"
        break
    fi
done
if [ -z "$EDGE_PORT" ]; then
    echo "❌ هیچ‌کدام از پورت‌های امتحان‌شده (22, ${DEFAULT_CUSTOMER_PORT}, ${CUSTOMER_SSH_PORT}) روی"
    echo "   ${TARGET_EDGE} با کلید دائمی پاسخ ندادند — این سرور هنوز کلید ندارد یا خاموش/فیلتر است."
    exit 1
fi
SSH_OPTS=(-i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
echo "   ✅ اتصال روی پورت ${EDGE_PORT} برقرار شد."

echo "🔹 ۳) توقفِ nvlbot روی همین Core (قبل از بکاپِ نهاییِ دیتابیس، تا نوشته‌ای گم نشود)..."
# 🐛🔧 رفع باگِ ریشه‌ایِ واقعی (دو مشکل با هم): ۱) promote_edge_to_core.sh (مرحلهٔ ۱۰، محافظِ
# Split-Brain) از طریقِ SSH به OLD_CORE_IP وصل می‌شود و اگر ببیند nvlbot آنجا هنوز active است،
# کل عملیات را رد می‌کند (مگر FORCE_PROMOTE=1) — نسخهٔ قبلیِ این اسکریپت nvlbot را فقط *بعد* از
# موفقیتِ promote متوقف می‌کرد، یعنی این محافظ همیشه رد می‌شد. ۲) حتی اگر آن محافظ رد نمی‌شد،
# بکاپِ دیتابیس (زیر) قبلاً *قبل* از توقفِ nvlbot گرفته می‌شد — یعنی هر نوشته‌ای (مشتریِ جدید،
# پرداخت، تمدید) بینِ لحظهٔ بکاپ و لحظهٔ توقفِ واقعیِ ربات (که قبلاً بعد از کل Promote بود) گم
# می‌شد. الان: اول nvlbot متوقف می‌شود (نوشتن‌ها فریز می‌شود)، بعد بکاپِ دیتابیس گرفته می‌شود —
# یعنی بکاپ همیشه دقیقاً آخرین وضعیتِ واقعی است. اگر ادامهٔ کار (Promote روی Edge) به هر دلیلی
# شکست بخورد، خودکار همین‌جا nvlbot را دوباره روشن می‌کنیم تا مشتری‌های همین سرور بی‌سرویس نمانند.
rollback_start_nvlbot() {
    echo "🔹 رول‌بک: nvlbot را همین‌جا (Core قدیمی) دوباره روشن می‌کنیم تا مشتری‌ها بی‌سرویس نمانند..."
    systemctl start nvlbot 2>/dev/null && echo "   ✅ nvlbot روی Core قدیمی دوباره فعال شد." \
        || echo "   ❌ روشن‌کردنِ خودکارِ nvlbot هم شکست خورد — دستی چک کنید: systemctl status nvlbot"
}
systemctl stop nvlbot 2>/dev/null || true
echo "   ✅ nvlbot روی این سرور متوقف شد — از این لحظه دیتابیس دیگر تغییر نمی‌کند."

echo "🔹 ۴) جمع‌آوریِ فایل‌های مهاجرت از خودِ همین Core..."
mkdir -p "$EXPORT_DIR"
umask 077

WG_CONF="/etc/wireguard/wg0.conf"
if [ ! -f "$WG_CONF" ]; then
    echo "❌ ${WG_CONF} پیدا نشد — این سرور Core فعالِ WireGuard نیست؟"
    rollback_start_nvlbot
    exit 1
fi
grep '^PrivateKey' "$WG_CONF" | awk -F'= ' '{print $2}' | tr -d ' ' > "${EXPORT_DIR}/core_private.key"
if [ ! -s "${EXPORT_DIR}/core_private.key" ]; then
    echo "❌ نتوانستیم PrivateKey را از ${WG_CONF} استخراج کنیم."
    rollback_start_nvlbot
    exit 1
fi
awk '/^\[Peer\]/{f=1} f' "$WG_CONF" > "${EXPORT_DIR}/wg0.conf.peers"
echo "   ✅ کلید WireGuard + peers استخراج شد."

# nvlbot همین الان متوقف است، پس دیگر لازم نیست نگرانِ نوشتنِ هم‌زمان باشیم؛ همچنان از
# sqlite3 .backup استفاده می‌کنیم چون در برابر یک فایلِ نیمه‌نوشته/WAL هم امن‌تر از cp خام است.
if sqlite3 "$DB_PATH" ".backup '${EXPORT_DIR}/master_bot.db'" 2>/dev/null; then
    echo "   ✅ دیتابیس با sqlite3 .backup (کپیِ امن، بعد از توقفِ ربات) گرفته شد."
else
    cp "$DB_PATH" "${EXPORT_DIR}/master_bot.db"
    echo "   ⚠️ sqlite3 .backup شکست خورد — با cp خام کپی شد."
fi

if [ -f /etc/gost/config.yaml ]; then
    cp /etc/gost/config.yaml "${EXPORT_DIR}/gost_config.yaml"
    echo "   ✅ gost_config.yaml کپی شد."
else
    echo "   ℹ️ /etc/gost/config.yaml نبود — رد شد (فقط Direct روی Edge جدید فعال خواهد شد)."
fi

if [ -d /etc/letsencrypt ]; then
    tar -czf "${EXPORT_DIR}/letsencrypt.tar.gz" -C /etc letsencrypt
    echo "   ✅ letsencrypt.tar.gz ساخته شد."
else
    echo "   ℹ️ /etc/letsencrypt نبود — رد شد."
fi

if [ -d /etc/ssl/cf ]; then
    tar -czf "${EXPORT_DIR}/cf_certs.tar.gz" -C /etc ssl/cf
    echo "   ✅ cf_certs.tar.gz ساخته شد."
fi

# 🆕 قبلاً این اسکریپت باینری‌های gost/badvpn-udpgw و کلید دائمیِ SSH ربات را خودش جمع
# نمی‌کرد و صرفاً امیدوار بود که از یک sync_bot_to_edges.sh قبلی، از قبل روی Edgeِ مقصد
# نشسته باشند. اگر آن Edge خیلی تازه بود یا آخرین sync رویش شکست خورده بود، این یعنی
# TLS/WSS، UDPGW، و اتصالِ خودکارِ ربات به سایر Edgeها بعد از فیل‌اوور بی‌صدا از کار
# می‌افتادند. الان مستقیماً از روی همین Core (که همین الان مطمئنیم سالم است) کپی می‌شوند.
GOST_BIN="/usr/local/bin/gost"
if [ -x "$GOST_BIN" ]; then
    cp "$GOST_BIN" "${EXPORT_DIR}/gost_bin"
    echo "   ✅ gost_bin کپی شد."
else
    echo "   ⚠️ ${GOST_BIN} پیدا نشد — TLS/WSS بعد از فیل‌اوور راه‌اندازی نخواهد شد مگر از قبل روی Edge باشد."
fi

BADVPN_UDPGW_BIN="/usr/local/bin/badvpn-udpgw"
if [ -x "$BADVPN_UDPGW_BIN" ]; then
    cp "$BADVPN_UDPGW_BIN" "${EXPORT_DIR}/badvpn_udpgw_bin"
    echo "   ✅ badvpn_udpgw_bin کپی شد."
else
    echo "   ⚠️ ${BADVPN_UDPGW_BIN} پیدا نشد — سرویسِ UDPGW بعد از فیل‌اوور نصب نخواهد شد مگر از قبل روی Edge باشد."
fi

EDGE_SSH_KEY_PRIV_SRC="/root/.ssh/edge_provision_ed25519"
if [ -f "$EDGE_SSH_KEY_PRIV_SRC" ]; then
    cp "$EDGE_SSH_KEY_PRIV_SRC" "${EXPORT_DIR}/edge_provision_ed25519"
    chmod 600 "${EXPORT_DIR}/edge_provision_ed25519"
    [ -f "${EDGE_SSH_KEY_PRIV_SRC}.pub" ] && cp "${EDGE_SSH_KEY_PRIV_SRC}.pub" "${EXPORT_DIR}/edge_provision_ed25519.pub"
    echo "   ✅ edge_provision_ed25519 کپی شد."
else
    echo "   ⚠️ ${EDGE_SSH_KEY_PRIV_SRC} پیدا نشد — ربات روی Core جدید (بعد از فیل‌اوور) نمی‌تواند خودکار به Edgeها وصل شود."
fi

# 🆕 وضعیتِ لاگینِ ادمین/نماینده‌ها — تا بعد از فیل‌اوور نیازی به لاگینِ مجدد نباشد.
BOT_PERSISTENCE_SRC="${BOT_DIR}/bot_persistence.pickle"
if [ -f "$BOT_PERSISTENCE_SRC" ]; then
    cp "$BOT_PERSISTENCE_SRC" "${EXPORT_DIR}/bot_persistence.pickle"
    echo "   ✅ bot_persistence.pickle کپی شد."
fi
if [ -f /etc/systemd/system/nvlbot.service ]; then
    cp /etc/systemd/system/nvlbot.service "${EXPORT_DIR}/nvlbot.service"
    echo "   ✅ فایل nvlbot.service کپی شد."
fi
# 🆕 اسنپ‌شاتِ سبک و هوشمندِ محیط: فقط فایل‌های اسکریپت (.sh، .py، .bak) منتقل می‌شوند
echo "🔹 ۴.۵) ساختِ اسنپ‌شاتِ اسکریپت‌ها (root_full_snapshot.tar.gz)..."
cd /root
tar -czf "${EXPORT_DIR}/root_full_snapshot.tar.gz" *.sh *.py *.bak 2>/dev/null || true
cd - >/dev/null
echo "   ✅ تمام اسکریپت‌های مدیریت و پایتون بسته‌بندی شدند (بدون فایل‌های حجیم)."

# 🆕 همون اسنپ‌شاتِ سطح-سیستمِ collect_core_migration_files.sh (پکیج‌های دستی، کرون،
# سرویس‌های systemd سفارشی، لیستِ فایل‌های /etc تغییریافته) — تا فیل‌اوورِ خودکار هم همون
# سطح از کامل‌بودن رو داشته باشه که Promoteِ دستی داره. عمداً محتوای /etc کپی نمیشه، فقط لیست.
echo "🔹 ۴.۷) اسنپ‌شاتِ سطح-سیستم (پکیج‌ها، کرون، سرویس‌های سفارشی، لیستِ /etc تغییریافته)..."
if command -v apt-mark >/dev/null 2>&1; then
    apt-mark showmanual > "${EXPORT_DIR}/manually_installed_packages.txt" 2>/dev/null || true
fi
crontab -l -u root > "${EXPORT_DIR}/root_crontab.txt" 2>/dev/null || : > "${EXPORT_DIR}/root_crontab.txt"
if [ -d /etc/cron.d ] && [ -n "$(ls -A /etc/cron.d 2>/dev/null)" ]; then
    mkdir -p "${EXPORT_DIR}/cron_d"
    cp /etc/cron.d/* "${EXPORT_DIR}/cron_d/" 2>/dev/null || true
fi
KNOWN_UNITS=(nvlbot.service gost.service badvpn-udpgw.service nvl-edge-sync.service nvl-edge-sync.timer
             wg-quick@wg0.service ssh.socket ssh.service sshd.service)
mkdir -p "${EXPORT_DIR}/custom_systemd_units"
: > "${EXPORT_DIR}/custom_systemd_units_enabled.txt"
for unit_path in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.socket; do
    [ -f "$unit_path" ] || continue
    unit_name="$(basename "$unit_path")"
    skip=0
    for k in "${KNOWN_UNITS[@]}"; do [ "$unit_name" = "$k" ] && skip=1 && break; done
    [ "$skip" = "1" ] && continue
    cp "$unit_path" "${EXPORT_DIR}/custom_systemd_units/${unit_name}"
    if systemctl is-enabled --quiet "$unit_name" 2>/dev/null; then
        echo "$unit_name" >> "${EXPORT_DIR}/custom_systemd_units_enabled.txt"
    fi
done
if command -v dpkg >/dev/null 2>&1; then
    timeout 30 dpkg -V 2>/dev/null | awk '$1 ~ /^..5/ {print $2}' | grep '^/etc/' \
        > "${EXPORT_DIR}/modified_etc_conffiles.txt" 2>/dev/null || : > "${EXPORT_DIR}/modified_etc_conffiles.txt"
    timeout 30 bash -c '
        find /etc -type f 2>/dev/null | while read -r f; do
            dpkg -S "$f" >/dev/null 2>&1 || echo "$f"
        done
    ' > "${EXPORT_DIR}/untracked_etc_files.txt" 2>/dev/null || : > "${EXPORT_DIR}/untracked_etc_files.txt"
fi
echo "   ✅ اسنپ‌شاتِ سطح-سیستم آماده شد."

echo "🔹 ۵) ارسالِ فایل‌های جمع‌آوری‌شده + خودِ promote_edge_to_core.sh به Edge..."
if ! ssh "${SSH_OPTS[@]}" "root@${TARGET_EDGE}" "mkdir -p ${REMOTE_MIGRATION_DIR}" 2>&1; then
    echo "❌ ساختِ پوشهٔ مقصد روی Edge شکست خورد."
    rollback_start_nvlbot
    exit 1
fi
if ! rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
        "${EXPORT_DIR}/" "root@${TARGET_EDGE}:${REMOTE_MIGRATION_DIR}/" 2>&1; then
    echo "❌ rsync فایل‌های مهاجرت به Edge شکست خورد."
    rollback_start_nvlbot
    exit 1
fi
if ! rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
        "$PROMOTE_SCRIPT_PATH" "root@${TARGET_EDGE}:${REMOTE_MIGRATION_DIR}/promote_edge_to_core.sh" 2>&1; then
    echo "❌ ارسال promote_edge_to_core.sh به Edge شکست خورد."
    rollback_start_nvlbot
    exit 1
fi
echo "   ✅ همه‌چیز روی ${TARGET_EDGE}:${REMOTE_MIGRATION_DIR} قرار گرفت."

# داده‌های حساس (کلید خصوصی، دیتابیس) روی خودِ Core دیگر لازم نیست بمانند
rm -rf "$EXPORT_DIR"

echo "🔹 ۶) اجرای remote «promote_edge_to_core.sh» روی Edge — با OLD_CORE_IP خودکار=${SELF_IP}..."
ssh "${SSH_OPTS[@]}" "root@${TARGET_EDGE}" \
    "OLD_CORE_IP='${SELF_IP}' bash ${REMOTE_MIGRATION_DIR}/promote_edge_to_core.sh '${CUSTOMER_SSH_PORT}' '${REMOTE_MIGRATION_DIR}'"
PROMOTE_EXIT=$?

if [ "$PROMOTE_EXIT" -ne 0 ]; then
    echo "❌ promote_edge_to_core.sh روی Edge با کد خطای ${PROMOTE_EXIT} برگشت."
    rollback_start_nvlbot
    exit "$PROMOTE_EXIT"
fi

echo "🔹 ۷) تأییدِ نهایی..."
echo "   ✅ nvlbot روی این سرور (Core قدیمی) قبلاً (مرحلهٔ ۳) متوقف شده و همچنان متوقف می‌ماند."
echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ Failover کامل شد — ${TARGET_EDGE}:${CUSTOMER_SSH_PORT} حالا Core جدید است."
echo "   کارِ باقی‌مانده (هنوز خودکار نیست):"
echo "   - روی هر Edge دیگر، Endpoint در wg0.conf را به ${TARGET_EDGE} تغییر دهید."
echo "   - DNS/host_pool ربات را به ${TARGET_EDGE} به‌عنوان پیش‌فرض تنظیم کنید."
echo "════════════════════════════════════════════════════════════"