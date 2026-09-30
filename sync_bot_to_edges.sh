#!/bin/bash
# ============================================================================
# sync_bot_to_edges.sh — همگام‌سازیِ دوره‌ایِ کدِ ربات به همهٔ Edgeها (Phase 1)
# ----------------------------------------------------------------------------
# این اسکریپت را روی Core نصب و به یک systemd timer وصل می‌کنید (پایین فایل
# توضیح داده شده). هر بار اجرا می‌شود:
#   ۱) لیست Edgeهای فعال را از دیتابیس ربات می‌خواند.
#   ۲) کدِ ربات (فایل اصلی + requirements.txt) را با rsync به یک پوشهٔ
#      «استندبای» روی هر Edge می‌فرستد — نه جای سرویس فعلی؛ کاملاً جدا و خاموش.
#   ۳) اگر requirements.txt عوض شده باشد، venv استندبای را آپدیت می‌کند.
#   ۴) آخرین نسخهٔ فایل سرویس systemd را هم می‌فرستد (ولی enable/start نمی‌کند).
#
# هیچ‌کدام از این کارها سرویسِ واقعیِ ربات را روی Edge روشن نمی‌کند — فقط همه‌چیز
# را «آماده و منتظر» نگه می‌دارد تا وقتی واقعاً promote_edge_to_core.sh زده شود.
#
# پیش‌نیاز یک‌باره (قبل از اولین اجرا): هیچ! این اسکریپت از همان کلید دائمیِ SSH استفاده
# می‌کند که خودِ ربات موقع افزودن هر Edge (دستی یا خودکار) به authorized_keys آن Edge اضافه
# می‌کند (تابع _install_local_pubkey_on_open_ssh در bot_final_v49-2.py). یعنی هر Edgeِ جدیدی
# که از طریق ربات اضافه شود، خودکار توسط این اسکریپت هم پوشش داده می‌شود — بدون هیچ کار دستی.
# ============================================================================
set -uo pipefail   # عمداً بدون -e: شکستِ sync روی یک Edge نباید بقیه را متوقف کند

# ============================== CONFIG =====================================
BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"                       # مسیر واقعیِ کد ربات روی Core
SERVICE_UNIT_PATH="/etc/systemd/system/nvlbot.service"      # فایل سرویس فعلی روی Core
SERVICE_NAME="nvlbot"

# 🐛🔧 رفع باگِ واقعی «اسم فایل ثابتِ کهنه»: قبلاً اینجا یک اسم فایل به‌صورت دستی (مثلاً
# bot_final_v49-2.py) هاردکد شده بود. هر بار که ربات دوباره نام‌گذاری/آپگرید می‌شد (که طبق
# سابقه مکرر اتفاق افتاده: v99 → v103 → v105 → v49-2 → v49-2-2 → v49-2-4 → ...)، این مقدار
# منسوخ می‌شد و rsync کدِ اصلی همیشه با «فایل پیدا نشد» شکست می‌خورد — و چون این شکست باعث
# continue شدنِ حلقه می‌شد، هیچ‌کدام از OPS_SCRIPTS (از جمله 02_recreate_ssh_users.py و خودِ
# فایل‌های systemd sync) هم به هیچ Edgeای نمی‌رسیدند، کاملاً بی‌سروصدا.
# الان به‌جای اسمِ ثابت، مستقیماً از ExecStart واقعیِ nvlbot.service (تنها منبع حقیقتِ واقعی
# دربارهٔ این‌که همین الان چه فایلی واقعاً در حال اجراست) استخراج می‌شود — دقیقاً همان الگویی که
# promote_edge_to_core.sh هم برای تطبیق ExecStart بعد از Promote استفاده می‌کند.
detect_bot_main_file() {
    local from_service=""
    if [ -f "$SERVICE_UNIT_PATH" ]; then
        from_service="$(grep -oE 'ExecStart=.*[[:space:]]([^[:space:]]*bot_final[^[:space:]]*\.py)' "$SERVICE_UNIT_PATH" \
            | grep -oE 'bot_final[^[:space:]]*\.py' | tail -n1)"
    fi
    if [ -n "$from_service" ] && [ -f "${BOT_DIR}/${from_service}" ]; then
        printf '%s' "$from_service"
        return 0
    fi
    # جایگزین: اگر از ExecStart چیزی درنیامد (یا فایلش دیگر وجود نداشت)، جدیدترین
    # bot_final_*.py موجود در BOT_DIR را پیدا کن.
    local newest
    newest="$(find "$BOT_DIR" -maxdepth 1 -name 'bot_final_*.py' -printf '%T@ %f\n' 2>/dev/null \
        | sort -rn | head -n1 | cut -d' ' -f2-)"
    printf '%s' "$newest"
}
BOT_MAIN_FILE="${BOT_MAIN_FILE:-$(detect_bot_main_file)}"   # قابل override با env، وگرنه خودکار تشخیص داده می‌شود
BOT_EXTRA_FILES=("requirements.txt")                        # هر فایل پشتیبان دیگری که ربات لازم دارد را اینجا اضافه کنید
DB_PATH="${BOT_DIR}/master_bot.db"
EDGE_SSH_KEY="/root/.ssh/edge_provision_ed25519"             # 🔗 همون کلید دائمیِ خودِ ربات (DO_SSH_KEY_PATH در bot_final_v49-2.py) — قبلاً روی هر Edge نصب شده/میشه
EDGE_STANDBY_DIR="/root/nvlbot_standby"
LOG_FILE="/var/log/nvl_edge_sync.log"
# 🆕 اسکریپت‌های Promote/Demote هم به همهٔ Edgeها فرستاده می‌شوند — تا هر لحظه هر Edgeای
# قرار بود Core جدید بشود، از قبل خودِ اسکریپتِ به‌روز را هم داشته باشد (نه فقط دیتای مهاجرت).
OPS_SCRIPTS_DIR="$(dirname "$0")"
# 🆕🐛 رفع باگِ حیاتیِ واقعی: قبلاً خودِ همین اسکریپت (sync_bot_to_edges.sh) در این لیست نبود!
# nvl-edge-sync.service که همراه هر Edge فرستاده می‌شود دقیقاً همین دستور را دارد:
#   ExecStart=/bin/bash /root/sync_bot_to_edges.sh
# یعنی وقتی یک Edge به Core ترفیع پیدا می‌کند و تایمرش فعال می‌شود، هر ۱۰ دقیقه سعی می‌کند
# فایلی را اجرا کند که هرگز به آن سرور منتقل نشده بود — بی‌صدا شکست می‌خورد و از همان لحظه،
# کل زنجیرهٔ خودتکثیریِ sync برای همیشه متوقف می‌ماند، بدون هیچ خطای قابل‌مشاهده‌ای. همچنین
# collect_core_migration_files.sh (که خودِ این اسکریپت صدا می‌زند)، core_side_failover.sh
# (واچ‌داگِ Failover خودمختار — بدون این هیچ Edgeای نمی‌تواند خودکار جانشین Core مسدودشده
# بشود)، preflight_check.sh، و نسخهٔ کاملِ update_all_edges_endpoint.sh هم به همین ترتیب جا
# افتاده بودند. با basename "$0" به‌جای اسمِ هاردکد هم مطمئن می‌شویم اگر این فایل هم روزی
# تغییرنام پیدا کرد (مثل بارها بار قبلی برای bot_final_*.py)، باز خودش را درست تشخیص می‌دهد.
SELF_SCRIPT_NAME="$(basename "$0")"
# 🆕 معماریِ Control-Plane/Data-Plane: این چهار فایل هم از این پس باید همیشه روی هر Edge
# تازه/به‌روز باشند — بدونشان، edge_ip_limiter.py هرگز نصب/به‌روز نمی‌شود و
# promote_standby_for_filtered_edge.py (موتورِ گامِ دومِ Failover) روی Core هم پیدا نمی‌شود
# (هرچند این یکی فقط باید روی Core بماند، نه لزوماً به هر Edge برود — ولی ارسالش بی‌ضرر است
# و برایِ اجرایِ دستیِ احتمالیِ آینده روی هر Edge هم آماده نگه می‌دارد).
OPS_SCRIPTS=("$SELF_SCRIPT_NAME" "apply_edge_fixes.sh" "collect_core_migration_files.sh" "core_side_failover.sh" \
             "preflight_check.sh" "promote_edge_to_core.sh" "demote_core_to_edge_v2.sh" \
             "update_edge_endpoint.sh" "update_all_edges_endpoint.sh" "02_recreate_ssh_users.py" \
             "nvl-edge-sync.service" "nvl-edge-sync.timer" \
             "edge_ip_limiter.py" "edge-ip-limiter.service" "setup_edge_datapath.sh" \
             "promote_standby_for_filtered_edge.py")
# =============================================================================

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }

# 🆕 اگر با همهٔ این تلاش‌ها هم هیچ فایل bot_final_*.py پیدا نشد، به‌جای شکستِ بی‌صدا و
# پیوسته‌ی هر ۱۰ دقیقه، همین اول با یک پیام روشن و صریح متوقف می‌شویم.
if [ -z "$BOT_MAIN_FILE" ]; then
    log "❌ نتوانستم فایل اصلی ربات را تشخیص بدهم (نه از ExecStart، نه با جست‌وجوی bot_final_*.py در ${BOT_DIR}). BOT_MAIN_FILE را دستی ست کنید."
    exit 1
fi
log "ℹ️ فایل اصلی ربات تشخیص داده‌شده: ${BOT_MAIN_FILE}"

if [ ! -f "$EDGE_SSH_KEY" ]; then
    log "❌ کلید SSH پیدا نشد: ${EDGE_SSH_KEY} — طبق پیش‌نیاز بالای فایل بسازیدش."
    exit 1
fi
if [ ! -f "${BOT_DIR}/${BOT_MAIN_FILE}" ]; then
    log "❌ فایل اصلیِ ربات پیدا نشد: ${BOT_DIR}/${BOT_MAIN_FILE} — مقدار BOT_MAIN_FILE را چک کنید."
    exit 1
fi
if [ ! -f "$DB_PATH" ]; then
    log "❌ دیتابیس پیدا نشد: ${DB_PATH}"
    exit 1
fi

# 🆕 قبل از هر چیز، پکیجِ کاملِ مهاجرت (core_private.key, wg0.conf.peers, master_bot.db,
# gost_config.yaml, gost_bin, letsencrypt.tar.gz, ...) را تازه می‌سازیم — تا لازم نباشد
# قبل از هر Promote دستی این ۷ فایل را جمع کنید؛ همیشه یک نسخهٔ تازه در /root/core_migration
# آماده است و همین‌جا به همهٔ Edgeها هم فرستاده می‌شود.
CORE_MIGRATION_DIR="/root/core_migration"
COLLECT_SCRIPT="$(dirname "$0")/collect_core_migration_files.sh"
if [ -f "$COLLECT_SCRIPT" ]; then
    bash "$COLLECT_SCRIPT" >> "$LOG_FILE" 2>&1
else
    log "⚠️ collect_core_migration_files.sh پیدا نشد — پکیجِ مهاجرت این دور تازه نشد (اگر از قبل وجود دارد، همان قدیمی ارسال می‌شود)."
fi

# لیست Edgeهای فعال از دیتابیس (فرض: جدول host_pool، ستون host و active)
mapfile -t EDGE_HOSTS < <(sqlite3 "$DB_PATH" "SELECT host FROM host_pool WHERE active=1;" 2>/dev/null)
if [ "${#EDGE_HOSTS[@]}" -eq 0 ]; then
    log "⚠️ هیچ Edge فعالی در host_pool پیدا نشد — چیزی برای sync نیست."
    exit 0
fi

SELF_IP=""
for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://checkip.amazonaws.com"; do
    CAND="$(curl -4 -s --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$CAND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        SELF_IP="$CAND"
        break
    fi
done

# 🆕🩹 لایهٔ دومِ محافظتی (self-heal) برای همان باگِ core_wg_public_ip: promote_edge_to_core.sh
# همین مقدار را لحظهٔ Promote یک‌بار تنظیم می‌کند، ولی اگر آن لحظه تشخیصِ IP به هر دلیلی شکست
# بخورد (مثلاً هر ۴ سرویس هم‌زمان کند بودند)، بدون این لایه، مقدارِ اشتباه تا Promote بعدی
# می‌ماند. چون این اسکریپت هر ۱۰ دقیقه روی همان سروری اجرا می‌شود که الان واقعاً Core است،
# همین‌جا هم — اگر SELF_IP را موفق تشخیص دادیم و با مقدارِ فعلیِ دیتابیس فرق داشت — خودکار
# اصلاحش می‌کنیم. یعنی حتی اگر لحظهٔ Promote این تشخیص شکست بخورد، حداکثر تا ۱۰ دقیقهٔ بعد
# خودش را درست می‌کند، بدون نیاز به هیچ کارِ دستی.
if [ -n "$SELF_IP" ]; then
    STORED_CORE_IP="$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='core_wg_public_ip';" 2>/dev/null)"
    if [ -n "$STORED_CORE_IP" ] && [ "$STORED_CORE_IP" != "$SELF_IP" ]; then
        log "⚠️ core_wg_public_ip در دیتابیس («${STORED_CORE_IP}») با IP واقعیِ همین سرور («${SELF_IP}») فرق دارد — خودکار اصلاح می‌شود."
        sqlite3 "$DB_PATH" "UPDATE settings SET value='${SELF_IP}' WHERE key='core_wg_public_ip';"
        log "   ✅ core_wg_public_ip روی ${SELF_IP} تنظیم شد."
    fi
fi

# 🆕 پورت پیش‌فرضِ مشتری‌ها (که اکثر Edgeها روش SSH را باز نگه می‌دارند، نه لزوماً ۲۲) —
# چون نمی‌دانیم آیا host_pool در نسخهٔ فعلی ستون پورتِ اختصاصی هر Edge را دارد یا نه، امن‌ترین
# راه این است که مثل خودِ تابع افزودن خودکار Edge در ربات، چند پورت محتمل را امتحان کنیم.
DEFAULT_CUSTOMER_PORT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='port';" 2>/dev/null)
DEFAULT_CUSTOMER_PORT="${DEFAULT_CUSTOMER_PORT:-8443}"

# پورتِ واقعاً بازِ یک Edge را با امتحان‌کردن چند کاندید پیدا می‌کند؛ در stdout همان پورت را چاپ می‌کند
detect_edge_port() {
    local edge="$1"
    local candidates=(22 "$DEFAULT_CUSTOMER_PORT")
    local p
    for p in "${candidates[@]}"; do
        if ssh -i "$EDGE_SSH_KEY" -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${edge}" "true" 2>/dev/null; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

SUCCESS=0
FAIL=0

for EDGE in "${EDGE_HOSTS[@]}"; do
    [ -z "$EDGE" ] && continue
    [ -n "$SELF_IP" ] && [ "$EDGE" = "$SELF_IP" ] && continue   # خودِ Core را sync نکن

    log "🔹 sync به ${EDGE} ..."

    EDGE_PORT=$(detect_edge_port "$EDGE")
    if [ -z "$EDGE_PORT" ]; then
        log "   ❌ هیچ‌کدام از پورت‌های امتحان‌شده (22, ${DEFAULT_CUSTOMER_PORT}) روی ${EDGE} پاسخ نداد — رد شد."
        FAIL=$((FAIL+1))
        continue
    fi
    SSH_OPTS=(-i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

    if ! ssh "${SSH_OPTS[@]}" "root@${EDGE}" "mkdir -p ${EDGE_STANDBY_DIR}" 2>>"$LOG_FILE"; then
        log "   ❌ اتصال SSH به ${EDGE}:${EDGE_PORT} شکست خورد — رد شد."
        FAIL=$((FAIL+1))
        continue
    fi

    RSYNC_FILES=("${BOT_DIR}/${BOT_MAIN_FILE}")
    for f in "${BOT_EXTRA_FILES[@]}"; do
        [ -f "${BOT_DIR}/${f}" ] && RSYNC_FILES+=("${BOT_DIR}/${f}")
    done

    if ! rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
            "${RSYNC_FILES[@]}" "root@${EDGE}:${EDGE_STANDBY_DIR}/" 2>>"$LOG_FILE"; then
        log "   ❌ rsync کد به ${EDGE} شکست خورد."
        FAIL=$((FAIL+1))
        continue
    fi

    # 🆕 پکیجِ کاملِ مهاجرت را هم همین الان به این Edge می‌فرستیم — تا وقتی روزی این Edge
    # قرار شد Promote شود، از قبل همه‌چیز آماده و تازه باشد (به جای جمع‌آوریِ دستیِ لحظه‌ای).
    if [ -d "$CORE_MIGRATION_DIR" ] && [ -n "$(ls -A "$CORE_MIGRATION_DIR" 2>/dev/null)" ]; then
        ssh "${SSH_OPTS[@]}" "root@${EDGE}" "mkdir -p ${CORE_MIGRATION_DIR}" 2>>"$LOG_FILE"
        rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8" \
            "${CORE_MIGRATION_DIR}/" "root@${EDGE}:${CORE_MIGRATION_DIR}/" 2>>"$LOG_FILE" \
            || log "   ⚠️ ارسال پکیجِ مهاجرت به ${EDGE} شکست خورد (کد ربات همچنان sync شد)."
    fi

    if [ -f "$SERVICE_UNIT_PATH" ]; then
        # فایل سرویس را با نام .staged می‌فرستیم — تا وقتی promote صریحاً جایگزینش نکرده،
        # سیستمی این را نمی‌شناسد و اجرا نمی‌کند.
        rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8" \
            "$SERVICE_UNIT_PATH" "root@${EDGE}:${EDGE_STANDBY_DIR}/${SERVICE_NAME}.service.staged" 2>>"$LOG_FILE"
    fi

    # 🐛🔧 رفع باگِ واقعی: چون Core اصلاً requirements.txt ندارد (پکیج‌ها دستی تو venv نصب
    # شده‌اند)، بخشِ قبلی که منتظر تغییرِ requirements.txt بود هرگز اجرا نمی‌شد و venv استندبای
    # همیشه خالی می‌ماند — باعث می‌شد Promote موقعِ ساختِ venv تازه با «ensurepip not available»
    # شکست بخورد. الان به‌جایش مستقیماً خودِ venvِ سالمِ Core را با rsync کپی می‌کنیم — نیازی به
    # اینترنت، pip، یا پکیجِ python3-venv روی خودِ Edge نیست.
    if [ -d "${BOT_DIR}/venv" ]; then
        rsync -az --delete -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8" \
            "${BOT_DIR}/venv/" "root@${EDGE}:${EDGE_STANDBY_DIR}/venv/" 2>>"$LOG_FILE" \
            || log "   ⚠️ rsync کردنِ venv به ${EDGE} شکست خورد (کد اصلی همچنان sync شد)."
    else
        log "   ⚠️ ${BOT_DIR}/venv روی Core پیدا نشد — venv استندبای روی ${EDGE} خالی می‌ماند."
    fi

    if [ -f "/root/badvpn-udpgw-built" ]; then
        rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8" \
            "/root/badvpn-udpgw-built" "root@${EDGE}:/root/badvpn-udpgw-built" 2>>"$LOG_FILE" \
            || log "   ⚠️ ارسال باینریِ badvpn-udpgw به ${EDGE} شکست خورد."
    fi

    # 🆕 اسکریپت‌های عملیاتیِ Promote/Demote/آپدیت-Endpoint را هم تازه نگه می‌داریم
    for script in "${OPS_SCRIPTS[@]}"; do
        if [ -f "${OPS_SCRIPTS_DIR}/${script}" ]; then
            rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o ConnectTimeout=8" \
                "${OPS_SCRIPTS_DIR}/${script}" "root@${EDGE}:/root/${script}" 2>>"$LOG_FILE"
            ssh "${SSH_OPTS[@]}" "root@${EDGE}" "chmod +x /root/${script}" 2>>"$LOG_FILE"
        fi
    done

    if [ -f "/root/apply_edge_fixes.sh" ]; then
        if ssh "${SSH_OPTS[@]}" "root@${EDGE}" "bash /root/apply_edge_fixes.sh" >> "$LOG_FILE" 2>&1; then
            log "   ✅ فیکس‌های سیستمی روی ${EDGE} تأیید/اعمال شد."
        else
            log "   ⚠️ اجرای apply_edge_fixes.sh روی ${EDGE} با خطا مواجه شد (کد اصلی همچنان sync شد)."
        fi
    fi

    ssh "${SSH_OPTS[@]}" "root@${EDGE}" \
        "date '+%Y-%m-%d %H:%M:%S' > ${EDGE_STANDBY_DIR}/.last_sync && echo ${EDGE_PORT} > ${EDGE_STANDBY_DIR}/.ssh_port" 2>>"$LOG_FILE"

    log "   ✅ ${EDGE}:${EDGE_PORT} sync شد."
    SUCCESS=$((SUCCESS+1))
done

# 🆕 خودِ Core هم مثل Edgeها فیکس‌های سیستمی را روی خودش (بدون SSH) اجرا می‌کند
if [ -f "/root/apply_edge_fixes.sh" ]; then
    bash /root/apply_edge_fixes.sh >> "$LOG_FILE" 2>&1 && \
        log "   ✅ فیکس‌های سیستمی روی خودِ Core تأیید/اعمال شد." || \
        log "   ⚠️ اجرای apply_edge_fixes.sh روی خودِ Core با خطا مواجه شد."
fi

log "🏁 پایان sync — موفق: ${SUCCESS} | ناموفق: ${FAIL} | کل: ${#EDGE_HOSTS[@]}"