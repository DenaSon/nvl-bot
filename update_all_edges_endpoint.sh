#!/bin/bash
# ============================================================================
# update_all_edges_endpoint.sh — آپدیت خودکارِ Endpoint روی همهٔ Edgeهای فعال
# ----------------------------------------------------------------------------
# این اسکریپت را روی Core جدید اجرا می‌کنید (همان‌جایی که update_edge_endpoint.sh
# قبلاً تک‌تک و دستی روی هر Edge اجرا می‌شد). این نسخه دقیقاً همان کارِ manual را
# برای همهٔ Edgeهای active=1 در host_pool، پشتِ‌سرِهم و خودکار انجام می‌دهد —
# با همان الگوی sync_bot_to_edges.sh / bootstrap_all_edges_venv.sh:
#   ۱) لیست Edgeهای فعال را از دیتابیس می‌خواند (به‌جز خودِ این Core).
#   ۲) با کلید دائمیِ SSH (همان edge_provision_ed25519) وصل می‌شود.
#   ۳) نسخهٔ محلیِ update_edge_endpoint.sh را روی آن Edge می‌گذارد (rsync).
#   ۴) همان‌جا اجرایش می‌کند: sudo bash update_edge_endpoint.sh <NEW_CORE_IP> <PORT>
#
# پیش‌نیاز: update_edge_endpoint.sh باید کنارِ همین اسکریپت (همون پوشه) روی Core باشد.
# Core قدیمی (تازه Demote‌شده) هم اگر هنوز در host_pool با active=1 باشد در این لیست
# می‌آید — بی‌ضرر است چون demote_core_to_edge.sh از قبل Endpoint خودش را درست
# ست کرده؛ این اسکریپت فقط دوباره همان مقدار را می‌نویسد (idempotent).
#
# نحوهٔ اجرا (روی Core):
#   sudo bash update_all_edges_endpoint.sh [NEW_CORE_PUBLIC_IP] [CORE_WG_PORT]
# اگر NEW_CORE_PUBLIC_IP داده نشود، خودش IP عمومیِ همین سرور را تشخیص می‌دهد
# (دقیقاً همان روشی که core_side_failover.sh استفاده می‌کند).
# مثال:
#   sudo bash update_all_edges_endpoint.sh
#   sudo bash update_all_edges_endpoint.sh 104.194.134.158 51820
# ============================================================================
set -uo pipefail   # عمداً بدون -e: شکست روی یک Edge نباید بقیه را متوقف کند

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"
DB_PATH="${BOT_DIR}/master_bot.db"
EDGE_SSH_KEY="/root/.ssh/edge_provision_ed25519"
LOCAL_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/update_edge_endpoint.sh"
CORE_WG_PORT="${2:-51820}"

if [ ! -f "$DB_PATH" ]; then
    echo "❌ دیتابیس پیدا نشد: ${DB_PATH}"
    exit 1
fi
if [ ! -f "$EDGE_SSH_KEY" ]; then
    echo "❌ کلید SSH پیدا نشد: ${EDGE_SSH_KEY}"
    exit 1
fi
if [ ! -f "$LOCAL_SCRIPT" ]; then
    echo "❌ update_edge_endpoint.sh کنار همین فایل پیدا نشد (${LOCAL_SCRIPT})."
    echo "   هر دو فایل را در یک پوشه روی Core بگذارید."
    exit 1
fi

# ۱) تشخیص IP عمومیِ همین Core — همون منطق core_side_failover.sh
if [ -n "${1:-}" ]; then
    NEW_CORE_PUBLIC_IP="$1"
else
    echo "🔹 تشخیص IP عمومیِ همین Core..."
    NEW_CORE_PUBLIC_IP=""
    for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://checkip.amazonaws.com"; do
        CAND="$(curl -4 -s --max-time 6 "$svc" 2>/dev/null | tr -d '[:space:]')"
        if [[ "$CAND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            NEW_CORE_PUBLIC_IP="$CAND"
            break
        fi
    done
    if [ -z "$NEW_CORE_PUBLIC_IP" ]; then
        echo "❌ نتوانستیم IP عمومیِ همین سرور را خودکار تشخیص دهیم."
        echo "   دستی بدهید: sudo bash $0 <NEW_CORE_PUBLIC_IP> [CORE_WG_PORT]"
        exit 1
    fi
fi
echo "   ✅ Core جدید: ${NEW_CORE_PUBLIC_IP}:${CORE_WG_PORT}"

# ۲) لیست Edgeهای فعال از دیتابیس
mapfile -t EDGE_HOSTS < <(sqlite3 "$DB_PATH" "SELECT host FROM host_pool WHERE active=1;" 2>/dev/null)
if [ "${#EDGE_HOSTS[@]}" -eq 0 ]; then
    echo "⚠️ هیچ Edge فعالی در host_pool پیدا نشد — چیزی برای آپدیت نیست."
    exit 0
fi

# Phase 6A: endpoint updates are management operations. Customer service ports are
# not management fallbacks because Relay Edge ports can DNAT to Core.
HAS_ADMIN_PORT_COL="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM pragma_table_info('host_pool') WHERE name='admin_ssh_port';" 2>/dev/null || echo 0)"

detect_edge_port() {
    local edge="$1"
    local p="22"
    if [ "$HAS_ADMIN_PORT_COL" = "1" ]; then
        local safe_edge="${edge//\'/\'\'}"
        local db_port
        db_port="$(sqlite3 "$DB_PATH" "SELECT admin_ssh_port FROM host_pool WHERE host='${safe_edge}' LIMIT 1;" 2>/dev/null)"
        if [[ "$db_port" =~ ^[0-9]+$ ]] && [ "$db_port" -ge 1 ] && [ "$db_port" -le 65535 ]; then
            p="$db_port"
        fi
    fi
    if ssh -i "$EDGE_SSH_KEY" -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${edge}" "true" 2>/dev/null; then
        echo "$p"
        return 0
    fi
    return 1
}

echo "🔹 ${#EDGE_HOSTS[@]} Edge فعال پیدا شد."
OK=0; FAIL=0; SKIP=0

for EDGE in "${EDGE_HOSTS[@]}"; do
    [ -z "$EDGE" ] && continue
    if [ "$EDGE" = "$NEW_CORE_PUBLIC_IP" ]; then
        echo "🔹 ${EDGE} — رد شد (خودِ Core جدید است، Endpoint لازم ندارد)."
        SKIP=$((SKIP+1))
        continue
    fi

    echo "🔹 ${EDGE} — در حال آپدیت..."
    EDGE_PORT=$(detect_edge_port "$EDGE")
    if [ -z "$EDGE_PORT" ]; then
        echo "   ❌ SSH مدیریتی ثبت‌شده جواب نداد — پورت سرویس مشتری عمداً امتحان نشد؛ رد شد."
        FAIL=$((FAIL+1))
        continue
    fi
    SSH_OPTS=(-i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

    if ! rsync -az -e "ssh -i ${EDGE_SSH_KEY} -p ${EDGE_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
            "$LOCAL_SCRIPT" "root@${EDGE}:/root/update_edge_endpoint.sh" 2>&1; then
        echo "   ❌ ارسال اسکریپت به ${EDGE} شکست خورد."
        FAIL=$((FAIL+1))
        continue
    fi

    if OUT=$(ssh "${SSH_OPTS[@]}" "root@${EDGE}" \
            "chmod +x /root/update_edge_endpoint.sh && bash /root/update_edge_endpoint.sh '${NEW_CORE_PUBLIC_IP}' '${CORE_WG_PORT}'" 2>&1); then
        echo "   ✅ ${EDGE}:${EDGE_PORT} آپدیت شد."
        echo "$OUT" | sed 's/^/      /'
        OK=$((OK+1))
    else
        echo "   ❌ اجرای اسکریپت روی ${EDGE} با خطا برگشت:"
        echo "$OUT" | sed 's/^/      /'
        FAIL=$((FAIL+1))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "🏁 نتیجه: ${OK} موفق | ${FAIL} ناموفق | ${SKIP} رد‌شده | کل: ${#EDGE_HOSTS[@]}"
if [ "$FAIL" -eq 0 ]; then
    echo "✅ همهٔ Edgeهای فعال الان به ${NEW_CORE_PUBLIC_IP} وصل‌اند."
else
    echo "⚠️ موارد ناموفق وجود دارند: مهاجرت کامل اعلام نمی‌شود."
fi
echo "════════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ]