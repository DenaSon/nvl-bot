#!/bin/bash
# ============================================================================
# preflight_check.sh — چکِ کاملاً فقط-خواندنی قبل از Failover واقعی
# ----------------------------------------------------------------------------
# هیچ فایلی را تغییر نمی‌دهد، هیچ سرویسی را متوقف/استارت نمی‌کند. فقط گزارش می‌دهد.
# اجرا روی Core:
#   sudo bash preflight_check.sh <TARGET_EDGE_IP>
# ============================================================================
set -uo pipefail

if [ "$#" -ne 1 ]; then
    echo "استفاده: sudo bash $0 <TARGET_EDGE_IP>"
    exit 1
fi

TARGET_EDGE="$1"
BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"
DB_PATH="${BOT_DIR}/master_bot.db"
EDGE_SSH_KEY="/root/.ssh/edge_provision_ed25519"

PASS=0
FAIL=0
ok()   { echo "   ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "   ❌ $1"; FAIL=$((FAIL+1)); }
info() { echo "   ℹ️ $1"; }

echo "🔹 ۱) سلامتِ دیتابیس ربات..."
if [ -f "$DB_PATH" ]; then
    RESULT=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;" 2>&1)
    if [ "$RESULT" = "ok" ]; then ok "master_bot.db سالم است (integrity_check: ok)"; else bad "master_bot.db مشکل دارد: ${RESULT}"; fi
else
    bad "master_bot.db در ${DB_PATH} پیدا نشد."
fi

echo "🔹 ۲) وضعیتِ WireGuard روی همین Core..."
if [ -f /etc/wireguard/wg0.conf ]; then
    ok "wg0.conf موجود است."
    if wg show wg0 >/dev/null 2>&1; then
        PEER_COUNT=$(wg show wg0 peers 2>/dev/null | wc -l)
        ok "اینترفیس wg0 فعال است — ${PEER_COUNT} peer."
    else
        bad "اینترفیس wg0 بالا نیست (wg show wg0 خطا داد)."
    fi
else
    bad "/etc/wireguard/wg0.conf پیدا نشد."
fi

echo "🔹 ۳) وضعیتِ لایهٔ TLS/WSS (gost)..."
if [ -f /etc/gost/config.yaml ]; then
    ok "gost_config.yaml موجود است."
    if systemctl is-active --quiet gost 2>/dev/null; then ok "سرویس gost فعال است."; else info "سرویس gost فعال نیست (اگر Direct-only می‌خواهید، مشکلی نیست)."; fi
else
    info "gost_config.yaml نیست — فقط Direct SSH منتقل خواهد شد."
fi

echo "🔹 ۴) وضعیتِ خودِ Edgeِ مقصد (${TARGET_EDGE}) در دیتابیس..."
ROW=$(sqlite3 "$DB_PATH" "SELECT active FROM host_pool WHERE host='${TARGET_EDGE}';" 2>/dev/null)
if [ "$ROW" = "1" ]; then
    ok "در host_pool با active=1 ثبت شده."
elif [ -n "$ROW" ]; then
    bad "در host_pool ثبت شده ولی active=${ROW} است (نه ۱)."
else
    bad "در host_pool اصلاً پیدا نشد."
fi

echo "🔹 ۵) اتصالِ SSH با کلید دائمی به Edgeِ مقصد..."
DEFAULT_CUSTOMER_PORT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='port';" 2>/dev/null)
DEFAULT_CUSTOMER_PORT="${DEFAULT_CUSTOMER_PORT:-8443}"
EDGE_PORT=""
for p in 22 "$DEFAULT_CUSTOMER_PORT"; do
    if ssh -i "$EDGE_SSH_KEY" -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new "root@${TARGET_EDGE}" "true" 2>/dev/null; then
        EDGE_PORT="$p"; break
    fi
done
if [ -n "$EDGE_PORT" ]; then
    ok "اتصال با کلید دائمی روی پورت ${EDGE_PORT} برقرار شد."
else
    bad "هیچ پورتی (22, ${DEFAULT_CUSTOMER_PORT}) با کلید دائمی جواب نداد."
fi

echo "🔹 ۶) وضعیتِ nvlbot_standby روی Edgeِ مقصد..."
if [ -n "$EDGE_PORT" ]; then
    STAGED=$(ssh -i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=8 "root@${TARGET_EDGE}" \
        "find /root/nvlbot_standby -maxdepth 1 -name 'bot_final_*.py' 2>/dev/null | head -n1" 2>/dev/null)
    LAST_SYNC=$(ssh -i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=8 "root@${TARGET_EDGE}" \
        "cat /root/nvlbot_standby/.last_sync 2>/dev/null" 2>/dev/null)
    if [ -n "$STAGED" ]; then
        ok "کد ربات stage شده: $(basename "$STAGED") — آخرین sync: ${LAST_SYNC:-نامعلوم}"
    else
        bad "nvlbot_standby خالی است — یک چرخهٔ تایمر (تا ۱۰ دقیقه) صبر کنید یا sync_bot_to_edges.sh را دستی بزنید."
    fi
else
    info "رد شد (چون اتصال SSH برقرار نشد)."
fi

echo "🔹 ۷) آیا nvlbot روی خودِ این Core (قبل از هر کاری) فعلاً فعال است؟..."
if systemctl is-active --quiet nvlbot; then
    ok "nvlbot روی این Core الان در حال اجراست (طبیعی — این همون Core فعلیه)."
else
    info "nvlbot روی این Core فعال نیست — عجیب است مگر از قبل متوقفش کرده باشید."
fi

echo "🔹 ۸) آیا فایل‌های عملیاتیِ لازم (بازسازیِ کاربرها + تایمرِ sync) روی Edgeِ مقصد هست؟..."
if [ -n "$EDGE_PORT" ]; then
    for f in 02_recreate_ssh_users.py nvl-edge-sync.service nvl-edge-sync.timer promote_edge_to_core.sh \
             sync_bot_to_edges.sh collect_core_migration_files.sh core_side_failover.sh \
             demote_core_to_edge.sh update_all_edges_endpoint.sh; do
        if ssh -i "$EDGE_SSH_KEY" -p "$EDGE_PORT" -o ConnectTimeout=8 "root@${TARGET_EDGE}" "test -f /root/${f}" 2>/dev/null; then
            ok "/root/${f} روی Edgeِ مقصد موجود است."
        else
            bad "/root/${f} روی Edgeِ مقصد پیدا نشد — یک چرخهٔ تایمر (تا ۱۰ دقیقه) صبر کنید یا sync_bot_to_edges.sh را دستی بزنید."
        fi
    done
else
    info "رد شد (چون اتصال SSH برقرار نشد)."
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "نتیجه: ${PASS} مورد ✅ | ${FAIL} مورد ❌"
if [ "$FAIL" -eq 0 ]; then
    echo "همه‌چیز برای اجرای واقعیِ core_side_failover.sh آماده به‌نظر می‌رسد."
else
    echo "قبل از اجرای واقعی، مواردِ ❌ بالا را برطرف کنید."
fi
echo "════════════════════════════════════════════════════════════"