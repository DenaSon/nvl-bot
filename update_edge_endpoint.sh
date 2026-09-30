#!/bin/bash
# ============================================================================
# آپدیت آدرس Core روی یک Edge — بعد از جابه‌جاییِ نقش Core/Edge
# ----------------------------------------------------------------------------
# این اسکریپت را روی هر Edgeِ دیگر (به‌جز دو سروری که نقششان عوض شد) اجرا کنید.
# فقط خط Endpoint را در wg0.conf عوض می‌کند — چون PublicKey و AllowedIPs (Core
# همیشه 10.77.0.1 است) تغییری نکرده، این تنها چیزی‌ست که لازم است.
#
# نحوهٔ اجرا:
#   sudo bash update_edge_endpoint.sh <NEW_CORE_PUBLIC_IP> [NEW_CORE_WG_PORT]
# مثال:
#   sudo bash update_edge_endpoint.sh 46.101.114.34
#   sudo bash update_edge_endpoint.sh 46.101.114.34 51820
# ============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

if [ "$#" -lt 1 ]; then
    echo "استفاده: sudo bash $0 <NEW_CORE_PUBLIC_IP> [NEW_CORE_WG_PORT]"
    exit 1
fi

NEW_CORE_PUBLIC_IP="$1"
CORE_WG_PORT="${2:-51820}"
WG_CONF="/etc/wireguard/wg0.conf"

if [ ! -f "$WG_CONF" ]; then
    echo "❌ ${WG_CONF} پیدا نشد — این سرور Edge نیست یا هنوز راه‌اندازی نشده."
    exit 1
fi

cp "$WG_CONF" "${WG_CONF}.bak.$(date +%s)"

# فقط خط Endpoint داخل بلاک [Peer] (که همیشه یکی‌ست، چون Edge فقط یک Peer یعنی Core دارد) عوض می‌شود
sed -i -E "s#^Endpoint[[:space:]]*=.*#Endpoint = ${NEW_CORE_PUBLIC_IP}:${CORE_WG_PORT}#" "$WG_CONF"

if ! grep -q "^Endpoint = ${NEW_CORE_PUBLIC_IP}:${CORE_WG_PORT}\$" "$WG_CONF"; then
    echo "❌ جایگزینیِ Endpoint موفق نبود — دستی wg0.conf را چک کنید."
    exit 1
fi
echo "✅ Endpoint به ${NEW_CORE_PUBLIC_IP}:${CORE_WG_PORT} تغییر کرد."

echo "🔹 اعمال زندهٔ تغییر (بدون توقف کامل تونل)..."
if wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null; then
    echo "   ✅ تغییر به‌صورت زنده اعمال شد (تونل قطع نشد)."
else
    echo "   ⚠️ اعمال زنده ناموفق بود؛ ری‌استارت کامل تونل به‌عنوان جایگزین..."
    systemctl restart wg-quick@wg0
fi
sleep 1

if ping -c 2 -W 2 10.77.0.1 >/dev/null 2>&1; then
    echo "✅ Core جدید از طریق تونل جواب داد — این Edge با موفقیت به Core جدید وصل شد."
else
    echo "⚠️ هنوز جواب نداد. دلایل ممکن:"
    echo "   - Core جدید هنوز این Edge را به‌عنوان Peer نمی‌شناسد (روی Core جدید core_add_edge.sh را بزنید)"
    echo "   - فایروال Core جدید پورت ${CORE_WG_PORT}/udp را باز نکرده"
fi