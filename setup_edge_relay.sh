#!/bin/bash
# ============================================================================
# راه‌اندازی یک سرور Edge — فقط رله‌کنندهٔ ترافیک به سمت Core (از طریق تونل خصوصی)
# ----------------------------------------------------------------------------
# این اسکریپت را روی هر VPS جدیدی که به‌عنوان "پشتیبان/Edge" می‌خرید (از هر
# شرکتی، هر کشوری) اجرا می‌کنید. این سرور خودش هیچ اکانت SSH واقعی، هیچ دیتابیس،
# و هیچ اطلاعات حساسی نداره — فقط بسته‌ها رو از IP عمومی خودش به سمت Core (روی
# تونل رمزنگاری‌شدهٔ WireGuard) هدایت می‌کنه. یعنی اگه این سرور هم لو بره/هک بشه،
# مهاجم فقط به یه رله‌ی خالی می‌رسه، نه به دیتابیس یا اکانت‌های واقعی.
#
# قبل از اجرا این ۴ مقدار رو از خروجی setup_core_wireguard.sh (که روی Core زدید)
# آماده داشته باشید:
#   1) CORE_PUBLIC_IP     — آی‌پی عمومی سرور Core
#   2) CORE_WG_PORT       — پیش‌فرض 51820
#   3) CORE_PUBLIC_KEY    — کلید عمومی Core
#   4) CUSTOMER_SSH_PORT  — پورتی که مشتری‌ها باهاش وصل می‌شن (مثلاً 8443)
#
# نحوهٔ اجرا (پارامترها رو با مقادیر واقعی جایگزین کنید):
#   bash setup_edge_relay.sh <CORE_PUBLIC_IP> <CORE_WG_PORT> <CORE_PUBLIC_KEY> <EDGE_WG_IP> <CUSTOMER_SSH_PORT>
# مثال:
#   bash setup_edge_relay.sh 46.101.114.34 51820 aBcD123...=  10.77.0.2 8443
#
# EDGE_WG_IP: یک IP داخلی یکتا برای همین Edge (10.77.0.2 برای اولین Edge،
# 10.77.0.3 برای دومی، و به همین ترتیب — خودتون شماره‌گذاری رو نگه دارید).
# ============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

if [ "$#" -lt 5 ]; then
    echo "استفاده: bash $0 <CORE_PUBLIC_IP> <CORE_WG_PORT> <CORE_PUBLIC_KEY> <EDGE_WG_IP> <CUSTOMER_SSH_PORT> [TLS_PORT]"
    exit 1
fi

CORE_PUBLIC_IP="$1"
CORE_WG_PORT="$2"
CORE_PUBLIC_KEY="$3"
EDGE_WG_IP="$4"
CUSTOMER_SSH_PORT="$5"
TLS_PORT="${6:-2088}" # پورت پیش‌فرض TLS اگر داده نشد

echo "🔹 ۱) نصب WireGuard و iptables-persistent..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard iptables-persistent >/dev/null
echo "   ✅ نصب شد."

echo "🔹 ۲) ساخت کلید این Edge..."
mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077
if [ ! -f edge_private.key ]; then
    wg genkey | tee edge_private.key | wg pubkey > edge_public.key
fi
EDGE_PRIV=$(cat edge_private.key)
EDGE_PUB=$(cat edge_public.key)
echo "   ✅ کلید عمومی این Edge: $EDGE_PUB"
echo "   ⚠️ این کلید رو الان جایی کپی کن — الان باید با core_add_edge.sh روی Core ثبتش کنی."

echo "🔹 ۳) ساخت تنظیمات wg0..."
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${EDGE_WG_IP}/24
PrivateKey = ${EDGE_PRIV}

[Peer]
PublicKey = ${CORE_PUBLIC_KEY}
Endpoint = ${CORE_PUBLIC_IP}:${CORE_WG_PORT}
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
EOF
echo "   ✅ /etc/wireguard/wg0.conf ساخته شد."

echo "🔹 ۴) فعال‌سازی تونل..."
systemctl enable wg-quick@wg0 >/dev/null 2>&1
systemctl restart wg-quick@wg0
sleep 1
wg show wg0 || { echo "❌ تونل بالا نیومد."; exit 1; }

echo "🔹 ۵) فعال‌سازی IP forwarding (برای رله‌کردن بسته‌ها)..."
sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "🔹 ۶) تنظیم قوانین فوروارد پورت (DNAT) به سمت Core..."
iptables -t nat -A PREROUTING -p tcp --dport "${CUSTOMER_SSH_PORT}" -j DNAT --to-destination "10.77.0.1:${CUSTOMER_SSH_PORT}"
# خط جدید برای فوروارد پورت TLS:
iptables -t nat -A PREROUTING -p tcp --dport "${TLS_PORT}" -j DNAT --to-destination "10.77.0.1:${TLS_PORT}"
iptables -t nat -A POSTROUTING -j MASQUERADE
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4
echo "   ✅ ترافیک پورت ${CUSTOMER_SSH_PORT} به Core فوروارد می‌شود (و بعد از ریبوت هم باقی می‌ماند)."

# 🆕 محدودیتِ «فقط root روی پورت ۲۲»: چون این سرور فعلاً Edge است، اکانتِ مشتری‌ای رویش
# وجود ندارد (احرازِ هویتِ واقعی همیشه روی Core انجام می‌شود)، ولی این محدودیت را همین الان
# هم می‌گذاریم تا اگر این Edge روزی به Core ارتقا یافت (promote_edge_to_core.sh)، از قبل
# سخت‌شده باشد و به تنظیمِ دستیِ جداگانه نیاز نداشته باشد.
echo "🔹 ۶.۵) محدودیتِ «پورت ۲۲ فقط برای root»..."
PORT22_DROPIN="/etc/ssh/sshd_config.d/99-nvlbot-port22-root-only.conf"
cat > "$PORT22_DROPIN" << 'EOF'
# فقط root می‌تواند از پورت 22 (مدیریتی) وارد شود.
Match LocalPort 22
    AllowUsers root
# ⚠️ حیاتی: این خط بلوکِ Match بالا را می‌بندد؛ بدون آن، بقیهٔ تنظیماتِ sshd هم شرطی به
# LocalPort==22 می‌شوند. Match all یعنی «از اینجا به بعد، بدون هیچ شرطی».
Match all
EOF
if sshd -t 2>/tmp/sshd_test_err3; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    echo "   ✅ اعمال شد."
else
    echo "   ⚠️ کانفیگِ جدید نامعتبر بود — نادیده گرفته شد."
    rm -f "$PORT22_DROPIN"
fi

echo ""
echo "🔹 ۷) تست اتصال به Core از داخل تونل..."
if ping -c 2 -W 2 10.77.0.1 >/dev/null 2>&1; then
    echo "   ✅ Core از طریق تونل جواب داد — تونل برقرار است."
else
    echo "   ⚠️ هنوز جواب نداد. طبیعیه اگه هنوز این Edge رو روی Core با core_add_edge.sh ثبت نکردی."
    echo "      کلید عمومی این Edge رو یادت نره: ${EDGE_PUB}"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ نصب این Edge کامل شد."
echo "   کلید عمومی این Edge: ${EDGE_PUB}"
echo "   IP داخلی این Edge:   ${EDGE_WG_IP}"
echo ""
echo "مرحلهٔ بعدی — روی سرور Core این رو بزن:"
echo "   bash core_add_edge.sh \"$(hostname)\" \"${EDGE_PUB}\" \"${EDGE_WG_IP}\""
echo ""
echo "بعدش برگرد همین‌جا و دوباره تست کن: ping -c 2 10.77.0.1"
echo "اگه جواب داد، IP عمومی همین سرور رو به «🌐 سرویس IP» ربات (host_pool) اضافه کن —"
echo "از اونجا به بعد سیستم سوییچ خودکار دامنه که از قبل ساخته شده، خودش این Edge رو مدیریت می‌کنه."
echo "════════════════════════════════════════════════════════════"