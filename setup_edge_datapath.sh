#!/bin/bash
# ============================================================================
# setup_edge_datapath.sh — راه‌اندازیِ یک سرور به‌عنوان Data-Plane واقعی (خروجِ مستقیم)
# ----------------------------------------------------------------------------
# جایگزینِ setup_edge_relay_2.sh در معماریِ جدیدِ Control-Plane/Data-Plane.
#
# تفاوتِ اصلی با نسخهٔ قبلی:
#   ❌ دیگر iptables DNAT/MASQUERADE به سمتِ Core نمی‌سازد — این سرور خودش مقصدِ نهاییِ
#      ترافیکِ مشتری است، نه یک رلهٔ توخالی.
#   ✅ sshd را مستقیماً روی پورتِ مشتری (علاوه بر ۲۲) به گوش می‌اندازد — چون از این پس
#      useradd/chpasswd واقعاً همین‌جا (نه روی Core) اجرا می‌شود (نگاه کنید به
#      bot_patch_notes.md برای تغییرِ سمتِ ربات).
#   ✅ badvpn-udpgw و اسکلتِ سرویسِ gost (برای TLS/WSS) را مستقیماً روی همین سرور آماده
#      می‌کند.
#   ✅ دیمنِ edge_ip_limiter.py (کنترلِ هوشمندِ تعدادِ دستگاه) را نصب/فعال می‌کند.
#   🔒 تونلِ WireGuard هنوز برقرار می‌شود، ولی فقط برای مدیریتِ Core→Edge (اجرای دستورات
#      از راه دور، sync فایلِ سقفِ IP Limiter، health-check) — نه برای عبورِ ترافیکِ مشتری.
#
# این اسکریپت روی خودِ Core هم قابلِ‌اجراست (چون طبقِ طراحیِ جدید، Core هم یک Data-Plane
# همیشه‌روشن برای Failover اضطراری است) — در آن صورت پارامترهای CORE_* را با مقادیرِ خودِ
# همین سرور بدهید یا صرفاً بخش‌های WireGuard را رد کنید (SKIP_WIREGUARD=1).
#
# نحوهٔ اجرا:
#   bash setup_edge_datapath.sh <CORE_PUBLIC_IP> <CORE_WG_PORT> <CORE_PUBLIC_KEY> \
#        <EDGE_WG_IP> <CUSTOMER_SSH_PORT> [TLS_PORT] [UDPGW_PORT]
# مثال:
#   bash setup_edge_datapath.sh 46.101.114.34 51820 aBcD123...=  10.77.0.5 8443 2088 7300
#
# متغیرهای محیطیِ اختیاری:
#   SKIP_WIREGUARD=1   اگر این سرور خودِ Core است و WireGuard از قبل بالاست، این مرحله رد می‌شود.
# ============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

if [ "$#" -lt 5 ]; then
    echo "استفاده: bash $0 <CORE_PUBLIC_IP> <CORE_WG_PORT> <CORE_PUBLIC_KEY> <EDGE_WG_IP> <CUSTOMER_SSH_PORT> [TLS_PORT] [UDPGW_PORT]"
    exit 1
fi

CORE_PUBLIC_IP="$1"
CORE_WG_PORT="$2"
CORE_PUBLIC_KEY="$3"
EDGE_WG_IP="$4"
CUSTOMER_SSH_PORT="$5"
TLS_PORT="${6:-2088}"
UDPGW_PORT="${7:-7300}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔹 ۱) نصب پیش‌نیازها (WireGuard, iptables-persistent)..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard iptables-persistent >/dev/null
echo "   ✅ نصب شد."

# ============================================================================
# ۲) WireGuard — فقط برای مدیریت (نه عبورِ ترافیکِ مشتری)
# ============================================================================
if [ "${SKIP_WIREGUARD:-0}" != "1" ]; then
    echo "🔹 ۲) ساخت/تأییدِ تونلِ WireGuardِ مدیریتی..."
    mkdir -p /etc/wireguard
    cd /etc/wireguard
    umask 077
    if [ ! -f edge_private.key ]; then
        wg genkey | tee edge_private.key | wg pubkey > edge_public.key
    fi
    EDGE_PRIV=$(cat edge_private.key)
    EDGE_PUB=$(cat edge_public.key)
    echo "   ✅ کلید عمومی این سرور: ${EDGE_PUB}"

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
    systemctl enable wg-quick@wg0 >/dev/null 2>&1
    systemctl restart wg-quick@wg0
    sleep 1
    wg show wg0 || { echo "❌ تونلِ مدیریتی بالا نیومد."; exit 1; }
    echo "   ✅ تونلِ مدیریتی برقرار است."
else
    echo "🔹 ۲) SKIP_WIREGUARD=1 — این مرحله رد شد (فرض بر این است که خودِ Core است)."
fi

# ============================================================================
# ۳) sshd روی پورتِ مشتری — چون از این پس useradd واقعاً همین‌جا اجرا می‌شود
# ============================================================================
echo "🔹 ۳) گوش‌دادنِ sshd روی پورتِ مشتری (${CUSTOMER_SSH_PORT}) علاوه بر ۲۲..."
mkdir -p /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/override.conf << EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:22
ListenStream=[::]:22
ListenStream=0.0.0.0:${CUSTOMER_SSH_PORT}
ListenStream=[::]:${CUSTOMER_SSH_PORT}
EOF
systemctl daemon-reload
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket
else
    # بعضی توزیع‌ها به‌صورتِ پیش‌فرض از ssh.socket استفاده نمی‌کنند و مستقیماً sshd روی
    # پورت‌های sshd_config گوش می‌دهد؛ در آن صورت به‌جای override سوکت، خطِ Port اضافه می‌شود.
    if ! grep -q "^Port ${CUSTOMER_SSH_PORT}\$" /etc/ssh/sshd_config 2>/dev/null; then
        echo "Port 22" >> /etc/ssh/sshd_config
        echo "Port ${CUSTOMER_SSH_PORT}" >> /etc/ssh/sshd_config
    fi
    sshd -t && (systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null)
fi
echo "   ✅ sshd روی ۲۲ و ${CUSTOMER_SSH_PORT} گوش می‌دهد."

echo "🔹 ۳.۵) محدودیتِ «پورتِ ۲۲ فقط برای root» (مشتری‌ها فقط از پورتِ اختصاصی وارد شوند)..."
PORT22_DROPIN="/etc/ssh/sshd_config.d/99-nvlbot-port22-root-only.conf"
cat > "$PORT22_DROPIN" << 'EOF'
Match LocalPort 22
    AllowUsers root
Match all
EOF
if sshd -t 2>/tmp/sshd_test_err; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    echo "   ✅ اعمال شد."
else
    echo "   ⚠️ کانفیگِ sshd نامعتبر شد — این محدودیت نادیده گرفته شد."
    rm -f "$PORT22_DROPIN"
fi

# ============================================================================
# ۴) badvpn-udpgw — مستقیماً روی همین سرور (نه Core)
# ============================================================================
echo "🔹 ۴) نصب/فعال‌سازیِ badvpn-udpgw (پورتِ اصلی ${UDPGW_PORT} + legacy روی 127.0.0.1:1234)..."
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
if [ ! -x "$BADVPN_BIN" ]; then
    for cand in "${SCRIPT_DIR}/badvpn-udpgw-built" "/root/badvpn-udpgw-built"; do
        if [ -f "$cand" ]; then
            cp "$cand" "$BADVPN_BIN"
            chmod +x "$BADVPN_BIN"
            echo "   ✅ باینری از ${cand} نصب شد."
            break
        fi
    done
fi
if [ -x "$BADVPN_BIN" ]; then
    cat > /etc/systemd/system/badvpn-udpgw.service << EOF
[Unit]
Description=BadVPN UDPGW (primary, port ${UDPGW_PORT})
After=network.target

[Service]
ExecStart=${BADVPN_BIN} --listen-addr 0.0.0.0:${UDPGW_PORT}
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/badvpn-udpgw-legacy.service << EOF
[Unit]
Description=BadVPN UDPGW (legacy port 1234 for old clients)
After=network.target

[Service]
ExecStart=${BADVPN_BIN} --listen-addr 127.0.0.1:1234
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now badvpn-udpgw badvpn-udpgw-legacy >/dev/null 2>&1
    echo "   ✅ هر دو سرویسِ udpgw فعال شدند."
else
    echo "   ⚠️ باینریِ badvpn-udpgw پیدا نشد — این مرحله رد شد (کنارِ این اسکریپت یا در"
    echo "      /root/badvpn-udpgw-built قرارش دهید و دوباره اجرا کنید)."
fi

# ============================================================================
# ۵) اسکلتِ سرویسِ gost — برای TLS/WSS (خودِ config.yaml را ربات/sync جداگانه می‌فرستد)
# ============================================================================
echo "🔹 ۵) آماده‌سازیِ سرویسِ gost (پورتِ TLS: ${TLS_PORT})..."
mkdir -p /etc/gost
GOST_BIN="/usr/local/bin/gost"
if [ ! -f /etc/systemd/system/gost.service ]; then
    cat > /etc/systemd/system/gost.service << EOF
[Unit]
Description=gost TLS/WSS endpoint
After=network.target

[Service]
ExecStart=${GOST_BIN} -C /etc/gost/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi
if [ -x "$GOST_BIN" ] && [ -f /etc/gost/config.yaml ]; then
    systemctl enable --now gost >/dev/null 2>&1
    echo "   ✅ gost فعال شد (config از قبل موجود بود)."
else
    systemctl enable gost >/dev/null 2>&1 || true
    echo "   ℹ️ باینری/کانفیگِ gost هنوز روی این سرور نیست — بعداً که Core آن‌ها را sync کرد،"
    echo "      خودکار بالا می‌آید (enable شده، فقط منتظرِ فایل‌هاست)."
fi

# ============================================================================
# ۶) فایروال — بازکردنِ صریحِ پورت‌های مشتری (این سرور دیگر پشتِ DNAT کسی نیست)
# ============================================================================
echo "🔹 ۶) بازکردنِ پورت‌های لازم روی فایروال..."
open_tcp() { iptables -C INPUT -p tcp --dport "$1" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$1" -j ACCEPT; }
open_udp() { iptables -C INPUT -p udp --dport "$1" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$1" -j ACCEPT; }
open_tcp 22
open_tcp "$CUSTOMER_SSH_PORT"
open_tcp "$TLS_PORT"
open_udp "$UDPGW_PORT"
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4
echo "   ✅ پورت‌های ۲۲, ${CUSTOMER_SSH_PORT}/tcp, ${TLS_PORT}/tcp, ${UDPGW_PORT}/udp باز شدند."

# ============================================================================
# ۷) دیمنِ IP Limiter (Kill-Oldest-IP)
# ============================================================================
echo "🔹 ۷) نصب/فعال‌سازیِ edge_ip_limiter.py..."
mkdir -p /etc/nvlbot /etc/ssh/user-limits
LIMITER_SRC="${SCRIPT_DIR}/edge_ip_limiter.py"
LIMITER_UNIT_SRC="${SCRIPT_DIR}/edge-ip-limiter.service"
if [ -f "$LIMITER_SRC" ] && [ -f "$LIMITER_UNIT_SRC" ]; then
    cp "$LIMITER_SRC" /usr/local/bin/edge_ip_limiter.py
    chmod +x /usr/local/bin/edge_ip_limiter.py
    cp "$LIMITER_UNIT_SRC" /etc/systemd/system/edge-ip-limiter.service
    cat > /etc/nvlbot/ip_limiter.env << EOF
IP_LIMITER_PORTS=22,${CUSTOMER_SSH_PORT}
EOF
    systemctl daemon-reload
    systemctl enable --now edge-ip-limiter >/dev/null 2>&1
    echo "   ✅ edge-ip-limiter فعال شد (پورت‌های پایش: 22,${CUSTOMER_SSH_PORT})."
else
    echo "   ⚠️ edge_ip_limiter.py یا edge-ip-limiter.service کنارِ همین اسکریپت پیدا نشد — رد شد."
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ این سرور به‌عنوانِ Data-Plane (خروجِ مستقیم) آماده است."
echo "   • sshd: پورت‌های ۲۲ (فقط root) و ${CUSTOMER_SSH_PORT} (مشتری)"
echo "   • gost (TLS/WSS): پورتِ ${TLS_PORT} — منتظرِ config.yaml"
echo "   • badvpn-udpgw: پورتِ ${UDPGW_PORT} + legacy 1234"
echo "   • edge-ip-limiter: فعال"
if [ "${SKIP_WIREGUARD:-0}" != "1" ]; then
echo "   • WireGuard مدیریتی: برقرار — کلیدِ عمومیِ این سرور را با core_add_edge.sh روی Core ثبت کنید."
fi
echo "════════════════════════════════════════════════════════════"