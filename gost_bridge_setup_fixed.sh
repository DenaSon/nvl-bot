#!/bin/bash
# ============================================================================
# Stealth Bridge Setup — نسخهٔ چندنمونه‌ای (Multi-Core)
# امکانِ پل‌کردنِ تعدادِ نامحدودی Core از پشتِ یک VPS ایران، هرکدام با پورتِ
# عمومیِ جداگانه، systemd service مستقل، و قانونِ فایروالِ اختصاصی.
#
# هر نمونه با یک NAME دلخواه (مثلاً core1, germany, finland) شناخته می‌شود —
# این باعث می‌شود بشود چند Core را کاملاً مستقل نصب/چک/حذف کرد بدون تداخل.
#
# استفاده:
#   نصب — روی Core:
#     bash gost_bridge_setup.sh core <NAME> <پورت_تونل> <IP_ایران> [پورت_مقصد=2252] [secret]
#   نصب — روی Edge (ایران)، برای هر Core یک‌بار با NAME مطابق:
#     bash gost_bridge_setup.sh edge <NAME> <پورت_عمومی> <IP_Core> <پورت_تونل> <secret>
#
#   مدیریت (روی هرکدام از دو نوع سرور):
#     bash gost_bridge_setup.sh list                 → لیستِ همهٔ نمونه‌های نصب‌شده روی این سرور
#     bash gost_bridge_setup.sh remove <NAME>         → حذفِ کاملِ یک نمونه (سرویس + فایروال)
# ============================================================================
set -uo pipefail

MODE="${1:-}"
GOST_VERSION="v3.0.0-rc.10"
SVC_PREFIX="gost-bridge"

valid_name() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "❌ NAME فقط می‌تواند حروف/اعداد/خط‌تیره باشد (بدون فاصله)."; exit 1; }
}

install_gost() {
    if command -v gost &>/dev/null; then return; fi
    echo "🔹 در حال نصب Gost ${GOST_VERSION}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GARCH="amd64" ;;
        aarch64) GARCH="arm64" ;;
        *) echo "❌ معماریِ $ARCH پشتیبانی نمی‌شود."; exit 1 ;;
    esac
    URL="https://github.com/go-gost/gost/releases/download/${GOST_VERSION}/gost_${GOST_VERSION#v}_linux_${GARCH}.tar.gz"
    TMPD=$(mktemp -d)
    if ! wget -qO "$TMPD/gost.tar.gz" "$URL"; then
        echo "❌ دانلود گاست ناموفق بود."; rm -rf "$TMPD"; exit 1
    fi
    tar -xzf "$TMPD/gost.tar.gz" -C "$TMPD"
    install -m 755 "$TMPD/gost" /usr/local/bin/gost
    rm -rf "$TMPD"
    echo "✅ گاست نصب شد."
}

write_systemd_unit() {
    local svc="$1" exec_line="$2"
    cat > "/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=Gost Stealth Bridge (${svc})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${exec_line}
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${svc}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$svc"
    sleep 1
    if systemctl is-active --quiet "$svc"; then
        echo "✅ ${svc} فعال و در حالِ اجراست."
    else
        echo "❌ سرویس ${svc} بالا نیامد:"
        journalctl -u "$svc" --no-pager -n 30
        exit 1
    fi
}

open_firewall_from() {
    local port="$1" src_ip="$2" comment="$3"
    iptables -C INPUT -p tcp --dport "$port" -s "$src_ip" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$port" -s "$src_ip" -j ACCEPT -m comment --comment "$comment"
    iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "$port" -j DROP -m comment --comment "$comment"
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1
    echo "✅ پورت ${port}: فقط ${src_ip} مجاز شد، بقیه بسته شدند."
}

open_firewall_public() {
    local port="$1" comment="$2"
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT -m comment --comment "$comment"
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1
    echo "✅ پورت عمومیِ ${port} برای همه باز شد."
}

# 🆕 قفل‌کردنِ پورتِ مقصد (مثلاً ۲۲۵۲) روی Core — فقط localhost و IPِ Edge اجازه دارند؛
# هدف این است که مشتری‌ها نتوانند این پورت را مستقیم بزنند و پلِ ایران را دور بزنند —
# وگرنه کل زحمتِ stealth-کردنِ ترافیک بی‌فایده می‌شود.
lock_target_port_to_bridge_only() {
    local port="$1" edge_ip="$2" comment="$3"
    iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT -m comment --comment "$comment"
    iptables -C INPUT -p tcp --dport "$port" -s "$edge_ip" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$port" -s "$edge_ip" -j ACCEPT -m comment --comment "$comment"
    iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "$port" -j DROP -m comment --comment "$comment"
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1
    echo "🔒 پورتِ مقصد ${port} قفل شد — فقط از localhost و IPِ Edge (${edge_ip}) قابل‌دسترسیه، بقیهٔ دنیا رد می‌شن."
    echo "   ⚠️ یعنی مشتری‌ها از این به بعد فقط از راهِ پلِ ایران (پورتِ عمومیِ روی Edge) می‌تونن وصل شن."
}

# 🆕 پیداکردنِ گواهیِ TLSِ واقعی (اگر باشد) وگرنه ساختِ یک گواهیِ خودامضا؛ برای relay+wss.
# گواهیِ واقعی (Let's Encrypt) خیلی بهتره چون ترافیک از دیدِ DPI شبیهِ یه HTTPSِ معمولی
# به یه دامنهٔ واقعی می‌شه، نه یه TLSِ ناشناس/خودامضا که خودش قابلِ‌مشکوک‌شدنه.
find_or_make_tls_cert() {
    local domain="$1"
    if [ -n "$domain" ] && [ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]; then
        echo "/etc/letsencrypt/live/${domain}/fullchain.pem" "/etc/letsencrypt/live/${domain}/privkey.pem"
        return
    fi
    mkdir -p /etc/gost-bridge-tls
    if [ ! -f /etc/gost-bridge-tls/selfsigned.crt ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout /etc/gost-bridge-tls/selfsigned.key -out /etc/gost-bridge-tls/selfsigned.crt \
            -subj "/CN=cloudflare.com" >/dev/null 2>&1
    fi
    echo "/etc/gost-bridge-tls/selfsigned.crt" "/etc/gost-bridge-tls/selfsigned.key"
}

remove_instance() {
    local svc="${SVC_PREFIX}-$1"
    echo "🔻 در حال حذفِ ${svc}..."
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
    systemctl daemon-reload
    while true; do
        RULE=$(iptables -S INPUT 2>/dev/null | grep -- "--comment \"${svc}\"" | head -1 || true)
        [ -z "$RULE" ] && break
        iptables $(echo "$RULE" | sed 's/^-A/-D/')
    done
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1
    rm -f "/root/.gost_bridge_secret_$1"
    echo "✅ ${svc} کاملاً حذف شد (سرویس + فایروال)."
}

list_instances() {
    echo "===== نمونه‌های نصب‌شدهٔ ${SVC_PREFIX} روی این سرور ====="
    local found=0
    for f in /etc/systemd/system/${SVC_PREFIX}-*.service; do
        [ -e "$f" ] || continue
        found=1
        svc=$(basename "$f" .service)
        name="${svc#${SVC_PREFIX}-}"
        state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        icon="❌"; [ "$state" = "active" ] && icon="✅"
        exec_line=$(grep "^ExecStart=" "$f" | sed 's/^ExecStart=//')
        echo "${icon} ${name}  (${state})"
        echo "     ${exec_line}"
    done
    [ "$found" -eq 0 ] && echo "هیچ نمونه‌ای پیدا نشد."
}

# ----------------------------------------------------------------------------
case "$MODE" in
core)
    NAME="${2:?NAME را بدهید, مثلاً core1}"; valid_name "$NAME"
    TUNNEL_PORT="${3:?پورت تونل را بدهید}"
    EDGE_IP="${4:?IP سرور ایران را بدهید}"
    TARGET_PORT="${5:-2252}"
    SECRET="${6:-$(openssl rand -hex 24)}"
    DOMAIN="${7:-}"
    SVC="${SVC_PREFIX}-${NAME}"

    install_gost
    read -r CERT_FILE KEY_FILE < <(find_or_make_tls_cert "$DOMAIN")
    # 🐛🔧 فیکسِ امنیتی: قبلاً relay+ws (بدونِ TLS) بود — هندشیکِ WS خام و بدونِ رمزنگاری
    # یه الگوی به‌راحتی قابل‌شناسایی برای DPI بود. الان relay+wss (روی TLS) با گواهیِ واقعی
    # (اگر دامنه داده بشه) یا خودامضا — ترافیکِ عبوری از مرز از دیدِ بیرون شبیهِ یه HTTPSِ
    # معمولیه، نه یه تونلِ مشکوک.
    write_systemd_unit "$SVC" "/usr/local/bin/gost -L \"relay+wss://:${TUNNEL_PORT}?secrets=${SECRET}&certFile=${CERT_FILE}&keyFile=${KEY_FILE}\" -F tcp://127.0.0.1:${TARGET_PORT}"
    # 🆕 به‌جای محدودکردن به یه IP خاص، فقط رنجِ IPهای کلادفلر مجازند
CF_RANGES_V4=$(curl -s https://www.cloudflare.com/ips-v4)
CF_RANGES_V6=$(curl -s https://www.cloudflare.com/ips-v6)
for cidr in $CF_RANGES_V4; do
    iptables -C INPUT -p tcp --dport "$TUNNEL_PORT" -s "$cidr" -j ACCEPT 2>/dev/null \
        || iptables -I INPUT -p tcp --dport "$TUNNEL_PORT" -s "$cidr" -j ACCEPT -m comment --comment "$SVC"
done
for cidr6 in $CF_RANGES_V6; do
    ip6tables -C INPUT -p tcp --dport "$TUNNEL_PORT" -s "$cidr6" -j ACCEPT 2>/dev/null \
        || ip6tables -I INPUT -p tcp --dport "$TUNNEL_PORT" -s "$cidr6" -j ACCEPT -m comment --comment "$SVC"
done
iptables -C INPUT -p tcp --dport "$TUNNEL_PORT" -j DROP 2>/dev/null \
    || iptables -A INPUT -p tcp --dport "$TUNNEL_PORT" -j DROP -m comment --comment "$SVC"
ip6tables -C INPUT -p tcp --dport "$TUNNEL_PORT" -j DROP 2>/dev/null \
    || ip6tables -A INPUT -p tcp --dport "$TUNNEL_PORT" -j DROP -m comment --comment "$SVC"
command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1
echo "✅ پورت ${TUNNEL_PORT}: فقط رنجِ IPv4/IPv6 کلادفلر مجازند."
    # 🆕 قفل‌کردنِ پورتِ مقصدِ واقعی (مثلاً ۲۲۵۲) — تا مشتری‌ها مجبور بشن فقط از راهِ پلِ
    # ایران (نه مستقیم) وصل بشن، وگرنه کل زحمتِ stealth بی‌فایده می‌شه.
    lock_target_port_to_bridge_only "$TARGET_PORT" "$EDGE_IP" "$SVC"

    echo ""
    echo "======================================================================"
    echo "✅ Core '${NAME}' آماده است (با TLS/wss)."
    echo "   IP این سرور : $(curl -s -4 --max-time 5 ifconfig.me || echo '<دستی چک کنید>')"
    echo "   پورت تونل   : ${TUNNEL_PORT}"
    echo "   secret      : ${SECRET}"
    if [ -n "$DOMAIN" ] && [ "$CERT_FILE" != "/etc/gost-bridge-tls/selfsigned.crt" ]; then
        echo "   گواهی       : واقعی (Let's Encrypt) روی ${DOMAIN}"
    else
        echo "   گواهی       : خودامضا (⚠️ برای مقاومتِ بیشتر، یه دامنه با گواهیِ واقعی بدید:"
        echo "                 gost_bridge_setup.sh core ${NAME} ${TUNNEL_PORT} ${EDGE_IP} ${TARGET_PORT} ${SECRET} yourdomain.com)"
    fi
    echo "   این مقادیر را برای اجرای 'edge' با همین NAME روی VPS ایران لازم دارید."
    echo "======================================================================"
    echo "$SECRET" > "/root/.gost_bridge_secret_${NAME}"
    chmod 600 "/root/.gost_bridge_secret_${NAME}"
    ;;

edge)
    NAME="${2:?NAME را بدهید (باید با NAME مرحلهٔ core یکی باشد)}"; valid_name "$NAME"
    PUBLIC_PORT="${3:?پورتِ عمومی را بدهید}"
    CORE_IP="${4:?IP سرور Core را بدهید}"
    TUNNEL_PORT="${5:?پورتِ تونل را بدهید}"
    SECRET="${6:?secret مرحلهٔ core را بدهید}"
    SVC="${SVC_PREFIX}-${NAME}"

    install_gost
    # 🐛🔧 هماهنگ با فیکسِ سمتِ core: الان relay+wss. چون گواهیِ سمتِ core ممکنه خودامضا
    # باشه (وقتی دامنه‌ای داده نشده)، secure=false می‌زاریم تا gost گیر ندهد به اینکه گواهی
    # را یه CA معتبر امضا نکرده — امن‌بودنِ خودِ کانالِ TLS (رمزنگاری) دست‌نخورده می‌مونه،
    # فقط چکِ «آیا این گواهی رو یه مرجعِ شناخته‌شده صادر کرده» رد می‌شه.
    write_systemd_unit "$SVC" "/usr/local/bin/gost -L tcp://:${PUBLIC_PORT} -F \"relay+wss://${CORE_IP}:${TUNNEL_PORT}?secrets=${SECRET}&secure=false\""
    open_firewall_public "$PUBLIC_PORT" "$SVC"

    echo ""
    echo "======================================================================"
    echo "✅ Edge برای Core '${NAME}' آماده است."
    echo "   مشتری‌ها روی IP این سرور، پورتِ ${PUBLIC_PORT} → Core '${NAME}' (${CORE_IP})"
    echo "======================================================================"
    ;;

list)
    list_instances
    ;;

remove)
    NAME="${2:?NAME ای که می‌خواهید حذف شود را بدهید}"; valid_name "$NAME"
    remove_instance "$NAME"
    ;;

*)
    cat <<'USAGE'
استفاده:
  نصب روی Core (تونل رمزنگاری‌شده با TLS/wss):
    bash gost_bridge_setup.sh core <NAME> <پورت_تونل> <IP_ایران> [پورت_مقصد=2252] [secret] [دامنه]
    اگر دامنه بدید و گواهیِ Let's Encrypt واقعی براش روی این سرور موجود باشه
    (/etc/letsencrypt/live/<دامنه>/)، همون استفاده می‌شه؛ وگرنه یه گواهیِ خودامضا
    ساخته می‌شه (کار می‌کنه، ولی مقاومتش در برابرِ شناسایی کمتره).
  نصب روی Edge (ایران) — یک‌بار به‌ازای هر Core، با همان NAME:
    bash gost_bridge_setup.sh edge <NAME> <پورت_عمومی> <IP_Core> <پورت_تونل> <secret>

  مدیریت:
    bash gost_bridge_setup.sh list
    bash gost_bridge_setup.sh remove <NAME>

نکته: NAME را خودتان انتخاب می‌کنید (مثلاً core1, germany, finland) — فقط باید در
مرحلهٔ core و edge برای همان Core یکسان باشد. هیچ محدودیتی در تعدادِ Coreها نیست.

⚠️ نصبِ core همچنین پورتِ مقصد (مثلاً 2252) را روی خودِ Core به‌طور خودکار قفل می‌کند
(فقط localhost + IP همان Edge) — یعنی مشتری‌ها دیگر نباید مستقیم آن پورت را بزنند،
باید حتماً پورتِ عمومیِ روی Edge (که در مرحلهٔ edge تعیین می‌شود) را به آن‌ها بدهید.
USAGE
    exit 1
    ;;
esac