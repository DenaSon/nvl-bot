#!/bin/bash
# ============================================================================
# ترفیعِ یک سرور Edge به Core واقعی (نسخهٔ مجهز به سلاح‌های NVL)
# ----------------------------------------------------------------------------
# ارتقا یافته با: لیمیتر هوشمند SSH، بهینه‌سازی ظرفیت ۲۰۴۸ کاربره، و BadVPN ۵-پورته
# ============================================================================

set -euo pipefail

PROMOTE_SUCCESS=0
OLD_CORE_STOPPED_BY_US=0
TARGET_ROLE_CHANGED=0
rollback_on_failure() {
    local failure_rc=$?
    [ "$PROMOTE_SUCCESS" = "1" ] && return "$failure_rc"
    if [ "$TARGET_ROLE_CHANGED" = "1" ]; then
        # The source wrapper normally stopped the old Core. Even in that flow,
        # a failed postcheck must stop our new bot/WG identity before it returns.
        echo "⚠️ ارتقا کامل نشد؛ نقش ناقص Core روی مقصد متوقف می‌شود."
        systemctl disable --now nvlbot >/dev/null 2>&1 || true
        systemctl disable --now wg-quick@wg0 >/dev/null 2>&1 || true
        if systemctl is-active --quiet nvlbot || systemctl is-active --quiet wg-quick@wg0 \
                || wg show wg0 >/dev/null 2>&1; then
            echo "❌ خاموش‌بودن کامل مقصد تأیید نشد؛ بازگشت Core قبلی نیازمند بررسی است."
            return "$failure_rc"
        fi
    fi
    if [ "$OLD_CORE_STOPPED_BY_US" = "1" ] && [ -n "${OLD_CORE_IP:-}" ]; then
        echo ""
        echo "⚠️⚠️⚠️ Promote ناتمام ماند — تلاش برای روشن‌کردنِ دوبارهٔ ربات روی Core قدیمی..."
        for p in 22 "${CUSTOMER_SSH_PORT:-22}"; do
            if ssh -i /root/.ssh/edge_provision_ed25519 -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
                    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${OLD_CORE_IP}" \
                    "systemctl start wg-quick@wg0 && systemctl start nvlbot" 2>/dev/null; then
                echo "   ✅ ربات روی Core قدیمی (${OLD_CORE_IP}) دوباره روشن شد."
                return "$failure_rc"
            fi
        done
        echo "   ❌ نتوانستیم خودکار دوباره روشنش کنیم — فوراً دستی بزنید: ssh root@${OLD_CORE_IP} systemctl start nvlbot"
    fi
    return "$failure_rc"
}
trap rollback_on_failure EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "استفاده: sudo bash $0 <CUSTOMER_SSH_PORT> <MIGRATION_DIR>"
    exit 1
fi

CUSTOMER_SSH_PORT="$1"
MIGRATION_DIR="$2"
CORE_WG_PORT=51820
CORE_WG_IP="10.77.0.1"
BOT_DIR="${BOT_DIR_OVERRIDE:-/root}"

sleep 3

for f in core_private.key wg0.conf.peers master_bot.db; do
    if [ ! -f "${MIGRATION_DIR}/${f}" ]; then
        echo "❌ فایل لازم پیدا نشد: ${MIGRATION_DIR}/${f}"
        exit 1
    fi
done

for f in gost_config.yaml letsencrypt.tar.gz gost_bin edge_provision_ed25519; do
    if [ ! -f "${MIGRATION_DIR}/${f}" ]; then
        echo "⚠️ فایل اختیاریِ ${f} پیدا نشد."
    fi
done

if [ -f "${MIGRATION_DIR}/root_full_snapshot.tar.gz" ]; then
    echo "🔹 ۰.۵) استخراجِ اسنپ‌شاتِ کاملِ محیطِ Core قبلی..."
    mkdir -p "${BOT_DIR}"
    tar -xzf "${MIGRATION_DIR}/root_full_snapshot.tar.gz" -C "${BOT_DIR}" \
        --exclude="master_bot.db*" --exclude="bot_persistence.pickle*" 2>/dev/null || true
    echo "   ✅ اسنپ‌شاتِ محیط منتقل شد."
fi

echo "🔹 ۱) توقف نقش قبلیِ Edge..."
TARGET_ROLE_CHANGED=1
systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
systemctl stop gost >/dev/null 2>&1 || true
iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -t nat -F POSTROUTING 2>/dev/null || true
echo "   ✅ نقش قبلی متوقف شد."

echo "🔹 ۲) نصب پیش‌نیازهای پایه، فایروال و ابزارهای کامپایل NVL..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard openssh-server sqlite3 ipset cmake make gcc g++ build-essential git >/dev/null
echo "   ✅ نصب پیش‌نیازها با موفقیت انجام شد."

echo "🔹 ۳) جایگذاریِ کلید خصوصیِ منتقل‌شدهٔ Core..."
mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077
cp "${MIGRATION_DIR}/core_private.key" /etc/wireguard/core_private.key
wg pubkey < /etc/wireguard/core_private.key > /etc/wireguard/core_public.key
CORE_PRIV=$(cat core_private.key)
CORE_PUB=$(cat core_public.key)
echo "   ✅ کلید منتقل شد."

echo "🔹 ۳.۵) نصبِ کلید دائمیِ SSH..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ -f "${MIGRATION_DIR}/edge_provision_ed25519" ]; then
    cp "${MIGRATION_DIR}/edge_provision_ed25519" /root/.ssh/edge_provision_ed25519
    chmod 600 /root/.ssh/edge_provision_ed25519
    [ -f "${MIGRATION_DIR}/edge_provision_ed25519.pub" ] && \
        cp "${MIGRATION_DIR}/edge_provision_ed25519.pub" /root/.ssh/edge_provision_ed25519.pub
fi

echo "🔹 ۳.۷) تضمین مجوز اجرایی درست برای باینری‌های مهاجرت‌شده..."
for BIN_PATH in /usr/local/bin/badvpn-udpgw /usr/local/bin/gost /usr/bin/gost; do
    if [ -f "$BIN_PATH" ]; then
        chmod 755 "$BIN_PATH"
    fi
done

echo "🔹 ۴) بازسازی wg0.conf با همان Peerهای قدیمی..."
if [ -f /etc/wireguard/wg0.conf ]; then
    cp /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.bak.$(date +%s)"
fi
{
    echo "[Interface]"
    echo "Address = ${CORE_WG_IP}/24"
    echo "ListenPort = ${CORE_WG_PORT}"
    echo "PrivateKey = ${CORE_PRIV}"
    echo ""
    cat "${MIGRATION_DIR}/wg0.conf.peers"
} > /etc/wireguard/wg0.conf

echo "🔹 ۵) فعال‌سازی تونل..."
systemctl enable wg-quick@wg0 >/dev/null 2>&1
systemctl restart wg-quick@wg0
sleep 1

echo "🔹 ۶) sshd روی پورت مشتری‌ها (۰.۰.۰.۰) بالا بیاید..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
else
    iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT
fi
# Ubuntu often leaves '#Port 22' commented. Adding a customer Port then
# suppresses the implicit SSH management port and breaks subsequent Demote.
if ! grep -qE '^[[:space:]]*Port[[:space:]]+22([[:space:]]|$)' /etc/ssh/sshd_config; then
    printf '\nPort 22\n' >> /etc/ssh/sshd_config
fi
if ! grep -qE "^[[:space:]]*Port[[:space:]]+${CUSTOMER_SSH_PORT}([[:space:]]|$)" /etc/ssh/sshd_config; then
    printf '\nPort %s\n' "${CUSTOMER_SSH_PORT}" >> /etc/ssh/sshd_config
fi
mkdir -p /run/sshd
chmod 0755 /run/sshd
if ! sshd -t; then
    echo "❌ تنظیمات SSH جدید معتبر نیست؛ قبل از ری‌استارت متوقف شد."
    exit 1
fi
# Existing Edge hardening uses Match LocalPort, which needs connection context.
if ! sshd -T -C 'user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22' \
        | awk '$1 == "port" && $2 == "22" {found=1} END {exit !found}'; then
    echo "❌ پورت مدیریتی ۲۲ در تنظیمات مؤثر SSH نیست؛ Promote متوقف شد."
    exit 1
fi

if systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; then
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
    systemctl restart ssh.socket
fi

if ! systemctl restart ssh 2>/dev/null && ! systemctl restart sshd 2>/dev/null; then
    exit 1
fi
sleep 1

echo "🔹 ۶.۵) محدودیتِ «پورت ۲۲ فقط برای root»..."
PORT22_DROPIN="/etc/ssh/sshd_config.d/99-nvlbot-port22-root-only.conf"
cat > "$PORT22_DROPIN" << 'EOF'
Match LocalPort 22
    AllowUsers root
Match all
EOF
if sshd -t 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
else
    rm -f "$PORT22_DROPIN"
fi

GOST_PORTS=()
if [ -f "${MIGRATION_DIR}/gost_config.yaml" ] && [ -f "${MIGRATION_DIR}/letsencrypt.tar.gz" ]; then
    echo "🔹 ۷) بازیابیِ گواهی‌های Let's Encrypt و کانفیگ gost..."
    mkdir -p /etc/letsencrypt
    tar -xzf "${MIGRATION_DIR}/letsencrypt.tar.gz" -C /etc
    if [ -f "${MIGRATION_DIR}/cf_certs.tar.gz" ]; then
        mkdir -p /etc/ssl/cf
        tar -xzf "${MIGRATION_DIR}/cf_certs.tar.gz" -C /etc
    fi
    mkdir -p /etc/gost
    cp "${MIGRATION_DIR}/gost_config.yaml" /etc/gost/config.yaml
    sed -i -E "s#(addr:[[:space:]]*127\.0\.0\.1:)[0-9]+#\1${CUSTOMER_SSH_PORT}#g" /etc/gost/config.yaml

    GOST_BIN_OK=0
    if [ -f "${MIGRATION_DIR}/gost_bin" ]; then
        systemctl stop gost >/dev/null 2>&1 || true
        cp "${MIGRATION_DIR}/gost_bin" /usr/local/bin/gost.new
        chmod 755 /usr/local/bin/gost.new
        mv -f /usr/local/bin/gost.new /usr/local/bin/gost
        GOST_BIN_OK=1
    elif [ -x /usr/local/bin/gost ]; then
        GOST_BIN_OK=1
    fi

    if [ ! -f /etc/systemd/system/gost.service ]; then
        cat > /etc/systemd/system/gost.service << 'EOF'
[Unit]
Description=GOST TLS/WSS forwarder
After=network.target
[Service]
ExecStart=/usr/local/bin/gost -C /etc/gost/config.yaml
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    if [ "$GOST_BIN_OK" = "1" ]; then
        systemctl enable gost >/dev/null 2>&1 || true
        systemctl restart gost
        sleep 1
        if systemctl is-active --quiet gost; then
            while IFS= read -r p; do GOST_PORTS+=("$p"); done < <(grep -oE '^\s*addr:\s*:[0-9]+' /etc/gost/config.yaml | grep -oE '[0-9]+' | sort -u)
        else
            systemctl disable gost >/dev/null 2>&1 || true
        fi
    else
        systemctl disable gost >/dev/null 2>&1 || true
    fi
fi

echo "🔹 ۸) باز کردن پورت‌های مشتری روی فایروال..."
ALL_CUSTOMER_PORTS=("${CUSTOMER_SSH_PORT}" "${GOST_PORTS[@]:-}")
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${CORE_WG_PORT}/udp" >/dev/null
    for p in "${ALL_CUSTOMER_PORTS[@]}"; do [ -n "$p" ] && ufw allow "${p}/tcp" >/dev/null; done
else
    iptables -C INPUT -p udp --dport "${CORE_WG_PORT}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "${CORE_WG_PORT}" -j ACCEPT
    for p in "${ALL_CUSTOMER_PORTS[@]}"; do
        [ -z "$p" ] && continue
        iptables -C INPUT -p tcp --dport "${p}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "${p}" -j ACCEPT
    done
    (command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1) || true
fi

echo "🔹 ۹) قرار دادن دیتابیسِ منتقل‌شده..."
mkdir -p "${BOT_DIR}"
if [ -f "${BOT_DIR}/master_bot.db" ]; then
    cp "${BOT_DIR}/master_bot.db" "${BOT_DIR}/master_bot.db.bak.$(date +%s)"
fi
cp "${MIGRATION_DIR}/master_bot.db" "${BOT_DIR}/master_bot.db"
DETECTED_OLD_CORE_IP="$(sqlite3 "${BOT_DIR}/master_bot.db" "SELECT value FROM settings WHERE key='core_wg_public_ip';" 2>/dev/null)"
if [[ ! "$DETECTED_OLD_CORE_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    DETECTED_OLD_CORE_IP=""
fi

echo "🔹 ۹.۵) تشخیص و اصلاحِ خودکارِ core_wg_public_ip..."
SELF_PUBLIC_IP=""
for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://checkip.amazonaws.com"; do
    CAND="$(curl -4 -s --max-time 6 "$svc" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$CAND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        SELF_PUBLIC_IP="$CAND"
        break
    fi
done
if [ -n "$SELF_PUBLIC_IP" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${BOT_DIR}/master_bot.db" "UPDATE settings SET value='${SELF_PUBLIC_IP}' WHERE key='core_wg_public_ip';"
else
    exit 1
fi

echo "🔹 ۹.۷) نصب/بازسازیِ سرویسِ قدرتمندِ BadVPN روی ۵ پورت محبوب..."
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    if [ -f "${MIGRATION_DIR}/badvpn_udpgw_bin" ]; then
        cp "${MIGRATION_DIR}/badvpn_udpgw_bin" /usr/local/bin/badvpn-udpgw
        chmod 755 /usr/local/bin/badvpn-udpgw
    else
        echo "   ⏳ در حال کامپایلِ اتوماتیک هسته BadVPN..."
        git clone https://github.com/ambrop72/badvpn.git /tmp/badvpn >/dev/null 2>&1
        cd /tmp/badvpn && mkdir build && cd build
        cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1
        make install >/dev/null 2>&1
        rm -rf /tmp/badvpn
    fi
fi

if command -v badvpn-udpgw >/dev/null 2>&1; then
    for PORT in 7300 8510 8515 8516 8517; do
        cat > /etc/systemd/system/badvpn-$PORT.service << EOF
[Unit]
Description=BadVPN UDPGW on port $PORT
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$PORT --max-clients 2000 --max-connections-for-client 10 --client-socket-sndbuf 100000
Restart=always
RestartSec=3
User=nobody
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now badvpn-$PORT.service >/dev/null 2>&1
    done
    echo "   ✅ سرویس‌های BadVPN روی پورت‌های 7300, 8510, 8515, 8516, 8517 با موفقیت فعال شدند."
else
    echo "   ❌ نصب BadVPN با خطا مواجه شد."
fi

if [ -f "${MIGRATION_DIR}/bot_persistence.pickle" ]; then
    cp "${MIGRATION_DIR}/bot_persistence.pickle" "${BOT_DIR}/bot_persistence.pickle"
fi

OLD_CORE_IP="${OLD_CORE_IP:-$DETECTED_OLD_CORE_IP}"
if [ -n "$OLD_CORE_IP" ] && [ "${FORCE_PROMOTE:-0}" != "1" ]; then
    echo "🔹 ۱۰) بررسیِ Split-Brain..."
    OLD_CORE_ALIVE=0
    for p in 22 "${CUSTOMER_SSH_PORT}"; do
        if ssh -i /root/.ssh/edge_provision_ed25519 -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${OLD_CORE_IP}" \
                "systemctl is-active --quiet nvlbot" 2>/dev/null; then
            OLD_CORE_ALIVE=1
            break
        fi
    done
    if [ "$OLD_CORE_ALIVE" = "1" ]; then
        for p in 22 "${CUSTOMER_SSH_PORT}"; do
            ssh -i /root/.ssh/edge_provision_ed25519 -p "$p" -o ConnectTimeout=6 -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${OLD_CORE_IP}" \
                "systemctl stop nvlbot" 2>/dev/null || true
        done
        OLD_CORE_STOPPED_BY_US=1
    fi
fi

echo "🔹 ۱۱) استقرارِ کدِ ربات..."
STANDBY_DIR="/root/nvlbot_standby"
# The source Core preflight has already staged this exact file and installed pip.
MAIN_MARKER="$STANDBY_DIR/.nvl_promotion_main"
[ -f "$MAIN_MARKER" ] || { echo "❌ Preflight marker missing; refusing promotion."; exit 1; }
STAGED_MAIN_NAME="$(cat "$MAIN_MARKER")"
[ "$STAGED_MAIN_NAME" = "bot_final_v49-2.py" ] ||
    { echo "❌ Unexpected staged bot script: $STAGED_MAIN_NAME"; exit 1; }
[ -s "$STANDBY_DIR/$STAGED_MAIN_NAME" ] ||
    { echo "❌ The selected bot script was not staged."; exit 1; }
[ -s "$STANDBY_DIR/requirements.txt" ] ||
    { echo "❌ requirements.txt was not staged."; exit 1; }
[ -x "$BOT_DIR/venv/bin/python3" ] &&
    "$BOT_DIR/venv/bin/python3" -m pip --version >/dev/null ||
    { echo "❌ Missing pip in destination venv; preflight failed."; exit 1; }
"$BOT_DIR/venv/bin/python3" -m py_compile "$STANDBY_DIR/$STAGED_MAIN_NAME"
systemctl stop nvlbot 2>/dev/null || true
for package in ops server_migration; do
    # A zero-byte __init__.py is a valid Python package initializer.
    [ -f "$STANDBY_DIR/$package/__init__.py" ] ||
        { echo "Missing staged Python package: $package"; exit 1; }
done
[ -s "$STANDBY_DIR/bot_import_preflight.py" ] ||
    { echo "Missing staged bot import checker"; exit 1; }
cp "$STANDBY_DIR/"*.py "$STANDBY_DIR/"*.sh "$STANDBY_DIR/requirements.txt" "$BOT_DIR/"
cp -a "$STANDBY_DIR/ops" "$STANDBY_DIR/server_migration" "$BOT_DIR/"
(cd "$BOT_DIR" && PYTHONPATH= "$BOT_DIR/venv/bin/python3" "$BOT_DIR/bot_import_preflight.py" "$BOT_DIR/$STAGED_MAIN_NAME") ||
    { echo "Bot runtime imports failed on destination"; exit 1; }

# Always prefer the service unit collected from the live Core during THIS run.
if [ -s "${MIGRATION_DIR}/nvlbot.service" ]; then
    sed -E "s#bot_final_[^ ]+\\.py#${STAGED_MAIN_NAME}#g" "${MIGRATION_DIR}/nvlbot.service" > /etc/systemd/system/nvlbot.service
elif [ -s "${STANDBY_DIR}/nvlbot.service.staged" ]; then
    sed -E "s#bot_final_[^ ]+\\.py#${STAGED_MAIN_NAME}#g" "${STANDBY_DIR}/nvlbot.service.staged" > /etc/systemd/system/nvlbot.service
else
    echo "❌ nvlbot.service از Core قبلی منتقل نشده است."
    exit 1
fi

# Restore source Core's private runtime BEFORE starting the destination bot.
# Archives are prepared on the trusted source Core; never print env contents.
if [ -f "${MIGRATION_DIR}/nvlbot_etc.tar.gz" ]; then
    tar -xzf "${MIGRATION_DIR}/nvlbot_etc.tar.gz" -C /etc ||
        { echo "❌ بازگردانی /etc/nvlbot شکست خورد."; exit 1; }
    if [ -f /etc/nvlbot/nvlbot.env ]; then chmod 600 /etc/nvlbot/nvlbot.env; fi
fi
if [ -f "${MIGRATION_DIR}/nvlbot_dropins.tar.gz" ]; then
    tar -xzf "${MIGRATION_DIR}/nvlbot_dropins.tar.gz" -C /etc/systemd/system ||
        { echo "❌ بازگردانی drop-in سرویس ربات شکست خورد."; exit 1; }
fi
systemctl daemon-reload
# Fail before account migration if a required systemd EnvironmentFile is absent.
REQUIRED_ENV_FILE="$(systemctl show nvlbot -p EnvironmentFiles --value 2>/dev/null | awk '{print $1}')"
if [ -n "$REQUIRED_ENV_FILE" ] && [ ! -f "$REQUIRED_ENV_FILE" ]; then
    echo "❌ فایل EnvironmentFile الزامی روی Core جدید موجود نیست: ${REQUIRED_ENV_FILE}"
    exit 1
fi

echo "🔹 ۱۲) بازسازیِ کاربرهای لینوکسی..."
RECREATE_SCRIPT="${BOT_DIR}/02_recreate_ssh_users.py"
if [ -f "$RECREATE_SCRIPT" ]; then
    PYBIN="${BOT_DIR}/venv/bin/python3"
    [ -x "$PYBIN" ] || PYBIN="python3"
    "$PYBIN" "$RECREATE_SCRIPT" || { echo "❌ بازسازی کاربران SSH شکست خورد."; exit 1; }
fi

echo "🔹 ۱۳) نصب تایمرِ nvl-edge-sync..."
if { [ ! -f "${BOT_DIR}/nvl-edge-sync.service" ] || [ ! -f "${BOT_DIR}/nvl-edge-sync.timer" ]; } && [ -n "${OLD_CORE_IP:-}" ]; then
    for p in "${CUSTOMER_SSH_PORT}" 22; do
        scp -i /root/.ssh/edge_provision_ed25519 -P "${p}" -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
            "root@${OLD_CORE_IP}:/root/nvl-edge-sync.service" "root@${OLD_CORE_IP}:/root/nvl-edge-sync.timer" "${BOT_DIR}/" 2>/dev/null || true
    done
fi
if [ -f "${BOT_DIR}/nvl-edge-sync.service" ] && [ -f "${BOT_DIR}/nvl-edge-sync.timer" ]; then
    cp "${BOT_DIR}/nvl-edge-sync.service" /etc/systemd/system/nvl-edge-sync.service
    cp "${BOT_DIR}/nvl-edge-sync.timer" /etc/systemd/system/nvl-edge-sync.timer
    systemctl daemon-reload
    systemctl enable --now nvl-edge-sync.timer >/dev/null 2>&1
fi

echo "🔹 ۱۴) اعمالِ خودکارِ تیونینگ‌های سطح-سرور (به‌همراه گنجایش ۲۰۴۸ کاربر SSH)..."
(
    set +e
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        modprobe tcp_bbr 2>/dev/null
        grep -q '^tcp_bbr$' /etc/modules-load.d/modules.conf 2>/dev/null || echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
        grep -q 'net.ipv4.tcp_congestion_control' /etc/sysctl.d/99-nvl-tuning.conf 2>/dev/null || {
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-nvl-tuning.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-nvl-tuning.conf
        }
        sysctl --system >/dev/null 2>&1
    fi

    # --- NVL Smart SSH Capacity Tuning ---
    SSHD_CONF="/etc/ssh/sshd_config"
    if [ -f "$SSHD_CONF" ]; then
        cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"
        sed -i 's/^MaxStartups.*/MaxStartups 2048:30:4096/' "$SSHD_CONF"
        grep -q "MaxSessions 2048" "$SSHD_CONF" || echo -e "\nMaxSessions 2048\nClientAliveInterval 30\nClientAliveCountMax 5\nTCPKeepAlive yes\nLoginGraceTime 60" >> "$SSHD_CONF"
        
        for opt in "UseDNS no" "GSSAPIAuthentication no"; do
            key="${opt%% *}"
            if grep -qE "^\s*${key}\b" "$SSHD_CONF"; then
                sed -i -E "s/^\s*${key}\b.*/${opt}/" "$SSHD_CONF"
            else
                echo "$opt" >> "$SSHD_CONF"
            fi
        done
        if sshd -t 2>/dev/null; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
            echo "   ✅ SSH برای گنجایش 2048 اتصال بهینه‌سازی شد."
        else
            cp "${SSHD_CONF}.bak.$(date +%s)" "$SSHD_CONF"
        fi
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        mkdir -p /etc/fail2ban/jail.d
        cat > /etc/fail2ban/jail.d/nvl-tuning.local << 'EOF'
[sshd]
maxretry = 20
findtime = 900
bantime = 900
EOF
        systemctl restart fail2ban 2>/dev/null
    fi

    if ! swapon --show 2>/dev/null | grep -q '/swapfile'; then
        if [ ! -f /swapfile ]; then
            fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null 2>&1
        fi
        swapon /swapfile 2>/dev/null
        grep -q '^/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    sysctl -w vm.swappiness=10 >/dev/null 2>&1
    grep -q '^vm.swappiness' /etc/sysctl.d/99-nvl-tuning.conf 2>/dev/null || echo "vm.swappiness=10" >> /etc/sysctl.d/99-nvl-tuning.conf
) || true

echo "🔹 ۱۵) بازیابیِ اسنپ‌شاتِ سطح-سیستم..."
(
    set +e
    if [ -f "${MIGRATION_DIR}/manually_installed_packages.txt" ] && [ -s "${MIGRATION_DIR}/manually_installed_packages.txt" ]; then
        CURRENT_MANUAL="$(apt-mark showmanual 2>/dev/null)"
        MISSING_PKGS=()
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            echo "$CURRENT_MANUAL" | grep -qxF "$pkg" || MISSING_PKGS+=("$pkg")
        done < "${MIGRATION_DIR}/manually_installed_packages.txt"
        if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING_PKGS[@]}" >/dev/null 2>&1
        fi
    fi
    if [ -f "${MIGRATION_DIR}/root_crontab.txt" ] && [ -s "${MIGRATION_DIR}/root_crontab.txt" ]; then
        crontab -u root "${MIGRATION_DIR}/root_crontab.txt" 2>/dev/null
    fi
    if [ -d "${MIGRATION_DIR}/cron_d" ] && [ -n "$(ls -A "${MIGRATION_DIR}/cron_d" 2>/dev/null)" ]; then
        cp "${MIGRATION_DIR}/cron_d/"* /etc/cron.d/ 2>/dev/null
    fi
    if [ -d "${MIGRATION_DIR}/custom_systemd_units" ] && [ -n "$(ls -A "${MIGRATION_DIR}/custom_systemd_units" 2>/dev/null)" ]; then
        cp "${MIGRATION_DIR}/custom_systemd_units/"* /etc/systemd/system/ 2>/dev/null
        systemctl daemon-reload
        if [ -f "${MIGRATION_DIR}/custom_systemd_units_enabled.txt" ]; then
            while IFS= read -r unit; do
                [ -z "$unit" ] && continue
                systemctl enable --now "$unit" >/dev/null 2>&1
            done < "${MIGRATION_DIR}/custom_systemd_units_enabled.txt"
        fi
    fi
) || true

echo "🔹 ۱۶) ساخت و راه‌اندازی لیمیتر قدرتمندِ ضدپینگ‌پنگِ NVL..."
cat << 'EOF' > /root/ip_limiter.py
#!/usr/bin/env python3
from __future__ import annotations
import os
import re
import sys
import time
import signal
import logging
import subprocess
from collections import defaultdict

USER_LIMITS_DIR = os.environ.get("IP_LIMITER_LIMITS_DIR", "/etc/ssh/user-limits")
POLL_INTERVAL_SECONDS = float(os.environ.get("IP_LIMITER_POLL_SECONDS", "5"))
SSH_PORTS = [p.strip() for p in os.environ.get("IP_LIMITER_PORTS", "22,2252").split(",") if p.strip()]
EXCLUDE_USERS = {u.strip() for u in os.environ.get("IP_LIMITER_EXCLUDE_USERS", "root").split(",") if u.strip()}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ip-limiter] %(levelname)s: %(message)s", stream=sys.stdout)
log = logging.getLogger("ip_limiter")

_seen_since: dict[tuple[str, str], float] = {}

def setup_firewall_cooldown():
    try:
        subprocess.run(["ipset", "create", "ssh_penalty", "hash:ip", "timeout", "10"], stderr=subprocess.DEVNULL)
        check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "ssh_penalty", "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
        if check.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "ssh_penalty", "src", "-j", "DROP"])
    except Exception: pass

def apply_cooldown(ip: str):
    try: subprocess.run(["ipset", "add", "ssh_penalty", ip, "timeout", "10"], stderr=subprocess.DEVNULL)
    except Exception: pass

def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return out.stdout or ""
    except Exception: return ""

def _read_limit(username: str) -> int | None:
    path = os.path.join(USER_LIMITS_DIR, username)
    try:
        with open(path, "r") as f:
            val = int(f.read().strip())
            return val if val > 0 else None
    except Exception: return None

def _pid_to_user_map() -> dict[int, str]:
    out = _run(["ps", "-ewwo", "pid=,euser=,args="])
    mapping = {}
    for line in out.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) >= 2:
            pid_s, user = parts[0], parts[1]
            m_sshd = re.search(r'sshd:\s*([a-zA-Z0-9_-]+)', line)
            if m_sshd:
                ext_u = m_sshd.group(1)
                if ext_u.lower() not in ('root', 'sshd'): user = ext_u
            try: mapping[int(pid_s)] = user
            except ValueError: continue
    return mapping

def _tick():
    now = time.monotonic()
    port_filter = " or ".join(f"sport = :{p}" for p in SSH_PORTS)
    out = _run(["ss", "-H", "-t", "-n", "-p", "state", "established", f"( {port_filter} )"])
    if not out.strip(): return
    
    pid_user = _pid_to_user_map()
    by_user: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    live_pairs = set()

    for line in out.splitlines():
        ip_ports = re.findall(r'(?:\[[a-fA-F0-9:]+\]|\d{1,3}(?:\.\d{1,3}){3}):\d+', line)
        if len(ip_ports) < 2: continue
        peer_ip = ip_ports[-1].rsplit(':', 1)[0].strip('[]')
        if peer_ip in ("127.0.0.1", "::1", "localhost"): continue

        pids = re.findall(r'pid=(\d+)', line)
        if not pids: continue
        user_found, user_pids = None, []
        for p_str in pids:
            try: p_int = int(p_str)
            except ValueError: continue
            u = pid_user.get(p_int)
            if u and u.lower() not in EXCLUDE_USERS and u.lower() != "root":
                user_found = u.lower()
                user_pids.append(p_int)

        if user_found:
            by_user[user_found][peer_ip].extend(user_pids)
            live_pairs.add((user_found, peer_ip))

    for username, ip_map in by_user.items():
        limit = _read_limit(username)
        if limit is None: continue
        unique_ips = list(ip_map.keys())
        if len(unique_ips) <= limit: continue

        unique_ips.sort(key=lambda ip: _seen_since.get((username, ip), now))
        excess = len(unique_ips) - limit
        for ip in unique_ips[:excess]:
            log.warning("✂️ ⏱️ کاربر «%s» قطع و 10 ثانیه جریمه شد. IP: %s", username, ip)
            apply_cooldown(ip)
            for pid in ip_map[ip]:
                try: os.kill(pid, signal.SIGKILL)
                except Exception: pass
            _seen_since.pop((username, ip), None)

    for key in list(_seen_since.keys()):
        if key not in live_pairs:
            _seen_since.pop(key, None)

def main():
    log.info("🚀 لیمیتر قدرتمند SSH استارت شد.")
    if os.geteuid() != 0: sys.exit(1)
    setup_firewall_cooldown()
    while True:
        try: _tick()
        except Exception: pass
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
EOF

chmod +x /root/ip_limiter.py
cat << 'EOF' > /etc/systemd/system/ssh-limiter.service
[Unit]
Description=Smart SSH IP Limiter (NVL)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/ip_limiter.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-limiter.service >/dev/null 2>&1
echo "   ✅ لیمیتر پیشرفته با موفقیت روشن شد."

echo ""
echo "════════════════════════════════════════════════════════════"
# Cutover completion is not merely successful dependency installation.
echo "🔹 ۱۷) شروع ربات و تأیید اجرای واقعی روی Core جدید..."
systemctl enable --now nvlbot
sleep 5
systemctl is-active --quiet nvlbot ||
    { echo "❌ nvlbot روی Core جدید پایدار نشد."; journalctl -u nvlbot -n 30 --no-pager; exit 1; }
test -s "$BOT_DIR/master_bot.db" || { echo "❌ دیتابیس روی Core جدید پیدا نشد."; exit 1; }
if [ "$(sqlite3 -readonly "$BOT_DIR/master_bot.db" 'PRAGMA quick_check;' 2>/dev/null)" != "ok" ]; then
    echo "❌ دیتابیس انتقال‌یافته از نظر SQLite سالم نیست."
    exit 1
fi
# Demote runs next on the original Core and needs this management listener.
if ! ss -H -lnt | awk '$4 ~ /:22$/ {found=1} END {exit !found}'; then
    echo "❌ پورت مدیریتی ۲۲ روی Core جدید LISTEN نیست؛ Demote امن نیست."
    exit 1
fi
if [ "$(wg show wg0 public-key 2>/dev/null)" != "$(wg pubkey < "${MIGRATION_DIR}/core_private.key")" ]; then
    echo "❌ هویت WireGuard Core جدید مطابق کلید مهاجرت نیست."
    exit 1
fi
echo "PROMOTE_POSTCHECK_OK: bot, SQLite, Core WG identity and SSH management:22"

PROMOTE_SUCCESS=1
echo "✅ ترفیع این سرور به Core کامل شد. دیتابیس و سرویس ربات بررسی شدند."
echo "════════════════════════════════════════════════════════════"
