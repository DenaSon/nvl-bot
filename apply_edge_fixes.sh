#!/bin/bash
# apply_edge_fixes.sh — فیکس‌های سطح سیستم که باید روی هر سرور (Edge یا Core) باشند؛
# idempotent — هر بار اجرا فقط چیزی را که هنوز اعمال نشده اضافه می‌کند.
set -uo pipefail
CHANGED=0

# --- فیکس ۱: badvpn-udpgw-legacy روی 127.0.0.1:1234 برای کلاینت‌های قدیمی ---
if ! systemctl is-enabled --quiet badvpn-udpgw-legacy 2>/dev/null; then
    BADVPN_BIN=""
    if systemctl list-unit-files badvpn-udpgw.service >/dev/null 2>&1; then
        BADVPN_BIN=$(systemctl show badvpn-udpgw -p ExecStart 2>/dev/null | grep -oE '/[^ ]*badvpn-udpgw' | head -n1)
    fi
    [ -z "$BADVPN_BIN" ] && [ -x /usr/local/bin/badvpn-udpgw ] && BADVPN_BIN=/usr/local/bin/badvpn-udpgw
    if [ -z "$BADVPN_BIN" ] && [ -f /root/badvpn-udpgw-built ]; then
        cp /root/badvpn-udpgw-built /usr/local/bin/badvpn-udpgw
        chmod +x /usr/local/bin/badvpn-udpgw
        BADVPN_BIN=/usr/local/bin/badvpn-udpgw
        echo "باینریِ badvpn-udpgw از نسخهٔ ارسالی نصب شد."
        CHANGED=1
    fi
    if [ -n "$BADVPN_BIN" ] && [ -x "$BADVPN_BIN" ]; then
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
        systemctl enable --now badvpn-udpgw-legacy >/dev/null 2>&1
        echo "badvpn-udpgw-legacy فعال شد."
        CHANGED=1
    else
        echo "باینری badvpn-udpgw پیدا نشد -- رد شد."
    fi
fi

# --- فیکس ۲: کاهش فشار RAM (PAM session tracking خاموش + rate-limit منطقی journald) ---
if grep -q "pam_systemd\.so" /etc/pam.d/common-session 2>/dev/null; then
    cp /etc/pam.d/common-session "/etc/pam.d/common-session.bak.$(date +%s)"
    sed -i '/pam_systemd\.so/d' /etc/pam.d/common-session
    echo "pam_systemd.so از common-session حذف شد."
    CHANGED=1
fi

JOURNALD_DROPIN=/etc/systemd/journald.conf.d/ratelimit.conf
if [ ! -f "$JOURNALD_DROPIN" ] || ! grep -q "RateLimitBurst=1000" "$JOURNALD_DROPIN"; then
    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nRateLimitIntervalSec=30s\nRateLimitBurst=1000\n' > "$JOURNALD_DROPIN"
    systemctl restart systemd-journald 2>/dev/null || true
    echo "journald rate-limit روی 1000 تنظیم شد."
    CHANGED=1
fi

# 🐛🔧 رفع باگِ واقعیِ «exit 0 وسط فایل»: قبلاً همین‌جا اسکریپت کامل خارج می‌شد و فیکس‌های
# ۳، ۴ و ۵ (از جمله تنظیمِ حیاتیِ ssh.socket روی پورت ۲۲۵۲) هیچ‌وقت اجرا نمی‌شدند — بدون
# هیچ خطای قابل‌مشاهده‌ای؛ اسکریپت موفق‌آمیز به نظر می‌رسید ولی نصفه‌کاره بود.

# --- فیکس ۳: MaxStartups باز، تا اتصال‌های هم‌زمانِ زیاد (موبایل‌نت) رد نشن ---
if ! grep -q "^MaxStartups 2048:30:4096$" /etc/ssh/sshd_config 2>/dev/null; then
    sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
    echo "MaxStartups 2048:30:4096" >> /etc/ssh/sshd_config
    if sshd -t; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        echo "MaxStartups روی 2048:30:4096 تنظیم شد."
        CHANGED=1
    fi
fi

# --- فیکس ۳: تضمین دائمیِ مجوز اجرایی و سلامتِ سرویس اصلیِ badvpn-udpgw ---
if [ -f /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/local/bin/badvpn-udpgw ]; then
    chmod 755 /usr/local/bin/badvpn-udpgw
    echo "مجوز اجرایی badvpn-udpgw اصلاح شد."
    CHANGED=1
fi
if systemctl list-unit-files badvpn-udpgw.service >/dev/null 2>&1 && ! systemctl is-active --quiet badvpn-udpgw; then
    systemctl restart badvpn-udpgw
    sleep 1
    if systemctl is-active --quiet badvpn-udpgw; then
        echo "سرویس badvpn-udpgw ری‌استارت و سالم شد."
    else
        echo "⚠️ badvpn-udpgw بعد از ری‌استارت هم بالا نیامد — دستی چک شود."
    fi
    CHANGED=1
fi

# --- فیکس ۴: تضمین دائمیِ گوش‌دادنِ sshd روی پورتِ ۲۲۵۲ (علاوه بر ۲۲) ---
SSH_SOCKET_OVERRIDE=/etc/systemd/system/ssh.socket.d/override.conf
if ! grep -q "2252" "$SSH_SOCKET_OVERRIDE" 2>/dev/null; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > "$SSH_SOCKET_OVERRIDE" << 'EOF'
[Socket]
ListenStream=
ListenStream=0.0.0.0:22
ListenStream=[::]:22
ListenStream=0.0.0.0:2252
ListenStream=[::]:2252
EOF
    systemctl daemon-reload
    systemctl restart ssh.socket
    echo "ssh.socket برای گوش‌دادن روی پورت 2252 هم تنظیم شد."
    CHANGED=1
fi

# --- فیکس ۵: محدودکردنِ پورتِ ۲۲ فقط به کاربرِ root (مشتری‌ها فیزیکاً نمی‌توانند از آن استفاده کنند) ---
DROPIN_P22=/etc/ssh/sshd_config.d/99-nvlbot-port22-root-only.conf
if [ ! -f "$DROPIN_P22" ]; then
    while true; do
        RULE=$(iptables -S INPUT 2>/dev/null | grep -- "--dport 22\b" | head -1 || true)
        [ -z "$RULE" ] && break
        iptables $(echo "$RULE" | sed 's/^-A/-D/') 2>/dev/null || break
    done
    iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    cat > "$DROPIN_P22" << 'EOF'
Match LocalPort 22
    AllowUsers root
Match all
EOF
    if sshd -t; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        echo "محدودیتِ پورتِ ۲۲ (فقط root) اعمال شد."
        CHANGED=1
    else
        echo "⚠️ کانفیگِ sshd نامعتبر بود -- فیکسِ پورتِ ۲۲ اعمال نشد."
        rm -f "$DROPIN_P22"
    fi
fi

[ "$CHANGED" -eq 0 ] && echo "همه‌چیز از قبل اعمال شده بود."
exit 0