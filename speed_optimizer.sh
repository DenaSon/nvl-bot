#!/bin/bash
# ============================================================================
# اسکریپت هوشمند بهینه‌سازی سرعت SSH (نسخه مستقیم - بدون تونل)
# ============================================================================

set -euo pipefail

# دریافت حالت از ربات (پیش‌فرض apply است)
MODE="${1:-apply}"

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا شود."
    exit 1
fi

# ---------------------------------------------------------
# بخش بازگردانی (Rollback)
# ---------------------------------------------------------
if [ "$MODE" = "rollback" ]; then
    echo "🔙 در حال لغو تنظیمات بهینه‌سازی و بازگردانی به حالت پیش‌فرض..."
    
    # بازگردانی BBR به الگوریتم استاندارد لینوکس (cubic/pfifo_fast)
    sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf 2>/dev/null || true
    
    # اگر قبلاً اضافه نشده بودند، مقادیر استاندارد را جایگزین می‌کنیم
    if ! grep -q "net.ipv4.tcp_congestion_control=cubic" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=pfifo_fast" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=cubic" >> /etc/sysctl.conf
    fi
    
    # حذف بافرهای شبکه
    rm -f /etc/sysctl.d/99-vpn-optimize.conf
    sysctl --system >/dev/null 2>&1
    
    echo "✅ تنظیمات با موفقیت به حالت پیش‌فرض کارخانه بازگشت."
    exit 0
fi

# ---------------------------------------------------------
# بخش اعمال بهینه‌سازی (Apply)
# ---------------------------------------------------------
echo "🚀 شروع فرآیند بهینه‌سازی شبکه (مخصوص اتصال مستقیم)..."

# ۱) BBR
echo "🔹 ۱) بررسی و فعال‌سازی الگوریتم BBR..."
modprobe tcp_bbr 2>/dev/null || true
if ! sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then
    echo "   ⚠️ ماژول BBR روی این کرنل در دسترس نیست."
elif ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null
    echo "   ✅ BBR با موفقیت فعال شد."
else
    echo "   ✅ BBR از قبل فعال است."
fi

# ۲) TCP Buffers & MTU Probing
echo "🔹 ۲) تنظیم پارامترهای Sysctl برای ترافیک بالا..."
cat <<EOF > /etc/sysctl.d/99-vpn-optimize.conf
# بهینه‌سازی بافرهای TCP برای سرعت‌های بالا
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
# عبور از فیلترینگ با تغییر خودکار سایز بسته‌ها
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
EOF
sysctl --system >/dev/null
echo "   ✅ پارامترهای هسته به‌روزرسانی شدند."

echo "✅ تمام بهینه‌سازی‌ها با موفقیت اعمال شد. سرعت کلاینت‌ها بهبود خواهد یافت."