#!/usr/bin/env python3
"""
02_recreate_ssh_users.py
=========================
این سرور جدیده و یوزرهای لینوکسیِ اکانت‌های SSH (که با useradd روی سرور قبلی
ساخته شده بودن) طبیعتاً منتقل نشدن - چون بکاپ فقط شاملِ /etc/passwd بود، نه
/etc/shadow (پسوردها). خوشبختانه پسورد هر اکانت به‌صورت متن ساده تو خودِ
master_bot.db (جدول ssh_accounts) ذخیره شده، پس این اسکریپت دقیقاً همون کاری
که خودِ ربات موقع ساخت اکانت انجام می‌ده رو برای همهٔ اکانت‌های موجود تو
دیتابیس تکرار می‌کنه:

    useradd -s /bin/false -e <expire_date> <username>
    echo "<username>:<password>" | chpasswd

فقط اکانت‌هایی که از قبل روی این سرور وجود ندارن ساخته می‌شن (امن برای اجرای
چندباره - اگه یه بار اجرا کردی و بعد اکانت جدید اضافه شد به دیتابیس، دوباره
اجراش کن، فقط جدیدها اضافه می‌شن).

اجرا (روی خودِ سرور، به‌عنوان root):
    python3 02_recreate_ssh_users.py
    python3 02_recreate_ssh_users.py --dry-run     # فقط نشون بده چیکار می‌کنه، چیزی نسازه
"""
import sqlite3
import subprocess
import sys
import argparse
import os

# 🐛🔧 رفع ناسازگاریِ واقعی: این مسیر قبلاً همیشه هارد-کد به «/root/master_bot.db» بود، در
# حالی‌که promote_edge_to_core.sh صراحتاً هشدار می‌دهد اگر ربات با WorkingDirectory/BOT_DB_PATH
# متفاوتی اجرا می‌شود، باید BOT_DIR_OVERRIDE ست شود — ولی این اسکریپت هیچ‌وقت به آن متغیر توجه
# نمی‌کرد، پس حتی وقتی BOT_DIR_OVERRIDE درست ست می‌شد، این اسکریپت همچنان می‌رفت سراغ «/root»
# و اگر دیتابیسِ واقعی جای دیگری بود، یا اکانتی پیدا نمی‌کرد یا (بدتر) یک master_bot.db خالیِ
# تازه در «/root» می‌ساخت. الان دقیقاً همان دو متغیرِ محیطی که بقیهٔ ناوگان (bot_final.py،
# promote_edge_to_core.sh) استفاده می‌کنند اینجا هم رعایت می‌شود.
DB_PATH = os.environ.get("BOT_DB_PATH") or os.path.join(os.environ.get("BOT_DIR_OVERRIDE", "/root"), "master_bot.db")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def user_exists(username):
    result = run(["id", username])
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="فقط نمایش، بدون ساخت واقعی")
    parser.add_argument("--include-inactive", action="store_true",
                         help="اکانت‌های غیرفعال رو هم بساز (پیش‌فرض: فقط فعال‌ها)")
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if args.include_inactive:
        cur.execute("SELECT username, password, expire_date, status FROM ssh_accounts")
    else:
        cur.execute("SELECT username, password, expire_date, status FROM ssh_accounts WHERE status LIKE '%فعال%' AND status NOT LIKE '%غیر%'")

    rows = cur.fetchall()
    conn.close()

    print(f"📋 {len(rows)} اکانت برای بازسازی پیدا شد.\n")

    created, synced, failed = 0, 0, 0

    for username, password, expire_date, status in rows:
        exists = user_exists(username)

        # 🐛🔧 رفع باگِ واقعی: قبلاً وقتی یوزر از قبل وجود داشت، اسکریپت کاملاً «رد» می‌شد و
        # هیچ‌وقت پسورد رو با دیتابیس sync نمی‌کرد — یعنی اگه پسوردِ یه اکانت تو ربات عوض
        # می‌شد (یا اکانت از یه منبعِ دیگه/مهاجرتِ قبلی با پسوردِ متفاوت روی این سرور ساخته
        # شده بود)، پسوردِ واقعیِ سیستم برای همیشه با دیتابیس ناهماهنگ می‌موند و مشتری با
        # لینکِ جدید هم «Password authentication failed» می‌گرفت. الان چکِ وجودِ یوزر فقط
        # تصمیمِ *ساختن* (useradd) رو کنترل می‌کنه، نه sync‌کردنِ پسورد رو.
        if args.dry_run:
            if exists:
                print(f"  🔍 [dry-run] پسورد/انقضا sync می‌شد: {username}")
            else:
                print(f"  🔍 [dry-run] ساخته می‌شد: {username} (انقضا: {expire_date})")
            created += 1
            continue

        if not exists:
            r1 = run(["useradd", "-s", "/bin/false", "-e", expire_date, username])
            if r1.returncode != 0:
                print(f"  ❌ {username} - خطا در useradd: {r1.stderr.strip()}")
                failed += 1
                continue
        else:
            r1 = run(["usermod", "-e", expire_date, username])
            if r1.returncode != 0:
                print(f"  ⚠️  {username} - آپدیتِ تاریخِ انقضا شکست خورد: {r1.stderr.strip()}")

        proc = subprocess.run(["chpasswd"], input=f"{username}:{password}",
                               capture_output=True, text=True)
        if proc.returncode != 0:
            verb = "پسورد ست نشد" if not exists else "پسورد sync نشد"
            print(f"  ⚠️  {username} - {'یوزر ساخته شد ولی ' if not exists else ''}{verb}: {proc.stderr.strip()}")
            failed += 1
            continue

        if exists:
            print(f"  🔄 {username} پسورد/انقضا sync شد.")
            synced += 1
        else:
            print(f"  ✅ {username} ساخته شد (انقضا: {expire_date})")
            created += 1

    print(f"\n=== خلاصه: {created} ساخته شد، {synced} sync شد (از قبل بود)، {failed} خطا ===")
    if not args.dry_run:
        print("\nبرای تست یه اکانت رو با ssh وصل شو و مطمئن شو لاگین کار می‌کنه.")


# 🐛🔧 رفع باگِ واقعی: قبلاً اینجا نوشته شده بود «if name == "main":» — چون نه «name» و
# نه «main» هیچ‌جای این فایل تعریف نشده بودن، خودِ پایتون همین‌جا با NameError کرش می‌کرد
# و کل اسکریپت، حتی یک‌بار هم، هیچ‌وقت واقعاً اجرا نمی‌شد.
if __name__ == "__main__":
    if sys.platform != "linux":
        print("این اسکریپت فقط روی لینوکس اجرا می‌شه.")
        sys.exit(1)
    main()