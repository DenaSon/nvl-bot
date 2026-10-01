import aiohttp
import qrcode
import io
import time
import logging
import json

log = logging.getLogger("V2RayEngine")

# Tokens are cached per Marzban backend/admin identity.  The previous single
# process-global token was unsafe as soon as NVL talked to more than one
# Marzban backend or admin account.
_MARZBAN_TOKEN_CACHE = {}


def _token_cache_key(url, user):
    return ((url or "").strip().rstrip("/"), (user or "").strip())


def clear_token_cache(url=None, user=None):
    """Clear one backend/admin token or the complete token cache."""
    if url is None and user is None:
        _MARZBAN_TOKEN_CACHE.clear()
        return
    _MARZBAN_TOKEN_CACHE.pop(_token_cache_key(url, user), None)


async def get_token(url, user, pwd, force_refresh=False):
    key = _token_cache_key(url, user)
    now = time.time()

    if force_refresh:
        _MARZBAN_TOKEN_CACHE.pop(key, None)
    else:
        cached = _MARZBAN_TOKEN_CACHE.get(key)
        if cached and cached[0] and now < cached[1]:
            return cached[0]

    token_url = f"{key[0]}/api/admin/token"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url,
                data={"username": user, "password": pwd, "grant_type": "password"},
                timeout=10,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    token = data.get("access_token")
                    if token:
                        _MARZBAN_TOKEN_CACHE[key] = (token, now + 1800)
                    return token
                return None
    except Exception as e:
        log.error("Marzban Auth Error: %s", e)
        return None


async def _response_payload(resp):
    """Decode JSON when possible and safely handle empty/204 responses."""
    text = await resp.text()
    if not text:
        return {}
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


async def api_request(method, endpoint, url, user, pwd, json_data=None, params=None):
    full_url = f"{(url or '').strip().rstrip('/')}{endpoint}"

    try:
        async with aiohttp.ClientSession() as session:
            for attempt in range(2):
                token = await get_token(url, user, pwd, force_refresh=(attempt == 1))
                if not token:
                    return False, "Marzban Auth Failed"

                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }

                async with session.request(
                    method,
                    full_url,
                    headers=headers,
                    json=json_data,
                    params=params,
                    timeout=15,
                ) as resp:
                    payload = await _response_payload(resp)
                    if 200 <= resp.status < 300:
                        return True, payload
                    if resp.status == 401 and attempt == 0:
                        continue
                    return False, payload

        return False, "Marzban request failed"
    except Exception as e:
        return False, f"Network Error: {e}"

async def create_user(url, admin_user, admin_pwd, username, expire_timestamp, data_limit_bytes, reset_strategy, user_count):
    payload = {
        "username": username,
        "proxies": {
            "vless": {},
            "vmess": {},
            "trojan": {},
            "shadowsocks": {}
        },
        "inbounds": {
            "vless": [
                "VLESS TCP REALITY",
                "VLESS TCP HTTP"
            ],
            "vmess": [
                "VMess WS"
            ],
            "trojan": [
                "Trojan WS"
            ],
            "shadowsocks": [
                "Shadowsocks TCP"
            ]
        },
        "data_limit": int(data_limit_bytes) if data_limit_bytes else 0,
        "data_limit_reset_strategy": reset_strategy,
        "note": f"IP_LIMIT:{user_count}" if user_count else "",
        "status": "active",
        "expire": int(expire_timestamp) if expire_timestamp else 0
    }
    ok, result = await api_request("POST", "/api/user", url, admin_user, admin_pwd, payload)
    if ok:
        sub_url = result.get('subscription_url', '')
        if sub_url.startswith('/'): sub_url = url.rstrip('/') + sub_url
        return True, sub_url
    return False, result

async def get_system_stats(url, admin_user, admin_pwd):
    return await api_request("GET", "/api/system", url, admin_user, admin_pwd)

def generate_qr(text):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf
async def get_user(url, admin_user, admin_pwd, username):
    return await api_request("GET", f"/api/user/{username}", url, admin_user, admin_pwd)

async def modify_user(url, admin_user, admin_pwd, username, **kwargs):
    return await api_request("PUT", f"/api/user/{username}", url, admin_user, admin_pwd, json_data=kwargs)

async def delete_user(url, admin_user, admin_pwd, username):
    return await api_request("DELETE", f"/api/user/{username}", url, admin_user, admin_pwd)

async def get_online_users_count(url, username, password, local_usernames=None):
    """
    با استفاده از API مرزبان، تعداد کاربرانی که در ۵ دقیقه اخیر متصل بوده‌اند را استخراج و می‌شمارد.
    """
    import aiohttp
    from datetime import datetime, timezone

    try:
        token = await get_token(url, username, password)
        if not token:
            return False, 0
            
        headers = {
            "Authorization": f"Bearer {token}",
            "accept": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            # ارسال پارامتر limit=100000 تا تمام کاربران سرور در یک درخواست دریافت شوند (جلوگیری از جا افتادن صفحات)
            async with session.get(f"{url}/api/users", headers=headers, params={"limit": 100000}, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # هندل کردن هوشمندِ ساختار خروجی مرزبان (اگر دیکشنری بود یا لیست مستقیم)
                    if isinstance(data, dict) and 'users' in data:
                        user_list = data['users']
                    elif isinstance(data, list):
                        user_list = data
                    else:
                        user_list = []
                        
                    online_count = 0
                    now = datetime.now(timezone.utc)
                    
                    for u in user_list:
                        u_name = u.get('username')
                        # اگر لیست یوزرهای محلی داده شده بود و این یوزر توش نبود، نادیده بگیر
                        if local_usernames is not None and u_name not in local_usernames:
                            continue
                            
                        if isinstance(u, dict) and u.get('status') == 'active':
                            online_at_str = u.get('online_at')
                            if online_at_str:
                                try:
                                    # جداسازی امن زمان: حذف میکروثانیه‌ها و فرمت‌بندی دستی که روی همهٔ نسخه‌های پایتون کار می‌کند
                                    base_time = online_at_str.split('.')[0].replace('Z', '')
                                    online_at = datetime.strptime(base_time, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                                    
                                    # اگر از آخرین اتصال کمتر از 300 ثانیه (5 دقیقه) گذشته باشد، آنلاین محسوب می‌شود
                                    if (now - online_at).total_seconds() <= 300:
                                        online_count += 1
                                except Exception:
                                    pass
                    return True, online_count
        return False, 0
    except Exception as e:
        import logging
        logging.error(f"خطا در دریافت کاربران آنلاین مرزبان: {e}")
        return False, 0