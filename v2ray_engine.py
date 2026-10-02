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
_MARZBAN_AUTH_ERRORS = {}


def normalize_marzban_base_url(url):
    """Normalize the configured Marzban base URL without swallowing real subpaths.

    Operators commonly paste https://host/api from API docs. NVL appends /api/*
    endpoints itself, so strip only a terminal /api to avoid /api/api/... requests.
    """
    base = (url or "").strip().rstrip("/")
    if base.lower().endswith("/api"):
        base = base[:-4].rstrip("/")
    return base


def _token_cache_key(url, user):
    return (normalize_marzban_base_url(url), (user or "").strip())


def _auth_error_key(url, user):
    return _token_cache_key(url, user)


def _set_auth_error(url, user, message):
    _MARZBAN_AUTH_ERRORS[_auth_error_key(url, user)] = str(message or "unknown auth error")


def get_last_auth_error(url, user):
    return _MARZBAN_AUTH_ERRORS.get(_auth_error_key(url, user))


def _format_auth_failure(status, payload):
    detail = payload
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or payload
    text = str(detail or "").strip().replace("\n", " ")
    if len(text) > 240:
        text = text[:237] + "..."
    if status == 401:
        return f"HTTP 401: {text or 'incorrect username or password'}"
    if status == 403:
        return f"HTTP 403: {text or 'access forbidden'}"
    if status == 404:
        return "HTTP 404: auth endpoint not found (check MARZBAN_URL; use the panel base URL, not a URL ending in /api/admin/token)"
    return f"HTTP {status}: {text or 'unexpected authentication response'}"


def clear_token_cache(url=None, user=None):
    """Clear one backend/admin token or the complete token cache."""
    if url is None and user is None:
        _MARZBAN_TOKEN_CACHE.clear()
        _MARZBAN_AUTH_ERRORS.clear()
        return
    key = _token_cache_key(url, user)
    _MARZBAN_TOKEN_CACHE.pop(key, None)
    _MARZBAN_AUTH_ERRORS.pop(key, None)


async def get_token(url, user, pwd, force_refresh=False):
    key = _token_cache_key(url, user)
    now = time.time()

    if not key[0]:
        _set_auth_error(url, user, "configuration error: MARZBAN_URL is empty")
        return None
    if not key[1]:
        _set_auth_error(url, user, "configuration error: MARZBAN_USERNAME is empty")
        return None
    if not pwd:
        _set_auth_error(url, user, "configuration error: MARZBAN_PASSWORD is empty")
        return None

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
                data={
                    "username": key[1],
                    "password": pwd,
                    "grant_type": "password",
                    "scope": "",
                    "client_id": "",
                    "client_secret": "",
                },
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=10,
            ) as resp:
                payload = await _response_payload(resp)
                if resp.status == 200:
                    if not isinstance(payload, dict):
                        _set_auth_error(url, user, "HTTP 200 but Marzban returned a non-JSON token response")
                        return None
                    token = payload.get("access_token")
                    if token:
                        _MARZBAN_TOKEN_CACHE[key] = (token, now + 1800)
                        _MARZBAN_AUTH_ERRORS.pop(key, None)
                        return token
                    _set_auth_error(url, user, "HTTP 200 but access_token is missing")
                    return None

                auth_error = _format_auth_failure(resp.status, payload)
                _set_auth_error(url, user, auth_error)
                log.warning("Marzban Auth Failed: base_url=%s user=%s error=%s", key[0], key[1], auth_error)
                return None
    except Exception as e:
        auth_error = f"network error: {type(e).__name__}: {e}"
        _set_auth_error(url, user, auth_error)
        log.error("Marzban Auth Error: base_url=%s user=%s error=%s", key[0], key[1], auth_error)
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
    base_url = normalize_marzban_base_url(url)
    full_url = f"{base_url}{endpoint}"

    try:
        async with aiohttp.ClientSession() as session:
            for attempt in range(2):
                token = await get_token(url, user, pwd, force_refresh=(attempt == 1))
                if not token:
                    detail = get_last_auth_error(url, user) or "unknown authentication error"
                    return False, f"Marzban Auth Failed — {detail}"

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