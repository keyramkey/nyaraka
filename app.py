import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import unicodedata
from functools import wraps
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, Response, abort, g, jsonify, request, send_from_directory

try:  # Web Push (pywebpush). App still boots without it; push features just report "not ready".
    from pywebpush import webpush, WebPushException
except Exception:  # pragma: no cover
    webpush = None
    WebPushException = Exception

# static_folder=None: Flask isn't allowed to serve the whole project folder
# (app.py, .env, *.sql would otherwise be downloadable). See static_files() below.
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024  # reject huge request bodies


def _load_local_env():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


_load_local_env()

def _resolve_session_secret() -> str:
    explicit = os.environ.get('SESSION_SECRET', '').strip()
    if explicit:
        if len(explicit) < 32:
            print('[SECURITY] SESSION_SECRET ni fupi. Tumia angalau herufi 32: python -c "import secrets; print(secrets.token_hex(32))"', flush=True)
        return explicit
    # Never derive the secret from the file path (it is guessable). Use a real secret instead.
    seed = (
        os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '').strip()
        or os.environ.get('DALIPAY_SECRET_KEY', '').strip()
        or os.environ.get('SUPABASE_SECRET_KEY', '').strip()
    )
    if seed:
        print('[SECURITY] SESSION_SECRET haijawekwa. Weka SESSION_SECRET yako mwenyewe kwenye Environment Variables.', flush=True)
        return hashlib.sha256(f'malimi:{seed}'.encode('utf-8')).hexdigest()
    print('[SECURITY] SESSION_SECRET haijawekwa. Secret ya muda imetengenezwa; session zitafutika seva ikizimwa.', flush=True)
    return secrets.token_hex(32)


SESSION_SECRET = _resolve_session_secret()
DEVICE_COOKIE_NAME = 'tra_device_token'
SESSION_COOKIE_NAME = 'malimi_session'
try:
    _session_days = max(1, min(365, int(os.environ.get('SESSION_MAX_AGE_DAYS', '30'))))
except ValueError:
    _session_days = 30
SESSION_MAX_AGE_SEC = 60 * 60 * 24 * _session_days
GENERATION_COIN_COST = 1
FREE_SIGNUP_COINS = 5

PACKAGES = {
    'coins_22': {'id': 'coins_22', 'label': '22 Coins', 'amountTzs': 2000, 'coins': 22, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_55': {'id': 'coins_55', 'label': '55 Coins', 'amountTzs': 5000, 'coins': 55, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_100': {'id': 'coins_100', 'label': '100 Coins', 'amountTzs': 9000, 'coins': 100, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_230': {'id': 'coins_230', 'label': '230 Coins', 'amountTzs': 20000, 'coins': 230, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_600': {'id': 'coins_600', 'label': '600 Coins', 'amountTzs': 50000, 'coins': 600, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_1200': {'id': 'coins_1200', 'label': '1,200 Coins', 'amountTzs': 100000, 'coins': 1200, 'unlimitedDays': 0, 'category': 'coins'},
    'unlimited_30d': {
        'id': 'unlimited_30d',
        'label': 'Unlimited (1 Month / 30 Days)',
        'amountTzs': 30000,
        'coins': 0,
        'unlimitedDays': 30,
        'category': 'unlimited',
    },
    'unlimited_55d': {
        'id': 'unlimited_55d',
        'label': 'Unlimited (55 Days)',
        'amountTzs': 50000,
        'coins': 0,
        'unlimitedDays': 55,
        'category': 'unlimited',
    },
}


def get_supabase_config():
    url = os.environ.get('SUPABASE_URL', '').strip().rstrip('/')
    if url and not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    if url.endswith('/rest/v1'):
        url = url[:-8]
    key = (
        os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '').strip()
        or os.environ.get('SUPABASE_SECRET_KEY', '').strip()
    )
    if not url or not key:
        raise RuntimeError('SUPABASE_URL na SUPABASE_SERVICE_ROLE_KEY hazijawekwa kwenye Environment Variables.')
    return url, key


def sb_headers(service_key: str, prefer: str = 'return=representation'):
    headers = {
        'apikey': service_key,
        'Content-Type': 'application/json',
        'Prefer': prefer,
    }
    # Legacy JWT service_role keys require Bearer; new sb_secret_ keys are opaque and fail if sent as Bearer JWT
    if service_key.startswith('eyJ'):
        headers['Authorization'] = f'Bearer {service_key}'
    return headers


def _extract_sb_error(resp: requests.Response) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            msg = body.get('message') or body.get('error_description') or body.get('error') or ''
            hint = body.get('hint') or ''
            return f'{msg} ({hint})'.strip() if hint else str(msg)
    except Exception:
        pass
    return resp.text[:200] if resp.text else f'HTTP {resp.status_code}'


def sb_select(table: str, params: dict):
    url, key = get_supabase_config()
    resp = requests.get(f'{url}/rest/v1/{table}', headers=sb_headers(key), params=params, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase select {table} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)
    return resp.json()


def sb_insert(table: str, payload: dict):
    url, key = get_supabase_config()
    resp = requests.post(f'{url}/rest/v1/{table}', headers=sb_headers(key), json=payload, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase insert {table} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)
    rows = resp.json()
    return rows[0] if isinstance(rows, list) and rows else rows


def sb_update(table: str, params: dict, payload: dict):
    url, key = get_supabase_config()
    resp = requests.patch(f'{url}/rest/v1/{table}', headers=sb_headers(key), params=params, json=payload, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase update {table} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)
    return resp.json()


def sb_rpc(fn_name: str, payload: dict):
    url, key = get_supabase_config()
    resp = requests.post(f'{url}/rest/v1/rpc/{fn_name}', headers=sb_headers(key), json=payload, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase RPC {fn_name} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)
    return resp.json()


def now_ms():
    return int(time.time() * 1000)


# ----------------------------------------------------------------------------
# Security helpers
# ----------------------------------------------------------------------------
VERBOSE_ERRORS = os.environ.get('VERBOSE_ERRORS', '').strip() == '1'  # dev only
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128  # stops huge passwords being used to burn CPU in scrypt
LOGIN_WINDOW_SEC = 15 * 60
LOGIN_MAX_FAILS_PER_EMAIL = 5
LOGIN_MAX_FAILS_PER_IP = 20
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')

# In-memory rate limiter. Per server instance only: on serverless/multi-instance
# hosting it slows attackers down but is not a hard global limit.
_rl_lock = threading.Lock()
_rl_hits = {}


def rl_count(key: str, window_sec: int) -> int:
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl_hits.get(key, []) if now - t < window_sec]
        if hits:
            _rl_hits[key] = hits
        else:
            _rl_hits.pop(key, None)
        return len(hits)


def rl_record(key: str):
    now = time.time()
    with _rl_lock:
        _rl_hits.setdefault(key, []).append(now)
        if len(_rl_hits) > 20000:
            cutoff = now - 3600
            for k in [k for k, v in _rl_hits.items() if not v or v[-1] < cutoff]:
                _rl_hits.pop(k, None)


def rl_reset(key: str):
    with _rl_lock:
        _rl_hits.pop(key, None)


def rate_limited(key: str, limit: int, window_sec: int) -> bool:
    """True if the limit is already reached; otherwise records this request."""
    if rl_count(key, window_sec) >= limit:
        return True
    rl_record(key)
    return False


def client_ip() -> str:
    fwd = request.headers.get('X-Forwarded-For', '')
    ip = fwd.split(',')[0].strip() if fwd else (request.remote_addr or '')
    return (ip or 'unknown')[:64]


def get_json_dict() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def clean_text(raw, max_len: int) -> str:
    text = ''.join(ch for ch in str(raw or '') if ch.isprintable())
    return text.strip()[:max_len]


def service_unavailable(err=None):
    if err is not None:
        print(f'[Service Unavailable] {err}', flush=True)
    return jsonify({'error': 'Huduma haipatikani kwa sasa. Tafadhali jaribu tena baadaye.'}), 503


def too_many_requests(message: str = 'Maombi mengi mno. Tafadhali subiri kidogo kisha ujaribu tena.'):
    return jsonify({'error': message}), 429


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.scrypt(password.encode('utf-8'), salt=salt.encode('utf-8'), n=16384, r=8, p=1, dklen=64)
    return f'{salt}:{derived.hex()}'


def verify_password(password: str, stored: str) -> bool:
    parts = stored.split(':')
    if len(parts) != 2:
        return False
    salt, original_hex = parts
    derived = hashlib.scrypt(password.encode('utf-8'), salt=salt.encode('utf-8'), n=16384, r=8, p=1, dklen=64)
    try:
        original = bytes.fromhex(original_hex)
    except ValueError:
        return False
    return hmac.compare_digest(derived, original)


# Used so that login takes the same time whether or not the email exists.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(8))


def sign_token(user_id: int, sid: str = '') -> str:
    claims = {'uid': user_id, 'exp': now_ms() + SESSION_MAX_AGE_SEC * 1000}
    if sid:
        claims['sid'] = sid
    payload_bytes = json.dumps(claims).encode('utf-8')
    payload = base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')
    sig = base64.urlsafe_b64encode(
        hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
    ).decode('ascii').rstrip('=')
    return f'{payload}.{sig}'


def verify_token(token: str):
    res = verify_token_full(token)
    return res[0] if res else None


def verify_token_full(token: str):
    """Returns (user_id, session_id) or None. session_id is '' for tokens issued before one-device login existed."""
    parts = token.split('.')
    if len(parts) != 2:
        return None
    payload, sig = parts
    expected = base64.urlsafe_b64encode(
        hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
    ).decode('ascii').rstrip('=')
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = payload + '=' * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
        uid = data.get('uid')
        exp = data.get('exp', 0)
        if not isinstance(uid, int) or isinstance(uid, bool) or not isinstance(exp, int):
            return None
        # Reject expired tokens and tokens with an expiry longer than we ever issue.
        if exp < now_ms() or exp > now_ms() + SESSION_MAX_AGE_SEC * 1000 + 60000:
            return None
        sid = data.get('sid') or ''
        return uid, (sid if isinstance(sid, str) else '')
    except Exception:
        return None


# ----------------------------------------------------------------------------
# Sessions: one device at a time
# ----------------------------------------------------------------------------
def new_session_id() -> str:
    return secrets.token_hex(16)


def set_user_session(user_id: int, sid: str):
    """The newest login wins: saving a new sid makes every older device's token invalid."""
    sb_update('users', {'id': f'eq.{user_id}'}, {'session_id': sid})


SESSION_REPLACED_MSG = 'Akaunti hii imeingia kwenye kifaa kingine. Kwa usalama, akaunti inatumika kifaa kimoja tu kwa wakati mmoja. Ingia tena kama unataka kuitumia hapa.'


def session_replaced_response():
    return jsonify({'error': SESSION_REPLACED_MSG, 'code': 'session_replaced'}), 401


def generate_initial_password() -> str:
    alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(8))


def find_user_by_identifier(identifier: str):
    identifier = (identifier or '').strip().lower()[:254]
    if not identifier:
        return None
    if '@' in identifier:
        params = {'select': '*', 'email': f'eq.{identifier}', 'limit': '1'}
    else:
        pn = normalize_phone_tz(identifier)
        if not pn:
            return None
        params = {'select': '*', 'phone': f'in.({",".join(phone_variants(pn))})', 'limit': '1'}
    rows = sb_select('users', params)
    return rows[0] if rows else None


_PHONE_CHARS = set('0123456789+ -()')


def find_login_candidates(identifier: str):
    """Login id can be a phone number, an email or the full name. Returns up to 5 matching rows
    (several people can share a name; the password then decides which one it is)."""
    identifier = ' '.join((identifier or '').strip().split())[:254]
    if not identifier:
        return []
    low = identifier.lower()
    if '@' in low:
        return sb_select('users', {'select': '*', 'email': f'eq.{low}', 'limit': '1'})
    if all(ch in _PHONE_CHARS for ch in identifier):
        pn = normalize_phone_tz(identifier)
        if not pn:
            return []
        return sb_select('users', {'select': '*', 'phone': f'in.({",".join(phone_variants(pn))})', 'limit': '1'})
    # name: case-insensitive exact match. Characters that act as wildcards/separators in a
    # PostgREST pattern are matched with eq (case-sensitive) instead of ilike.
    if any(ch in identifier for ch in '%_*\\,()'):
        return sb_select('users', {'select': '*', 'full_name': f'eq.{identifier}', 'limit': '5'})
    return sb_select('users', {'select': '*', 'full_name': f'ilike.{identifier}', 'limit': '5'})


def sanitize_identifier(raw) -> str:
    if not isinstance(raw, str):
        return ''
    return ''.join(ch for ch in raw.strip() if ch.isalnum() or ch in ('_', '-'))[:128]


def _is_https() -> bool:
    return (
        request.is_secure
        or request.headers.get('X-Forwarded-Proto', '') == 'https'
        or os.environ.get('VERCEL') == '1'
    )


def _cookie_attrs() -> str:
    return 'HttpOnly; Secure; SameSite=None; Partitioned' if _is_https() else 'HttpOnly; SameSite=Lax'


def set_device_cookie(response, token: str):
    max_age = 60 * 60 * 24 * 365 * 2
    response.headers.add(
        'Set-Cookie',
        f'{DEVICE_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; {_cookie_attrs()}',
    )


def set_session_cookie(response, token: str):
    response.headers.add(
        'Set-Cookie',
        f'{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_MAX_AGE_SEC}; {_cookie_attrs()}',
    )


def clear_session_cookie(response):
    response.headers.add(
        'Set-Cookie',
        f'{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; {_cookie_attrs()}',
    )


def _allowed_origins() -> set:
    raw = os.environ.get('ALLOWED_ORIGINS', '')
    return {o.strip().rstrip('/').lower() for o in raw.split(',') if o.strip()}


def verify_same_origin():
    host = (request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or '').split(',')[0].strip().lower()
    source = request.headers.get('Origin') or request.headers.get('Referer') or ''
    if not source:
        # Browsers always send Origin on cross-site POSTs; no header = non-browser client.
        return True
    try:
        parsed = urlparse(source)
    except Exception:
        return False
    if f'{parsed.scheme}://{parsed.netloc}'.lower() in _allowed_origins():
        return True
    return bool(host) and parsed.netloc.lower() == host


CSRF_EXEMPT_PATHS = {'/api/payments/dalipay/webhook', '/api/payments/dalipay/callback'}


@app.before_request
def csrf_guard():
    # The session cookie is SameSite=None, so EVERY state-changing API route
    # (not only login/register) must check where the request came from.
    if (
        request.method in ('POST', 'PUT', 'PATCH', 'DELETE')
        and request.path.startswith('/api/')
        and request.path not in CSRF_EXEMPT_PATHS
        and not verify_same_origin()
    ):
        return jsonify({'error': 'Invalid request origin.'}), 403


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    # Set FRAME_ANCESTORS (e.g. "'self' https://your-site.com") if this app must be embedded in an iframe.
    frame_ancestors = os.environ.get('FRAME_ANCESTORS', '').strip() or "'self'"
    resp.headers.setdefault(
        'Content-Security-Policy',
        f"frame-ancestors {frame_ancestors}; base-uri 'self'; object-src 'none'",
    )
    if _is_https():
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    if request.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth[7:].strip() if auth.startswith('Bearer ') else (request.cookies.get(SESSION_COOKIE_NAME, '') or '')
        if not token:
            return jsonify({'error': 'Tafadhali ingia kwenye akaunti yako kwanza.'}), 401
        verified = verify_token_full(token)
        if verified is None:
            return jsonify({'error': 'Session imeisha. Tafadhali ingia tena.'}), 401
        uid, token_sid = verified
        try:
            rows = sb_select('users', {'select': 'id,email,phone,is_blocked,session_id', 'id': f'eq.{uid}', 'limit': '1'})
        except RuntimeError as e:
            return service_unavailable(e)
        if not rows:
            return jsonify({'error': 'Session imeisha. Tafadhali ingia tena.'}), 401
        if rows[0].get('is_blocked'):
            return jsonify({'error': 'Akaunti yako imezuiwa. Tafadhali wasiliana na msaada.'}), 403
        g.is_admin = is_admin_row(rows[0])
        # One device at a time (admins are exempt). Tokens from before this feature carry no sid and
        # stay valid only until the account's next login stores a session id.
        stored_sid = rows[0].get('session_id') or ''
        if not g.is_admin and stored_sid and token_sid != stored_sid:
            return session_replaced_response()
        g.user_id = uid
        return fn(*args, **kwargs)

    return wrapper


def sanitize_user(row: dict):
    unlimited_until = int(row.get('unlimited_until') or 0)
    return {
        'id': int(row['id']),
        'fullName': row['full_name'],
        'email': row.get('email') or '',
        'phone': row.get('phone') or '',
        'coins': int(row.get('coins') or 0),
        'unlimitedUntil': unlimited_until,
        'isUnlimited': unlimited_until > now_ms(),
        'freeBonusGranted': bool(row.get('free_bonus_granted')),
        'isAdmin': is_admin_row(row),
        'isBlocked': bool(row.get('is_blocked')),
        'mustChangePassword': bool(row.get('must_change_password')),
    }


def normalize_phone_tz(raw: str):
    digits = ''.join(ch for ch in raw if ch.isdigit())
    if digits.startswith('255') and len(digits) == 12:
        return digits
    if digits.startswith('0') and len(digits) == 10:
        return '255' + digits[1:]
    if len(digits) == 9 and digits[0] in ('6', '7'):
        return '255' + digits
    return None


def to_local_tz_phone(normalized_phone: str) -> str:
    if normalized_phone.startswith('255') and len(normalized_phone) == 12:
        return '0' + normalized_phone[3:]
    return normalized_phone


VALID_DALIPAY_PROVIDERS = ('Tigo', 'Airtel', 'Halopesa', 'Azampesa', 'Mpesa')


def resolve_dalipay_provider(raw_provider: str, normalized_phone: str) -> str:
    cleaned = (raw_provider or '').strip().lower()
    for p in VALID_DALIPAY_PROVIDERS:
        if p.lower() == cleaned:
            return p
    local = to_local_tz_phone(normalized_phone)
    prefix = local[:3]
    if prefix in ('074', '075', '076', '079'):
        return 'Mpesa'
    if prefix in ('071', '065', '067', '077'):
        return 'Tigo'
    if prefix in ('078', '068', '069'):
        return 'Airtel'
    if prefix in ('061', '062'):
        return 'Halopesa'
    return 'Mpesa'


def resolve_dalipay_urls():
    explicit_api = os.environ.get('DALIPAY_API_URL', '').strip().rstrip('/')
    raw_base = (os.environ.get('DALIPAY_BASE_URL', '') or 'https://app.dalipay.co.tz').strip().rstrip('/')
    if not raw_base.startswith(('http://', 'https://')):
        raw_base = f'https://{raw_base}'
    if raw_base.endswith('/api/v1/collections'):
        raw_base = raw_base[:-len('/api/v1/collections')]
    elif raw_base.endswith('/api/v1'):
        raw_base = raw_base[:-len('/api/v1')]
    collections_url = explicit_api or f'{raw_base}/api/v1/collections'
    return raw_base, collections_url


def get_contact_config():
    raw_wa = os.environ.get('CONTACT_WHATSAPP', '').strip()
    raw_phone = os.environ.get('CONTACT_PHONE', '').strip()
    wa_digits_raw = ''.join(ch for ch in raw_wa if ch.isdigit())
    wa_digits = normalize_phone_tz(raw_wa) or (wa_digits_raw if len(wa_digits_raw) >= 9 else '')
    phone_clean = ''.join(ch for ch in raw_phone if ch.isdigit() or ch == '+')
    phone_href = f'tel:{phone_clean}' if phone_clean else ''
    return {
        'whatsapp': raw_wa,
        'whatsappDigits': wa_digits,
        'phone': raw_phone,
        'phoneHref': phone_href,
    }



# ----------------------------------------------------------------------------
# Admin + settings (prices, offers)
# ----------------------------------------------------------------------------
def phone_variants(n):
    return [to_local_tz_phone(n), n, '+' + n]


def admin_emails():
    return {e.strip().lower() for e in os.environ.get('ADMIN_EMAILS', '').split(',') if e.strip()}


def is_admin_row(row):
    return bool(row) and (row.get('email') or '').strip().lower() in admin_emails()


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(g, 'is_admin', False):
            return jsonify({'error': 'Huna ruhusa ya admin.'}), 403
        return fn(*args, **kwargs)
    return wrapper


def sb_delete(table, params):
    url, key = get_supabase_config()
    resp = requests.delete(f'{url}/rest/v1/{table}', headers=sb_headers(key), params=params, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase delete {table} failed ({resp.status_code})', response=resp)


def get_settings():
    try:
        rows = sb_select('app_settings', {'select': 'key,value', 'key': 'in.(packages,offer)'})
        return {r_['key']: r_['value'] for r_ in rows}
    except Exception as e:
        print(f'[Settings] {e}', flush=True)
        return {}


def save_setting(key, value):
    url, k = get_supabase_config()
    resp = requests.post(f'{url}/rest/v1/app_settings', params={'on_conflict': 'key'},
                         headers=sb_headers(k, 'resolution=merge-duplicates,return=minimal'),
                         json={'key': key, 'value': value, 'updated_at': now_ms()}, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'save setting failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)


def base_packages(st):
    stored = st.get('packages')
    return stored if isinstance(stored, list) and stored else list(PACKAGES.values())


def active_offer(st):
    o = st.get('offer')
    if isinstance(o, dict) and int(o.get('endsAt') or 0) > now_ms() and int(o.get('discountPercent') or 0) > 0:
        return o
    return None


def public_offer(st):
    o = active_offer(st)
    if not o:
        return None
    return {k: o.get(k) for k in ('title', 'description', 'endsAt', 'discountPercent')}


def effective_packages(st):
    o = active_offer(st) or {}
    disc = int(o.get('discountPercent') or 0)
    out = []
    for p in base_packages(st):
        if not p.get('active', True):
            continue
        q = dict(p)
        q['originalAmountTzs'], q['originalCoins'], q['bonusCoins'] = p['amountTzs'], p['coins'], 0
        if disc:
            q['amountTzs'] = max(100, round(p['amountTzs'] * (100 - disc) / 100))
        out.append(q)
    return out


def norm_pkg(p):
    unl = p.get('category') == 'unlimited'
    amount, coins, days = int(p.get('amountTzs')), int(p.get('coins') or 0), int(p.get('unlimitedDays') or 0)
    if not 100 <= amount <= 10000000:
        raise ValueError('Bei lazima iwe kati ya TZS 100 na 10,000,000.')
    if unl and not 1 <= days <= 365:
        raise ValueError('Siku za Unlimited ziwe 1 hadi 365.')
    if not unl and not 1 <= coins <= 100000:
        raise ValueError('Coins ziwe 1 hadi 100,000.')
    pid = sanitize_identifier(p.get('id')) or f"{'u' if unl else 'c'}_{secrets.token_hex(3)}"
    return {'id': pid, 'category': 'unlimited' if unl else 'coins', 'amountTzs': amount,
            'coins': 0 if unl else coins, 'unlimitedDays': days if unl else 0,
            'label': f'Unlimited ({days} Days)' if unl else f'{coins:,} Coins', 'active': bool(p.get('active', True))}


def _q(name):
    return re.sub(r'[^A-Za-z0-9_\-+@. ]', '', request.args.get(name, '')).strip()[:40]


@app.route('/api/admin/stats', methods=['GET'])
@require_auth
@require_admin
def admin_stats():
    try:
        users = sb_select('users', {'select': 'id,is_blocked', 'limit': '20000'})
        pays = sb_select('payments', {'select': 'amount_tzs,status', 'limit': '20000'})
        gens = sb_select('generations', {'select': 'id', 'limit': '20000'})
    except RuntimeError as e:
        return service_unavailable(e)
    done = [x for x in pays if x['status'] == 'completed']
    return jsonify({'users': len(users), 'blocked': sum(1 for u in users if u.get('is_blocked')),
                    'revenue': sum(int(x['amount_tzs']) for x in done), 'completed': len(done),
                    'pending': sum(1 for x in pays if x['status'] == 'pending'),
                    'failed': sum(1 for x in pays if x['status'] == 'failed'), 'documents': len(gens)})


@app.route('/api/admin/payments', methods=['GET'])
@require_auth
@require_admin
def admin_payments():
    q, st = _q('q'), request.args.get('status', '')
    params = {'select': '*', 'order': 'created_at.desc', 'limit': '100'}
    if q:
        conds = [f'reference.ilike.*{q}*', f'provider_ref.ilike.*{q}*', f'phone_number.ilike.*{q}*']
        if q.startswith('0') and q[1:].isdigit():
            conds.append(f'phone_number.ilike.*255{q[1:]}*')
        params['or'] = '(' + ','.join(conds) + ')'
    if st in ('pending', 'completed', 'failed'):
        params['status'] = f'eq.{st}'
    try:
        rows = sb_select('payments', params)
        ids = sorted({int(x['user_id']) for x in rows})
        users = {}
        if ids:
            for u in sb_select('users', {'select': 'id,full_name,email,phone', 'id': f'in.({",".join(map(str, ids))})'}):
                users[int(u['id'])] = u
    except RuntimeError as e:
        return service_unavailable(e)
    for x in rows:
        u = users.get(int(x['user_id'])) or {}
        x['user'] = {'name': u.get('full_name', ''), 'email': u.get('email') or '', 'phone': u.get('phone') or ''}
    return jsonify({'payments': rows})


@app.route('/api/admin/payments/<reference>/settle', methods=['POST'])
@require_auth
@require_admin
def admin_settle(reference):
    reference = sanitize_identifier(reference)
    try:
        res = sb_rpc('settle_dalipay_payment', {'p_reference': reference, 'p_provider_ref': '', 'p_now_ms': now_ms()})
    except RuntimeError as e:
        return service_unavailable(e)
    if not isinstance(res, dict) or not res.get('ok'):
        return jsonify({'error': (res or {}).get('error', 'Imeshindwa.')}), 404
    return jsonify({'ok': True})


@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_admin
def admin_users():
    q = _q('q')
    params = {'select': 'id,full_name,email,phone,coins,unlimited_until,is_blocked,created_at', 'order': 'created_at.desc', 'limit': '100'}
    if q:
        conds = [f'full_name.ilike.*{q}*', f'email.ilike.*{q}*', f'phone.ilike.*{q}*']
        if q.startswith('0') and q[1:].isdigit():
            conds.append(f'phone.ilike.*255{q[1:]}*')
        params['or'] = '(' + ','.join(conds) + ')'
    try:
        rows = sb_select('users', params)
    except RuntimeError as e:
        return service_unavailable(e)
    for u in rows:
        u['isAdmin'] = is_admin_row(u)
        u['isUnlimited'] = int(u.get('unlimited_until') or 0) > now_ms()
    return jsonify({'users': rows})


def _target(uid):
    rows = sb_select('users', {'select': 'id,email,coins', 'id': f'eq.{uid}', 'limit': '1'})
    if not rows:
        return None, (jsonify({'error': 'Mtumiaji hapatikani.'}), 404)
    if is_admin_row(rows[0]) or uid == g.user_id:
        return None, (jsonify({'error': 'Huwezi kufanya hivi kwa akaunti ya admin.'}), 400)
    return rows[0], None


@app.route('/api/admin/users/<int:uid>/block', methods=['POST'])
@require_auth
@require_admin
def admin_block(uid):
    row, err = _target(uid)
    if err:
        return err
    sb_update('users', {'id': f'eq.{uid}'}, {'is_blocked': bool(get_json_dict().get('blocked'))})
    return jsonify({'ok': True})


@app.route('/api/admin/users/<int:uid>/password', methods=['POST'])
@require_auth
@require_admin
def admin_set_password(uid):
    """Admin gives a customer who forgot their password a new initial password.
    Empty newPassword = generate one. The customer is asked to change it after login."""
    row, err = _target(uid)
    if err:
        return err
    pw = str(get_json_dict().get('newPassword') or '').strip() or generate_initial_password()
    perr = _validate_new_password(pw)
    if perr:
        return jsonify({'error': perr}), 400
    sb_update('users', {'id': f'eq.{uid}'}, {
        'password_hash': hash_password(pw),
        'must_change_password': True,
        'session_id': new_session_id(),   # signs the customer out everywhere
    })
    return jsonify({'ok': True, 'password': pw})


@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@require_auth
@require_admin
def admin_delete_user(uid):
    row, err = _target(uid)
    if err:
        return err
    sb_delete('users', {'id': f'eq.{uid}'})
    return jsonify({'ok': True})


@app.route('/api/admin/users/<int:uid>/coins', methods=['POST'])
@require_auth
@require_admin
def admin_coins(uid):
    row, err = _target(uid)
    if err:
        return err
    try:
        delta = int(get_json_dict().get('delta'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Weka namba sahihi.'}), 400
    if not -100000 <= delta <= 100000:
        return jsonify({'error': 'Kiasi ni kikubwa mno.'}), 400
    new = max(0, int(row.get('coins') or 0) + delta)
    sb_update('users', {'id': f'eq.{uid}'}, {'coins': new})
    return jsonify({'ok': True, 'coins': new})


@app.route('/api/admin/packages', methods=['GET', 'PUT', 'DELETE'])
@require_auth
@require_admin
def admin_packages():
    try:
        if request.method == 'GET':
            return jsonify({'packages': base_packages(get_settings())})
        if request.method == 'DELETE':
            save_setting('packages', [])
            return jsonify({'ok': True})
        raw = get_json_dict().get('packages')
        if not isinstance(raw, list) or not raw or len(raw) > 30:
            return jsonify({'error': 'Weka vifurushi 1 hadi 30.'}), 400
        pk = [norm_pkg(x) for x in raw]
        if len({x['id'] for x in pk}) != len(pk):
            return jsonify({'error': 'Vifurushi vina ID zinazojirudia.'}), 400
        save_setting('packages', pk)
        return jsonify({'ok': True, 'packages': pk})
    except (ValueError, TypeError) as e:
        return jsonify({'error': str(e) or 'Taarifa si sahihi.'}), 400
    except RuntimeError as e:
        return service_unavailable(e)


@app.route('/api/admin/offer', methods=['GET', 'POST', 'DELETE'])
@require_auth
@require_admin
def admin_offer():
    try:
        if request.method == 'GET':
            return jsonify({'offer': public_offer(get_settings())})
        if request.method == 'DELETE':
            save_setting('offer', {})
            return jsonify({'ok': True})
        d = get_json_dict()
        title = clean_text(d.get('title'), 60)
        desc = ''.join(c for c in str(d.get('description') or '') if c.isprintable() or c == '\n').strip()[:800]
        mins, disc = int(d.get('durationMinutes')), int(d.get('discountPercent') or 0)
        if not title or not 1 <= mins <= 525600 or not 1 <= disc <= 90:
            return jsonify({'error': 'Jaza kichwa, muda, na punguzo % (1 hadi 90).'}), 400
        save_setting('offer', {'title': title, 'description': desc, 'endsAt': now_ms() + mins * 60000,
                               'discountPercent': disc})
        return jsonify({'ok': True})
    except (ValueError, TypeError):
        return jsonify({'error': 'Taarifa si sahihi.'}), 400
    except RuntimeError as e:
        return service_unavailable(e)


# ----------------------------------------------------------------------------
# Web Push (PWA notifications) + admin broadcast
# ----------------------------------------------------------------------------
PUSH_CHUNK = 100      # subscriptions handled per request (keeps each call well inside serverless time limits)
PUSH_WORKERS = 16
PUSH_TITLE_MAX, PUSH_BODY_MAX = 60, 180
B64URL_RE = re.compile(r'^[A-Za-z0-9_\-]+$')
# Subscription endpoints are supplied by browsers; only talk to real push services (blocks SSRF).
PUSH_HOST_SUFFIXES = ('fcm.googleapis.com', 'android.googleapis.com', 'push.services.mozilla.com',
                      'push.apple.com', 'notify.windows.com')


def vapid_config():
    pub = os.environ.get('VAPID_PUBLIC_KEY', '').strip()
    priv = os.environ.get('VAPID_PRIVATE_KEY', '').strip()
    subject = os.environ.get('VAPID_SUBJECT', '').strip()
    if not subject:
        first = next(iter(sorted(admin_emails())), '')
        subject = first or 'admin@example.com'
    if not subject.startswith(('mailto:', 'https://')):
        subject = f'mailto:{subject}'
    return pub, priv, subject


def push_ready() -> bool:
    pub, priv, _ = vapid_config()
    return bool(webpush and pub and priv)


def push_host_allowed(endpoint: str) -> bool:
    try:
        u = urlparse(endpoint)
    except Exception:
        return False
    host = (u.hostname or '').lower()
    if u.scheme != 'https' or not host:
        return False
    extra = tuple(h.strip().lower() for h in os.environ.get('PUSH_ALLOWED_HOSTS', '').split(',') if h.strip())
    return any(host == suf or host.endswith('.' + suf) for suf in PUSH_HOST_SUFFIXES + extra)


def safe_push_url(raw) -> str:
    """Only same-site relative paths (e.g. /?view=wallet) so a notification can never open another website."""
    url = str(raw or '').strip()
    if not url.startswith('/') or url.startswith('//') or '\\' in url or len(url) > 200:
        return '/'
    if any(ord(ch) < 32 for ch in url):
        return '/'
    return url


def sb_count(table: str, params: dict) -> int:
    url, key = get_supabase_config()
    headers = sb_headers(key, 'count=exact')
    headers['Range-Unit'] = 'items'
    headers['Range'] = '0-0'
    resp = requests.get(f'{url}/rest/v1/{table}', headers=headers, params={**params, 'select': 'id'}, timeout=15)
    if resp.status_code not in (200, 206):
        raise requests.HTTPError(f'Supabase count {table} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)
    try:
        return int(resp.headers.get('Content-Range', '').split('/')[-1])
    except ValueError:
        return 0


def sb_upsert(table: str, payload: dict, conflict: str):
    url, key = get_supabase_config()
    resp = requests.post(f'{url}/rest/v1/{table}', params={'on_conflict': conflict},
                         headers=sb_headers(key, 'resolution=merge-duplicates,return=minimal'), json=payload, timeout=15)
    if not resp.ok:
        raise requests.HTTPError(f'Supabase upsert {table} failed ({resp.status_code}): {_extract_sb_error(resp)}', response=resp)


def optional_user_id():
    auth = request.headers.get('Authorization', '')
    token = auth[7:].strip() if auth.startswith('Bearer ') else (request.cookies.get(SESSION_COOKIE_NAME, '') or '')
    return verify_token(token) if token else None


@app.route('/api/push/key', methods=['GET'])
def api_push_key():
    pub, priv, _ = vapid_config()
    ready = push_ready()
    return jsonify({'configured': ready, 'publicKey': pub if ready else ''})


@app.route('/api/push/subscribe', methods=['POST'])
def api_push_subscribe():
    if rate_limited(f'push_sub:{client_ip()}', 40, 3600):
        return too_many_requests()
    d = get_json_dict()
    endpoint = str(d.get('endpoint') or '').strip()
    keys = d.get('keys') if isinstance(d.get('keys'), dict) else {}
    p256dh, auth = str(keys.get('p256dh') or '').strip(), str(keys.get('auth') or '').strip()
    if (not endpoint or len(endpoint) > 1500 or not push_host_allowed(endpoint)
            or not (60 <= len(p256dh) <= 128 and B64URL_RE.match(p256dh))
            or not (16 <= len(auth) <= 40 and B64URL_RE.match(auth))):
        return jsonify({'error': 'Taarifa za arifa si sahihi.'}), 400
    try:
        uid = optional_user_id()
        if uid is not None and not sb_select('users', {'select': 'id', 'id': f'eq.{uid}', 'limit': '1'}):
            uid = None
        row = {
            'endpoint': endpoint, 'p256dh': p256dh, 'auth': auth,
            'user_agent': clean_text(request.headers.get('User-Agent', ''), 200), 'updated_at': now_ms(),
        }
        if uid is not None:  # a guest re-sync must not unlink a device that already belongs to a user
            row['user_id'] = uid
        sb_upsert('push_subscriptions', row, 'endpoint')
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Push Subscribe Error] {e}', flush=True)
        return jsonify({'error': 'Imeshindwa kuwasha arifa. Jaribu tena.'}), 500
    return jsonify({'ok': True})


@app.route('/api/push/unsubscribe', methods=['POST'])
def api_push_unsubscribe():
    endpoint = str(get_json_dict().get('endpoint') or '').strip()[:1500]
    if endpoint and not rate_limited(f'push_unsub:{client_ip()}', 40, 3600):
        try:
            sb_delete('push_subscriptions', {'endpoint': f'eq.{endpoint}'})
        except Exception as e:
            print(f'[Push Unsubscribe] {e}', flush=True)
    return jsonify({'ok': True})


@app.route('/api/notifications', methods=['GET'])
def api_notifications():
    """In-app notification inbox: the latest broadcasts sent by admin (same list for everyone)."""
    if rate_limited(f'notif_list:{client_ip()}', 120, 60):
        return too_many_requests()
    try:
        rows = sb_select('push_messages', {'select': 'id,title,body,url,created_at', 'order': 'id.desc', 'limit': '30'})
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Notifications] {e}', flush=True)
        return jsonify({'items': []})
    return jsonify({'items': rows})


def _push_one(sub: dict, payload: str, priv: str, subject: str) -> str:
    try:
        webpush(
            subscription_info={'endpoint': sub['endpoint'], 'keys': {'p256dh': sub['p256dh'], 'auth': sub['auth']}},
            data=payload, vapid_private_key=priv, vapid_claims={'sub': subject}, ttl=60 * 60 * 24, timeout=8,
            headers={'Urgency': 'high'},
        )
        return 'ok'
    except WebPushException as e:
        code = getattr(getattr(e, 'response', None), 'status_code', None)
        return 'gone' if code in (404, 410) else 'fail'
    except Exception:
        return 'fail'


@app.route('/api/admin/push/stats', methods=['GET'])
@require_auth
@require_admin
def admin_push_stats():
    try:
        history = sb_select('push_messages', {'select': 'id,title,body,url,total,sent,failed,created_at',
                                              'order': 'id.desc', 'limit': '10'})
        return jsonify({
            'configured': push_ready(), 'libInstalled': webpush is not None,
            'subscribers': sb_count('push_subscriptions', {}),
            'mine': sb_count('push_subscriptions', {'user_id': f'eq.{g.user_id}'}),
            'history': history,
        })
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Push Stats] {e}', flush=True)
        return jsonify({'error': 'Jedwali la arifa halipo. Endesha supabase_schema.sql tena.'}), 500


@app.route('/api/admin/push/send', methods=['POST'])
@require_auth
@require_admin
def admin_push_send():
    """Broadcast in chunks. The client calls it repeatedly, passing messageId + afterId, until nextAfterId is null.
    test=true sends only to the admin's own devices and is not logged."""
    pub, priv, subject = vapid_config()
    if webpush is None:
        return jsonify({'error': 'Maktaba ya pywebpush haijasakinishwa. Angalia requirements.txt kisha ufanye deploy upya.'}), 503
    if not (pub and priv):
        return jsonify({'error': 'VAPID keys hazijawekwa kwenye Environment Variables.'}), 503
    d = get_json_dict()
    test = bool(d.get('test'))
    try:
        after = max(0, int(d.get('afterId') or 0))
        msg_id = int(d['messageId']) if d.get('messageId') else None
    except (TypeError, ValueError):
        return jsonify({'error': 'Taarifa si sahihi.'}), 400
    try:
        if msg_id:
            rows = sb_select('push_messages', {'select': '*', 'id': f'eq.{msg_id}', 'limit': '1'})
            if not rows:
                return jsonify({'error': 'Ujumbe haupatikani.'}), 404
            msg = rows[0]
        else:
            title = clean_text(d.get('title'), PUSH_TITLE_MAX)
            body = ''.join(c for c in str(d.get('body') or '') if c.isprintable() or c == '\n').strip()[:PUSH_BODY_MAX]
            url = safe_push_url(d.get('url'))
            if not title or not body:
                return jsonify({'error': 'Jaza kichwa na ujumbe.'}), 400
            msg = {'id': 0, 'title': title, 'body': body, 'url': url, 'sent': 0, 'failed': 0, 'total': 0}
            if not test:
                msg['total'] = sb_count('push_subscriptions', {})
                created = sb_insert('push_messages', {'title': title, 'body': body, 'url': url, 'total': msg['total'],
                                                      'sent': 0, 'failed': 0, 'created_at': now_ms()})
                msg['id'] = int(created['id'])

        q = {'select': 'id,endpoint,p256dh,auth', 'id': f'gt.{after}', 'order': 'id.asc', 'limit': str(PUSH_CHUNK)}
        if test:
            q['user_id'] = f'eq.{g.user_id}'
        subs = sb_select('push_subscriptions', q)
        payload = json.dumps({'title': msg['title'], 'body': msg['body'], 'url': msg['url'],
                              'tag': f"msg-{msg['id']}" if msg['id'] else 'malimi-test'}, ensure_ascii=False)
        with ThreadPoolExecutor(max_workers=PUSH_WORKERS) as pool:
            results = list(pool.map(lambda sub: _push_one(sub, payload, priv, subject), subs))
        ok, gone = results.count('ok'), [s_['id'] for s_, r_ in zip(subs, results) if r_ == 'gone']
        failed = len(results) - ok - len(gone)
        if gone:
            sb_delete('push_subscriptions', {'id': f"in.({','.join(str(i) for i in gone)})"})
        sent_total, failed_total = int(msg.get('sent') or 0) + ok, int(msg.get('failed') or 0) + failed + len(gone)
        if not test and msg['id']:
            sb_update('push_messages', {'id': f"eq.{msg['id']}"}, {'sent': sent_total, 'failed': failed_total})
        done = test or len(subs) < PUSH_CHUNK
        return jsonify({'ok': True, 'messageId': msg['id'] or None, 'test': test, 'total': msg.get('total') or len(subs),
                        'sent': sent_total, 'failed': failed_total, 'removed': len(gone),
                        'nextAfterId': None if done else int(subs[-1]['id'])})
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Push Send] {e}', flush=True)
        return jsonify({'error': 'Imeshindwa kutuma. Hakikisha umeendesha supabase_schema.sql tena.'}), 500


# ----------------------------------------------------------------------------
# Forgot password (security questions), change password, security questions, delete account
# ----------------------------------------------------------------------------
def _validate_new_password(pw: str):
    if len(pw) < MIN_PASSWORD_LEN or len(pw) > MAX_PASSWORD_LEN:
        return f'Nenosiri jipya liwe na herufi {MIN_PASSWORD_LEN} hadi {MAX_PASSWORD_LEN}.'
    return None


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def api_change_password():
    data = get_json_dict()
    current_pw = str(data.get('currentPassword', ''))
    new_pw = str(data.get('newPassword', ''))
    key = f'chpw:{g.user_id}'
    if rl_count(key, LOGIN_WINDOW_SEC) >= LOGIN_MAX_FAILS_PER_EMAIL:
        return too_many_requests('Majaribio mengi yasiyo sahihi. Subiri dakika 15 kisha ujaribu tena.')
    err = _validate_new_password(new_pw)
    if err:
        return jsonify({'error': err}), 400
    try:
        rows = sb_select('users', {'select': 'id,password_hash', 'id': f'eq.{g.user_id}', 'limit': '1'})
        if not rows:
            return jsonify({'error': 'Akaunti haipatikani.'}), 404
        if len(current_pw) > MAX_PASSWORD_LEN or not verify_password(current_pw, rows[0]['password_hash']):
            rl_record(key)
            return jsonify({'error': 'Nenosiri la sasa si sahihi.'}), 401
        if current_pw == new_pw:
            return jsonify({'error': 'Nenosiri jipya lazima liwe tofauti na la sasa.'}), 400
        sb_update('users', {'id': f'eq.{g.user_id}'}, {'password_hash': hash_password(new_pw), 'must_change_password': False})
    except RuntimeError as e:
        return service_unavailable(e)
    rl_reset(key)
    return jsonify({'ok': True, 'message': 'Nenosiri limebadilishwa.'})


@app.route('/api/auth/delete-account', methods=['POST'])
def api_delete_account():
    """Permanent account + data deletion. Works logged in (in-app) or logged out (public
    /delete-account page required by Google Play): identifier + password prove ownership."""
    data = get_json_dict()
    identifier = str(data.get('identifier') or '').strip().lower()[:254]
    password = str(data.get('password', ''))
    if data.get('confirm') is not True:
        return jsonify({'error': 'Thibitisha kwanza kuwa unataka kufuta akaunti.'}), 400
    if len(password) > MAX_PASSWORD_LEN:
        password = ''
    id_key, ip_key = f'delete:id:{identifier}', f'delete:ip:{client_ip()}'
    if rl_count(id_key, LOGIN_WINDOW_SEC) >= LOGIN_MAX_FAILS_PER_EMAIL or rl_count(ip_key, LOGIN_WINDOW_SEC) >= LOGIN_MAX_FAILS_PER_IP:
        return too_many_requests('Majaribio mengi yasiyo sahihi. Subiri dakika 15 kisha ujaribu tena.')
    try:
        row = find_user_by_identifier(identifier)
        ok = verify_password(password, row['password_hash'] if row else DUMMY_PASSWORD_HASH)
        if not row or not ok:
            rl_record(id_key)
            rl_record(ip_key)
            return jsonify({'error': 'Namba/barua pepe au nenosiri si sahihi.'}), 401
        if is_admin_row(row):
            return jsonify({'error': 'Akaunti ya admin haiwezi kufutwa hapa.'}), 403
        # payments, generations are removed with the user (ON DELETE CASCADE);
        # device_claims keep only an anonymous record (user_id -> NULL) to stop free-coin abuse.
        sb_delete('users', {'id': f'eq.{int(row["id"])}'})
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Delete Account Error] {e}', flush=True)
        return jsonify({'error': 'Imeshindwa kufuta akaunti. Tafadhali jaribu tena au wasiliana na msaada.'}), 500
    rl_reset(id_key)
    resp = jsonify({'ok': True, 'message': 'Akaunti yako na data zimefutwa.'})
    clear_session_cookie(resp)
    return resp


@app.route('/delete-account')
@app.route('/futa-akaunti')
def delete_account_page():
    # Public URL for Google Play "Data safety -> account deletion" (same app, opens the deletion form).
    return send_from_directory('.', 'index.html')


@app.route('/sw.js')
def service_worker():
    # Must be served from the site root (scope "/") and must never be cached by the browser/CDN,
    # otherwise users would not receive service-worker updates.
    resp = send_from_directory('.', 'sw.js', mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


@app.route('/manifest.webmanifest')
def web_manifest():
    resp = send_from_directory('.', 'manifest.webmanifest', mimetype='application/manifest+json')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/api/packages', methods=['GET'])
def api_packages():
    st = get_settings()
    eff = effective_packages(st)
    supabase_ready = bool(
        os.environ.get('SUPABASE_URL', '').strip()
        and (
            os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '').strip()
            or os.environ.get('SUPABASE_SECRET_KEY', '').strip()
        )
    )
    return jsonify(
        {
            'generationCost': GENERATION_COIN_COST,
            'freeSignupCoins': FREE_SIGNUP_COINS,
            'packages': eff,
            'offer': public_offer(st),
            'serverNow': now_ms(),
            'contact': get_contact_config(),
            'dalipayConfigured': bool(
                os.environ.get('DALIPAY_SECRET_KEY', '').strip()
                and os.environ.get('DALIPAY_PUBLIC_KEY', '').strip()
            ),
            'supabaseConfigured': supabase_ready,
        }
    )


@app.route('/api/auth/register', methods=['POST'])
def api_register():
    if not verify_same_origin():
        return jsonify({'error': 'Invalid request origin.'}), 403

    data = get_json_dict()
    if rate_limited(f'register:ip:{client_ip()}', 10, 60 * 60):
        return too_many_requests('Usajili mwingi mno kutoka mtandao huu. Jaribu tena baadaye.')

    full_name = clean_text(data.get('fullName', ''), 100)
    email = str(data.get('email', '')).strip().lower()
    phone_n = normalize_phone_tz(str(data.get('phone', ''))[:32])
    phone = to_local_tz_phone(phone_n) if phone_n else ''
    password = str(data.get('password', ''))
    device_id = sanitize_identifier(data.get('deviceId') or data.get('device_id') or '')

    if len(full_name) < 2:
        return jsonify({'error': 'Jaza jina kamili.'}), 400
    if not phone_n:
        return jsonify({'error': 'Weka namba sahihi ya simu ya Tanzania (mfano 0754123456).'}), 400
    if email and (len(email) > 254 or not EMAIL_RE.match(email)):
        return jsonify({'error': 'Barua pepe si sahihi.'}), 400
    if len(password) < MIN_PASSWORD_LEN or len(password) > MAX_PASSWORD_LEN:
        return jsonify({'error': f'Nenosiri liwe na herufi {MIN_PASSWORD_LEN} hadi {MAX_PASSWORD_LEN}.'}), 400

    try:
        if sb_select('users', {'select': 'id', 'phone': f'in.({",".join(phone_variants(phone_n))})', 'limit': '1'}):
            return jsonify({'error': 'Namba hii ya simu tayari imesajiliwa. Tafadhali ingia.'}), 409
        existing_users = bool(email) and sb_select('users', {'select': 'id', 'email': f'eq.{email}', 'limit': '1'})
        if existing_users:
            return jsonify({'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}), 409

        existing_cookie = sanitize_identifier(request.cookies.get(DEVICE_COOKIE_NAME, ''))

        # Check Supabase device_claims for both device_id and persistent browser cookie
        already_claimed = False
        if device_id:
            if sb_select('device_claims', {'select': 'id', 'device_id': f'eq.{device_id}', 'limit': '1'}):
                already_claimed = True
        if not already_claimed and existing_cookie:
            if sb_select('device_claims', {'select': 'id', 'cookie_token': f'eq.{existing_cookie}', 'limit': '1'}):
                already_claimed = True

        cookie_token = existing_cookie or secrets.token_hex(24)
        starting_coins = 0 if already_claimed else FREE_SIGNUP_COINS
        ts = now_ms()
        sid = new_session_id()

        user_row = sb_insert(
            'users',
            {
                'full_name': full_name,
                'email': email or None,
                'phone': phone,
                'password_hash': hash_password(password),
                'coins': starting_coins,
                'unlimited_until': 0,
                'free_bonus_granted': not already_claimed,
                'session_id': sid,
                'created_at': ts,
            },
        )
        user_id = int(user_row['id'])

        sb_insert(
            'device_claims',
            {
                'device_id': device_id or None,
                'cookie_token': cookie_token,
                'user_id': user_id,
                'created_at': ts,
            },
        )
    except RuntimeError as e:
        return service_unavailable(e)
    except requests.HTTPError as e:
        print(f'[Supabase Register Error] {e}', flush=True)
        detail = str(e)
        if '23505' in detail or 'duplicate key' in detail:
            return jsonify({'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}), 409
        if VERBOSE_ERRORS:  # developer hints: only shown when VERBOSE_ERRORS=1
            if '42501' in detail or 'permission denied' in detail:
                return jsonify({'error': 'Ruhusa ya Supabase (42501) imekataliwa kwa service_role. Endesha supabase_schema.sql mpya (yenye GRANT ... TO service_role) kwenye SQL Editor.'}), 500
            if '42P01' in detail or 'Could not find the table' in detail:
                return jsonify({'error': 'Majedwali ya Supabase hayajaundwa. Endesha supabase_schema.sql kwenye Supabase SQL Editor.'}), 500
            if '401' in detail or 'Invalid API key' in detail:
                return jsonify({'error': 'SUPABASE_SERVICE_ROLE_KEY si sahihi. Tumia Secret key (sb_secret_...).'}), 500
            return jsonify({'error': f'Tatizo la Supabase: {detail}'}), 500
        return jsonify({'error': 'Imeshindwa kusajili akaunti. Tafadhali jaribu tena baadaye.'}), 500
    except Exception as e:
        print(f'[Register Error] {e}', flush=True)
        return jsonify({'error': 'Imeshindwa kusajili akaunti kwenye Supabase.'}), 500

    session_token = sign_token(user_id, sid)
    resp = jsonify(
        {
            'token': session_token,
            'user': sanitize_user(user_row),
            'bonusAwarded': not already_claimed,
            'message': (
                'Kifaa hiki au kivinjari hiki tayari kilishapokea coin za bure. Akaunti imeundwa na coin 0.'
                if already_claimed
                else 'Karibu! Umepokea coin 5 za bure kwa kuanza.'
            ),
        }
    )
    resp.status_code = 201
    set_device_cookie(resp, cookie_token)
    set_session_cookie(resp, session_token)
    return resp


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    if not verify_same_origin():
        return jsonify({'error': 'Invalid request origin.'}), 403

    data = get_json_dict()
    email = str(data.get('identifier') or data.get('email') or '').strip().lower()[:254]
    password = str(data.get('password', ''))
    if len(password) > MAX_PASSWORD_LEN:
        password = ''  # can never match; avoids hashing giant inputs
    device_id = sanitize_identifier(data.get('deviceId') or data.get('device_id') or '')

    email_key = f'login:id:{email}'
    ip_key = f'login:ip:{client_ip()}'
    if (
        rl_count(email_key, LOGIN_WINDOW_SEC) >= LOGIN_MAX_FAILS_PER_EMAIL
        or rl_count(ip_key, LOGIN_WINDOW_SEC) >= LOGIN_MAX_FAILS_PER_IP
    ):
        return too_many_requests('Majaribio mengi yasiyo sahihi. Subiri dakika 15 kisha ujaribu tena.')

    try:
        candidates = find_login_candidates(email)
    except RuntimeError as e:
        return service_unavailable(e)

    # Always run scrypt, even for unknown ids, so response time doesn't reveal which accounts exist.
    if not candidates:
        verify_password(password, DUMMY_PASSWORD_HASH)
    matches = [row for row in candidates if verify_password(password, row['password_hash'])]
    if not matches:
        rl_record(email_key)
        rl_record(ip_key)
        return jsonify({'error': 'Jina/namba ya simu/barua pepe au nenosiri si sahihi.'}), 401
    if len(matches) > 1:
        return jsonify({'error': 'Majina yanafanana na nenosiri ni lile lile. Tafadhali ingia kwa namba ya simu au barua pepe.'}), 409
    user_row = matches[0]
    rl_reset(email_key)
    if user_row.get('is_blocked'):
        return jsonify({'error': 'Akaunti yako imezuiwa. Tafadhali wasiliana na msaada.'}), 403

    cookie_token = sanitize_identifier(request.cookies.get(DEVICE_COOKIE_NAME, '')) or secrets.token_hex(24)
    if device_id:
        existing_dev = sb_select('device_claims', {'select': 'id', 'device_id': f'eq.{device_id}', 'limit': '1'})
        if not existing_dev:
            sb_insert(
                'device_claims',
                {
                    'device_id': device_id,
                    'cookie_token': cookie_token,
                    'user_id': int(user_row['id']),
                    'created_at': now_ms(),
                },
            )

    sid = new_session_id()
    try:
        set_user_session(int(user_row['id']), sid)   # kicks any other device off this account
    except RuntimeError as e:
        return service_unavailable(e)
    session_token = sign_token(int(user_row['id']), sid)
    resp = jsonify({'token': session_token, 'user': sanitize_user(user_row)})
    set_device_cookie(resp, cookie_token)
    set_session_cookie(resp, session_token)
    return resp


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    if not verify_same_origin():
        return jsonify({'error': 'Invalid request origin.'}), 403
    resp = jsonify({'ok': True})
    clear_session_cookie(resp)
    return resp


@app.route('/api/auth/ping', methods=['GET'])
@require_auth
def api_ping():
    """Cheap check used by the app to notice quickly that the account was opened on another device."""
    return jsonify({'ok': True})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def api_me():
    try:
        rows = sb_select('users', {'select': '*', 'id': f'eq.{g.user_id}', 'limit': '1'})
        if not rows:
            return jsonify({'error': 'Akaunti haipatikani.'}), 404
        user_row = rows[0]

        payments = sb_select(
            'payments',
            {
                'select': 'reference,package_label,amount_tzs,coins_awarded,unlimited_days,phone_number,status,created_at,completed_at',
                'user_id': f'eq.{g.user_id}',
                'order': 'created_at.desc',
                'limit': '20',
            },
        )
        generations = sb_select(
            'generations',
            {
                'select': 'id,doc_type,doc_label,coins_spent,created_at',
                'user_id': f'eq.{g.user_id}',
                'order': 'created_at.desc',
                'limit': '20',
            },
        )
        return jsonify({'user': sanitize_user(user_row), 'payments': payments, 'generations': generations})
    except RuntimeError as e:
        return service_unavailable(e)


@app.route('/api/documents/generate', methods=['POST'])
@require_auth
def api_generate_document():
    data = get_json_dict()
    doc_type = data.get('docType')
    if doc_type not in ('tin', 'bl'):
        return jsonify({'error': 'Aina ya hati si sahihi.'}), 400

    if rate_limited(f'generate:user:{g.user_id}', 30, 60):
        return too_many_requests()

    doc_label = clean_text(
        data.get('docLabel') or ('TIN Certificate' if doc_type == 'tin' else 'Business License'), 120
    ) or ('TIN Certificate' if doc_type == 'tin' else 'Business License')
    try:
        result = sb_rpc(
            'deduct_generation_coins',
            {
                'p_user_id': g.user_id,
                'p_doc_type': doc_type,
                'p_doc_label': doc_label,
                'p_cost': GENERATION_COIN_COST,
                'p_now_ms': now_ms(),
            },
        )
        if not result.get('ok'):
            return jsonify({'error': result.get('error', 'Salio halitoshi.')}), int(result.get('status_code', 402))

        spent = int(result.get('coins_spent', 0))
        is_unlimited = bool(result.get('is_unlimited', False))
        return jsonify(
            {
                'ok': True,
                'coinsSpent': spent,
                'user': sanitize_user(result['user']),
                'message': 'Unlimited inafanya kazi (coin 0 zimekatwa).' if is_unlimited else f'Coin {spent} zimekatwa kwa mafanikio.',
            }
        )
    except RuntimeError as e:
        return service_unavailable(e)
    except Exception:
        return jsonify({'error': 'Hitilafu imetokea wakati wa kukata coin.'}), 500


@app.route('/api/payments/dalipay/initiate', methods=['POST'])
@require_auth
def api_dalipay_initiate():
    data = get_json_dict()
    package_id = str(data.get('packageId', ''))[:50]
    phone_clean = normalize_phone_tz(str(data.get('phoneNumber', ''))[:32])
    if not phone_clean:
        return jsonify({'error': 'Weka namba sahihi ya simu ya Tanzania (mfano 0754123456).'}), 400

    # Each request sends a USSD push to a phone: limit per user and per phone number.
    if rate_limited(f'pay:user:{g.user_id}', 5, 10 * 60) or rate_limited(f'pay:phone:{phone_clean}', 3, 10 * 60):
        return too_many_requests('Umejaribu malipo mara nyingi. Subiri dakika chache kisha ujaribu tena.')

    pkg = next((x for x in effective_packages(get_settings()) if x['id'] == package_id), None)
    if not pkg:
        return jsonify({'error': 'Kifurushi kilichochaguliwa hakipo.'}), 400
    amount_tzs = pkg['amountTzs']
    coins_awarded = pkg['coins']
    unlimited_days = pkg['unlimitedDays']
    package_label = pkg['label']

    public_key = os.environ.get('DALIPAY_PUBLIC_KEY', '').strip()
    secret_key = os.environ.get('DALIPAY_SECRET_KEY', '').strip()
    _, collections_url = resolve_dalipay_urls()

    if not public_key or not secret_key:
        print('[Config] DALIPAY_PUBLIC_KEY / DALIPAY_SECRET_KEY hazijawekwa.', flush=True)
        return (
            jsonify(
                {
                    'error': 'Malipo hayapatikani kwa sasa. Tafadhali jaribu tena baadaye.'
                }
            ),
            503,
        )

    # Dalipay external_id max length is 30 chars
    reference = f'DP-{now_ms()}-{secrets.token_hex(4).upper()}'[:30]
    provider = resolve_dalipay_provider(str(data.get('provider') or ''), phone_clean)
    local_account = to_local_tz_phone(phone_clean)

    customer_name = ''
    try:
        u_rows = sb_select('users', {'select': 'full_name', 'id': f'eq.{g.user_id}', 'limit': '1'})
        if u_rows:
            customer_name = str(u_rows[0].get('full_name') or '').strip()[:100]
    except Exception:
        customer_name = ''

    try:
        sb_insert(
            'payments',
            {
                'reference': reference,
                'user_id': g.user_id,
                'package_id': package_id,
                'package_label': package_label,
                'amount_tzs': amount_tzs,
                'coins_awarded': coins_awarded,
                'unlimited_days': unlimited_days,
                'phone_number': phone_clean,
                'status': 'pending',
                'created_at': now_ms(),
            },
        )
    except RuntimeError as e:
        return service_unavailable(e)

    payload_body = {
        'account_number': local_account,
        'amount': amount_tzs,
        'currency': 'TZS',
        'provider': provider,
        'external_id': reference,
    }
    if customer_name:
        payload_body['customer_name'] = customer_name

    try:
        resp = requests.post(
            collections_url,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Public-Key': public_key,
                'X-Secret-Key': secret_key,
            },
            json=payload_body,
            timeout=20,
        )
        res_json = resp.json() if resp.content else {}
        nested_data = res_json.get('data') if isinstance(res_json.get('data'), dict) else {}

        if not resp.ok or res_json.get('success') is False:
            sb_update('payments', {'reference': f'eq.{reference}'}, {'status': 'failed'})
            print(f'[Dalipay] request rejected ({resp.status_code}): {str(res_json.get("message") or "")[:200]}', flush=True)
            return jsonify({'error': 'Ombi la malipo limekataliwa. Tafadhali jaribu tena.', 'reference': reference}), 502

        provider_ref = str(
            nested_data.get('uuid')
            or nested_data.get('reference')
            or res_json.get('uuid')
            or res_json.get('transaction_id')
            or res_json.get('id')
            or ''
        )
        provider_ref = sanitize_identifier(provider_ref)
        if provider_ref:
            sb_update('payments', {'reference': f'eq.{reference}'}, {'provider_ref': provider_ref})

        upstream_status = str(nested_data.get('status') or res_json.get('status') or '').lower()
        if upstream_status in ('success', 'succeeded', 'completed', 'paid'):
            sb_rpc(
                'settle_dalipay_payment',
                {'p_reference': reference, 'p_provider_ref': provider_ref, 'p_now_ms': now_ms()},
            )
            user_rows = sb_select('users', {'select': '*', 'id': f'eq.{g.user_id}', 'limit': '1'})
            return jsonify(
                {
                    'ok': True,
                    'reference': reference,
                    'status': 'completed',
                    'amountTzs': amount_tzs,
                    'packageLabel': package_label,
                    'user': sanitize_user(user_rows[0]) if user_rows else None,
                    'message': 'Malipo yamethibitishwa! Salio lako limesasishwa.',
                }
            )

        return jsonify(
            {
                'ok': True,
                'reference': reference,
                'status': 'pending',
                'amountTzs': amount_tzs,
                'packageLabel': package_label,
                'message': 'Ombi la malipo limetumwa kwenye simu yako. Weka PIN kukamilisha.',
            }
        )
    except Exception:
        app.logger.exception('Dalipay initiate failed')
        sb_update('payments', {'reference': f'eq.{reference}'}, {'status': 'failed'})
        return jsonify({'error': 'Imeshindwa kuwasiliana na mfumo wa malipo.', 'reference': reference}), 502


@app.route('/api/payments/status/<reference>', methods=['GET'])
@require_auth
def api_payment_status(reference):
    reference = sanitize_identifier(reference)
    if not reference:
        return jsonify({'error': 'Muamala haupatikani.'}), 404
    try:
        payments = sb_select(
            'payments',
            {'select': '*', 'reference': f'eq.{reference}', 'user_id': f'eq.{g.user_id}', 'limit': '1'},
        )
        if not payments:
            return jsonify({'error': 'Muamala haupatikani.'}), 404
        payment = payments[0]

        public_key = os.environ.get('DALIPAY_PUBLIC_KEY', '').strip()
        secret_key = os.environ.get('DALIPAY_SECRET_KEY', '').strip()
        provider_ref = sanitize_identifier(str(payment.get('provider_ref') or ''))  # goes into a URL path
        if payment.get('status') == 'pending' and provider_ref and public_key and secret_key:
            try:
                base_url, _ = resolve_dalipay_urls()
                st_resp = requests.get(
                    f'{base_url}/api/v1/collections/{provider_ref}/status',
                    headers={
                        'Accept': 'application/json',
                        'X-Public-Key': public_key,
                        'X-Secret-Key': secret_key,
                    },
                    timeout=8,
                )
                if st_resp.ok and st_resp.content:
                    st_json = st_resp.json()
                    nested = st_json.get('data') if isinstance(st_json.get('data'), dict) else {}
                    upstream_status = str(nested.get('status') or st_json.get('status') or '').lower()
                    if upstream_status in ('success', 'succeeded', 'completed', 'paid'):
                        sb_rpc(
                            'settle_dalipay_payment',
                            {'p_reference': reference, 'p_provider_ref': provider_ref, 'p_now_ms': now_ms()},
                        )
                        refreshed = sb_select(
                            'payments',
                            {'select': '*', 'reference': f'eq.{reference}', 'user_id': f'eq.{g.user_id}', 'limit': '1'},
                        )
                        if refreshed:
                            payment = refreshed[0]
                    elif upstream_status in ('failed', 'cancelled', 'canceled', 'expired'):
                        sb_update('payments', {'reference': f'eq.{reference}', 'status': 'eq.pending'}, {'status': 'failed'})
                        payment['status'] = 'failed'
            except Exception:
                pass

        user_row = sb_select('users', {'select': '*', 'id': f'eq.{g.user_id}', 'limit': '1'})[0]
        return jsonify(
            {
                'reference': payment['reference'],
                'status': payment['status'],
                'packageLabel': payment['package_label'],
                'amountTzs': int(payment['amount_tzs']),
                'user': sanitize_user(user_row),
            }
        )
    except RuntimeError as e:
        return service_unavailable(e)


def _handle_dalipay_webhook():
    callback_secret = os.environ.get('DALIPAY_CALLBACK_SECRET', '').strip()
    if not callback_secret:
        print('[Config] DALIPAY_CALLBACK_SECRET haijawekwa; webhook imekataliwa.', flush=True)
        return jsonify({'error': 'Webhook not available.'}), 503

    raw_body = request.get_data()
    sig_header = (
        request.headers.get('X-Dalipay-Signature')
        or request.headers.get('X-Webhook-Signature')
        or request.headers.get('X-Signature')
        or ''
    ).strip()

    if not raw_body or not sig_header:
        return jsonify({'error': 'Missing webhook signature.'}), 401

    cleaned_sig = sig_header[7:] if sig_header.lower().startswith('sha256=') else sig_header
    expected_hex = hmac.new(callback_secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(cleaned_sig.lower().encode('utf-8'), expected_hex.encode('utf-8')):
        return jsonify({'error': 'Invalid webhook signature.'}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    event_data = payload.get('data') if isinstance(payload.get('data'), dict) else {}
    reference = sanitize_identifier(
        event_data.get('external_id')
        or payload.get('external_id')
        or payload.get('reference')
        or payload.get('order_id')
        or payload.get('merchant_reference')
        or ''
    )
    status_raw = str(event_data.get('status') or payload.get('status') or payload.get('event') or '').lower()
    provider_ref = str(
        event_data.get('uuid')
        or event_data.get('reference')
        or payload.get('transaction_id')
        or payload.get('id')
        or ''
    )
    provider_ref = sanitize_identifier(provider_ref)

    if not reference:
        return jsonify({'error': 'Missing payment reference.'}), 400

    if status_raw in ('success', 'succeeded', 'completed', 'paid', 'payment.success', 'collection.success'):
        res = sb_rpc(
            'settle_dalipay_payment',
            {'p_reference': reference, 'p_provider_ref': provider_ref, 'p_now_ms': now_ms()},
        )
        if not isinstance(res, dict) or not res.get('ok'):
            err = res.get('error', 'Settlement failed') if isinstance(res, dict) else 'Settlement failed'
            code = int(res.get('status_code', 404)) if isinstance(res, dict) else 500
            return jsonify({'error': err}), code
        return jsonify({'received': True, 'status': 'completed'})

    if status_raw in ('failed', 'cancelled', 'canceled', 'expired', 'payment.failed', 'collection.failed'):
        sb_update('payments', {'reference': f'eq.{reference}', 'status': 'eq.pending'}, {'status': 'failed'})
        return jsonify({'received': True, 'status': 'failed'})

    return jsonify({'received': True, 'status': status_raw or 'ignored'})


@app.route('/api/payments/dalipay/webhook', methods=['POST'])
@app.route('/api/payments/dalipay/callback', methods=['POST'])
def api_dalipay_webhook():
    try:
        return _handle_dalipay_webhook()
    except Exception:
        app.logger.exception('Dalipay webhook failed')
        return jsonify({'error': 'Webhook processing failed.'}), 500


ALLOWED_STATIC_EXT = {
    '.html', '.css', '.js', '.mjs', '.json', '.webmanifest', '.txt',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.otf', '.mp3', '.mp4', '.webm', '.wav', '.ogg',
}
BLOCKED_STATIC_NAMES = {
    'app.py', 'vercel.json', 'package.json', 'package-lock.json', 'requirements.txt',
    'node_modules', '__pycache__', 'venv', '.venv', 'api',
}


@app.route('/<path:path>')
def static_files(path):
    # Only serve public front-end assets. Never source code, .env, .sql, dotfiles or config.
    parts = [seg for seg in path.replace('\\', '/').split('/') if seg]
    if not parts or any(seg.startswith('.') or seg.lower() in BLOCKED_STATIC_NAMES for seg in parts):
        abort(404)
    if os.path.splitext(parts[-1])[1].lower() not in ALLOWED_STATIC_EXT:
        abort(404)
    return send_from_directory('.', path)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
