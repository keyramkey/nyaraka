import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, g, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')


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

SESSION_SECRET = os.environ.get('SESSION_SECRET') or secrets.token_hex(32)
DEVICE_COOKIE_NAME = 'tra_device_token'
GENERATION_COIN_COST = 5
FREE_SIGNUP_COINS = 10

PACKAGES = {
    'coins_22': {'id': 'coins_22', 'label': '22 Coins', 'amountTzs': 2000, 'coins': 22, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_55': {'id': 'coins_55', 'label': '55 Coins', 'amountTzs': 5000, 'coins': 55, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_100': {'id': 'coins_100', 'label': '100 Coins', 'amountTzs': 9000, 'coins': 100, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_230': {'id': 'coins_230', 'label': '230 Coins', 'amountTzs': 20000, 'coins': 230, 'unlimitedDays': 0, 'category': 'coins'},
    'coins_600': {'id': 'coins_600', 'label': '600 Coins', 'amountTzs': 50000, 'coins': 600, 'unlimitedDays': 0, 'category': 'coins'},
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


def sign_token(user_id: int) -> str:
    payload_bytes = json.dumps({'uid': user_id, 'exp': now_ms() + 7 * 24 * 60 * 60 * 1000}).encode('utf-8')
    payload = base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')
    sig = base64.urlsafe_b64encode(
        hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
    ).decode('ascii').rstrip('=')
    return f'{payload}.{sig}'


def verify_token(token: str):
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
        if not isinstance(data.get('uid'), int) or data.get('exp', 0) < now_ms():
            return None
        return data['uid']
    except Exception:
        return None


def sanitize_identifier(raw) -> str:
    if not isinstance(raw, str):
        return ''
    return ''.join(ch for ch in raw.strip() if ch.isalnum() or ch in ('_', '-'))[:128]


def set_device_cookie(response, token: str):
    max_age = 60 * 60 * 24 * 365 * 2
    is_https = (
        request.is_secure
        or request.headers.get('X-Forwarded-Proto', '') == 'https'
        or os.environ.get('VERCEL') == '1'
    )
    attrs = 'HttpOnly; Secure; SameSite=None; Partitioned' if is_https else 'HttpOnly; SameSite=Lax'
    response.headers.add(
        'Set-Cookie',
        f'{DEVICE_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; {attrs}',
    )


def verify_same_origin():
    origin = request.headers.get('Origin')
    host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or ''
    if origin and host:
        try:
            if urlparse(origin).netloc != host:
                return False
        except Exception:
            return False
    return True


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Tafadhali ingia kwenye akaunti yako kwanza.'}), 401
        uid = verify_token(auth[7:].strip())
        if uid is None:
            return jsonify({'error': 'Session imeisha. Tafadhali ingia tena.'}), 401
        g.user_id = uid
        return fn(*args, **kwargs)

    return wrapper


def sanitize_user(row: dict):
    unlimited_until = int(row.get('unlimited_until') or 0)
    return {
        'id': int(row['id']),
        'fullName': row['full_name'],
        'email': row['email'],
        'phone': row.get('phone') or '',
        'coins': int(row.get('coins') or 0),
        'unlimitedUntil': unlimited_until,
        'isUnlimited': unlimited_until > now_ms(),
        'freeBonusGranted': bool(row.get('free_bonus_granted')),
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


def compute_custom_coins(amount_tzs: int) -> int:
    if amount_tzs < 1000:
        return 0
    return int((amount_tzs / 9000) * 100)


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/api/packages', methods=['GET'])
def api_packages():
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
            'packages': list(PACKAGES.values()),
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

    data = request.get_json(silent=True) or {}
    full_name = str(data.get('fullName', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    phone = str(data.get('phone', '')).strip()
    password = str(data.get('password', ''))
    device_id = sanitize_identifier(data.get('deviceId') or data.get('device_id') or '')

    if len(full_name) < 2 or '@' not in email or len(password) < 6:
        return jsonify({'error': 'Jaza jina kamili, barua pepe sahihi, na nenosiri (angalau herufi 6).'}), 400

    try:
        existing_users = sb_select('users', {'select': 'id', 'email': f'eq.{email}', 'limit': '1'})
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

        user_row = sb_insert(
            'users',
            {
                'full_name': full_name,
                'email': email,
                'phone': phone,
                'password_hash': hash_password(password),
                'coins': starting_coins,
                'unlimited_until': 0,
                'free_bonus_granted': not already_claimed,
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
        return jsonify({'error': str(e)}), 503
    except requests.HTTPError as e:
        print(f'[Supabase Register Error] {e}', flush=True)
        detail = str(e)
        if '42501' in detail or 'permission denied' in detail:
            return jsonify({'error': 'Ruhusa ya Supabase (42501) imekataliwa kwa service_role. Endesha supabase_schema.sql mpya (yenye GRANT ... TO service_role) kwenye SQL Editor.'}), 500
        if '42P01' in detail or 'Could not find the table' in detail:
            return jsonify({'error': 'Majedwali ya Supabase hayajaundwa. Endesha supabase_schema.sql kwenye Supabase SQL Editor.'}), 500
        if '401' in detail or 'Invalid API key' in detail:
            return jsonify({'error': 'SUPABASE_SERVICE_ROLE_KEY si sahihi. Tumia Secret key (sb_secret_...).'}), 500
        return jsonify({'error': f'Tatizo la Supabase: {detail}'}), 500
    except Exception as e:
        print(f'[Register Error] {e}', flush=True)
        return jsonify({'error': 'Imeshindwa kusajili akaunti kwenye Supabase.'}), 500

    resp = jsonify(
        {
            'token': sign_token(user_id),
            'user': sanitize_user(user_row),
            'bonusAwarded': not already_claimed,
            'message': (
                'Kifaa hiki au kivinjari hiki tayari kilishapokea coin za bure. Akaunti imeundwa na coin 0.'
                if already_claimed
                else 'Karibu! Umepokea coin 10 za bure kwa kuanza.'
            ),
        }
    )
    resp.status_code = 201
    set_device_cookie(resp, cookie_token)
    return resp


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    if not verify_same_origin():
        return jsonify({'error': 'Invalid request origin.'}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))
    device_id = sanitize_identifier(data.get('deviceId') or data.get('device_id') or '')

    try:
        rows = sb_select('users', {'select': '*', 'email': f'eq.{email}', 'limit': '1'})
        user_row = rows[0] if rows else None
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 503

    if not user_row or not verify_password(password, user_row['password_hash']):
        return jsonify({'error': 'Barua pepe au nenosiri si sahihi.'}), 401

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

    resp = jsonify({'token': sign_token(int(user_row['id'])), 'user': sanitize_user(user_row)})
    set_device_cookie(resp, cookie_token)
    return resp


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
        return jsonify({'error': str(e)}), 503


@app.route('/api/documents/generate', methods=['POST'])
@require_auth
def api_generate_document():
    data = request.get_json(silent=True) or {}
    doc_type = data.get('docType')
    if doc_type not in ('tin', 'bl'):
        return jsonify({'error': 'Aina ya hati si sahihi.'}), 400

    doc_label = str(data.get('docLabel') or ('TIN Certificate' if doc_type == 'tin' else 'Business License')).strip()[:120]
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
        return jsonify({'error': str(e)}), 503
    except Exception:
        return jsonify({'error': 'Hitilafu imetokea wakati wa kukata coin.'}), 500


@app.route('/api/payments/dalipay/initiate', methods=['POST'])
@require_auth
def api_dalipay_initiate():
    data = request.get_json(silent=True) or {}
    package_id = str(data.get('packageId', ''))
    phone_clean = normalize_phone_tz(str(data.get('phoneNumber', '')))
    if not phone_clean:
        return jsonify({'error': 'Weka namba sahihi ya simu ya Tanzania (mfano 0754123456).'}), 400

    if package_id == 'custom':
        try:
            amount_tzs = int(data.get('customAmountTzs', 0))
        except (TypeError, ValueError):
            amount_tzs = 0
        if amount_tzs < 1000 or amount_tzs > 5000000:
            return jsonify({'error': 'Kiasi cha kawaida lazima kiwe kuanzia TZS 1,000 hadi 5,000,000.'}), 400
        coins_awarded = compute_custom_coins(amount_tzs)
        unlimited_days = 0
        package_label = f'{coins_awarded} Coins (Custom)'
    else:
        pkg = PACKAGES.get(package_id)
        if not pkg:
            return jsonify({'error': 'Kifurushi kilichochaguliwa hakipo.'}), 400
        amount_tzs = pkg['amountTzs']
        coins_awarded = pkg['coins']
        unlimited_days = pkg['unlimitedDays']
        package_label = pkg['label']

    public_key = os.environ.get('DALIPAY_PUBLIC_KEY', '').strip()
    secret_key = os.environ.get('DALIPAY_SECRET_KEY', '').strip()
    api_url = os.environ.get('DALIPAY_API_URL', '').strip() or 'https://api.dalipay.co.tz/v1/payments/mobile'

    if not public_key or not secret_key:
        return (
            jsonify(
                {
                    'error': 'Malipo ya Dalipay hayajaunganishwa bado. Weka DALIPAY_PUBLIC_KEY, DALIPAY_SECRET_KEY, na DALIPAY_CALLBACK_SECRET kwenye Environment Variables.'
                }
            ),
            503,
        )

    reference = f'DP-{now_ms()}-{secrets.token_hex(4).upper()}'
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
        return jsonify({'error': str(e)}), 503

    try:
        resp = requests.post(
            api_url,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Bearer {secret_key}',
                'X-Public-Key': public_key,
            },
            json={
                'amount': amount_tzs,
                'currency': 'TZS',
                'phone_number': phone_clean,
                'reference': reference,
                'description': f'MALIMI COPY - {package_label}',
            },
            timeout=20,
        )
        res_json = resp.json() if resp.content else {}
        if not resp.ok:
            sb_update('payments', {'reference': f'eq.{reference}'}, {'status': 'failed'})
            return jsonify({'error': res_json.get('message') or 'Ombi la malipo ya Dalipay limekataliwa.', 'reference': reference}), 502

        provider_ref = str(res_json.get('transaction_id') or res_json.get('id') or '')
        if provider_ref:
            sb_update('payments', {'reference': f'eq.{reference}'}, {'provider_ref': provider_ref})

        return jsonify(
            {
                'ok': True,
                'reference': reference,
                'status': 'pending',
                'amountTzs': amount_tzs,
                'packageLabel': package_label,
                'message': 'Ombi la malipo limetumwa kwenye simu yako kupitia Dalipay. Thibitisha USSD push.',
            }
        )
    except Exception:
        sb_update('payments', {'reference': f'eq.{reference}'}, {'status': 'failed'})
        return jsonify({'error': 'Imeshindwa kuwasiliana na seva ya Dalipay.', 'reference': reference}), 502


@app.route('/api/payments/status/<reference>', methods=['GET'])
@require_auth
def api_payment_status(reference):
    try:
        payments = sb_select(
            'payments',
            {'select': '*', 'reference': f'eq.{reference}', 'user_id': f'eq.{g.user_id}', 'limit': '1'},
        )
        if not payments:
            return jsonify({'error': 'Muamala haupatikani.'}), 404
        payment = payments[0]
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
        return jsonify({'error': str(e)}), 503


def _handle_dalipay_webhook():
    callback_secret = os.environ.get('DALIPAY_CALLBACK_SECRET', '').strip()
    if not callback_secret:
        return jsonify({'error': 'DALIPAY_CALLBACK_SECRET is not configured.'}), 503

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
    if not hmac.compare_digest(cleaned_sig, expected_hex):
        return jsonify({'error': 'Invalid webhook signature.'}), 401

    payload = request.get_json(silent=True) or {}
    reference = sanitize_identifier(payload.get('reference') or payload.get('order_id') or payload.get('merchant_reference') or '')
    status_raw = str(payload.get('status') or payload.get('event') or '').lower()
    provider_ref = str(payload.get('transaction_id') or payload.get('id') or '')

    if not reference:
        return jsonify({'error': 'Missing payment reference.'}), 400

    if status_raw in ('success', 'succeeded', 'completed', 'paid', 'payment.success'):
        res = sb_rpc(
            'settle_dalipay_payment',
            {'p_reference': reference, 'p_provider_ref': provider_ref, 'p_now_ms': now_ms()},
        )
        if not res.get('ok'):
            return jsonify({'error': res.get('error', 'Settlement failed')}), int(res.get('status_code', 404))
        return jsonify({'received': True, 'status': 'completed'})

    if status_raw in ('failed', 'cancelled', 'canceled', 'expired', 'payment.failed'):
        sb_update('payments', {'reference': f'eq.{reference}', 'status': 'eq.pending'}, {'status': 'failed'})
        return jsonify({'received': True, 'status': 'failed'})

    return jsonify({'received': True, 'status': status_raw or 'ignored'})


@app.route('/api/payments/dalipay/webhook', methods=['POST'])
@app.route('/api/payments/dalipay/callback', methods=['POST'])
def api_dalipay_webhook():
    return _handle_dalipay_webhook()


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
