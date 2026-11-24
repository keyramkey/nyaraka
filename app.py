import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, g, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')

DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'tra_filler.db'))
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


def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH, isolation_level=None)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            coins INTEGER NOT NULL DEFAULT 0,
            unlimited_until INTEGER NOT NULL DEFAULT 0,
            free_bonus_granted INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            cookie_token TEXT,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_device_claims_device ON device_claims(device_id);
        CREATE INDEX IF NOT EXISTS idx_device_claims_cookie ON device_claims(cookie_token);
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            package_id TEXT NOT NULL,
            package_label TEXT NOT NULL,
            amount_tzs INTEGER NOT NULL,
            coins_awarded INTEGER NOT NULL DEFAULT 0,
            unlimited_days INTEGER NOT NULL DEFAULT 0,
            phone_number TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            provider_ref TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            completed_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS generations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            doc_type TEXT NOT NULL,
            doc_label TEXT NOT NULL,
            coins_spent INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    conn.close()


init_db()


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


def set_device_cookie(response, token: str):
    max_age = 60 * 60 * 24 * 365 * 2
    response.headers.add(
        'Set-Cookie',
        f'{DEVICE_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=None; Partitioned',
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


def sanitize_user(row):
    unlimited_until = int(row['unlimited_until'] or 0)
    return {
        'id': int(row['id']),
        'fullName': row['full_name'],
        'email': row['email'],
        'phone': row['phone'] or '',
        'coins': int(row['coins'] or 0),
        'unlimitedUntil': unlimited_until,
        'isUnlimited': unlimited_until > now_ms(),
        'freeBonusGranted': bool(row['free_bonus_granted']),
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
    return jsonify(
        {
            'generationCost': GENERATION_COIN_COST,
            'freeSignupCoins': FREE_SIGNUP_COINS,
            'packages': list(PACKAGES.values()),
            'dalipayConfigured': bool(
                os.environ.get('DALIPAY_SECRET_KEY', '').strip()
                and os.environ.get('DALIPAY_PUBLIC_KEY', '').strip()
            ),
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
    device_id = str(data.get('deviceId') or data.get('device_id') or '').strip()[:128]

    if len(full_name) < 2 or '@' not in email or len(password) < 6:
        return jsonify({'error': 'Jaza jina kamili, barua pepe sahihi, na nenosiri (angalau herufi 6).'}), 400

    db = get_db()
    if db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
        return jsonify({'error': 'Barua pepe hii tayari imesajiliwa. Tafadhali ingia.'}), 409

    existing_cookie = request.cookies.get(DEVICE_COOKIE_NAME, '').strip()

    # Detect returning device_id OR returning browser cookie
    already_claimed = False
    if device_id:
        if db.execute('SELECT id FROM device_claims WHERE device_id = ? LIMIT 1', (device_id,)).fetchone():
            already_claimed = True
    if not already_claimed and existing_cookie:
        if db.execute('SELECT id FROM device_claims WHERE cookie_token = ? LIMIT 1', (existing_cookie,)).fetchone():
            already_claimed = True

    cookie_token = existing_cookie or secrets.token_hex(24)
    starting_coins = 0 if already_claimed else FREE_SIGNUP_COINS
    bonus_flag = 0 if already_claimed else 1
    ts = now_ms()

    db.execute('BEGIN IMMEDIATE')
    try:
        cur = db.execute(
            'INSERT INTO users (full_name, email, phone, password_hash, coins, unlimited_until, free_bonus_granted, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)',
            (full_name, email, phone, hash_password(password), starting_coins, bonus_flag, ts),
        )
        user_id = cur.lastrowid
        db.execute(
            'INSERT INTO device_claims (device_id, cookie_token, user_id, created_at) VALUES (?, ?, ?, ?)',
            (device_id or None, cookie_token, user_id, ts),
        )
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK')
        return jsonify({'error': 'Imeshindwa kusajili akaunti.'}), 500

    user_row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
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
    device_id = str(data.get('deviceId') or data.get('device_id') or '').strip()[:128]

    db = get_db()
    user_row = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user_row or not verify_password(password, user_row['password_hash']):
        return jsonify({'error': 'Barua pepe au nenosiri si sahihi.'}), 401

    cookie_token = request.cookies.get(DEVICE_COOKIE_NAME, '').strip() or secrets.token_hex(24)
    if device_id and not db.execute('SELECT id FROM device_claims WHERE device_id = ? LIMIT 1', (device_id,)).fetchone():
        db.execute(
            'INSERT INTO device_claims (device_id, cookie_token, user_id, created_at) VALUES (?, ?, ?, ?)',
            (device_id, cookie_token, int(user_row['id']), now_ms()),
        )

    resp = jsonify({'token': sign_token(int(user_row['id'])), 'user': sanitize_user(user_row)})
    set_device_cookie(resp, cookie_token)
    return resp


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def api_me():
    db = get_db()
    user_row = db.execute('SELECT * FROM users WHERE id = ?', (g.user_id,)).fetchone()
    if not user_row:
        return jsonify({'error': 'Akaunti haipatikani.'}), 404

    payments = [
        dict(r)
        for r in db.execute(
            'SELECT reference, package_label, amount_tzs, coins_awarded, unlimited_days, phone_number, status, created_at, completed_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
            (g.user_id,),
        ).fetchall()
    ]
    generations = [
        dict(r)
        for r in db.execute(
            'SELECT id, doc_type, doc_label, coins_spent, created_at FROM generations WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
            (g.user_id,),
        ).fetchall()
    ]
    return jsonify({'user': sanitize_user(user_row), 'payments': payments, 'generations': generations})


@app.route('/api/documents/generate', methods=['POST'])
@require_auth
def api_generate_document():
    data = request.get_json(silent=True) or {}
    doc_type = data.get('docType')
    if doc_type not in ('tin', 'bl'):
        return jsonify({'error': 'Aina ya hati si sahihi.'}), 400

    doc_label = str(data.get('docLabel') or ('TIN Certificate' if doc_type == 'tin' else 'Business License')).strip()[:120]
    ts = now_ms()
    db = get_db()
    db.execute('BEGIN IMMEDIATE')
    try:
        user_row = db.execute('SELECT * FROM users WHERE id = ?', (g.user_id,)).fetchone()
        if not user_row:
            db.execute('ROLLBACK')
            return jsonify({'error': 'Akaunti haipatikani.'}), 404

        is_unlimited = int(user_row['unlimited_until'] or 0) > ts
        current_coins = int(user_row['coins'] or 0)

        if not is_unlimited and current_coins < GENERATION_COIN_COST:
            db.execute('ROLLBACK')
            return (
                jsonify(
                    {
                        'error': f'Salio lako ni coin {current_coins}. Unahitaji coin {GENERATION_COIN_COST} kutengeneza hati. Tafadhali nunua coin kupitia Dalipay.',
                        'requiredCoins': GENERATION_COIN_COST,
                        'currentCoins': current_coins,
                    }
                ),
                402,
            )

        spent = 0 if is_unlimited else GENERATION_COIN_COST
        if spent > 0:
            db.execute('UPDATE users SET coins = coins - ? WHERE id = ?', (spent, g.user_id))
        db.execute(
            'INSERT INTO generations (user_id, doc_type, doc_label, coins_spent, created_at) VALUES (?, ?, ?, ?, ?)',
            (g.user_id, doc_type, doc_label, spent, ts),
        )
        updated = db.execute('SELECT * FROM users WHERE id = ?', (g.user_id,)).fetchone()
        db.execute('COMMIT')
        return jsonify(
            {
                'ok': True,
                'coinsSpent': spent,
                'user': sanitize_user(updated),
                'message': 'Unlimited inafanya kazi (coin 0 zimekatwa).' if is_unlimited else f'Coin {spent} zimekatwa kwa mafanikio.',
            }
        )
    except Exception:
        db.execute('ROLLBACK')
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
    db = get_db()
    db.execute(
        'INSERT INTO payments (reference, user_id, package_id, package_label, amount_tzs, coins_awarded, unlimited_days, phone_number, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (reference, g.user_id, package_id, package_label, amount_tzs, coins_awarded, unlimited_days, phone_clean, 'pending', now_ms()),
    )

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
                'description': f'TRA Document Filler - {package_label}',
            },
            timeout=20,
        )
        res_json = resp.json() if resp.content else {}
        if not resp.ok:
            db.execute('UPDATE payments SET status = ? WHERE reference = ?', ('failed', reference))
            return jsonify({'error': res_json.get('message') or 'Ombi la malipo ya Dalipay limekataliwa.', 'reference': reference}), 502

        provider_ref = str(res_json.get('transaction_id') or res_json.get('id') or '')
        if provider_ref:
            db.execute('UPDATE payments SET provider_ref = ? WHERE reference = ?', (provider_ref, reference))

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
        db.execute('UPDATE payments SET status = ? WHERE reference = ?', ('failed', reference))
        return jsonify({'error': 'Imeshindwa kuwasiliana na seva ya Dalipay.', 'reference': reference}), 502


@app.route('/api/payments/status/<reference>', methods=['GET'])
@require_auth
def api_payment_status(reference):
    db = get_db()
    payment = db.execute('SELECT * FROM payments WHERE reference = ? AND user_id = ?', (reference, g.user_id)).fetchone()
    if not payment:
        return jsonify({'error': 'Muamala haupatikani.'}), 404
    user_row = db.execute('SELECT * FROM users WHERE id = ?', (g.user_id,)).fetchone()
    return jsonify(
        {
            'reference': payment['reference'],
            'status': payment['status'],
            'packageLabel': payment['package_label'],
            'amountTzs': int(payment['amount_tzs']),
            'user': sanitize_user(user_row),
        }
    )


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
    reference = str(payload.get('reference') or payload.get('order_id') or payload.get('merchant_reference') or '').strip()
    status_raw = str(payload.get('status') or payload.get('event') or '').lower()
    provider_ref = str(payload.get('transaction_id') or payload.get('id') or '')

    if not reference:
        return jsonify({'error': 'Missing payment reference.'}), 400

    db = get_db()
    if status_raw in ('success', 'succeeded', 'completed', 'paid', 'payment.success'):
        db.execute('BEGIN IMMEDIATE')
        try:
            payment = db.execute('SELECT * FROM payments WHERE reference = ?', (reference,)).fetchone()
            if not payment:
                db.execute('ROLLBACK')
                return jsonify({'error': 'Payment reference not found.'}), 404
            if payment['status'] == 'completed':
                db.execute('COMMIT')
                return jsonify({'received': True, 'status': 'completed'})

            user_row = db.execute('SELECT id, unlimited_until FROM users WHERE id = ?', (int(payment['user_id']),)).fetchone()
            if not user_row:
                db.execute('ROLLBACK')
                return jsonify({'error': 'User not found.'}), 404

            ts = now_ms()
            if int(payment['coins_awarded'] or 0) > 0:
                db.execute('UPDATE users SET coins = coins + ? WHERE id = ?', (int(payment['coins_awarded']), int(user_row['id'])))
            if int(payment['unlimited_days'] or 0) > 0:
                cur_until = int(user_row['unlimited_until'] or 0)
                base_ts = cur_until if cur_until > ts else ts
                next_until = base_ts + int(payment['unlimited_days']) * 24 * 60 * 60 * 1000
                db.execute('UPDATE users SET unlimited_until = ? WHERE id = ?', (next_until, int(user_row['id'])))

            db.execute(
                'UPDATE payments SET status = ?, provider_ref = COALESCE(NULLIF(?, ""), provider_ref), completed_at = ? WHERE reference = ?',
                ('completed', provider_ref, ts, reference),
            )
            db.execute('COMMIT')
            return jsonify({'received': True, 'status': 'completed'})
        except Exception:
            db.execute('ROLLBACK')
            return jsonify({'error': 'Failed to settle payment.'}), 500

    if status_raw in ('failed', 'cancelled', 'canceled', 'expired', 'payment.failed'):
        db.execute('UPDATE payments SET status = ? WHERE reference = ? AND status = ?', ('failed', reference, 'pending'))
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
