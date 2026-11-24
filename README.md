# TRA Documents Exact Filler

TIN Certificate + Business License generator with Coin Wallet, Device Anti-Abuse (Cookie + `device_id`), Unlimited Plans, and Dalipay Checkout + Webhook.

## Environment Variables (Required for Dalipay)

Set these on your server or `.env` (never expose secret keys in client JS):

```env
DALIPAY_PUBLIC_KEY=your_dalipay_public_key
DALIPAY_SECRET_KEY=your_dalipay_secret_key
DALIPAY_CALLBACK_SECRET=your_dalipay_callback_secret
DALIPAY_API_URL=https://api.dalipay.co.tz/v1/payments/mobile
SESSION_SECRET=your_random_session_secret
```

Configure your Dalipay Merchant Dashboard Webhook URL to:
`https://yourdomain.com/api/payments/dalipay/webhook`

## Coin & Unlimited Pricing

- **Welcome Bonus:** 10 Free Coins on first registration per device/browser (`device_id` + `HttpOnly` cookie check; duplicate accounts on the same device receive 0 coins)
- **Generation Cost:** 5 Coins per TIN Certificate or Business License (0 Coins while Unlimited is active)
- **Packages:** 22 Coins (2,000 TZS) · 55 Coins (5,000 TZS) · 100 Coins (9,000 TZS) · 230 Coins (20,000 TZS) · 600 Coins (50,000 TZS) · Custom amount
- **Unlimited Plans:** 1 Month / 30 Days (30,000 TZS) · 55 Days (50,000 TZS)

## Run locally with Python (Flask)

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Files

- `index.html` – Frontend UI with 3× HiDPI templates, dynamic QR, Device ID + Cookie registration, and Dalipay checkout
- `app.py` – Flask + SQLite backend (`device_id` + Cookie anti-abuse, 5-coin deduction, Dalipay API + HMAC webhook)
- `tin_template.png` – Updated TIN Certificate template
- `bl_template.png` – Updated Business License template
- `requirements.txt` – Python dependencies
