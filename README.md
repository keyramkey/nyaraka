# TRA Documents Exact Filler

TIN Certificate + Business License generator with **Supabase** database, Coin Wallet, Device Anti-Abuse (`HttpOnly` Cookie + `device_id`), Unlimited Plans, and Dalipay Checkout + Webhook.

## 1. Setup Supabase Database

1. Open your Supabase project → **SQL Editor**.
2. Paste and run the contents of `supabase_schema.sql`.
3. This creates `users`, `device_claims`, `payments`, `generations`, enables Row Level Security, and creates atomic RPC functions (`deduct_generation_coins`, `settle_dalipay_payment`).

## 2. Environment Variables on Vercel

Add these in Vercel → **Project Settings → Environment Variables** (server-side only):

```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
DALIPAY_PUBLIC_KEY=your_dalipay_public_key
DALIPAY_SECRET_KEY=your_dalipay_secret_key
DALIPAY_CALLBACK_SECRET=your_dalipay_callback_secret
DALIPAY_BASE_URL=https://app.dalipay.co.tz
SESSION_SECRET=your_random_64_char_secret
CONTACT_WHATSAPP=255754000000
CONTACT_PHONE=0754000000
```

Configure your Dalipay Merchant Dashboard Webhook URL to:
`https://your-vercel-domain.vercel.app/api/payments/dalipay/webhook`

## 3. Coin & Unlimited Pricing

- **Welcome Bonus:** 10 Free Coins on first registration per device/browser (`device_id` + `HttpOnly` cookie check; duplicate accounts on the same device receive 0 coins)
- **Generation Cost:** 5 Coins per TIN Certificate or Business License (0 Coins while Unlimited is active)
- **Packages:** 22 Coins (2,000 TZS) · 55 Coins (5,000 TZS) · 100 Coins (9,000 TZS) · 230 Coins (20,000 TZS) · 600 Coins (50,000 TZS) · 1,200 Coins (100,000 TZS)
- **Unlimited Plans:** 1 Month / 30 Days (30,000 TZS) · 55 Days (50,000 TZS)

## 4. Files

- `app.py` – Flask + Supabase backend (`device_id` + Cookie anti-abuse, atomic coin deduction, Dalipay API + HMAC webhook)
- `supabase_schema.sql` – Supabase PostgreSQL schema & atomic RPC functions
- `index.html` – Frontend UI with 3× HiDPI templates, dynamic QR, Device ID + Cookie registration, and Dalipay checkout
- `tin_template.png` – Updated TIN Certificate template
- `bl_template.png` – Updated Business License template
- `vercel.json` – Vercel Python serverless routing
- `requirements.txt` – Python dependencies (`flask`, `requests`)
