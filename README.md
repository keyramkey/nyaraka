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
ADMIN_EMAILS=admin@example.com
```

Configure your Dalipay Merchant Dashboard Webhook URL to:
`https://your-vercel-domain.vercel.app/api/payments/dalipay/webhook`

## 3. Coin & Unlimited Pricing

- **Welcome Bonus:** 5 Free Coins on first registration per device/browser (`device_id` + `HttpOnly` cookie check; duplicate accounts on the same device receive 0 coins)
- **Generation Cost:** 1 Coin per TIN Certificate or Business License (0 Coins while Unlimited is active)
- **Packages:** 22 Coins (2,000 TZS) · 55 Coins (5,000 TZS) · 100 Coins (9,000 TZS) · 230 Coins (20,000 TZS) · 600 Coins (50,000 TZS) · 1,200 Coins (100,000 TZS)
- **Unlimited Plans:** 1 Month / 30 Days (30,000 TZS) · 55 Days (50,000 TZS)

## 4. Files

- `app.py` – Flask + Supabase backend (`device_id` + Cookie anti-abuse, atomic coin deduction, Dalipay API + HMAC webhook)
- `supabase_schema.sql` – Supabase PostgreSQL schema & atomic RPC functions
- `index.html` – Frontend UI with 3× HiDPI templates, dynamic QR, Device ID + Cookie registration, and Dalipay checkout
- `tin_template.png` – Updated TIN Certificate template
- `bl_template.png` – Updated Business License template
- `vercel.json` – Vercel Python serverless routing
- `requirements.txt` – Python dependencies (`flask`, `requests`, `pywebpush`)
- `sw.js`, `manifest.webmanifest`, `offline.html`, `favicon.ico`, `favicon.svg`, `icons/` – PWA (service worker, installable app, icons)
- `tools/make_icons.py`, `tools/generate_vapid.py` – icon generator and VAPID key generator (not served publicly)

## 5. Admin Dashboard

1. Re-run `supabase_schema.sql` (the migration at the bottom is safe to re-run): adds `is_blocked`, `app_settings`, and makes `email` optional.
2. Set `ADMIN_EMAILS` (comma-separated). Register that account yourself right away (phone is required, email = the admin email). On login it opens the dashboard directly.
3. Admin can: see all payments + search by reference/phone, manually confirm a payment, search/block/unblock/delete users, add or remove coins, edit package prices (add/disable packages), and run timed offers (discount %). Offers vanish automatically when time ends.
4. Users: phone number is required, email optional. Login works with phone or email.

## 6. Security Questions, Password Reset & Account Deletion

**Re-run `supabase_schema.sql`** (new migration at the bottom, safe to re-run): adds `security_answers`, `reset_fails`, `reset_locked_until` and changes `device_claims.user_id` to `ON DELETE SET NULL`.

- **Register:** user answers 3 security questions (mother's name, ward/kata, year of finishing Standard 7). Answers are stored as salted scrypt hashes (case/spaces ignored).
- **Forgot password** (link "Umesahau nenosiri?" on the Login tab): phone/email → one random question → wrong answer gives a *different* question → correct answer → set new password. 5 wrong answers lock the account for 30 min; each further wrong answer doubles the lock (max 24h). Reset tokens expire in 10 min and work once.
- **Existing users** (no questions yet): Profile → *Weka Maswali ya Usalama* (needs password). Until then forgot password tells them to contact support.
- **Change password:** Profile → *Badili Nenosiri*.
- **Delete account / data (Google Play):** in-app Profile → *Futa Akaunti na Data* (and drawer menu), plus public page **`https://your-domain/delete-account`** (also `/futa-akaunti`) — put this URL in Play Console → App content → Data safety → *Account deletion*. Deletes user, payments, generations. The anonymous device record stays (user link set to NULL) so deleting + re-registering cannot give free coins again. Admin accounts cannot be deleted from this form.


## 7. PWA + Push Notifications (arifa hata app ikiwa imefungwa)

**Hatua za kuwasha (mara moja tu):**

1. Endesha tena `supabase_schema.sql` (migration mpya chini: `push_subscriptions`, `push_messages`).
2. Tengeneza VAPID keys: `pip install cryptography` kisha `python tools/generate_vapid.py`.
3. Weka kwenye Vercel → Environment Variables kisha **Redeploy**:
   ```env
   VAPID_PUBLIC_KEY=...
   VAPID_PRIVATE_KEY=...
   VAPID_SUBJECT=mailto:your-email@example.com
   ```
   Usibadilishe keys baadaye (watumiaji wote watalazimika kuwasha arifa upya). Usiweke `VAPID_PRIVATE_KEY` kwenye GitHub.
4. `requirements.txt` sasa ina `pywebpush`; Vercel itaisakinisha wakati wa deploy.

**Kwa mtumiaji:** banner ya "Washa arifa" inaonekana baada ya sekunde chache (ukiifunga, haitarudi kwa siku 7). Pia kuna *Profile → Arifa za simu* na menu ya pembeni → *Washa Arifa* / *Weka App kwenye Simu*.
Android/Chrome: inaweka app kama PWA na arifa zinafika hata app imefungwa. iPhone (iOS 16.4+): lazima kwanza *Share → Add to Home Screen*, kisha ufungue app hiyo na uwashe arifa.

**Kwa admin:** tab mpya **Arifa**: andika kichwa + ujumbe, chagua ukurasa utakaofunguka mtu akibonyeza arifa, angalia muonekano, bonyeza *Jaribu kwangu* (inakuja kwenye simu yako tu) au *Tuma kwa wote*. Ujumbe unatumwa kwa vipande (devices 100 kwa ombi) ili usikatike kwenye Vercel. Subscriptions zilizokufa (410/404) zinafutwa zenyewe. Kwenye tab ya **Offer** kuna kisanduku "Tuma arifa ya offer kwa watumiaji wote" (kimewashwa kwa default): ukiweka offer, arifa inatumwa papo hapo.

**Usalama:** subscription endpoint inakubaliwa tu kutoka push services halali (FCM, Mozilla, Apple, Windows) ili seva isitumike kupiga URL za ndani (SSRF); link ya arifa inaruhusiwa kuwa ndani ya tovuti yako tu; admin pekee ndiye anaweza kutuma.

**Kubadilisha icon:** hariri `tools/make_icons.py` kisha endesha `python tools/make_icons.py` (inahitaji `pillow` na `numpy`). Ukibadilisha `sw.js`, badilisha `VERSION` ndani yake.
