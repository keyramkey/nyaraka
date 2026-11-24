# TRA Documents Exact Filler

TIN Certificate + Business License generator (Tanzania Revenue Authority style).

## Deploy on Vercel (Recommended)

1. Push this repo to GitHub
2. Go to https://vercel.com → New Project → Import GitHub repo
3. Framework Preset: **Other**
4. Click **Deploy**

No build needed. Works as pure static site.

## Run locally with Python

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Run as pure static (no Python)

```bash
# Python
python -m http.server 8000

# or Node
npx serve .
```

## Files

- `index.html` – main app
- `tin_template.png` – TIN Certificate template
- `bl_template.png` – Business License template
- `app.py` – optional Flask server
