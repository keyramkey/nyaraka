"""Generates all PWA icons / favicons into ./icons (run: python tools/make_icons.py).
Needs: pip install pillow numpy"""
import os
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'icons')
os.makedirs(OUT, exist_ok=True)
S = 1024  # master canvas; everything is drawn on a 512 grid and scaled x2


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(size, c1, c2, c3=None):
    y, x = np.mgrid[0:size, 0:size].astype(np.float32)
    t = np.clip((x + y) / (2 * (size - 1)), 0, 1)[..., None]
    c1, c2 = np.array(c1, np.float32), np.array(c2, np.float32)
    if c3 is None:
        arr = c1 + (c2 - c1) * t
    else:
        c3 = np.array(c3, np.float32)
        arr = np.where(t < .55, c1 + (c2 - c1) * (t / .55), c2 + (c3 - c2) * ((t - .55) / .45))
    return Image.fromarray(arr.astype(np.uint8), 'RGB').convert('RGBA')


def rr(d, box, r, fill):
    d.rounded_rectangle([v * 2 for v in box], radius=r * 2, fill=fill)


def layer():
    return Image.new('RGBA', (S, S), (0, 0, 0, 0))


def shadow(img, blur=14, dy=10, alpha=90):
    a = img.split()[3].point(lambda v: int(v * alpha / 255))
    sh = Image.new('RGBA', img.size, (4, 12, 24, 0))
    sh.putalpha(a)
    sh = sh.filter(ImageFilter.GaussianBlur(blur * 2))
    out = Image.new('RGBA', img.size, (0, 0, 0, 0))
    out.paste(sh, (0, dy * 2), sh)
    return out


def artwork(simple=False):
    """The pictogram (two sheets + check badge), drawn on a transparent 1024 canvas, fitted to ~ 72% of it."""
    art = layer()
    # back sheet (the "copy"), rotated
    back = layer()
    rr(ImageDraw.Draw(back), (150, 92, 354, 356), 26, (255, 255, 255, 120))
    back = back.rotate(9, resample=Image.BICUBIC, center=(256 * 2, 256 * 2))
    art.alpha_composite(back)
    # front sheet
    front = layer()
    d = ImageDraw.Draw(front)
    rr(d, (142, 118, 372, 420), 30, (255, 255, 255, 255))
    # folded corner
    d.polygon([(300 * 2, 118 * 2), (372 * 2, 190 * 2), (372 * 2, 158 * 2), (332 * 2, 118 * 2)], fill=(255, 255, 255, 255))
    d.polygon([(300 * 2, 118 * 2), (372 * 2, 190 * 2), (330 * 2, 190 * 2), (300 * 2, 160 * 2)], fill=(186, 230, 224, 255))
    # content
    rr(d, (176, 168, 262, 190), 11, (15, 118, 110, 255))
    if not simple:
        rr(d, (176, 214, 338, 230), 8, (203, 213, 225, 255))
        rr(d, (176, 248, 338, 264), 8, (203, 213, 225, 255))
        rr(d, (176, 282, 296, 298), 8, (203, 213, 225, 255))
    art.alpha_composite(shadow(front, 12, 8, 70))
    art.alpha_composite(front)
    # check badge
    badge = layer()
    d = ImageDraw.Draw(badge)
    cx, cy, r = 352, 372, 78
    d.ellipse([(cx - r - 10) * 2, (cy - r - 10) * 2, (cx + r + 10) * 2, (cy + r + 10) * 2], fill=(255, 255, 255, 255))
    g = gradient(S, (52, 211, 153), (5, 150, 105))
    m = Image.new('L', (S, S), 0)
    ImageDraw.Draw(m).ellipse([(cx - r) * 2, (cy - r) * 2, (cx + r) * 2, (cy + r) * 2], fill=255)
    badge.paste(g, (0, 0), m)
    d = ImageDraw.Draw(badge)
    pts = [((cx - 34) * 2, (cy + 2) * 2), ((cx - 10) * 2, (cy + 26) * 2), ((cx + 36) * 2, (cy - 24) * 2)]
    d.line(pts, fill=(255, 255, 255, 255), width=26 if not simple else 32, joint='curve')
    for p in (pts[0], pts[2]):
        d.ellipse([p[0] - 13, p[1] - 13, p[0] + 13, p[1] + 13], fill=(255, 255, 255, 255))
    art.alpha_composite(shadow(badge, 10, 8, 80))
    art.alpha_composite(badge)
    return art


def fit(art, scale, dx=0, dy=0):
    """Scale artwork about the canvas centre."""
    n = int(S * scale)
    a = art.resize((n, n), Image.LANCZOS)
    out = layer()
    out.alpha_composite(a, ((S - n) // 2 + dx, (S - n) // 2 + dy))
    return out


def background(radius_frac=None):
    bg = gradient(S, (20, 184, 166), (13, 105, 112), (11, 19, 36))
    # soft highlight top-left
    hl = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(hl).ellipse([-300, -380, 760, 520], fill=(255, 255, 255, 46))
    hl = hl.filter(ImageFilter.GaussianBlur(90))
    bg.alpha_composite(hl)
    if radius_frac:
        m = Image.new('L', (S, S), 0)
        ImageDraw.Draw(m).rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * radius_frac), fill=255)
        bg.putalpha(m)
    return bg


def save(img, name, size):
    img.resize((size, size), Image.LANCZOS).save(os.path.join(OUT, name), optimize=True)


art, art_simple = artwork(), artwork(simple=True)

# any-purpose (rounded, transparent corners)
base = background(0.225)
base.alpha_composite(fit(art, 1.0, 0, 6))
save(base, 'icon-512.png', 512)
save(base, 'icon-192.png', 192)

# maskable: full-bleed, content inside the 80% safe zone
mk = background()
mk.alpha_composite(fit(art, 0.74, 0, 4))
save(mk, 'icon-maskable-512.png', 512)
save(mk, 'icon-maskable-192.png', 192)

# iOS home screen icon: opaque, no transparency (iOS rounds it itself)
ap = background()
ap.alpha_composite(fit(art, 0.9, 0, 4))
save(ap.convert('RGB').convert('RGBA'), 'apple-touch-icon.png', 180)

# favicons: simplified art, bigger on the tile
fv = background(0.22)
fv.alpha_composite(fit(art_simple, 1.12, -6, 8))
save(fv, 'favicon-32.png', 32)
save(fv, 'favicon-16.png', 16)
save(fv, 'favicon-48.png', 48)
fv.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, '..', 'favicon.ico'), sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])

# notification badge: MUST be monochrome (white on transparent) - Android uses only the alpha channel
b = layer()
d = ImageDraw.Draw(b)
rr(d, (120, 70, 392, 442), 44, (255, 255, 255, 255))
d.polygon([(312 * 2, 70 * 2), (392 * 2, 150 * 2), (392 * 2, 70 * 2)], fill=(0, 0, 0, 0))
cut = layer()
dc = ImageDraw.Draw(cut)
dc.line([(190 * 2, 262 * 2), (238 * 2, 310 * 2), (326 * 2, 210 * 2)], fill=(255, 255, 255, 255), width=40, joint='curve')
for p in ((190 * 2, 262 * 2), (326 * 2, 210 * 2)):
    dc.ellipse([p[0] - 20, p[1] - 20, p[0] + 20, p[1] + 20], fill=(255, 255, 255, 255))
a = b.split()[3]
ca = cut.split()[3]
a = Image.fromarray(np.clip(np.array(a, np.int16) - np.array(ca, np.int16), 0, 255).astype(np.uint8), 'L')
badge = Image.new('RGBA', (S, S), (255, 255, 255, 0))
badge.putalpha(a)
save(badge, 'badge-96.png', 96)

# social / splash style large image used in notifications & share previews
print('OK ->', sorted(os.listdir(OUT)))
