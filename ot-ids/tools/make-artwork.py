#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Generate every branded image the ISO build kit uses from two source files.

Sources, in this repository's branding/ folder:
  branding/logo.png     square mark, 256x256, transparent corners
  branding/banner.png   full emblem with wordmark on black, 960x820

Run:  python3 ot-ids/tools/make-artwork.py        (needs Pillow: pip install pillow)

Replace the two source files with new artwork of the same layout and re-run to
regenerate everything. WORDMARK_BOX below is the wordmark's position inside
banner.png; adjust it if the banner changes.
"""
import base64
import io
import pathlib

from PIL import Image, ImageDraw

KIT = pathlib.Path(__file__).resolve().parent.parent
BR = KIT / "overlay" / "branding"
SRC = KIT.parent / "branding"
WEB = BR / "web"

WORDMARK_BOX = (24, 559, 936, 670)  # left, top, right, bottom of the lettering in banner.png
BLACK = (0, 0, 0, 255)
L = Image.LANCZOS

mark = Image.open(SRC / "logo.png").convert("RGBA")
emblem = Image.open(SRC / "banner.png").convert("RGBA")
wordmark = emblem.crop(WORDMARK_BOX)


def fit(img, w=None, h=None):
    """Scale to a target width or height, keeping the aspect ratio."""
    r = (w / img.width) if w else (h / img.height)
    return img.resize((max(1, round(img.width * r)), max(1, round(img.height * r))), L)


def canvas(w, h, color=BLACK):
    return Image.new("RGBA", (w, h), color)


def paste_center(bg, fg, cx, cy):
    bg.alpha_composite(fg, (round(cx - fg.width / 2), round(cy - fg.height / 2)))


def lockup(height, pad, gap):
    """Mark + wordmark side by side on black; returns a tight RGBA image."""
    m = fit(mark, h=height)
    wm = fit(wordmark, h=round(height * 0.62))
    img = canvas(pad + m.width + gap + wm.width + pad, height + 2 * pad)
    img.alpha_composite(m, (pad, pad))
    img.alpha_composite(wm, (pad + m.width + gap, pad + (height - wm.height) // 2))
    return img


def banner(w, h, radius=18):
    """Lockup centred on a black band with rounded corners (readable on any page colour)."""
    lk = lockup(height=h - 24, pad=0, gap=round(h * 0.16))
    if lk.width > w - 28:
        lk = fit(lk, w=w - 28)
    band = canvas(w, h)
    paste_center(band, lk, w / 2, h / 2)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, h - 1), radius=radius, fill=255)
    band.putalpha(mask)
    return band


def save(img, path, rgb=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    (img.convert("RGB") if rgb else img).save(path, optimize=True)
    print(f"  {path.relative_to(KIT)}  {img.width}x{img.height}")


print("Boot screens")
# UEFI (GRUB): the title sits on the top line and the menu starts at 52% height,
# so the emblem goes in the band between them.
grub = canvas(640, 480)
paste_center(grub, fit(emblem, h=204), 320, 140)
save(grub, BR / "splash.png", rgb=True)

# Legacy BIOS (syslinux): the menu starts 12 text rows down, so keep the emblem higher and smaller.
bios = canvas(640, 480)
paste_center(bios, fit(emblem, h=168), 320, 92)
buf = io.BytesIO()
bios.convert("RGB").save(buf, format="PNG", optimize=True)
svg = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    'version="1.1" width="640" height="480" viewBox="0 0 640 480">\n'
    '  <rect width="640" height="480" fill="#000000"/>\n'
    '  <image x="0" y="0" width="640" height="480" xlink:href="data:image/png;base64,'
    + base64.b64encode(buf.getvalue()).decode()
    + '"/>\n</svg>\n'
)
(BR / "splash.svg").write_text(svg)
print("  overlay/branding/splash.svg  640x480")

print("Desktop wallpaper")
wall = canvas(1920, 1080)
paste_center(wall, fit(emblem, h=700), 960, 540)
save(wall, BR / "wallpaper.png", rgb=True)

print("Web: icons")
for size in (16, 24, 32, 48, 64, 70, 144, 150, 192, 310, 512):
    save(mark.resize((size, size), L), WEB / "favicon" / f"favicon{size}.png")
save(mark.resize((114, 114), L), WEB / "favicon" / "apple-touch-icon-precomposed.png")
save(mark.resize((110, 110), L), WEB / "favicon" / "facebook.png")
for folder in ("favicon", "icon"):
    (WEB / folder).mkdir(parents=True, exist_ok=True)
    mark.save(WEB / folder / "favicon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64)])
    print(f"  overlay/branding/web/{folder}/favicon.ico")
big = mark.resize((450, 450), L)
save(big, WEB / "icon" / "icon.png")        # dashboards mark and loading logo (light theme)
save(big, WEB / "icon" / "icon_dark.png")   # same, dark theme

print("Web: banners")
save(banner(986, 168), WEB / "logo" / "Malcolm_outline_banner_dark.png")  # dashboards header logo
save(banner(998, 266, radius=24), WEB / "logo" / "Malcolm_outline_banner.png")
save(banner(978, 163), WEB / "logo" / "Malcolm_banner.png")               # upload page banner
save(banner(986, 168), WEB / "brand-banner.png")                          # general use
save(banner(480, 82, radius=10), WEB / "brand-report-header.png")         # report header

print("Web: landing page header")
# The page shows only the middle band of this image (about 290 px of 1080), so
# the lockup has to sit in that band.
mast = canvas(1920, 1080)
lk = lockup(height=190, pad=0, gap=34)
if lk.width > 1300:
    lk = fit(lk, w=1300)
paste_center(mast, lk, 960, 540)
save(mast, WEB / "masthead.png", rgb=True)
print("done")
