#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generates the kernoid brand kit: master SVGs, PNG exports, favicon.ico and the website's head icons.

The mark is >0<: two brackets point at a 0 with a dot in its middle. The 0 is the core and its orbit at once – the
kernel of an injective map (ker f = {0}), ring 0 where a kernel runs; the dot is the core inside the core; the
brackets say that everything maps onto it. It is drawn glitched: a violet and a mint channel shifted apart, one band
torn sideways, a few stray pixels. Small sizes (favicon, 16–48 px) use the 0 alone, without the glitch, in glitch
white (violet + mint added as light).

The wordmark is set in IBM Plex Mono Bold (fonts/, SIL OFL 1.1) and converted to outlines, so it needs no font where it
is shown: "kern" + the 0 of the mark + "id". Only the 0 glitches; "kern" is glitch white (glitch black on light),
"id" is mint. The dot in the 0 is also the dot of kern.id and kerno.id.

Needs rsvg-convert (Homebrew: librsvg) and fontTools (pip install fonttools). Run from anywhere:
    python3 generate.py
Edit this file, not the exports.
"""
import os, shutil, struct, subprocess

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
SVG, PNG, WEB = (os.path.join(HERE, d) for d in ("svg", "png", "web"))

NIGHT = "#0B0D10"       # near-black – backgrounds
SHELL = "#D8FFFF"       # glitch white: violet + mint added as light (#9B8CFF + #3DDC97, clamped) – strokes, text on dark
MINT = "#3DDC97"        # the core, "oid", the one accent
VIOLET = "#9B8CFF"      # the second glitch channel – only inside the glitch, never as a second accent
STEEL = "#5B7083"       # rules, secondary
REED = "#7D8590"        # muted text
INK = "#052345"         # glitch black: dark violet × dark mint multiplied like inks (#5B47D6 × #0F7F52) – strokes, text on light
MINT_DARK = "#0F7F52"   # mint on light backgrounds
VIOLET_DARK = "#5B47D6" # violet on light backgrounds
GRID = "#151A20"        # faint grid on dark

GLITCH_WHITE = SHELL

DARK = dict(face=SHELL, mint=MINT, violet=VIOLET, bg=NIGHT, text=GLITCH_WHITE)
LIGHT = dict(face=INK, mint=MINT_DARK, violet=VIOLET_DARK, bg="#FFFFFF", text=INK)

# --- mark (drawn in a 120×70 box) ----------------------------------------------------------------------------------

BRACKETS = '<path d="M14,15 L34,35 L14,55"/><path d="M106,15 L86,35 L106,55"/>'
ZERO = '<path d="M53,12 H67 L72,17 V53 L67,58 H53 L48,53 V17 Z"/>'
DOT = (57, 32, 6)         # the core: x, y, size
SHIFT = 3                 # channel offset (violet left, mint right)
TEAR = (27, 8, 6)         # torn band: y, height, sideways shift
NOISE = [                 # stray pixels: x, y, w, h, channel
    (38, 6, 5, 2, "mint"), (80, 62, 7, 2, "mint"), (2, 38, 4, 2, "mint"), (74, 4, 2, 2, "mint"),
    (110, 18, 6, 2, "violet"), (28, 63, 6, 2, "violet"), (96, 58, 3, 3, "violet"),
    (90, 7, 3, 3, "face"), (20, 3, 2, 2, "face"), (113, 40, 2, 2, "face"),
]
MARK_BOX = "0 0 120 70"


def strokes(color, width=7):
    return (f'<g fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="miter">'
            f'{BRACKETS}{ZERO}</g>')


def mark(p=DARK, uid="m", noise=True):
    """The glitched >0<. uid keeps mask/clip ids unique when several marks share one SVG."""
    y, h, dx = TEAR
    x, yy, s = DOT
    defs = (f'<defs><mask id="{uid}-cut"><rect x="-20" y="-20" width="160" height="110" fill="#fff"/>'
            f'<rect x="-20" y="{y}" width="160" height="{h}" fill="#000"/></mask>'
            f'<clipPath id="{uid}-band"><rect x="-20" y="{y}" width="160" height="{h}"/></clipPath></defs>')
    layers = (f'<g transform="translate({-SHIFT} 0)">{strokes(p["violet"])}</g>'
              f'<g transform="translate({SHIFT} 0)">{strokes(p["mint"])}</g>'
              + strokes(p["face"], 5))
    torn = f'<g clip-path="url(#{uid}-band)"><g transform="translate({dx} 0)">{strokes(p["face"], 5)}</g></g>'
    dust = "".join(f'<rect x="{a}" y="{b}" width="{w}" height="{hh}" fill="{p[c]}"/>'
                   for a, b, w, hh, c in NOISE) if noise else ""
    return (defs + f'<g mask="url(#{uid}-cut)">{layers}</g>' + torn
            + f'<rect x="{x}" y="{yy}" width="{s}" height="{s}" fill="{p["mint"]}"/>' + dust)


def flat_mark(face, kern):
    """One- or two-colour >0< without glitch – single-colour print, stamps."""
    x, y, s = DOT
    return (f'<g fill="none" stroke="{face}" stroke-width="7" stroke-linejoin="miter">{BRACKETS}</g>'
            f'<g fill="none" stroke="{kern}" stroke-width="7" stroke-linejoin="miter">{ZERO}</g>'
            f'<rect x="{x}" y="{y}" width="{s}" height="{s}" fill="{kern}"/>')


def small_zero(kern=GLITCH_WHITE, width=9, dot=True):
    """The 0 alone, without glitch – favicon and small icons. Centred in its own 40×56 box (0 0 40 56)."""
    body = (f'<path d="M14,6 H26 L32,12 V44 L26,50 H14 L8,44 V12 Z" fill="none" stroke="{kern}" '
            f'stroke-width="{width}" stroke-linejoin="miter"/>')
    return body + (f'<rect x="16.5" y="24.5" width="7" height="7" fill="{kern}"/>' if dot else "")


def placed(body, cx, cy, width, box=(120, 70)):
    """Places a box-sized drawing so that its centre lands on cx/cy at the given width."""
    k = width / box[0]
    return f'<g transform="translate({cx} {cy}) scale({k:.4f}) translate({-box[0] / 2} {-box[1] / 2})">{body}</g>'


def icon(bg=NIGHT, rounded=True, uid="icon"):
    """App/avatar icon: the glitched mark on night, rounded square (macOS-like radius) or full bleed."""
    r = 160 if rounded else 0
    return svg("0 0 1024 1024", f'<rect width="1024" height="1024" rx="{r}" fill="{bg}"/>'
               + placed(mark(uid=uid), 512, 512, 860))


def small_icon(bg=NIGHT):
    """16–48 px: the 0 alone on night, no glitch."""
    return svg("0 0 1024 1024", f'<rect width="1024" height="1024" rx="160" fill="{bg}"/>'
               + placed(small_zero(dot=True), 512, 512, 480, box=(40, 56)))


# --- wordmark (IBM Plex Mono Bold as outlines; baseline y=100, x-height 56) --------------------------------------------

FONT = os.path.join(HERE, "fonts", "IBMPlexMono-Bold.ttf")
XH = 56.0                 # x-height in wordmark units
Z_STEM = 0.195            # stroke of the 0, as a share of the x-height – matches the weight of IBM Plex Mono Bold
Z_SHIFT = 0.28            # channel offset, as a share of the stroke
Z_TEAR = (0.72, 0.15, 0.5)  # torn band: top (share of x-height above the baseline), height (share), shift (share of stroke)
Z_NOISE = [(-0.8, 0.85, 5, 3, "mint"), (0.75, 1.0, 4, 3, "violet"), (0.6, -0.08, 7, 3, "mint"),
           (-0.9, 0.12, 4, 3, "violet"), (0.05, 1.18, 3, 3, "text")]   # x (share of the 0's width), y (share of x-height)
_FONT = None


def font():
    global _FONT
    if _FONT is None:
        f = TTFont(FONT)
        _FONT = (f.getGlyphSet(), f.getBestCmap(), f["hmtx"], XH / f["OS/2"].sxHeight)
    return _FONT


def glyph_bounds(ch):
    gs, cmap, _, k = font()
    bp = BoundsPen(gs)
    gs[cmap[ord(ch)]].draw(bp)
    return [v * k for v in bp.bounds]


def zero_glyph(p, zx, zw, uid, glitch=True):
    """The 0 of the mark, set into the space of the font's o (x from zx, width zw)."""
    s = XH * Z_STEM
    x0, x1, y0, y1 = zx + s / 2, zx + zw - s / 2, 100 - XH - 1 + s / 2, 100 + 1 - s / 2
    c = min(x1 - x0, y1 - y0) * 0.28
    d = (f"M{x0 + c:.2f},{y0:.2f} H{x1 - c:.2f} L{x1:.2f},{y0 + c:.2f} V{y1 - c:.2f} L{x1 - c:.2f},{y1:.2f} "
         f"H{x0 + c:.2f} L{x0:.2f},{y1 - c:.2f} V{y0 + c:.2f} Z")
    zero = lambda col, w: f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{w:.2f}" stroke-linejoin="miter"/>'
    dot = s * 0.95
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    core = f'<rect x="{cx - dot / 2:.2f}" y="{cy - dot / 2:.2f}" width="{dot:.2f}" height="{dot:.2f}" fill="{p["mint"]}"/>'
    if not glitch:
        return zero(p["text"], s) + core
    top, shift = s * 0.72, s * Z_SHIFT
    ty, th, tdx = 100 - XH * Z_TEAR[0], XH * Z_TEAR[1], s * Z_TEAR[2]
    defs = (f'<defs><mask id="{uid}-cut"><rect x="{zx - 40:.1f}" y="-20" width="{zw + 80:.1f}" height="160" fill="#fff"/>'
            f'<rect x="{zx - 40:.1f}" y="{ty:.2f}" width="{zw + 80:.1f}" height="{th:.2f}" fill="#000"/></mask>'
            f'<clipPath id="{uid}-band"><rect x="{zx - 40:.1f}" y="{ty:.2f}" width="{zw + 80:.1f}" height="{th:.2f}"/>'
            f'</clipPath></defs>')
    layers = (f'<g transform="translate({-shift:.2f} 0)">{zero(p["violet"], s)}</g>'
              f'<g transform="translate({shift:.2f} 0)">{zero(p["mint"], s)}</g>' + zero(p["text"], top))
    torn = f'<g clip-path="url(#{uid}-band)"><g transform="translate({tdx:.2f} 0)">{zero(p["text"], top)}</g></g>'
    dust = "".join(f'<rect x="{cx + a * zw:.1f}" y="{100 - XH * b:.1f}" width="{w}" height="{h}" fill="{p[col]}"/>'
                   for a, b, w, h, col in Z_NOISE)
    return defs + f'<g mask="url(#{uid}-cut)">{layers}</g>' + torn + core + dust


def wordmark_body(p=DARK, text="kern0id", uid="wm", glitch=True):
    """Sets text in IBM Plex Mono Bold; "0" becomes the 0 of the mark, "id" (and ".id") is mint."""
    gs, cmap, hmtx, k = font()
    ob = glyph_bounds("o")
    x, parts, zero = 0.0, [], ""
    for i, ch in enumerate(text):
        g = cmap[ord("o" if ch == "0" else ch)]
        if ch == "0":
            zero = zero_glyph(p, x + ob[0], ob[2] - ob[0], uid, glitch)
        else:
            sp = SVGPathPen(gs)
            gs[g].draw(TransformPen(sp, (k, 0, 0, -k, x, 100)))
            mint = ch in "id" and text.find("id") <= i or ch == "." and text.endswith(".id")
            parts.append(f'<path d="{sp.getCommands()}" fill="{p["mint"] if mint else p["text"]}"/>')
        x += hmtx[g][0] * k
    return "".join(parts) + zero, x


WM_TOP = 18               # top of the wordmark box (above the ascenders and the noise)


def wordmark(p=DARK, text="kern0id", uid="wm", glitch=True):
    body, width = wordmark_body(p, text, uid, glitch)
    return svg(f"-12 {WM_TOP} {width + 24} {112 - WM_TOP}", body)


def lockup(p=DARK, uid="lockup"):
    """Mark left, wordmark right – headers, documents."""
    body, width = wordmark_body(p, uid=uid + "-wm")
    mark_w = 170
    x0 = mark_w + 34
    return svg(f"-12 {WM_TOP - 6} {x0 + width + 24} {112 - WM_TOP + 12}",
               placed(mark(p, uid=uid), mark_w / 2, 63, mark_w) + f'<g transform="translate({x0} 0)">{body}</g>')


def social():
    """1280×640: GitHub social preview, link previews – terminal style."""
    body, width = wordmark_body(DARK, uid="social-wm")
    mono = 'font-family="IBM Plex Mono, SF Mono, Menlo, Consolas, monospace"'
    grid = "".join(f'<line x1="{x}" y1="0" x2="{x}" y2="640" stroke="{GRID}"/>' for x in range(0, 1281, 64)) + \
           "".join(f'<line x1="0" y1="{y}" x2="1280" y2="{y}" stroke="{GRID}"/>' for y in range(0, 641, 64))
    return svg("0 0 1280 640", f'<rect width="1280" height="640" fill="{NIGHT}"/>{grid}'
               + placed(mark(uid="social"), 280, 320, 420) +
               f'<text x="560" y="168" {mono} font-size="26" fill="{REED}">$ dig +short kerno.id</text>'
               f'<g transform="translate(556 186) scale(1.35)">{body}</g>'
               f'<text x="562" y="420" {mono} font-size="28" fill="{SHELL}">email · identity · storage – one core</text>'
               f'<text x="562" y="466" {mono} font-size="24" fill="{REED}">// sovereign, free software · a falkOSS project</text>'
               f'<rect x="562" y="492" width="16" height="30" fill="{MINT}"/>')


def favicon_svg():
    """The 0 alone, transparent, no glitch: glitch white on dark tabs, ink on light ones."""
    style = (f'<style>.k{{stroke:{GLITCH_WHITE}}}.d{{fill:{GLITCH_WHITE}}}'
             f'@media (prefers-color-scheme: light){{.k{{stroke:{INK}}}.d{{fill:{INK}}}}}</style>')
    body = small_zero().replace(f'stroke="{GLITCH_WHITE}"', 'class="k"').replace(f'fill="{GLITCH_WHITE}"', 'class="d"')
    return svg("-8 0 56 56", style + body)


# --- output ----------------------------------------------------------------------------------------------------------

def svg(view_box, body, size=None):
    dims = f' width="{size[0]}" height="{size[1]}"' if size else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}"{dims}>\n{body}\n</svg>\n'


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def render(src, dst, w, h=None):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    args = ["rsvg-convert", "-w", str(w)] + (["-h", str(h)] if h else []) + ["-o", dst, src]
    subprocess.run(args, check=True)


def ico(dst, pngs):
    """favicon.ico with PNG entries (16, 32, 48)."""
    data = [open(p, "rb").read() for p in pngs]
    out = struct.pack("<HHH", 0, 1, len(data))
    offset = 6 + 16 * len(data)
    for s, d in zip((16, 32, 48), data):
        out += struct.pack("<BBBBHHII", s, s, 0, 0, 1, 32, len(d), offset)
        offset += len(d)
    with open(dst, "wb") as f:
        f.write(out + b"".join(data))


def main():
    for d in (SVG, PNG, WEB):
        if os.path.isdir(d):
            shutil.rmtree(d)   # generated output only
    files = {
        "kernoid-icon.svg": icon(),
        "kernoid-icon-square.svg": icon(rounded=False),
        "kernoid-icon-small.svg": small_icon(),
        "kernoid-mark-on-dark.svg": svg(MARK_BOX, mark(DARK)),
        "kernoid-mark-on-light.svg": svg(MARK_BOX, mark(LIGHT)),
        "kernoid-mark-black.svg": svg(MARK_BOX, flat_mark("#000000", "#000000")),
        "kernoid-mark-white.svg": svg(MARK_BOX, flat_mark("#FFFFFF", "#FFFFFF")),
        "kernoid-zero-on-dark.svg": svg("-8 0 56 56", small_zero(GLITCH_WHITE)),
        "kernoid-zero-on-light.svg": svg("-8 0 56 56", small_zero(INK)),
        "kernoid-wordmark-on-dark.svg": wordmark(DARK, uid="wmd"),
        "kernoid-wordmark-on-light.svg": wordmark(LIGHT, uid="wml"),
        "kernoid-wordmark-flat-on-dark.svg": wordmark(DARK, uid="wfd", glitch=False),
        "kernoid-wordmark-flat-on-light.svg": wordmark(LIGHT, uid="wfl", glitch=False),
        "kernoid-lockup-on-dark.svg": lockup(DARK),
        "kernoid-lockup-on-light.svg": lockup(LIGHT),
        "kernoid-social-1280x640.svg": social(),
        "favicon.svg": favicon_svg(),
    }
    for name, content in files.items():
        write(os.path.join(SVG, name), content)
    s = lambda n: os.path.join(SVG, n)
    for size in (64, 128, 256, 512, 1024):
        render(s("kernoid-icon.svg"), os.path.join(PNG, "icon", f"kernoid-icon-{size}.png"), size)
        render(s("kernoid-icon-square.svg"), os.path.join(PNG, "icon-square", f"kernoid-icon-square-{size}.png"), size)
    for size in (16, 32, 48):
        render(s("kernoid-icon-small.svg"), os.path.join(PNG, "icon-small", f"kernoid-icon-small-{size}.png"), size)
    for size in (256, 512, 1024):
        for v in ("on-dark", "on-light", "black", "white"):
            render(s(f"kernoid-mark-{v}.svg"), os.path.join(PNG, "mark", f"kernoid-mark-{v}-{size}.png"), size)
    for v in ("on-dark", "on-light"):
        render(s(f"kernoid-wordmark-{v}.svg"), os.path.join(PNG, "wordmark", f"kernoid-wordmark-{v}-1200.png"), 1200)
        render(s(f"kernoid-wordmark-flat-{v}.svg"), os.path.join(PNG, "wordmark", f"kernoid-wordmark-flat-{v}-1200.png"), 1200)
        render(s(f"kernoid-lockup-{v}.svg"), os.path.join(PNG, "lockup", f"kernoid-lockup-{v}-1200.png"), 1200)
    render(s("kernoid-icon-square.svg"), os.path.join(PNG, "social", "github-avatar-500.png"), 500)
    render(s("kernoid-social-1280x640.svg"), os.path.join(PNG, "social", "kernoid-social-1280x640.png"), 1280, 640)

    # Website head assets (copied into the website repository)
    os.makedirs(WEB, exist_ok=True)
    shutil.copy(s("favicon.svg"), os.path.join(WEB, "favicon.svg"))
    render(s("kernoid-icon-square.svg"), os.path.join(WEB, "apple-touch-icon.png"), 180)
    render(s("kernoid-icon.svg"), os.path.join(WEB, "icon-192.png"), 192)
    render(s("kernoid-icon.svg"), os.path.join(WEB, "icon-512.png"), 512)
    shutil.copy(os.path.join(PNG, "social", "kernoid-social-1280x640.png"), os.path.join(WEB, "social.png"))
    ico(os.path.join(WEB, "favicon.ico"),
        [os.path.join(PNG, "icon-small", f"kernoid-icon-small-{n}.png") for n in (16, 32, 48)])
    write(os.path.join(WEB, "site.webmanifest"),
          '{\n  "name": "kernoid",\n  "short_name": "kernoid",\n  "icons": [\n'
          '    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},\n'
          '    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}\n  ],\n'
          f'  "theme_color": "{NIGHT}",\n  "background_color": "{NIGHT}",\n  "display": "standalone"\n}}\n')
    print("brand kit written to", HERE)


if __name__ == "__main__":
    main()
