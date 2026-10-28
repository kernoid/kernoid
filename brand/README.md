# kernoid – brand kit

**kernoid** – one sovereign core for email, identity and storage. The name joins *kerno* (Esperanto: core, kernel)
and *id* (identity); *-oid* nods to algebraic structures like the monoid – small, closed, composable.

Everything here is generated: edit `generate.py`, then run `python3 generate.py` (needs `rsvg-convert` from Homebrew
`librsvg` and `fontTools`: `pip install fonttools`). It writes `svg/`, `png/` and `web/`.

## Marks

The look is a terminal with a fault in it: near-black, light strokes, mint as the one accent – and one controlled
glitch. Straight cuts, no gradients, no glow.

- **Mark** – `>0<`: two brackets point at a **0 with a dot** in its middle.
  - The 0 is the core and its orbit at once: the kernel of an injective map (**ker f = {0}**), **ring 0** where a
    kernel runs. The dot is the core inside the core. The brackets say that everything maps onto it.
  - It is drawn **glitched**: a violet and a mint channel shifted apart, the light layer on top, one band torn
    sideways, a few stray pixels. Parameters in `generate.py`: `SHIFT`, `TEAR`, `NOISE`.
- **Wordmark** – `kern0id`, set in **IBM Plex Mono Bold** and converted to outlines (no font needed where it is
  shown). The o is the 0 of the mark and the **only part that glitches**; `kern` is glitch white (glitch black on
  light), `id` is mint. The dot in the 0 doubles as the dot of the domains: read the 0 as an o and it says
  **kerno.id**, leave it out and it says **kern.id**.
- **Flat wordmark** – the same without the glitch, for small sizes and running headers.
- **Lockup** – mark left, wordmark right.
- **Icon** – the glitched mark on near-black; **small icon** and **favicon** (16–48 px) – the 0 alone, without
  glitch, in glitch white.
- **Social preview** – a prompt: `$ dig +short kerno.id` → kern0id, on a faint grid, with a block cursor.

Always written in lowercase – **kernoid**, also at the start of a sentence and in titles; the same in handles and
domains.

## Where to use what

| Use | File |
|---|---|
| GitHub org avatar | `png/social/github-avatar-500.png` |
| GitHub social preview, link previews | `png/social/kernoid-social-1280x640.png` |
| Website `<head>` | `web/` – favicon.svg (follows light/dark), favicon.ico, apple-touch-icon.png, icon-192/512.png, site.webmanifest, social.png |
| Headers, documents on dark / light | `svg/kernoid-lockup-on-dark.svg`, `-on-light.svg` (PNG: `png/lockup/`) |
| Wordmark alone | `svg/kernoid-wordmark-on-dark.svg`, `-on-light.svg`; without glitch: `-flat-` |
| Mark alone (transparent) | `svg/kernoid-mark-on-dark.svg`, `-on-light.svg`; one colour, no glitch: `-black.svg`, `-white.svg` |
| The 0 alone | `svg/kernoid-zero-on-dark.svg`, `-on-light.svg` |
| App-like icon | `png/icon/` (rounded), `png/icon-square/` (edge to edge), `png/icon-small/` (16–48 px) |
| Print, stickers | the SVGs (vector); the one-colour marks for single-colour print, stamps, lasering |

Website head:

```html
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
```

## Colours

| Name | Hex | Use |
|---|---|---|
| Night | `#0B0D10` | backgrounds |
| Glitch white | `#D8FFFF` | strokes and text on dark, favicon – violet + mint **added as light** (`#9B8CFF + #3DDC97`, clamped) |
| Mint | `#3DDC97` | the dot, `id`, the one accent (links, cursor, highlights); one glitch channel |
| Violet | `#9B8CFF` | the other glitch channel – **only inside the glitch**, never as a second accent |
| Steel | `#5B7083` | rules, secondary |
| Reed | `#7D8590` | muted text, comments |
| Glitch black | `#052345` | strokes and text on light – dark violet × dark mint **multiplied like inks** (`#5B47D6 × #0F7F52`) |
| Mint (on light) | `#0F7F52` | dot and `id` on light backgrounds |
| Violet (on light) | `#5B47D6` | glitch channel on light backgrounds |

One accent only: mint. Violet exists only as the second channel of the glitch.

## Type

- **IBM Plex Mono** (Bold for the wordmark) – headings, labels, navigation, code. In `fonts/` with its licence
  (SIL OFL 1.1, Reserved Font Name “Plex”; used unmodified).
- **IBM Plex Sans** – longer text, documents (the whitepaper template uses Plex Sans and Mono).
- On the web, nothing is loaded from other servers: self-host the fonts or fall back to the system stacks.

## Don'ts

- Don't glitch anything else: in the wordmark only the 0 glitches; text stays clean.
- Don't recolour the dot or add accent colours; don't use violet outside the glitch; don't put the bright colours on
  light backgrounds (use the on-light palette).
- Don't use the glitched mark below about 64 px – use the small icon (the 0 alone).
- Don't stretch, rotate, or add glow or gradients. Keep clear space around the mark of at least the width of one
  bracket.
- Don't write *Kernoid*, *KernOID*, *KERNOID* or *Kerno* in running text – it is **kernoid**.

## Relation to falkOSS

kernoid is a falkOSS project with its own identity. Use “a falkOSS project” plus at most the small falkOSS mark in
footers – not the falkOSS amber in kernoid's design.

## Licence

The name and brand belong to falkOSS – Falcon Lake Open Source Software gUG (haftungsbeschränkt) i. G., the
publisher of kernoid. The artwork may be used to refer to kernoid; not for other products or in a way that suggests
endorsement. `generate.py` is AGPL-3.0-or-later; the font in `fonts/` is under the SIL Open Font License 1.1
(`fonts/OFL.txt`). [OPEN: trademark registration of “kernoid”.]
