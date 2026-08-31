# Aletheia brand

Clean hand-crafted vector logos and a single-source-of-truth palette.

## Files

- `logo.svg` -- master mark; uses `currentColor` so CSS `color: <hex>` decides fill
- `logo-mono.svg` -- explicit `#EAEAEA` (dark-mode monochrome)
- `logo-accent.svg` -- explicit `#3EE0D0` (accent cyan, hero placements)
- `favicon.svg` -- tighter viewBox for browser tabs
- `logo-wordmark.svg` -- horizontal mark + ALETHEIA wordmark (README banner)
- `social-preview.svg` -- 1280x640 dark banner (GitHub social preview)
- `palette.css` -- the design tokens

## Palette

| Token | Hex | Purpose |
|---|---|---|
| `--al-bg` | `#0F1218` | app / hero |
| `--al-surface` | `#161B22` | cards, code blocks |
| `--al-border` | `#2A313C` | dividers |
| `--al-text` | `#EAEAEA` | body |
| `--al-text-mute` | `#8A93A6` | secondary |
| `--al-accent` | `#3EE0D0` | logo, links, focus |
| `--al-accent-hi` | `#5FE9DB` | interactive hover |
| `--al-warn` | `#E8B04F` | suspicious / packer detected |
| `--al-danger` | `#F26E6E` | anti-analysis, hard fail |
| `--al-ok` | `#5FD98A` | likely clean, tests green |

## PNG rasters (on demand)

The SVGs are the master. Rasterize when a specific tool needs PNG:

```bash
magick -background none docs/brand/logo-accent.svg -resize 256x256 docs/brand/logo-256.png
magick -background none docs/brand/favicon.svg -resize 32x32 docs/brand/favicon-32.png
```
