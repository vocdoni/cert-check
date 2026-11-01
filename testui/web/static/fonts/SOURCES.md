# Font and brand asset sources

Everything here is served from the same origin (CSP `font-src 'self'`). Nothing is fetched at
runtime and no npm package is involved.

## Fonts

The four woff2 files are copied byte for byte from the vocdoni.io brand kit, which hosts the
fontsource subsets (SIL Open Font License 1.1):

- source: `github.com/vocdoni/vocdoni.io`, `public/fonts/files`
- local copy of the kit: `~/.cache/cert-check/brand/fonts/`
- recorded by ruling R34; `web_test.go` (`TestFontSources`) recomputes every digest below

| File | Family | Subset |
|---|---|---|
| `fraunces-latin-full-normal.woff2` | Fraunces (variable, all axes) | latin |
| `fraunces-latin-ext-full-normal.woff2` | Fraunces (variable, all axes) | latin-ext |
| `hanken-grotesk-latin-wght-normal.woff2` | Hanken Grotesk (variable, wght) | latin |
| `hanken-grotesk-latin-ext-wght-normal.woff2` | Hanken Grotesk (variable, wght) | latin-ext |

## Licences

The OFL texts come from the upstream font repositories, downloaded on 2026-10-31 into
`~/.cache/cert-check/fonts-licences/<font>/OFL.txt` and copied unchanged:

- `OFL-Fraunces.txt`: `https://raw.githubusercontent.com/undercasetype/Fraunces/master/OFL.txt`
  (undercasetype/Fraunces)
- `OFL-HankenGrotesk.txt`: `https://raw.githubusercontent.com/marcologous/hanken-grotesk/master/OFL.txt`
  (marcologous/hanken-grotesk)

## Brand assets

- `favicon.ico`: copied byte for byte from the brand kit `favicon.ico`.
- `img/vocdoni-logo.svg`: derived from the brand kit `vocdoni-logo.svg` (SHA-256
  `b1891d74517bfb8807c7111bf537d613be714d25a585b8ea20de2f991d60c6ce`). The paths and geometry are
  unchanged. The site's Tailwind `class`, `aria-hidden` and `data-fc-idx` attributes and the inline
  `oklch` style overrides are removed, so every path paints with `fill="currentColor"`. The root
  carries `color="#202019"` (the brand ink), because an `<img>` cannot inherit the page text colour.

## SHA-256

```
7e744849028e2219e2aa1bc467dc4032980dc4487c9c3da3010081cd72d3b103  fonts/fraunces-latin-full-normal.woff2
e9521563d0935c9bda4277e242cc88c75993a77878f5f7eed537989e94f976c9  fonts/fraunces-latin-ext-full-normal.woff2
e9201eddf1d41d0b62253295d869ce3cf65768f7102b797f02c7f8c876b4a9d5  fonts/hanken-grotesk-latin-wght-normal.woff2
768af2923e0ab1549f1dfba0a5c8ea749c4c01f01d8e77ffaf7fcd12f57a0a24  fonts/hanken-grotesk-latin-ext-wght-normal.woff2
bdf4c22802eaf804f998195871c6b8938aac2ac14b2d78a8bd66a6f1eced833b  fonts/OFL-Fraunces.txt
e02ccb89a86839b22feff7872ff5cc355cc0f58318d29eee20e2cf83a612f16d  fonts/OFL-HankenGrotesk.txt
6aad61d0bb3a64a431679b938ea4290679ba2f10c647414485bfb4eaa9893380  favicon.ico
```
