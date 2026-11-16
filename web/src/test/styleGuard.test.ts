// docs/UI.md §12: the style guard. Every non-test .ts/.tsx under features/, components/ and app/ uses the named tokens of §1, never
// a hand-typed value, so a page cannot drift from the standard again. A named exception carries `ui-guard: <reason>` in a comment on
// its line or one of the two lines above, and is listed in ALLOWED below with the same reason; an entry no longer used fails too.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

const PALETTE = '(?:white|black|(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\\d{2,3})'
const COLOUR_UTIL = '(?:bg|text|border(?:-[trblxyse])?|ring(?:-offset)?|outline|fill|stroke|from|via|to|decoration|divide|shadow|inset-shadow|accent|caret|placeholder)'
const ARBITRARY_COLOUR_UTIL = '(?:bg|border(?:-[trblxyse])?|ring(?:-offset)?|outline|fill|stroke|from|via|to|decoration|divide|accent|caret|placeholder)' // text-[…] and shadow-[…] have their own rules
const COLOUR_VALUE = '(?:#[0-9a-fA-F]{3,8}\\b|rgba?\\(|hsla?\\(|oklch\\(|white\\b|black\\b)'
const SPACING_UTIL = '(?:p[xytrblse]?|m[xytrblse]?|gap(?:-[xy])?|space-[xy]|inset(?:-[xy])?|top|right|bottom|left|start|end|translate-[xyz]|scroll-[mp][xytrblse]?|indent)'
const START = '(?<![\\w-])-?' // a class starts the token (after a space, quote, backtick or a variant's colon); `-` for negative values

const TOKENS = 'the theme tokens of docs/UI.md §1 (bg-surface, text-muted, border-rule, text-danger…)'
const SIZES = 'text-caption (12 px), text-meta (13), text-sm (14), text-base (16), text-lg (18), or page-title (20)'

/** What is refused, and what to use instead. */
const RULES: { name: string; re: RegExp; use: string }[] = [
  { name: 'hand-typed text size or colour', re: new RegExp(`${START}text-\\[[^\\]]*\\]`, 'g'), use: SIZES },
  { name: 'size outside the six', re: /(?<![\w-])text-(?:xs|[2-9]xl)(?![\w-])/g, use: SIZES },
  { name: 'hand-typed radius', re: new RegExp(`${START}rounded(?:-[trblse]{1,2})?-\\[[^\\]]*\\]`, 'g'), use: 'rounded-sm (4 px: chips, checkboxes), rounded-md (6 px: buttons, inputs, cards), rounded-lg (8 px: dialogs, popovers, menus) or rounded-full' },
  { name: 'hand-typed shadow', re: new RegExp(`${START}(?:inset-)?shadow-\\[[^\\]]*\\]`, 'g'), use: 'no shadow in the page; shadow-md on popovers and menus, shadow-lg on dialogs; a named @utility (nav-current) for a bar' },
  { name: 'hand-typed spacing', re: new RegExp(`${START}${SPACING_UTIL}-\\[[^\\]]*\\]`, 'g'), use: 'the 4 px spacing scale (p-3, gap-2, mt-1.5…)' },
  { name: 'hand-typed colour', re: new RegExp(`${START}${ARBITRARY_COLOUR_UTIL}-\\[[^\\]]*\\]`, 'g'), use: TOKENS },
  { name: 'Tailwind palette colour', re: new RegExp(`${START}${COLOUR_UTIL}-${PALETTE}(?![\\w-])`, 'g'), use: `${TOKENS}; transparent, current and inherit are allowed` },
  { name: 'arbitrary style property', re: /(?<![\w-])\[(?:color|background(?:-color)?|margin[a-z-]*|padding[a-z-]*|font-size|border-radius|box-shadow):[^\]]*\]/g, use: 'the token utilities' },
  { name: 'colour in an SVG or JSX attribute', re: new RegExp(`\\b(?:fill|stroke|color|stopColor|floodColor|lightingColor)=\\{?\\s*["'\`]${COLOUR_VALUE}`, 'g'), use: `${TOKENS}: fill-ink, stroke-accent…` },
  { name: 'colour in a style object or CSS string', re: new RegExp(`\\b(?:color|background(?:-?[cC]olor)?|border(?:-?(?:[tT]op|[rR]ight|[bB]ottom|[lL]eft))?-?[cC]olor|border|fill|stroke|outline(?:-?[cC]olor)?)\\s*:\\s*["'\`]?\\s*${COLOUR_VALUE}`, 'g'), use: `${TOKENS} as classes, or var(--token) in index.css` },
  { name: 'hex colour string', re: /(?<!(?:href|to|hash)\s*[=:]\s*\{?\s*)["'`]#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{8})["'`]/g, use: TOKENS },
  { name: 'style={{…}} setting colour, background, margin, padding or font size', re: /style=\{\{[^}]*\b(?:color|background\w*|margin\w*|padding\w*|fontSize|border\w*Color)\s*:/g, use: 'classes with the tokens; style= only for computed geometry (a width in %)' },
]

/** The named exceptions of docs/UI.md §12: file, the exact text refused, and why it stays. */
const ALLOWED: { file: string; text: string; why: string }[] = [
  { file: 'components/common/QrCode.tsx', text: 'fill="white', why: 'a QR code is black on white in both themes, or phones cannot read it' },
  { file: 'components/common/QrCode.tsx', text: 'fill="black', why: 'a QR code is black on white in both themes, or phones cannot read it' },
  { file: 'components/brand/Logo.tsx', text: "'#e7a748'", why: 'SIGNAL, the logo\'s amber dot, the one colour outside the theme' },
  { file: 'components/ui/switch.tsx', text: 'translate-x-[18px]', why: 'the switch thumb at the end of its 36 px track' },
  { file: 'components/common/PageFrame.tsx', text: 'shadow-[inset_0_-1px_0_var(--color-rule)]', why: 'the rule under the tab row: the scroll box clips a border' },
  { file: 'components/common/UnderlineNav.tsx', text: 'shadow-[inset_0_-1px_0_var(--color-rule)]', why: 'the rule under the link row: the scroll box clips a border' },
  { file: 'components/common/DataTable.tsx', text: 'shadow-[inset_3px_0_0_var(--danger)]', why: 'the 3 px tone bar of a row that needs a look' },
  { file: 'components/common/DataTable.tsx', text: 'shadow-[inset_3px_0_0_var(--warn)]', why: 'the 3 px tone bar of a row that needs a look' },
]

function sources(): { file: string; lines: string[] }[] {
  return ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
    .filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f) && !/\.d\.ts$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), lines: readFileSync(join(SRC, root, f), 'utf8').split('\n') })))
}

type Hit = { file: string; line: number; text: string; rule: string; use: string; marked: boolean }

function scan(files: { file: string; lines: string[] }[]): Hit[] {
  const hits: Hit[] = []
  for (const { file, lines } of files) {
    lines.forEach((l, i) => {
      for (const r of RULES) {
        for (const m of l.matchAll(r.re)) {
          const marked = lines.slice(Math.max(0, i - 2), i + 1).some((x) => x.includes('ui-guard:'))
          hits.push({ file, line: i + 1, text: m[0], rule: r.name, use: r.use, marked })
        }
      }
    })
  }
  return hits
}

const allowedHit = (h: Hit) => ALLOWED.some((a) => a.file === h.file && h.text.includes(a.text))

describe('style guard (docs/UI.md §12)', () => {
  const files = sources()
  const hits = scan(files)

  it('reads the app sources', () => {
    expect(files.length).toBeGreaterThan(200)
    expect(files.some((f) => f.file === 'components/ui/button.tsx')).toBe(true)
  })

  it('no hand-typed size, colour, radius, shadow or spacing: only the named tokens', () => {
    const bad = hits.filter((h) => !allowedHit(h)).map((h) => `${h.file}:${h.line} ${h.text} (${h.rule}): use ${h.use}`)
    expect(bad, `Hand-typed values; use the tokens, or add a named exception (a ui-guard: comment and an ALLOWED entry):\n${bad.join('\n')}`).toEqual([])
  })

  it('every exception says why on its line (a ui-guard: comment) and is still used', () => {
    const unmarked = hits.filter((h) => allowedHit(h) && !h.marked).map((h) => `${h.file}:${h.line} ${h.text}: add a // ui-guard: <reason> comment`)
    expect(unmarked).toEqual([])
    const stale = ALLOWED.filter((a) => !hits.some((h) => h.file === a.file && h.text.includes(a.text))).map((a) => `${a.file} ${a.text}`)
    expect(stale, 'ALLOWED entries no longer used: remove them').toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    const t = (src: string) => scan([{ file: 'x.tsx', lines: [src] }]).map((h) => h.text)
    expect(t('<p className="text-[13px] sm:text-[12px] text-xs text-2xl">')).toEqual(['text-[13px]', 'text-[12px]', 'text-xs', 'text-2xl'])
    expect(t("cn('rounded-[4px] shadow-[0_1px_2px_#000] -mt-[3px] px-[10px] bg-[#fff] border-[var(--x)]')")).toHaveLength(6)
    expect(t('<span className="bg-red-500 text-white hover:border-black/40 shadow-black/60">')).toEqual(['bg-red-500', 'text-white', 'border-black', 'shadow-black'])
    expect(t('<circle fill="#e7a748" /><rect fill="white" />')).toEqual(['fill="#e7a748', 'fill="white', '"#e7a748"'])
    expect(t("const css = 'body { color: black; background: #fff }'")).toEqual(['color: black', 'background: #fff'])
    expect(t("<div style={{ color: 'red', width: '10%' }} />")).toEqual(['style={{ color:'])
    expect(t("const SIGNAL = '#e7a748'")).toEqual(["'#e7a748'"])
    // allowed: tokens, keywords, layout values, comments naming issues, anchors, variants, regexes
    expect(t('<p className="text-meta text-caption text-sm bg-surface text-danger border-danger/40 bg-transparent text-current fill-ink">')).toEqual([])
    expect(t('<div className="grid-cols-[minmax(0,1fr)_auto] max-w-[72ch] z-[60] max-h-[min(28rem,var(--h))] transition-[width] data-[state=open]:bg-sunken after:content-[""] [overflow-wrap:anywhere]">')).toEqual([])
    expect(t('// #824 review, see #bad and href="#facade" to="#decade"; /[0-9a-f]{8}-[0-9a-f]{4}/; /xoxb-[\\w-]+/')).toEqual([])
    expect(t("<div style={{ width: `${pct}%` }} /><svg fill=\"none\" stroke=\"currentColor\" />")).toEqual([])
  })
})
