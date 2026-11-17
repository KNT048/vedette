// kien G5: an action, link or banner with nothing to act on is not shown ("Fix by updating the operating system" with no update,
// "0 fragile devices: see them", "Select all 0"). This guard reads every non-test .tsx under features/, components/ and app/ and
// fails on a <Link> or <Button> whose label states a count (t('…', { count: x })) when nothing near it checks that count: a
// `x ? … : null`, `x > 0 && …`, `if (!x) return null`, or a `disabled=` that reads it. A named exception carries
// `empty-guard: <reason>` in a comment on the tag's line or one of the two lines above it, and is listed in ALLOWED with the same
// reason; an entry no longer used fails too. The KpiStrip draws a 0 as plain text by itself (components/common/PageFrame.tsx).
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']
/** How far back (characters) a check of the count may be: the component that draws the tag. */
const WINDOW = 1500

/** The named exceptions: file, a piece of the count expression, and why it can never be 0 there. */
const ALLOWED: { file: string; text: string; why: string }[] = [
  { file: 'features/findings/FindingsPage.tsx', text: 'ids.length', why: 'the bulk dialog opens only from the selection bar, which shows only with a selection' },
  { file: 'features/notify/IncidentsPage.tsx', text: 'ids.length', why: 'the bulk dialog opens only from the selection bar, which shows only with a selection' },
  { file: 'features/findings/FindingsPage.tsx', text: 'all', why: 'PlanLine returns null when the plan has no item, so all is at least 1' },
  { file: 'features/findings/FixGroups.tsx', text: 'g.members.length', why: 'a fix group has at least two findings by construction (fixGroups)' },
  { file: 'features/feeds/HomeDashboard.tsx', text: 's.open.total', why: 'the Fix first card is drawn only when it lists open findings (an empty one returns earlier)' },
]

function sources() {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

type Hit = { file: string; line: number; count: string; marked: boolean }

/** The index of the `>` that ends the opening tag starting at `at` (braces and strings inside it skipped). */
function openEnd(text: string, at: number): number {
  let depth = 0
  let quote = ''
  for (let i = at + 1; i < text.length; i++) {
    const c = text[i]
    if (quote) { if (c === quote && text[i - 1] !== '\\') quote = ''; continue }
    if (c === '{') depth++
    else if (c === '}') depth--
    else if (c === '"' || c === "'" || (depth > 0 && c === '`')) quote = c
    else if (c === '>' && depth === 0) return i
  }
  return text.length
}

function scan(files: { file: string; text: string }[]): Hit[] {
  const hits: Hit[] = []
  for (const { file, text } of files) {
    const lines = text.split('\n')
    for (const m of text.matchAll(/<(Link|Button|DownloadButton)(?=[\s>])/g)) {
      const close = openEnd(text, m.index)
      if (text[close - 1] === '/') continue // self-closing: no label of its own
      const end = text.indexOf(`</${m[1]}>`, close)
      if (end < 0) continue
      const tag = text.slice(m.index, end)
      const c = /t\(\s*['"`][^'"`]+['"`]\s*,\s*\{[^}]*\bcount:\s*([^,}]+)/.exec(tag)
      if (!c) continue
      const count = c[1]!.trim()
      const root = count.replace(/^[!(]+/, '').split(/[.?\s([]/)[0]!
      if (/^[A-Z][A-Z0-9_]*$/.test(root)) continue // a constant (days, a limit), not a count of things
      const before = text.slice(Math.max(0, m.index - WINDOW), m.index)
      const r = esc(root)
      const guarded = new RegExp(`(?:${esc(count)}|\\b${r}\\b[\\w.?]*)\\s*(?:\\?|&&|>|!==\\s*0)`).test(before)
        || new RegExp(`if \\([^)]*\\b${r}\\b[^)]*\\)\\s*return`).test(before)
        || new RegExp(`\\sdisabled=\\{[^}]*\\b${r}\\b`).test(tag.slice(0, tag.indexOf('>') + 1))
      if (guarded) continue
      const line = text.slice(0, m.index).split('\n').length
      const marked = lines.slice(Math.max(0, line - 3), line).some((l) => l.includes('empty-guard:'))
      hits.push({ file, line, count, marked })
    }
  }
  return hits
}

const allowedHit = (h: Hit) => ALLOWED.some((a) => a.file === h.file && h.count.includes(a.text))

describe('empty action guard (kien G5)', () => {
  const files = sources()
  const hits = scan(files)

  it('reads the app sources', () => {
    expect(files.length).toBeGreaterThan(200)
  })

  it('a link or button that states a count is shown only when that count is not 0', () => {
    const bad = hits.filter((h) => !allowedHit(h)).map((h) => `${h.file}:${h.line} count: ${h.count}`)
    expect(bad, `Actions that can say "0 …" and lead nowhere; draw them only when the count is above 0 ({n > 0 ? <Link…> : null}), or add a named exception (an empty-guard: comment and an ALLOWED entry):\n${bad.join('\n')}`).toEqual([])
  })

  it('every exception says why (an empty-guard: comment) and is still used', () => {
    expect(hits.filter((h) => allowedHit(h) && !h.marked).map((h) => `${h.file}:${h.line}: add a // empty-guard: <reason> comment`)).toEqual([])
    const stale = ALLOWED.filter((a) => !hits.some((h) => h.file === a.file && h.count.includes(a.text))).map((a) => `${a.file} ${a.text}`)
    expect(stale, 'ALLOWED entries no longer used: remove them').toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    const t = (src: string) => scan([{ file: 'x.tsx', text: src }]).map((h) => h.count)
    expect(t(`<Link to="/devices">{t('fragile', { count: devices })}</Link>`)).toEqual(['devices'])
    expect(t(`<Button onClick={go}>{t('install', { count: s.pending.length })}</Button>`)).toEqual(['s.pending.length'])
    expect(t(`{devices > 0 ? <Link to="/d">{t('fragile', { count: devices })}</Link> : null}`)).toEqual([])
    expect(t(`{n ? <Link to="/d">{t('x', { count: n })}</Link> : null}`)).toEqual([])
    expect(t(`if (!others.length) return null\nreturn <Link to="/d">{t('x', { count: others.length - 1 })}</Link>`)).toEqual([])
    expect(t(`<Button disabled={!sel.length}>{t('x', { count: sel.length })}</Button>`)).toEqual([])
    expect(t(`<Link to="/later">{t('snooze', { count: SNOOZE_DAYS })}</Link>`)).toEqual([])
  })
})
