// docs/UI.md §8 (busy state, kien G1): every button that waits on the server shows the same busy state, the Button's `busy` and
// `busyLabel` (spinner, "Saving…", aria-busy, no width jump), so a person knows the box is working. This guard reads every
// non-test .tsx under features/, components/ and app/ and fails on a <Button> that waits without it. A named exception carries
// `busy-guard: <reason>` in a comment inside the tag or on one of the two lines above it, and is listed in ALLOWED below with the
// same reason; an entry no longer used fails too.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

/** State that means "the action is waiting on the server": react-query's flags and the names the code gives them. */
const WAITING = /\b(?:\w+\.)?(?:isPending|isFetching|isMutating)\b|\b(?:busy|pending|saving|submitting)\b/
/** A label swapped by hand while waiting: `{save.isPending ? t('saving') : t('save')}`. */
const HAND_LABEL = /\b(?:\w+\.)?(?:isPending|isFetching|isMutating)\s*\?|\b(?:busy|pending|saving|submitting)\s*\?/
/** A spinner drawn by hand inside a button. */
const HAND_SPINNER = /animate-spin|LoaderCircle|Loader2/
/** Cancel, Close, Back and Keep are not the action that waits: they are only held while it runs, with no spinner. */
const NOT_THE_ACTION = /t\(\s*['"][\w:.]*\b(?:cancel|close|back|keep\w*)['"]/i

const RULES = {
  noBusy: 'waits on the server (its disabled= reads a pending state) but has no busy= prop: add busy={x.isPending} busyLabel={t(\'common:busy.saving\')}',
  handLabel: 'swaps its label by hand while waiting: use busy= and busyLabel= instead',
  handSpinner: 'draws its own spinner: the Button draws it when busy= is true',
  noLabel: 'has busy= but no busyLabel= (say what is happening: "Saving…") and no aria-label=',
}
type Rule = keyof typeof RULES

/** The named exceptions: file, a piece of the tag's text, and why it stays. */
const ALLOWED: { file: string; text: string; why: string }[] = []

function sources() {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

type Tag = { at: number; open: string; body: string }

/** Every <Button …> opening tag (braces, strings and arrows inside it skipped) with the text up to its </Button>. */
function buttons(text: string): Tag[] {
  const out: Tag[] = []
  for (const m of text.matchAll(/<Button(?=[\s>/])/g)) {
    let i = m.index + 7
    let depth = 0
    let quote = ''
    for (; i < text.length; i++) {
      const c = text[i]
      if (quote) { if (c === quote && text[i - 1] !== '\\') quote = ''; continue }
      if (c === '{') depth++
      else if (c === '}') depth--
      else if (c === '"' || c === "'" || (depth > 0 && c === '`')) quote = c
      else if (c === '>' && depth === 0) break
    }
    const open = text.slice(m.index, i + 1)
    const end = open.endsWith('/>') ? i + 1 : text.indexOf('</Button>', i)
    out.push({ at: m.index, open, body: text.slice(i + 1, end < 0 ? i + 1 : end) })
  }
  return out
}

/** The expression of a {…} prop, or null. */
function prop(open: string, name: string): string | null {
  const k = open.search(new RegExp(`\\s${name}=\\{`))
  if (k < 0) return null
  const s = open.indexOf('{', k)
  let depth = 0
  for (let i = s; i < open.length; i++) {
    if (open[i] === '{') depth++
    else if (open[i] === '}' && --depth === 0) return open.slice(s + 1, i)
  }
  return null
}
const has = (open: string, name: string) => new RegExp(`\\s${name}(?:=|[\\s/>])`).test(open)

type Hit = { file: string; line: number; rule: Rule; tag: string; marked: boolean }

function scan(files: { file: string; text: string }[]): Hit[] {
  const hits: Hit[] = []
  for (const { file, text } of files) {
    for (const b of buttons(text)) {
      if (has(b.open, 'asChild')) continue // a link styled as a button: it does not wait
      const line = text.slice(0, b.at).split('\n').length
      const above = text.split('\n').slice(Math.max(0, line - 3), line - 1).join('\n')
      const marked = /busy-guard:/.test(b.open) || /busy-guard:/.test(above)
      const hit = (rule: Rule) => hits.push({ file, line, rule, tag: b.open.replace(/\s+/g, ' ').slice(0, 160), marked })
      const busy = has(b.open, 'busy')
      const disabled = prop(b.open, 'disabled')
      if (!busy && disabled && WAITING.test(disabled) && !NOT_THE_ACTION.test(b.body)) hit('noBusy')
      if (HAND_LABEL.test(b.body)) hit('handLabel')
      if (HAND_SPINNER.test(b.body)) hit('handSpinner')
      if (busy && !has(b.open, 'busyLabel') && !has(b.open, 'aria-label')) hit('noLabel')
    }
  }
  return hits
}

const allowedHit = (h: Hit) => ALLOWED.some((a) => a.file === h.file && h.tag.includes(a.text))

describe('busy guard (docs/UI.md §8, kien G1)', () => {
  const files = sources()
  const hits = scan(files)

  it('reads the app sources', () => {
    expect(files.length).toBeGreaterThan(200)
    expect(files.some((f) => f.file === 'features/findings/Recommendation.tsx')).toBe(true)
  })

  it('every button that waits on the server shows the busy state (busy= and busyLabel=)', () => {
    const bad = hits.filter((h) => !allowedHit(h)).map((h) => `${h.file}:${h.line} ${RULES[h.rule]}\n    ${h.tag}`)
    expect(bad, `Buttons without the shared busy state; use <Button busy={x.isPending} busyLabel={t('common:busy.saving')}>, or add a named exception (a busy-guard: comment and an ALLOWED entry):\n${bad.join('\n')}`).toEqual([])
  })

  it('every exception says why (a busy-guard: comment) and is still used', () => {
    expect(hits.filter((h) => allowedHit(h) && !h.marked).map((h) => `${h.file}:${h.line}: add a // busy-guard: <reason> comment`)).toEqual([])
    const stale = ALLOWED.filter((a) => !hits.some((h) => h.file === a.file && h.tag.includes(a.text))).map((a) => `${a.file} ${a.text}`)
    expect(stale, 'ALLOWED entries no longer used: remove them').toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    const t = (src: string) => scan([{ file: 'x.tsx', text: src }]).map((h) => h.rule)
    // caught
    expect(t(`<Button disabled={!can || save.isPending} onClick={() => save.mutate(v)}>{t('common:save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<Button\n  variant="primary"\n  disabled={busy}\n  onClick={() => go(a > b)}\n>{t('run')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<Button busy={ask.isPending} busyLabel={t('asking')}>{ask.isPending ? t('running') : t('ask')}</Button>`)).toEqual(['handLabel'])
    expect(t(`<Button disabled={x}>{find.isPending ? <LoaderCircle className="animate-spin" /> : null}{t('find')}</Button>`)).toEqual(['handLabel', 'handSpinner'])
    expect(t(`<Button busy={del.isPending}>{t('delete')}</Button>`)).toEqual(['noLabel'])
    // left alone: the pattern, icon buttons named by aria-label, Cancel held while the action runs, links, plain disabled
    expect(t(`<Button busy={save.isPending} busyLabel={t('common:busy.saving')} disabled={!dirty}>{t('common:save')}</Button>`)).toEqual([])
    expect(t(`<Button size="icon" busy={del.isPending} aria-label={t('del', { name })}><Trash2 /></Button>`)).toEqual([])
    expect(t(`<Button disabled={save.isPending} onClick={close}>{t('common:cancel')}</Button>`)).toEqual([])
    expect(t(`<Button asChild disabled={busy}><Link to="/x">{t('open')}</Link></Button>`)).toEqual([])
    expect(t(`<Button disabled={!admin || !dirty} title={why}>{t('common:save')}</Button>`)).toEqual([])
  })
})
