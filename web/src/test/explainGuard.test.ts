// A heading or block that only explains and offers nothing to do ("Vedette acts as the osquery server; osquery only reads.")
// is not shown: an explanation that helps becomes an info icon beside the thing it explains. This guard reads every non-test
// .tsx under features/, components/ and app/ with a small tag scanner and fails on:
//  - a <Section> whose children and actions hold only prose (text, t('…') lines, InfoTip, Card, a Notice without actions);
//  - an info notice (<Notice tone="off">) with no actions whose title, info and text are only prose: an explanation set apart
//    as a box. Notices of other tones (warn, danger, accent) state a condition the reader must know and are not counted;
//  - an h2–h5 heading whose block holds only prose. The block is the heading's own wrapper, widened to the largest
//    ancestor that holds no other heading.
//  - a paragraph of the page that is one long t('…') line (more than LONG_WORDS words in English) outside an info icon, a dialog,
//    a fold (details), a notice or an empty state: a block of explanation set in the page instead of behind ⓘ.
// Anything that is a control or data counts as content: button, a, input, select, textarea, details, table, form, any other
// component (Button, Link, DataTable, CodeBlock, Field …) and any `{expression}` that is not a t('…') line. A bulleted list of
// t('…') lines is prose too.
// A named exception is listed in ALLOWED with the reason; an entry that no longer matches fails too, so the list cannot rot.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']
const HEADINGS = new Set(['h2', 'h3', 'h4', 'h5'])
/** Tags that are controls or data wherever they appear (also inside an attribute or an expression). */
const CONTENT_TAG = /<(?!\/)(?!(?:p|span|div|strong|em|b|i|br|code|small|time|ul|ol|li|InfoTip|Card|Trans|StoryTag|Notice|h[2-5]|section|header)\b)[A-Za-z]/

/** The named exceptions: file, the heading's text, and why it stays. */
const ALLOWED: { file: string; heading: string; why: string }[] = [
  { file: 'features/core/parts.tsx', heading: "t('readOnly'", why: 'says the reader\'s role cannot change the section: a state of this page, not an explanation' },
  { file: 'features/scanning/EnginesTab.tsx', heading: "t('adminOnly')", why: 'says the reader\'s role cannot change the engines: a state of this page' },
  { file: 'features/scanning/SafetyTab.tsx', heading: "t('safety.adminOnly')", why: 'says the reader\'s role cannot change the settings: a state of this page' },
  { file: 'features/response/ApprovePage.tsx', heading: 't(`approve.state.', why: 'the state of an approval link (expired, used, decided): the whole answer of that page' },
  { file: 'features/core/BugReportDialog.tsx', heading: "t('bug.noSend')", why: 'tells the person, inside the dialog that drafts the report, that nothing leaves the box by itself (a privacy statement next to the action)' },
]

type Hit = { file: string; line: number; heading: string }

/** A paragraph longer than this in English is an explanation (the page shows a title and one short line, about 12 words). */
const LONG_WORDS = 30
/** Where a long text belongs: behind ⓘ, in a dialog, folded, in a notice or an empty state, or a field's help. */
const HOLDS_TEXT = new Set(['InfoTip', 'DialogContent', 'details', 'Notice', 'EmptyState', 'Field', 'AiBlock', 'Dialog'])
/** Long paragraphs in the page that predate this rule: each moves behind an info icon in its own change; a fixed one must leave. */
const LONG_KNOWN: string[] = [
  'features/reports/PdplDocument.tsx long: doc.pdpl.regimeNote', // a printed document: its text is the content
]
const LOCALES = join(SRC, 'locales/en')
const words: Record<string, unknown> = Object.fromEntries(readdirSync(LOCALES).map((f) => [f.replace(/\.json$/, ''), JSON.parse(readFileSync(join(LOCALES, f), 'utf8'))]))
/** The English text of a key ('ns:a.b' or 'a.b' of the file's own namespace); a plural key reads its _other form. */
function english(key: string, own: string): string | null {
  const [ns, path] = key.includes(':') ? key.split(':') as [string, string] : [own, key]
  const at = (p: string) => p.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), words[ns])
  const v = at(path) ?? at(`${path}_other`)
  return typeof v === 'string' ? v : null
}

function sources() {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

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
    else if (c === '<' && depth === 0 && /\w/.test(text[i - 1]!)) i = text.indexOf('>', i) // a generic: <DataTable<Row> …>
    else if (c === '>' && depth === 0) return i
  }
  return text.length
}

/** The index after the `}` that closes the brace group opened at `at` (strings and template literals skipped). */
function braceEnd(text: string, at: number): number {
  let depth = 0
  let quote = ''
  for (let i = at; i < text.length; i++) {
    const c = text[i]
    if (quote) { if (c === quote && text[i - 1] !== '\\') quote = ''; continue }
    if (c === '"' || c === "'" || c === '`') quote = c
    else if (c === '{') depth++
    else if (c === '}' && --depth === 0) return i + 1
  }
  return text.length
}

/** A `<` starts a tag unless it follows an identifier directly (a generic `Segmented<Platform>`, `a<b`). */
const startsTag = (text: string, i: number) => text[i + 1] === '/' || (/[A-Za-z>]/.test(text[i + 1] ?? '') && !/[\w)\]]/.test(text[i - 1] ?? ' '))

type El = { tag: string; start: number; end: number; open: number; parent: El | null }

/** Every element in the file (also inside expressions) with its extent and parent. */
function elements(text: string): El[] {
  const out: El[] = []
  const stack: El[] = []
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '<' || !startsTag(text, i)) continue
    const close = openEnd(text, i)
    if (text[i + 1] === '/') {
      const el = stack.pop()
      if (el) el.end = close + 1
      i = close
      continue
    }
    const tag = /^<([A-Za-z][\w.]*)?/.exec(text.slice(i))![1] ?? ''
    const el: El = { tag, start: i, end: close + 1, open: close + 1, parent: stack[stack.length - 1] ?? null }
    out.push(el)
    if (text[close - 1] !== '/') stack.push(el)
    i = close
  }
  return out
}

/** True when the markup in `slice` holds a control, data or an expression that is not a t('…') line. */
function hasContent(slice: string): boolean {
  for (let i = 0; i < slice.length; i++) {
    if (slice[i] === '<' && startsTag(slice, i)) {
      const close = openEnd(slice, i)
      const open = slice.slice(i, close + 1)
      if (/^<\//.test(open)) { i = close; continue }
      if (CONTENT_TAG.test(open) && /^<(?!\/)/.test(open) && !/^<(?:p|span|div|strong|em|b|i|br|code|small|time|ul|ol|li|InfoTip|Card|Trans|StoryTag|Notice|h[2-5]|section|header|>)(?![\w.])/.test(open)) return true
      if (/\bactions=/.test(open)) return true
      // attributes: a control or data component passed as a prop
      const attrs = open.replace(/^<\w*/, '')
      if (CONTENT_TAG.test(attrs)) return true
      i = close
    } else if (slice[i] === '{') {
      const end = braceEnd(slice, i)
      const expr = slice.slice(i + 1, end - 1).trim()
      // a list of t('…') lines ({KEYS.map((k) => <li key={k}>{t(`x.${k}`)}</li>)}) is prose too
      const mapped = /\.map\(\s*\(?[\w\s,]*\)?\s*=>\s*\(?\s*(<[\s\S]*>)\s*\)?\s*\)$/.exec(expr)
      if (mapped && !hasContent(mapped[1]!.replace(/\bkey=\{[^}]*\}/g, ''))) { i = end - 1; continue }
      if (CONTENT_TAG.test(expr)) return true
      if (expr && !/^t\(/.test(expr) && !/^\/\*/.test(expr)) return true
      i = end - 1
    }
  }
  return false
}

export function scan(files: { file: string; text: string }[]): Hit[] {
  const hits: Hit[] = []
  for (const { file, text } of files) {
    const els = elements(text)
    const titled = (e: El) => HEADINGS.has(e.tag) || e.tag === 'Section'
    const headingsIn = (e: El) => els.filter((x) => titled(x) && x.start >= e.start && x.end <= e.end).length
    const lineOf = (i: number) => text.slice(0, i).split('\n').length
    for (const e of els) {
      if (e.tag === 'Section') {
        const head = text.slice(e.start, e.open)
        const body = text.slice(e.open, text.lastIndexOf('</Section>', e.end))
        if (headingsIn(e) === 1 && !/\bactions=/.test(head) && !hasContent(body) && !CONTENT_TAG.test(head.replace(/^<\w*/, ''))) {
          hits.push({ file, line: lineOf(e.start), heading: /title=\{([^}]*)\}/.exec(head)?.[1] ?? '' })
        }
      } else if (e.tag === 'Notice') {
        // a notice with no action whose title and text are only prose: an explanation set apart as a box
        const head = text.slice(e.start, e.open)
        const selfClosing = /\/>$/.test(head)
        const body = selfClosing ? '' : text.slice(e.open, text.lastIndexOf('</Notice>', e.end))
        const attrs = head.replace(/^<\w*/, '').replace(/\b(?:info|title)=\{t\([^{}]*(?:\{[^{}]*\}[^{}]*)*\)\}/g, '')
        if (/\btone="off"/.test(head) && !/\bactions=/.test(head) && !hasContent(body) && !CONTENT_TAG.test(attrs) && !/=\{(?!t\()/.test(attrs)) {
          hits.push({ file, line: lineOf(e.start), heading: /title=\{([^}]*)\}/.exec(head)?.[1] ?? 'Notice' })
        }
      } else if (e.tag === 'p' && !text.slice(e.start, e.open).endsWith('/>') && !/\brole=/.test(text.slice(e.start, e.open))) { // a status line is a state
        const m = /^\s*\{t\(\s*'([\w.:-]+)'[^{}]*(?:\{[^{}]*\}[^{}]*)*\)\}\s*$/.exec(text.slice(e.open, text.lastIndexOf('</p>', e.end)))
        const own = /useTranslation\(\s*\[?\s*'([\w-]+)'/.exec(text)?.[1] ?? 'common'
        const en = m ? english(m[1]!, own) : null
        let held = false
        for (let a = e.parent; a && !held; a = a.parent) held = HOLDS_TEXT.has(a.tag) || /\binfo=\{/.test(text.slice(a.start, a.open)) && a.tag === ''
        if (en && en.split(/\s+/).length > LONG_WORDS && !held) hits.push({ file, line: lineOf(e.start), heading: `long: ${m![1]}` })
      } else if (HEADINGS.has(e.tag)) {
        // the heading's wrapper, widened while no other heading is inside
        let block = e
        while (block.parent && headingsIn(block.parent) === 1) block = block.parent
        if (block !== e && !hasContent(text.slice(block.open, text.lastIndexOf('</', block.end)))) {
          hits.push({ file, line: lineOf(e.start), heading: text.slice(e.open, text.lastIndexOf('</', e.end)).trim() })
        }
      }
    }
  }
  return hits
}

describe('explanation-only blocks', () => {
  const hits = scan(sources())
  const allowed = (h: Hit) => ALLOWED.some((a) => a.file === h.file && h.heading.includes(a.heading)) || LONG_KNOWN.includes(`${h.file} ${h.heading}`)

  it('a heading or section has something to act on or read besides prose', () => {
    const bad = hits.filter((h) => !allowed(h)).map((h) => `${h.file}:${h.line} ${h.heading}`)
    // eslint-disable-next-line no-console
    if (process.env.EXPLAIN_COUNT) console.log(`explain-only blocks: ${hits.length} (allowed ${hits.length - bad.length})\n${hits.map((h) => `${h.file}:${h.line} ${h.heading}`).join('\n')}`)
    expect(bad, 'a heading that only explains: turn the text into an info icon beside the thing it explains, or give the block an action').toEqual([])
  })

  it('every allowed entry still matches a block', () => {
    const stale = ALLOWED.filter((a) => !hits.some((h) => h.file === a.file && h.heading.includes(a.heading))).map((a) => `${a.file} ${a.heading}`)
    expect(stale).toEqual([])
    expect(LONG_KNOWN.filter((k) => !hits.some((h) => `${h.file} ${h.heading}` === k)), 'long paragraphs that moved: remove them').toEqual([])
  })

  it('the guard catches what it must', () => {
    const one = (text: string) => scan([{ file: 'x.tsx', text }]).map((h) => h.heading)
    expect(one("<Section title={t('a')}><Card><ul>{K.map((k) => <li key={k}>{t(`b.${k}`)}</li>)}</ul></Card></Section>")).toHaveLength(1)
    const long = "const { t } = useTranslation('scanning'); <div><p>{t('safety.appliesTo')}</p></div>"
    expect(one(long)).toEqual(['long: safety.appliesTo'])
    expect(one("const { t } = useTranslation('scanning'); <InfoTip topic=\"x\"><p>{t('safety.appliesTo')}</p></InfoTip>")).toEqual([])
  })
})
