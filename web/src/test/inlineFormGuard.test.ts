// An add or edit form never opens inside the page content (pushed above or between list rows). A short one is a dialog over the
// page; a long one is its own page (…/new, …/<id>/edit) with Back. The list stays as it was underneath.
//
// This guard reads every non-test .tsx under features/, components/ and app/ and counts each <form> that is not hosted by a dialog:
// - inside a <DialogContent> … </DialogContent> region of its own file, or
// - in a component (`function XForm`) that is rendered inside a <DialogContent> region of any file.
// It also counts an edit in place without a <form>: a component that keeps or takes an editing state (editing, renaming, isEditing) and
// swaps a field (Input, Textarea) into the page for it, with no dialog of its own (a title or a row that turns into a field).
// Every other <form> must be named in ALLOWED (file, how many forms it covers, why), or carry an `inline-form-guard: <reason>`
// comment on its line or one of the two lines above. An entry that covers more or fewer forms than the file has fails too.
//
// Known limits (a static, per-file read): a form hosted by a dialog through a component passed as a prop is not followed, and a
// form in a component that is hosted by a dialog only through another hosted component is not followed more than one level.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

/** Forms that are not add/edit forms of one item. */
const SETTINGS = 'edits one settings object in place (a page of settings, not an item added to a list)'
const OWN_PAGE = 'is the whole content of its own page, not a form among list rows'
const SEARCH = 'is a search or jump box, not an add/edit form'

const ALLOWED: { file: string; count: number; why: string }[] = [
  { file: 'features/ai/AiSettings.tsx', count: 2, why: SETTINGS },
  { file: 'features/ai/AssistantPage.tsx', count: 1, why: 'is the question box of the assistant: it asks, it does not add or edit a stored item' },
  { file: 'features/core/AccountPage.tsx', count: 3, why: SETTINGS },
  { file: 'features/core/ChangePasswordPage.tsx', count: 1, why: OWN_PAGE },
  { file: 'features/core/GeneralSection.tsx', count: 1, why: SETTINGS },
  { file: 'features/core/NetworkSection.tsx', count: 3, why: SETTINGS },
  { file: 'features/core/SetupPage.tsx', count: 1, why: 'is the first-run wizard: a page of steps, not a form among list rows' },
  { file: 'features/core/SpanCard.tsx', count: 1, why: SETTINGS },
  { file: 'features/core/UsersSection.tsx', count: 1, why: SETTINGS },
  { file: 'features/feeds/HomePage.tsx', count: 1, why: SEARCH },
  { file: 'features/feeds/LookupPage.tsx', count: 1, why: SEARCH },
  { file: 'features/logs/SiemSettings.tsx', count: 1, why: SETTINGS },
  { file: 'features/notify/ChannelsSettings.tsx', count: 1, why: SETTINGS },
  { file: 'features/reports/PdplTab.tsx', count: 1, why: SETTINGS },
  { file: 'features/reports/SettingsTab.tsx', count: 1, why: SETTINGS },
  { file: 'features/response/ApproverIdentities.tsx', count: 1, why: 'is the code step that links an approver identity on its own row, not an add/edit form' },
  { file: 'features/response/ResponseSettings.tsx', count: 1, why: SETTINGS },
  { file: 'features/scanning/SafetyTab.tsx', count: 1, why: 'edits the one scan-scope settings object in place; adding and editing a range or an exclusion opens a dialog' },
  { file: 'components/common/Pager.tsx', count: 1, why: SEARCH },
  { file: 'app/LoginPage.tsx', count: 1, why: OWN_PAGE },
]

type Src = { file: string; text: string }
function sources(): Src[] {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

/** [start, end) of each <DialogContent …> … </DialogContent> region. */
function dialogRegions(text: string): [number, number][] {
  const out: [number, number][] = []
  for (const m of text.matchAll(/<DialogContent\b/g)) {
    const end = text.indexOf('</DialogContent>', m.index)
    out.push([m.index, end < 0 ? text.length : end])
  }
  return out
}
const within = (regions: [number, number][], at: number) => regions.some(([a, b]) => at >= a && at < b)

/** The component a position sits in: the last top-level `function Name` / `const Name =` before it. */
function enclosing(text: string, at: number): string | null {
  let name: string | null = null
  for (const m of text.matchAll(/^(?:export\s+)?(?:default\s+)?(?:function\s+([A-Z]\w*)|const\s+([A-Z]\w*)\s*=)/gm)) {
    if (m.index > at) break
    name = m[1] ?? m[2] ?? null
  }
  return name
}

export function inlineForms() {
  const all = sources()
  // `file|Name`: a component rendered inside a dialog in that file.
  const used = new Set<string>()
  for (const { file, text } of all) {
    const regions = dialogRegions(text)
    for (const m of text.matchAll(/<([A-Z]\w*)\b/g)) if (within(regions, m.index)) used.add(`${file}|${m[1]}`)
  }
  /** Is component `name`, defined in `file`, rendered in a dialog there or in a file that imports it from there? */
  const hostedIn = (file: string, name: string) => {
    if (used.has(`${file}|${name}`)) return true
    const base = file.replace(/\.tsx$/, '').split('/').pop()!
    return all.some((o) => used.has(`${o.file}|${name}`) && new RegExp(`import[^;]*\\b${name}\\b[^;]*from\\s+['"][^'"]*/${base}['"]`).test(o.text))
  }
  const found: { file: string; line: number; name: string | null; marked: boolean }[] = []
  for (const { file, text } of all) {
    const regions = dialogRegions(text)
    const lines = text.split('\n')
    for (const m of text.matchAll(/<form\b/g)) {
      if (within(regions, m.index)) continue
      const name = enclosing(text, m.index)
      if (name && hostedIn(file, name)) continue
      const line = text.slice(0, m.index).split('\n').length
      const marked = [line - 3, line - 2, line - 1].some((i) => /inline-form-guard:\s*\S/.test(lines[i] ?? ''))
      found.push({ file, line, name, marked })
    }
  }
  return found
}

/** Components that edit in place: an editing state and a field outside any dialog, in a component not hosted by a dialog. */
export function editsInPlace(all = sources()) {
  const out: string[] = []
  for (const { file, text } of all) {
    const regions = dialogRegions(text)
    const starts = [...text.matchAll(/^(?:export\s+)?(?:default\s+)?(?:function\s+([A-Z]\w*)|const\s+([A-Z]\w*)\s*=)/gm)].map((m) => ({ at: m.index, name: m[1] ?? m[2]! }))
    starts.forEach((c, i) => {
      const end = starts[i + 1]?.at ?? text.length
      const body = text.slice(c.at, end)
      const state = /const \[(?:editing|renaming|isEditing|inlineEdit)\w*, set\w+\] = useState/.test(body) || /\b(?:editing|renaming)\??:\s*boolean/.test(body)
      if (!state || /<Dialog\b/.test(body)) return
      const field = [...body.matchAll(/<(?:Input|Textarea)\b/g)].find((m) => !within(regions, c.at + m.index))
      if (field) out.push(`${file}: ${c.name}`)
    })
  }
  return out
}

describe('inline form guard', () => {
  it('nothing is edited in place: an editing state opens a dialog (or its own page), not a field inside the page', () => {
    expect(editsInPlace(), 'Open the edit in a dialog over the page').toEqual([])
    const src = (text: string) => editsInPlace([{ file: 'x.tsx', text }])
    expect(src('function Title() {\n  const [editing, setEditing] = useState(false)\n  return editing ? <Input value={v} /> : <h1>{v}</h1>\n}\n')).toEqual(['x.tsx: Title'])
    expect(src('function Title() {\n  const [editing, setEditing] = useState(false)\n  return <Dialog open={editing}><DialogContent title="x"><Input /></DialogContent></Dialog>\n}\n')).toEqual([])
  })

  const found = inlineForms()
  const open = found.filter((f) => !f.marked)

  it('every form that is not in a dialog is named with a reason', () => {
    const byFile = new Map<string, number>()
    for (const f of open) byFile.set(f.file, (byFile.get(f.file) ?? 0) + 1)
    const problems: string[] = []
    for (const [file, n] of byFile) {
      const a = ALLOWED.find((x) => x.file === file)
      if (!a) problems.push(`${file}: ${n} form(s) in the page content (lines ${open.filter((f) => f.file === file).map((f) => f.line).join(', ')}): open it in a dialog, or give it its own page with Back; or name it in ALLOWED with a reason`)
      else if (a.count !== n) problems.push(`${file}: ALLOWED covers ${a.count} form(s) but the file has ${n}`)
    }
    for (const a of ALLOWED) if (!byFile.has(a.file)) problems.push(`${a.file}: ALLOWED entry no longer matches a form: remove it`)
    expect(problems).toEqual([])
  })

  it('every ALLOWED entry gives a reason', () => {
    expect(ALLOWED.filter((a) => a.why.trim().length < 10)).toEqual([])
  })
})
