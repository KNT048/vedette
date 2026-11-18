// docs/UI.md §8 (busy state): every button that waits on the server shows the same busy state, the Button's `busy` and
// `busyLabel` (spinner, "Saving…", aria-busy, no width jump), so a person knows the box is working. This guard reads every
// non-test .tsx under features/, components/ and app/ and fails on a <Button> that waits without it. A named exception carries
// `busy-guard: <reason>` in a comment inside the tag, on its line or on one of the two lines above it, and is listed in ALLOWED below with the
// same reason and the number of tags it covers; an entry covering more or fewer tags fails too.
//
// Known limits (a static, per-file read; #930: no cross-file analyzer):
// - a helper or hook imported from another file (`onClick={() => saveThing(v)}` with saveThing in api.ts) is not followed;
// - props passed by a spread (`<Button {...props}>`) are not seen;
// - a form whose onSubmit comes from a parent (`<form onSubmit={props.onSubmit}>`) is not known to call the server.
// What it does follow in one file: `.mutate(`/`.mutateAsync(` and `onClick={save.mutate}`, a destructured
// `const { mutate: save } = useX()`, a download(), and functions of the file (a hook returning a mutation included) two levels deep.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

/** State that means "the action is waiting on the server": react-query's flags and the names the code gives them. */
const WAIT_NAMES = 'busy|pending|saving|submitting|loading|working|sending|testing|deleting|inFlight|isSaving|isBusy|isSending|isSubmitting|isWorking'
const WAITING = new RegExp(`\\b(?:\\w+\\.)?(?:isPending|isFetching|isMutating|isLoading)\\b|\\b(?:${WAIT_NAMES})\\b`)
/** A label swapped by hand while waiting: `{save.isPending ? t('saving') : t('save')}`. */
const HAND_LABEL = new RegExp(`\\b(?:\\w+\\.)?(?:isPending|isFetching|isMutating|isLoading)\\s*\\?|\\b(?:${WAIT_NAMES})\\s*\\?`)
/** A spinner drawn by hand inside a button. */
const HAND_SPINNER = /animate-spin|LoaderCircle|Loader2/
/** A call that waits on the server: a react-query mutation, or a file download (lib/api download() fetches the whole file first). */
const SERVER_CALL = /\.mutate(?:Async)?\b|(?<![\w.])download\(/
/** Cancel, Close and Back are not the action that waits: they are only held while it runs. Exempt only when they do not call the
 * server themselves (an action named "Keep separate" or "Cancel reboot" that runs a mutation is checked like any other). */
const NOT_THE_ACTION = /t\(\s*['"][\w:.]*\b(?:cancel|close|back)['"]/

const RULES = {
  noBusy: 'waits on the server (its disabled= reads a pending state, or its onClick/onSelect calls a mutation or a download, itself or through a function of this file) but has no busy= prop: add busy={x.isPending} busyLabel={t(\'common:busy.saving\')}',
  submitNoBusy: 'is the submit button of a form whose onSubmit calls a mutation, but has no busy= prop: add busy={x.isPending} busyLabel={t(\'common:busy.saving\')}',
  handLabel: 'swaps its label by hand while waiting: use busy= and busyLabel= instead',
  handSpinner: 'draws its own spinner: the Button draws it when busy= is true',
  noLabel: 'has busy= but no busyLabel= (say what is happening: "Saving…"); only an icon button (size="icon") may go without one',
  rawButton: 'is a raw <button> that waits on the server: use the shared <Button busy= busyLabel=>',
  menuItem: 'is a menu item that waits on the server: the menu closes, so nothing shows the wait; run it from a <Button busy=> or name the exception',
}
type Rule = keyof typeof RULES

/** The named exceptions: file, a piece of the tag's text, how many tags it covers (a second identical tag fails), and why. */
const ALLOWED: { file: string; text: string; count: number; why: string }[] = [
  { file: 'components/ui/button.tsx', text: '<button className', count: 1, why: 'the Button itself: its native button is the one that draws the busy state' },
  { file: 'features/core/SetupPage.tsx', text: 'key="next"', count: 1, why: 'Continue only moves to the next step of the wizard; Finish (busy) is the step that calls the server' },
  { file: 'features/inventory/DevicePage.tsx', text: "remove(sw, 'software.correctionUndone')", count: 1, why: 'Undo correction in a software line\'s menu: the line\'s More button shows the wait' },
  { file: 'features/inventory/DevicePage.tsx', text: "remove(sw, 'software.removed')", count: 1, why: 'Remove in a software line\'s menu: the line\'s More button shows the wait' },
  { file: 'features/inventory/DevicePage.tsx', text: 'ask.mutate(undefined', count: 1, why: 'Ask the agent now in an agent line\'s menu: the line\'s More button shows the wait' },
]

function sources() {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

type Tag = { at: number; open: string; body: string }

/** Every <Name …> opening tag (braces, strings and arrows inside it skipped) with the text up to its closing tag. */
function tags(text: string, name: string): Tag[] {
  const out: Tag[] = []
  for (const m of text.matchAll(new RegExp(`<${name}(?=[\\s>/])`, 'g'))) {
    let i = m.index + name.length + 1
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
    const end = open.endsWith('/>') ? i + 1 : text.indexOf(`</${name}>`, i)
    out.push({ at: m.index, open, body: text.slice(i + 1, end < 0 ? i + 1 : end) })
  }
  return out
}

/** The text of a function of this file named `fn` (function fn(…) {…}, const fn = (…) => …, const fn = useCallback(…)), or '':
 * from its name to the first line end where every bracket opened since is closed again. */
function bodyOf(text: string, fn: string): string {
  const m = new RegExp(`(?:function\\s+${fn}\\s*\\(|(?:const|let)\\s+${fn}\\s*=)`).exec(text)
  if (!m) return ''
  let depth = m[0].endsWith('(') ? 1 : 0 // function fn( opened its parameter list
  for (let i = m.index + m[0].length; i < text.length; i++) {
    const c = text[i]
    if (c === '(' || c === '{' || c === '[') depth++
    else if (c === ')' || c === '}' || c === ']') depth--
    else if (c === '\n' && depth <= 0) return text.slice(m.index + m[0].length, i)
  }
  return text.slice(m.index + m[0].length)
}

/** The names a file binds to a mutation's function by destructuring: `const { mutate } = …`, `const { mutateAsync: save } = …`. */
function mutators(text: string): RegExp | null {
  const names: string[] = []
  for (const m of text.matchAll(/(?:const|let)\s*\{([^{}]*\bmutate(?:Async)?\b[^{}]*)\}\s*=/g)) {
    for (const part of m[1]!.split(',')) {
      const [key, alias] = part.split(':').map((x) => x.trim())
      if (key === 'mutate' || key === 'mutateAsync') names.push(alias || key)
    }
  }
  return names.length ? new RegExp(`(?<![\\w.])(?:${names.join('|')})\\b`) : null
}

/** Does this handler expression call the server, itself or through functions of this file (two levels deep)? */
function callsServer(text: string, expr: string | null, depth = 2, bound = mutators(text)): boolean {
  if (!expr) return false
  if (SERVER_CALL.test(expr) || bound?.test(expr)) return true
  if (depth === 0) return false
  const names = new Set([...expr.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\(/g)].map((m) => m[1]!))
  const bare = /^\s*([A-Za-z_]\w*)\s*$/.exec(expr)?.[1]
  if (bare) names.add(bare)
  return [...names].some((n) => callsServer(text, bodyOf(text, n), depth - 1, bound))
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
    const lines = text.split('\n')
    const at = (pos: number, open: string) => {
      const line = text.slice(0, pos).split('\n').length
      const marked = /busy-guard:/.test(open) || lines.slice(Math.max(0, line - 3), line).some((l) => l.includes('busy-guard:'))
      return (rule: Rule) => hits.push({ file, line, rule, tag: open.replace(/\s+/g, ' ').slice(0, 160), marked })
    }
    // the forms whose onSubmit calls the server, as spans of the file: a submit Button inside one of them waits too
    const serverForms = tags(text, 'form').filter((f) => callsServer(text, prop(f.open, 'onSubmit'))).map((f) => [f.at, f.at + f.open.length + f.body.length] as const)
    for (const b of tags(text, 'Button')) {
      const serverForm = serverForms.some(([from, to]) => b.at > from && b.at < to)
      const hit = at(b.at, b.open)
      const busy = has(b.open, 'busy')
      const disabled = prop(b.open, 'disabled')
      const handler = prop(b.open, 'onClick') ?? prop(b.open, 'onSelect')
      const server = callsServer(text, handler)
      const waits = (disabled !== null && WAITING.test(disabled)) || server
      if (!busy && waits && !(NOT_THE_ACTION.test(b.body) && !server)) hit('noBusy')
      if (!busy && !waits && serverForm && /\stype="submit"/.test(b.open)) hit('submitNoBusy')
      if (HAND_LABEL.test(b.body)) hit('handLabel')
      if (HAND_SPINNER.test(b.body)) hit('handSpinner')
      const label = /\sbusyLabel=(?:""|''|\{\s*(?:''|""|``)\s*\})/.test(b.open) ? null : has(b.open, 'busyLabel')
      // an icon-only button (size="icon", or nothing in it but one icon) is named by its aria-label; every other one says what it does
      const iconOnly = /\ssize="icon"/.test(b.open) || /^\s*<\w+[^<>]*\/>\s*$/.test(b.body)
      if (busy && !label && !(iconOnly && has(b.open, 'aria-label'))) hit('noLabel')
    }
    for (const b of tags(text, 'button')) {
      const disabled = prop(b.open, 'disabled')
      if ((disabled !== null && WAITING.test(disabled)) || callsServer(text, prop(b.open, 'onClick'))) at(b.at, b.open)('rawButton')
    }
    for (const b of tags(text, 'DropdownMenuItem')) {
      const disabled = prop(b.open, 'disabled')
      if ((disabled !== null && WAITING.test(disabled)) || callsServer(text, prop(b.open, 'onSelect') ?? prop(b.open, 'onClick'))) at(b.at, b.open)('menuItem')
    }
  }
  return hits
}

const covers = (a: (typeof ALLOWED)[number], h: Hit) => a.file === h.file && h.tag.includes(a.text)
const allowedHit = (h: Hit) => ALLOWED.some((a) => covers(a, h))

describe('busy guard (docs/UI.md §8)', () => {
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
    const off = ALLOWED.map((a) => ({ a, n: hits.filter((h) => covers(a, h)).length })).filter(({ a, n }) => n !== a.count).map(({ a, n }) => `${a.file} ${a.text}: covers ${n} tags, the entry says ${a.count}`)
    expect(off, 'ALLOWED entries must cover exactly the tags they name: a new identical tag needs its own review (and count), an unused entry goes').toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    const t = (src: string) => scan([{ file: 'x.tsx', text: src }]).map((h) => h.rule)
    // caught
    expect(t(`<Button disabled={!can || save.isPending} onClick={() => save.mutate(v)}>{t('common:save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<Button\n  variant="primary"\n  disabled={busy}\n  onClick={() => go(a > b)}\n>{t('run')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<Button busy={ask.isPending} busyLabel={t('asking')}>{ask.isPending ? t('running') : t('ask')}</Button>`)).toEqual(['handLabel'])
    expect(t(`<Button disabled={x}>{find.isPending ? <LoaderCircle className="animate-spin" /> : null}{t('find')}</Button>`)).toEqual(['handLabel', 'handSpinner'])
    expect(t(`<Button busy={del.isPending}>{t('delete')}</Button>`)).toEqual(['noLabel'])
    // #930: no disabled= at all, a call through a function of the file, a download, other pending names, "Keep" and
    // "Cancel reboot" actions that call the server, raw buttons, menu items, a form's submit button, an empty busy label
    expect(t(`<Button onClick={() => save.mutate(v)}>{t('common:save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`function confirm() {\n  void keep.mutateAsync(id).then(close)\n}\n<Button onClick={confirm}>{t('same.keepConfirm')}</Button>`)).toEqual(['noBusy'])
    expect(t(`const dl = (p: string) => () => void download(p, 'f.csv')\n<Button onClick={dl('/x')}>{t('export')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<Button disabled={isSaving}>a</Button><Button disabled={q.isLoading}>b</Button><Button disabled={sending}>c</Button><Button disabled={inFlight}>d</Button>`)).toEqual(['noBusy', 'noBusy', 'noBusy', 'noBusy'])
    expect(t(`<Button onClick={() => reboot.mutate()}>{t('os.reboot.cancel')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<button disabled={save.isPending}>x</button>`)).toEqual(['rawButton'])
    expect(t(`<Button asChild><button disabled={save.isPending}>x</button></Button>`)).toEqual(['rawButton'])
    expect(t(`<DropdownMenuItem disabled={del.isPending} onSelect={() => del.mutate(id)}>x</DropdownMenuItem>`)).toEqual(['menuItem'])
    expect(t(`<form onSubmit={submit}><Button type="submit">{t('save')}</Button></form>\nfunction submit() {\n  save.mutate(v)\n}`)).toEqual(['submitNoBusy'])
    expect(t(`<Button busy={x.isPending} busyLabel="">{t('save')}</Button>`)).toEqual(['noLabel'])
    // #930: a mutation passed by reference, a destructured mutate, a hook of the file that returns one; a submit button
    // inside the server form only (the local form beside it is not flagged)
    expect(t(`<Button onClick={save.mutate}>{t('save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`const { mutate: saveIt } = useSave()\n<Button onClick={() => saveIt(v)}>{t('save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`const { mutateAsync } = useSave()\n<Button onClick={() => void mutateAsync(v)}>{t('save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`function useSaver() {\n  const m = useMutation({ mutationFn })\n  return (v: string) => m.mutate(v)\n}\nconst saveIt = useSaver()\n<Button onClick={() => saveIt(v)}>{t('save')}</Button>`)).toEqual(['noBusy'])
    expect(t(`<form onSubmit={(e) => { e.preventDefault(); save.mutate(v) }}><Button type="submit">{t('save')}</Button></form>\n<form onSubmit={(e) => { e.preventDefault(); setQ(v) }}><Button type="submit">{t('find')}</Button></form>`)).toEqual(['submitNoBusy'])
    expect(t(`<Button size="sm" busy={x.isPending} aria-label={t('test', { name })}>{t('test')}</Button>`)).toEqual(['noLabel'])
    // left alone: the pattern, icon buttons named by aria-label, Cancel held while the action runs, links, plain disabled
    expect(t(`<Button busy={save.isPending} busyLabel={t('common:busy.saving')} disabled={!dirty}>{t('common:save')}</Button>`)).toEqual([])
    expect(t(`<Button size="icon" busy={del.isPending} aria-label={t('del', { name })}><Trash2 /></Button>`)).toEqual([])
    expect(t(`<Button disabled={save.isPending} onClick={close}>{t('common:cancel')}</Button>`)).toEqual([])
    expect(t(`<Button asChild><Link to="/x">{t('open')}</Link></Button>`)).toEqual([])
    expect(t(`<Button disabled={!admin || !dirty} title={why}>{t('common:save')}</Button>`)).toEqual([])
    expect(t(`<Button size="sm" busy={del.isPending} aria-label={t('del', { name })}><Trash2 /></Button>`)).toEqual([])
    expect(t(`function download() {\n  a.click()\n}\n<Button onClick={download}>{t('get')}</Button>`)).toEqual([])
    expect(t(`<Button onClick={() => setOpen(true)} disabled={save.isPending}>{t('dialog.back')}</Button>`)).toEqual([])
  })
})
