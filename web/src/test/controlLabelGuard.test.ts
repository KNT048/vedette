// Every check box, switch and radio button has a name a screen reader reads out (WCAG 4.1.2). This guard reads every non-test
// .tsx under features/, components/ and app/ and counts each <Checkbox>, <Switch> and <RadioItem> that has none of:
//  - aria-label or aria-labelledby on the control;
//  - an id whose expression is also the htmlFor of a <label>/<Label> in the same file (id={x} … htmlFor={x}, or the same literal);
//  - a <label> that wraps it (an open <label …> before it with no </label> in between);
//  - a spread of props ({...props}) the caller fills: the caller's own file is read for that.
// A control that is named another way carries a `control-label-guard: <reason>` comment on its line or one of the two lines above.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']
const CONTROL = /<(Checkbox|Switch|RadioItem)\b/g

function sources() {
  return ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

/** The opening tag starting at `at`, up to its closing `>` (braces, strings and arrow functions inside skipped). */
function openTag(text: string, at: number): string {
  let depth = 0
  let quote = ''
  for (let i = at + 1; i < text.length; i++) {
    const c = text[i]
    if (quote) { if (c === quote && text[i - 1] !== '\\') quote = ''; continue }
    if (c === '{') depth++
    else if (c === '}') depth--
    else if (c === '"' || c === "'" || c === '`') quote = c
    else if (c === '>' && depth === 0) return text.slice(at, i + 1)
  }
  return text.slice(at)
}

/** The value of attribute `name` in a tag: the text inside {…} or the quoted literal. */
function attr(tag: string, name: string): string | null {
  const at = tag.search(new RegExp(`\\s${name}=`))
  if (at < 0) return null
  const start = tag.indexOf('=', at) + 1
  if (tag[start] === '"' || tag[start] === "'") return tag.slice(start + 1, tag.indexOf(tag[start]!, start + 1))
  let depth = 0
  for (let i = start; i < tag.length; i++) {
    if (tag[i] === '{') depth++
    else if (tag[i] === '}' && --depth === 0) return tag.slice(start + 1, i).trim()
  }
  return null
}

function unnamed(file: string, text: string): string[] {
  const out: string[] = []
  const htmlFor = new Set([...text.matchAll(/\shtmlFor=/g)].map((m) => attr(text.slice(m.index, m.index + 400), 'htmlFor')))
  for (const m of text.matchAll(CONTROL)) {
    const tag = openTag(text, m.index)
    if (/\saria-label(ledby)?=/.test(tag) || /\{\.\.\.props\}/.test(tag)) continue
    const id = attr(tag, 'id')
    if (id && htmlFor.has(id)) continue
    const before = text.slice(0, m.index)
    const opened = Math.max(before.lastIndexOf('<label '), before.lastIndexOf('<label>'), before.lastIndexOf('<Label '))
    if (opened >= 0 && !/<\/(label|Label)>/.test(before.slice(opened))) continue
    const line = before.split('\n').length
    const near = text.split('\n').slice(Math.max(0, line - 3), line).join('\n')
    if (/control-label-guard:/.test(near)) continue
    out.push(`${file}:${line} <${m[1]}${id ? ` id={${id}}` : ''}>`)
  }
  return out
}

describe('every check box, switch and radio button has an accessible name', () => {
  it('finds none without a name', () => {
    expect(sources().flatMap(({ file, text }) => unnamed(file, text))).toEqual([])
  })

  it('the scan sees the ways a control is named and the ways it is not', () => {
    expect(unnamed('a.tsx', '<Checkbox id="x" /><Label htmlFor="x">A</Label>')).toEqual([])
    expect(unnamed('a.tsx', '<Switch id={`${p}-on`} checked /><Label htmlFor={`${p}-on`}>On</Label>')).toEqual([])
    expect(unnamed('a.tsx', '<label className="flex"><Checkbox checked={a} onCheckedChange={(v) => set(v === true)} />Keep</label>')).toEqual([])
    expect(unnamed('a.tsx', '<RadioItem value="a" aria-label={t("a")} />')).toEqual([])
    expect(unnamed('a.tsx', '<Checkbox id="x" /><Label htmlFor="y">A</Label>')).toEqual(['a.tsx:1 <Checkbox id={x}>'])
    expect(unnamed('a.tsx', '<label>A</label>\n<Switch checked={on} />')).toEqual(['a.tsx:2 <Switch>'])
  })
})
