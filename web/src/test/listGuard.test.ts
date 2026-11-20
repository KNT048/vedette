// The list guard: every list that pages goes through the one shared table (DataTable) and its shared search box and pager
// (components/common/Pager.tsx). A page of its own pager, its own slice of rows into pages, or a list with the table's search box
// turned off and no search of the page's own fails here.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..')
const ROOTS = ['features', 'components', 'app']
const SHARED = new Set(['components/common/DataTable.tsx', 'components/common/Pager.tsx', 'components/common/listParams.ts'])

const files = ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
  .filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f) && !/\.d\.ts$/.test(f))
  .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))

/** What only the shared components may do: page rows, draw page controls, keep a list's page in the URL. */
const OWN_PAGING: { name: string; re: RegExp }[] = [
  { name: 'a table pages itself (getPaginationRowModel)', re: /getPaginationRowModel/ },
  { name: 'a pager of its own (the table.prev / table.next / table.page texts)', re: /['"`](?:common:)?table\.(?:prev|next|page|first|last|goTo)['"`]/ },
  { name: 'rows sliced into pages by hand', re: /\.slice\(\s*\w+\s*\*\s*\w+/ },
  { name: 'a list page number of its own in the URL', re: /(?:params|searchParams|p)\.(?:get|set)\(\s*['"]page['"]/ },
]

/** The opening tags of the DataTables in a source text (the text of each tag, props and all). */
function tables(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(/<DataTable\b/g)) {
    let depth = 0
    let quote = ''
    let i = m.index! + m[0].length
    if (text[i] === '<') i = text.indexOf('>', i) + 1 // the type argument: <DataTable<Row> …
    for (; i < text.length; i++) {
      const c = text[i]!
      if (quote) { if (c === '\\') i++; else if (c === quote) quote = '' } else if (c === '"' || c === "'" || c === '`') quote = c
      else if (c === '{') depth++
      else if (c === '}') depth--
      else if (c === '>' && depth === 0 && text[i - 1] !== '=') break
    }
    out.push(text.slice(m.index!, i))
  }
  return out
}

describe('list guard: one shared search box and pager', () => {
  it('reads the app sources', () => {
    expect(files.length).toBeGreaterThan(200)
    expect(files.some((f) => f.file === 'components/common/DataTable.tsx')).toBe(true)
  })

  it('no list pages itself or draws its own pager: DataTable and Pager do it for every list', () => {
    const bad = files.filter((f) => !SHARED.has(f.file)).flatMap((f) => OWN_PAGING.filter((r) => r.re.test(f.text)).map((r) => `${f.file}: ${r.name}`))
    expect(bad, 'Use DataTable (with server={…} when the box pages the list) instead').toEqual([])
  })

  it('a table whose search box is off sits on a page with a search of its own (ListSearch or TokenSearch)', () => {
    const bad = files.filter((f) => /<DataTable[\s\S]{0,400}?search=\{false\}/.test(f.text) && !/<(?:ListSearch|TokenSearch)\b|<DeviceSearch\b/.test(f.text)).map((f) => f.file)
    expect(bad).toEqual([])
  })

  it('a list the server pages uses the shared table in server mode, not a page of rows shown as the whole list', () => {
    // every useListParams outside the shared table feeds a DataTable of the same file
    const bad = files.filter((f) => !SHARED.has(f.file) && /useListParams\(/.test(f.text) && !/<DataTable\b/.test(f.text)).map((f) => f.file)
    expect(bad).toEqual([])
  })

  it('every DataTable has its own explicit, unique urlKey, so a list keeps its page, search, size and sort in the URL', () => {
    const sites = files.filter((f) => !SHARED.has(f.file)).flatMap((f) => tables(f.text).map((tag) => ({ file: f.file, tag })))
    expect(sites.length).toBeGreaterThan(50)
    // a server-paged table takes the key from the page's useListParams('<key>'): it has none of its own
    const missing = sites.filter((s) => !/\burlKey=/.test(s.tag) && !/\bserver=/.test(s.tag)).map((s) => s.file)
    expect(missing, 'Give every DataTable urlKey="…": a key derived from the caption changes with the text and can be shared by two lists').toEqual([])
    const literal = sites.map((s) => /\burlKey="([^"]+)"/.exec(s.tag)?.[1]).filter((k): k is string => !!k)
    const dup = literal.filter((k, i) => literal.indexOf(k) !== i)
    expect(dup, 'two lists with one urlKey share one page number').toEqual([])
  })

  it('a link of the page\'s own query (to="?tab=…") without an anchor goes through a KPI tile, which keeps the lists\' pages', () => {
    const bad = files.flatMap((f) => [...f.text.matchAll(/<Link\b[^>]*\bto=(?:"|\{["'`])\?[^"'`#]*["'`]/g)].map(() => f.file))
    expect(bad, 'A bare "?tab=…" link replaces the whole query and drops every list page: use KpiTile/KpiStrip, or useKeepListParams()').toEqual([])
  })

  it('the guard catches what it must', () => {
    expect(tables('<DataTable caption="x" data={d} />')).toHaveLength(1)
    expect(tables('<DataTable<Row> urlKey="a" caption={t(\'x\')} data={d.map((r) => <b key={r.id}>{r.n}</b>)} />')[0]).toMatch(/urlKey="a"/)
    expect(/<Link\b[^>]*\bto=(?:"|\{["'`])\?[^"'`#]*["'`]/.test('<Link to="?tab=software">x</Link>')).toBe(true)
    expect(/<Link\b[^>]*\bto=(?:"|\{["'`])\?[^"'`#]*["'`]/.test('<Link to="?tab=rules#templates">x</Link>')).toBe(false)
    const hit = (s: string) => OWN_PAGING.some((r) => r.re.test(s))
    expect(hit("<Button onClick={next}>{t('table.next')}</Button>")).toBe(true)
    expect(hit('const rows = items.slice(page * size, (page + 1) * size)')).toBe(true)
    expect(hit("const page = Number(params.get('page'))")).toBe(true)
    expect(hit('getPaginationRowModel: getPaginationRowModel()')).toBe(true)
    expect(hit("const head = items.slice(0, 20); t('table.empty')")).toBe(false)
  })
})
