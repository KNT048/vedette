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

  it('the guard catches what it must', () => {
    const hit = (s: string) => OWN_PAGING.some((r) => r.re.test(s))
    expect(hit("<Button onClick={next}>{t('table.next')}</Button>")).toBe(true)
    expect(hit('const rows = items.slice(page * size, (page + 1) * size)')).toBe(true)
    expect(hit("const page = Number(params.get('page'))")).toBe(true)
    expect(hit('getPaginationRowModel: getPaginationRowModel()')).toBe(true)
    expect(hit("const head = items.slice(0, 20); t('table.empty')")).toBe(false)
  })
})
