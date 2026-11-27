// The layout guard: every page builds its tabs, list toolbars, count lines, row toggles and the way back from a detail page with
// the shared parts, so two tabs or two pages never draw the same thing two ways (docs/UI.md §3–§5):
//  - tabs: PageTabs (panels of one page) or UnderlineNav (links between pages); components/ui/tabs is private to PageTabs and no
//    page writes role="tab" / role="tablist" itself;
//  - the search above a list: DataTable's own, or ListToolbar (search first, then filters, then actions) when the page keeps it
//    above a server-paged list; no page places a ListSearch itself;
//  - the count line of a list: DataTable `summary` or ListSummary; a page that renders a DataTable does not write its own
//    role="status" line with a count next to it;
//  - a row or block that opens: ExpandToggle (a chevron pointing right when closed, down when open); no page pairs aria-expanded
//    with a chevron icon of its own;
//  - a detail page goes back with breadcrumbs (PageHeader `breadcrumbs`), not a "Back to …" arrow link.
// A named exception is listed in ALLOWED with why it stays; an entry no longer used fails too, so the list only shrinks.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

const files = ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
  .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
  .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))

type Rule = { id: string; why: string; owners: string[]; hits: (text: string) => number }

const count = (text: string, re: RegExp) => [...text.matchAll(re)].length

/** The role="status" elements of a source whose opening tag or the two lines after it interpolate a count ({ count: … }). */
function countLines(text: string): number {
  const lines = text.split('\n')
  let n = 0
  lines.forEach((l, i) => {
    if (/role="status"/.test(l) && /\{\s*count:/.test(lines.slice(i, i + 3).join('\n'))) n++
  })
  return n
}

const RULES: Rule[] = [
  {
    id: 'private-tabs', why: 'tabs are PageTabs (panels) or UnderlineNav (links): components/ui/tabs is private to PageTabs',
    owners: ['components/common/PageFrame.tsx'], hits: (t) => count(t, /from '@\/components\/ui\/tabs'/g),
  },
  {
    id: 'hand-tabs', why: 'a tab row of its own (role="tab" / "tablist"): use PageTabs or UnderlineNav',
    owners: [], hits: (t) => count(t, /role=["'](?:tab|tablist)["']/g),
  },
  {
    id: 'list-search', why: 'a search placed by hand: DataTable draws it, or ListToolbar above a server-paged list',
    owners: ['components/common/ListParts.tsx', 'components/common/Pager.tsx', 'components/common/DataTable.tsx'], hits: (t) => count(t, /<ListSearch\b/g),
  },
  {
    id: 'count-line', why: 'a list\'s count line of its own next to a DataTable: pass it as DataTable `summary` (or ListSummary)',
    owners: ['components/common/ListParts.tsx', 'components/common/Pager.tsx', 'components/common/DataTable.tsx'],
    hits: (t) => (/<DataTable\b/.test(t) ? countLines(t) : 0),
  },
  {
    id: 'expand-toggle', why: 'a disclosure chevron of its own (aria-expanded with a Chevron icon): use ExpandToggle',
    owners: ['components/common/ListParts.tsx'],
    hits: (t) => (/\bChevron(?:Down|Right|Up)\b/.test(t) ? count(t, /aria-expanded=/g) : 0),
  },
  {
    id: 'back-link', why: 'a "Back to …" arrow link: a detail page names its parents with PageHeader breadcrumbs',
    owners: [], hits: (t) => count(t, /<ArrowLeft\b/g),
  },
]

/** Exceptions that stay, with the reason; each must still match exactly `hits` times. */
const ALLOWED: { rule: string; file: string; hits: number; why: string }[] = [
  { rule: 'expand-toggle', file: 'app/Sidebar.tsx', hits: 1, why: 'a navigation group of the shell: its header is the whole row, with the group name and its badge' },
  { rule: 'count-line', file: 'features/feeds/ParserEditor.tsx', hits: 1, why: 'the result of one parser test run (accepted and rejected chips), not the count of a list' },
]

describe('layout guard: tabs, list toolbars, count lines, row toggles and breadcrumbs come from the shared parts', () => {
  it('reads the app sources', () => {
    expect(files.length).toBeGreaterThan(200)
  })

  for (const rule of RULES) {
    it(`${rule.id}: ${rule.why}`, () => {
      const found = files
        .filter((f) => !rule.owners.includes(f.file))
        .map((f) => ({ file: f.file, hits: rule.hits(f.text) }))
        .filter((f) => f.hits > 0)
      const allowed = ALLOWED.filter((a) => a.rule === rule.id)
      const bad = found.filter((f) => !allowed.some((a) => a.file === f.file && a.hits === f.hits)).map((f) => `${f.file} (${f.hits})`)
      expect(bad, `${rule.why}:\n${bad.join('\n')}`).toEqual([])
      const stale = allowed.filter((a) => !found.some((f) => f.file === a.file && f.hits === a.hits)).map((a) => `${a.file} (${a.hits})`)
      expect(stale, `ALLOWED entries that no longer match (remove them or fix the count):\n${stale.join('\n')}`).toEqual([])
    })
  }

  it('the rules find what they are written for', () => {
    const byId = Object.fromEntries(RULES.map((r) => [r.id, r]))
    expect(byId['private-tabs']!.hits(`import { Tabs } from '@/components/ui/tabs'`)).toBe(1)
    expect(byId['hand-tabs']!.hits('<div role="tablist"><button role="tab" /></div>')).toBe(2)
    expect(byId['list-search']!.hits('<ListSearch value={q} onChange={setQ} label="x" />')).toBe(1)
    expect(byId['count-line']!.hits(`<p role="status">{t('x', { count: n })}</p>\n<DataTable caption="x" />`)).toBe(1)
    expect(byId['count-line']!.hits(`<p role="status">{t('saved')}</p>\n<DataTable caption="x" />`)).toBe(0)
    expect(byId['expand-toggle']!.hits(`<Button aria-expanded={open}><ChevronDown /></Button>`)).toBe(1)
    expect(byId['back-link']!.hits(`<Link to="/x"><ArrowLeft />Back</Link>`)).toBe(1)
  })
})
