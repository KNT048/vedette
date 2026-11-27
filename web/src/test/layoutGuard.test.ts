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
//  - a detail page goes back with breadcrumbs (PageHeader `breadcrumbs`), not a "Back to …" arrow link;
//  - a page title is the short noun of the page's sidebar entry or settings menu entry ("Findings", "Devices", "Logs", "Updates"), never a
//    sentence or a count: those go in the header's `meta` line under it (see PAGE_TITLES);
//  - a tab panel does not open with a heading that repeats its tab's name ("Trap hits" in the Hits tab): its Section has no
//    `title`, only a `label` (the English texts of the feature's tab labels and Section titles are compared).
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

const LOCALES: Record<string, unknown> = Object.fromEntries(readdirSync(join(SRC, 'locales/en')).filter((f) => f.endsWith('.json'))
  .map((f) => [f.replace(/\.json$/, ''), JSON.parse(readFileSync(join(SRC, 'locales/en', f), 'utf8')) as unknown]))

/** The English text of an i18n key used in a file of namespace `ns` ("common:x.y" names its own); a plural key's other form. */
function english(ns: string, key: string): string | undefined {
  const [n, k] = key.includes(':') ? key.split(':', 2) as [string, string] : [ns, key]
  const at = (path: string) => path.split('.').reduce<unknown>((o, p) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[p] : undefined), LOCALES[n])
  const v = at(k) ?? at(`${k}_other`)
  return typeof v === 'string' ? v : undefined
}
const words = (s: string) => s.toLowerCase().replace(/\(.*?\)|\{\{.*?\}\}/g, '').replace(/\s+/g, ' ').trim()
const nsOf = (text: string) => /useTranslation\('(\w+)'\)/.exec(text)?.[1] ?? 'common'
const featureOf = (file: string) => file.split('/').slice(0, 2).join('/')

/** Per feature: the tab labels of its PageTabs, in words. */
const tabLabels = new Map<string, Set<string>>()
for (const f of files) {
  for (const block of f.text.match(/<PageTabs[\s\S]*?\]\}\s*\/>/g) ?? []) {
    for (const m of block.matchAll(/label: t\('([^']+)'/g)) {
      const v = english(nsOf(f.text), m[1]!)
      if (v) tabLabels.set(featureOf(f.file), new Set([...(tabLabels.get(featureOf(f.file)) ?? []), words(v)]))
    }
  }
}

/** The Sections of a file whose title repeats a tab label of its feature (the same words, or ending in them). */
function tabHeadings(file: string, text: string): string[] {
  const labels = tabLabels.get(featureOf(file)) ?? new Set<string>()
  return [...text.matchAll(/<Section\b[^>]*?\btitle=\{t\('([^']+)'/g)].flatMap((m) => {
    const v = english(nsOf(text), m[1]!)
    const w = v ? words(v) : ''
    return w && [...labels].some((l) => w === l || w.endsWith(` ${l}`)) ? [m[1]!] : []
  })
}

const TAB_HEADING_ALLOWED: { file: string; key: string; why: string }[] = [
  { file: 'features/exposure/ExposurePage.tsx', key: 'settings.scanTitle', why: 'one of three blocks of the Settings tab, each with its own heading' },
  { file: 'features/honeypot/DevicePanel.tsx', key: 'device.title', why: 'a block of the device page, not of the trap page\'s Hits tab' },
  { file: 'features/inventory/DeclaredSoftwareSection.tsx', key: 'declaredPage.title', why: 'a settings page of its own, not the device page\'s Software tab' },
  { file: 'features/reports/PdplTab.tsx', key: 'pdpl.report.title', why: 'one block of the assessment tab, not the Report tab' },
  { file: 'features/response/MetricsTab.tsx', key: 'ai.title', why: 'one of several blocks of the metrics tab, not the Requests tab' },
  { file: 'features/response/MetricsTab.tsx', key: 'metrics.rejectedTitle', why: 'one of several blocks of the metrics tab, not the Requests tab' },
]

/** The page behind each sidebar entry and settings menu entry: its source file and the translation key of its entry. The page's
 *  PageHeader title is that same key (`t('common:shell.findings')`, or `t('settings.users')` in core), so the heading is the word the
 *  person just clicked. A status line or a count goes in `meta`. A new nav or settings entry must be listed here (or in
 *  TITLE_EXEMPT) or the test below fails. */
const PAGE_TITLES: { entry: string; file: string; key: string }[] = [
  { entry: 'common:shell.findings', file: 'features/findings/FindingsPage.tsx', key: 'common:shell.findings' },
  { entry: 'common:shell.devices', file: 'features/inventory/DevicesPage.tsx', key: 'common:shell.devices' },
  { entry: 'common:shell.exposure', file: 'features/exposure/ExposurePage.tsx', key: 'common:shell.exposure' },
  { entry: 'common:shell.logs', file: 'features/logs/LogsPage.tsx', key: 'common:shell.logs' },
  { entry: 'common:shell.assistant', file: 'features/ai/AssistantPage.tsx', key: 'common:shell.assistant' },
  { entry: 'common:shell.honeypot', file: 'features/honeypot/HoneypotPage.tsx', key: 'common:shell.honeypot' },
  { entry: 'common:shell.reports', file: 'features/reports/ReportsPage.tsx', key: 'common:shell.reports' },
  { entry: 'common:shell.incidents', file: 'features/notify/IncidentsPage.tsx', key: 'common:shell.incidents' },
  { entry: 'common:shell.detection', file: 'features/detection/DetectionPage.tsx', key: 'common:shell.detection' },
  { entry: 'common:shell.response', file: 'features/response/ResponsePage.tsx', key: 'common:shell.response' },
  { entry: 'common:shell.lookup', file: 'features/feeds/LookupPage.tsx', key: 'common:shell.lookup' },
  { entry: 'common:shell.scanning', file: 'features/scanning/ScanningPage.tsx', key: 'common:shell.scanning' },
  { entry: 'common:shell.siem', file: 'features/logs/SiemSettings.tsx', key: 'common:shell.siem' },
  { entry: 'common:shell.aiSettings', file: 'features/ai/AiSettings.tsx', key: 'common:shell.aiSettings' },
  { entry: 'common:shell.feedsSettings', file: 'features/feeds/FeedsSettings.tsx', key: 'common:shell.feedsSettings' },
  { entry: 'common:shell.channels', file: 'features/notify/ChannelsSettings.tsx', key: 'common:shell.channels' },
  { entry: 'common:shell.responseSettings', file: 'features/response/ResponseSettings.tsx', key: 'common:shell.responseSettings' },
  { entry: 'core:settings.general', file: 'features/core/GeneralSection.tsx', key: 'settings.general' },
  { entry: 'core:settings.modules', file: 'features/core/ModulesSection.tsx', key: 'settings.modules' },
  { entry: 'core:settings.users', file: 'features/core/UsersSection.tsx', key: 'settings.users' },
  { entry: 'core:settings.connections', file: 'features/core/ConnectionsSection.tsx', key: 'settings.connections' },
  { entry: 'core:settings.audit', file: 'features/core/AuditSection.tsx', key: 'settings.audit' },
  { entry: 'core:settings.updates', file: 'features/core/UpdatesSection.tsx', key: 'settings.updates' },
  { entry: 'core:settings.network', file: 'features/core/NetworkSection.tsx', key: 'settings.network' },
  { entry: 'core:settings.privacy', file: 'features/core/PrivacySection.tsx', key: 'settings.privacy' },
  { entry: 'core:settings.mcp', file: 'features/core/McpSection.tsx', key: 'settings.mcp' },
  { entry: 'core:settings.data', file: 'features/core/DataSection.tsx', key: 'settings.data' },
  { entry: 'core:settings.myAccount', file: 'features/core/AccountPage.tsx', key: 'settings.myAccount' },
]

/** Entries whose page keeps a heading of its own, with why. */
const TITLE_EXEMPT: { entry: string; why: string }[] = [
  { entry: 'common:shell.home', why: 'the dashboard: its heading is the answer to "is anything I run being exploited?", not the word Home' },
  { entry: 'common:shell.declared', why: 'a block of the device settings, drawn as a Section, not a page with its own header' },
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

  it('tab-heading: a tab panel does not open with a heading that repeats the tab name (Section `label`, not `title`)', () => {
    const found = files.flatMap((f) => tabHeadings(f.file, f.text).map((key) => ({ file: f.file, key })))
    const bad = found.filter((x) => !TAB_HEADING_ALLOWED.some((a) => a.file === x.file && a.key === x.key)).map((x) => `${x.file} ${x.key}`)
    expect(bad).toEqual([])
    const stale = TAB_HEADING_ALLOWED.filter((a) => !found.some((x) => x.file === a.file && x.key === a.key)).map((a) => `${a.file} ${a.key}`)
    expect(stale).toEqual([])
    expect(tabLabels.get('features/honeypot')?.has('hits')).toBe(true)
    expect(tabHeadings('features/honeypot/X.tsx', `useTranslation('honeypot')\n<Section id="x" title={t('hits.title')}>`)).toEqual(['hits.title'])
  })

  it('page-title: a page header carries its sidebar or settings entry name, not a sentence or a count', () => {
    // Every entry of the shell is listed.
    const entries = files.flatMap((f) => [...f.text.matchAll(/\blabel: '((?:common:shell|core:settings)\.\w+)'/g)].map((m) => m[1]!))
    const unlisted = [...new Set(entries)].filter((e) => !PAGE_TITLES.some((p) => p.entry === e) && !TITLE_EXEMPT.some((x) => x.entry === e))
    expect(unlisted, `nav or settings entries with no page in PAGE_TITLES (add the page, or an exemption with why):\n${unlisted.join('\n')}`).toEqual([])
    const gone = [...PAGE_TITLES.map((p) => p.entry), ...TITLE_EXEMPT.map((x) => x.entry)].filter((e) => !entries.includes(e))
    expect(gone, `listed entries that no longer exist:\n${gone.join('\n')}`).toEqual([])
    // Each listed page titles itself with that key, and no header of its file computes a title from data.
    const bad = PAGE_TITLES.flatMap((p) => {
      const text = files.find((f) => f.file === p.file)?.text
      if (text === undefined) return [`${p.file}: no such file`]
      const out: string[] = []
      if (!new RegExp(`<PageHeader\\s+title=\\{t\\('${p.key}'\\)\\}`).test(text)) out.push(`${p.file}: no PageHeader title={t('${p.key}')}`)
      for (const m of text.matchAll(/<PageHeader\s+title=\{(?!t\(')([^}]{0,40})/g)) out.push(`${p.file}: PageHeader title computed from data (${m[1]}): put the status in meta`)
      return out
    })
    expect(bad).toEqual([])
    // The names themselves are short nouns: a status sentence in a locale entry would pass the checks above.
    for (const p of PAGE_TITLES) {
      const [ns, k] = p.entry.split(':') as [string, string]
      const v = english(ns, k) ?? ''
      expect(v.split(' ').length, `${p.entry} reads as a sentence: "${v}"`).toBeLessThanOrEqual(5)
      expect(v, `${p.entry} carries a count or punctuation: "${v}"`).not.toMatch(/[.:,{}\d]/)
    }
  })

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
