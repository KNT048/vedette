// One status model: a finding's status, a device's badge, a CVE's severity, how a match is verified and how a finding was handled
// each have one component (components/common/status). This guard counts the whole class: every chip in features/, components/
// and app/ whose words name one of these ideas, every component that drew one its own way, and every run of CVE ids built by hand
// (a joined string or one element per id) instead of <CveList>. A named exception is listed in ALLOWED with why it stays; an entry
// no longer used fails too, so the list only shrinks.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']
/** The one home of the status components: what they render is the point. */
const OWNER = 'components/common/status/'
/** The generic Chip itself. */
const CHIP_FILE = 'components/common/StatusChip.tsx'

/** The ideas, by the words a chip shows (placeholders removed). */
const CONCEPTS: { name: string; re: RegExp }[] = [
  { name: 'finding status', re: /\b(?:exploited|under attack|public exploit|update recommended|in (?:cisa |vulncheck )?kev)\b/i },
  { name: 'handled status', re: /^\s*(?:patched|mitigated|false positive|not relevant|risk accepted)\b/i },
  { name: 'verification', re: /\b(?:confirmed|suspected|unverified|not proved|detected by the agent|needs your check)\b/i },
  { name: 'severity', re: /^\s*(?:critical|high|medium|low|info)\s*$/i },
  { name: 'device not added', re: /\bnot (?:added yet|approved)\b/i },
]

/** Components that drew one of these ideas their own way before the status components, by the module they come from (another
 *  feature's RiskChip, an action's risk, is not one of them). */
const LEGACY: { name: string; from: RegExp }[] = [
  { name: 'StatusChip', from: /\/StatusChip$/ },
  { name: 'SeverityChip', from: /\/StatusChip$/ },
  { name: 'FindingStatusChip', from: /(?:findings\/|\.\/)AcceptRisk$/ },
  { name: 'RiskChip', from: /(?:findings\/|\.\/)Risk$/ },
  { name: 'CvssScore', from: /(?:findings\/|\.\/)Cvss$/ },
]

/** Named exceptions: the file, the locale key (or the text) of the chip, and why it stays. */
const ALLOWED: { file: string; key: string; why: string }[] = [
  { file: 'features/findings/NotAdded.tsx', key: 'notAdded.chip', why: '"Not added yet" has one component, this one, used wherever a device nobody added is named' },
  { file: 'features/exposure/OwnerChip.tsx', key: 'status.commitYes', why: 'whether a person confirmed they may scan a public address, not a vulnerability' },
  { file: 'features/exposure/OwnerChip.tsx', key: 'status.commitNo', why: 'whether a person confirmed they may scan a public address, not a vulnerability' },
  { file: 'features/findings/Recommendation.tsx', key: 'rec.confirmedChip', why: 'a mitigation pack the maintainers reviewed, not a vulnerability' },
  { file: 'features/findings/Plan.tsx', key: 'plan.tier.', why: 'the EPSS likelihood tier ("Likely to be exploited"), a forecast and not a status' },
  { file: 'features/feeds/TierCvePage.tsx', key: 'tierCve.tier.', why: 'the EPSS likelihood tier ("Likely to be exploited"), a forecast and not a status' },
]

const ALLOWED_RUNS: { file: string; text: string; why: string }[] = [
  { file: 'features/feeds/LookupPage.tsx', text: 'vulns.map((v) => (', why: 'search results: one row per CVE with its product and the day it was listed' },
  { file: 'features/findings/Plan.tsx', text: 'cves.map((c) => (', why: 'a table of CVEs with tier, severity, EPSS and evidence columns, one row each' },
]

type Source = { file: string; text: string }

function sources(): Source[] {
  return ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))
}

type Locales = Record<string, unknown>
function locales(): Locales {
  const dir = join(SRC, 'locales', 'en')
  return Object.fromEntries(readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => [f.replace(/\.json$/, ''), JSON.parse(readFileSync(join(dir, f), 'utf8'))]))
}

function leaves(o: unknown, p = ''): [string, string][] {
  if (typeof o === 'string') return [[p, o]]
  if (o && typeof o === 'object') return Object.entries(o).flatMap(([k, v]) => leaves(v, p ? `${p}.${k}` : k))
  return []
}

/** The words a key can show: a literal key with its plural forms, or every key under a prefix built at run time. */
function wordsOf(all: Locales, ns: string, key: string, prefix: boolean): string[] {
  const [n, k] = key.includes(':') ? [key.slice(0, key.indexOf(':')), key.slice(key.indexOf(':') + 1)] : [ns, key]
  const flat = leaves(all[n])
  const hit = prefix ? flat.filter(([p]) => p.startsWith(k)) : flat.filter(([p]) => p === k || p === `${k}_one` || p === `${k}_other`)
  return hit.map(([, v]) => v.replace(/\{\{[^}]*\}\}/g, '').trim())
}

/** The end of a JSX opening tag that starts at `from` (`<Chip`): the first `>` outside braces and quotes. */
function tagEnd(text: string, from: number): number {
  let depth = 0
  let quote = ''
  for (let i = from; i < text.length; i++) {
    const c = text[i]!
    if (quote) { if (c === quote && text[i - 1] !== '\\') quote = ''; continue }
    if (c === '"' || c === "'" || c === '`') quote = c
    else if (c === '{') depth++
    else if (c === '}') depth--
    else if (c === '>' && depth === 0) return i
  }
  return -1
}

/** The namespace of the nearest useTranslation above `at` ("common" when it names none). */
function namespaceAt(text: string, at: number): string {
  let ns = 'common'
  for (const m of text.slice(0, at).matchAll(/useTranslation\(\s*\[?\s*(?:'([\w-]+)')?/g)) ns = m[1] ?? 'common'
  return ns
}

export type Hit = { file: string; line: number; what: string; key: string; concept: string }

/** Chips of the concepts and legacy concept components outside the status components. */
export function scanChips(files: Source[], all: Locales): Hit[] {
  const hits: Hit[] = []
  for (const { file, text } of files) {
    if (file.startsWith(OWNER) || file === CHIP_FILE) continue
    const lineOf = (i: number) => text.slice(0, i).split('\n').length
    const imported = [...text.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*'([^']+)'/g)]
      .flatMap((m) => m[1]!.split(',').map((n) => n.trim().split(/\s+as\s+/)[0]!).filter((n) => LEGACY.some((l) => l.name === n && l.from.test(m[2]!))))
    if (imported.length) {
      for (const m of text.matchAll(new RegExp(`<(${imported.join('|')})\\b`, 'g'))) {
        hits.push({ file, line: lineOf(m.index), what: `<${m[1]}>`, key: m[1]!, concept: 'drawn its own way' })
      }
    }
    for (const m of text.matchAll(/<Chip\b/g)) {
      const open = tagEnd(text, m.index)
      if (open < 0 || text[open - 1] === '/') continue
      const close = text.indexOf('</Chip>', open)
      if (close < 0) continue
      const children = text.slice(open + 1, close)
      const ns = namespaceAt(text, m.index)
      // every key the children can show: quoted keys (also inside a ternary in t(…)) and keys built at run time (`a.${x}`)
      for (const k of children.matchAll(/(['`])([\w:-]+(?:\.[\w-]+)*\.?)(\$\{|\1)/g)) {
        const key = k[2]!
        const concept = wordsOf(all, ns, key, k[3] === '${').map((w) => CONCEPTS.find((c) => c.re.test(w))?.name).find(Boolean)
        if (concept) hits.push({ file, line: lineOf(m.index), what: '<Chip>', key, concept })
      }
    }
  }
  return hits
}

export type Run = { file: string; line: number; text: string }

/** Runs of CVE ids built by hand: a joined string of them, or one element per id. A table's sort or search key is not shown. */
export function scanRuns(files: Source[]): Run[] {
  const runs: Run[] = []
  const RES = [
    /\b\w*cves\b(?:\.slice\([^)]*\))?\.join\(/gi,
    /\b\w*(?:cves|vulns)\b(?:\.slice\([^)]*\))?\.map\(\s*\(?[\w\s,{}]*\)?\s*=>\s*\(?\s*</gi,
  ]
  for (const { file, text } of files) {
    if (file.startsWith(OWNER)) continue
    for (const re of RES) {
      for (const m of text.matchAll(re)) {
        if (/accessorFn:\s*\(?\w+\)?\s*=>\s*[\w.]*$/.test(text.slice(Math.max(0, m.index - 40), m.index))) continue
        runs.push({ file, line: text.slice(0, m.index).split('\n').length, text: m[0].replace(/\s+/g, ' ') })
      }
    }
  }
  return runs
}

const allowedChip = (h: Hit) => ALLOWED.some((a) => a.file === h.file && a.key === h.key)
const allowedRun = (r: Run) => ALLOWED_RUNS.some((a) => a.file === r.file && r.text.includes(a.text))

describe('status guard: one component per status idea', () => {
  const files = sources()
  const all = locales()
  const chips = scanChips(files, all)
  const runs = scanRuns(files)

  it('reads the app sources and locales', () => {
    expect(files.length).toBeGreaterThan(200)
    expect(Object.keys(all)).toContain('common')
  })

  it('reports the counts of the class', () => {
    // Re-run on any commit for the numbers: every chip of the ideas outside the components, and every hand-built CVE run.
    const counts = chips.filter((h) => !allowedChip(h)).reduce<Record<string, number>>((o, h) => ({ ...o, [h.concept]: (o[h.concept] ?? 0) + 1 }), {})
    const by = Object.entries(counts).map(([c, n]) => `${c} ${n}`).join(', ')
    console.info(`status chips outside the status components: ${chips.length} (${chips.filter((h) => !allowedChip(h)).length} not allowed: ${by || 'none'}); CVE runs outside CveList: ${runs.length} (${runs.filter((r) => !allowedRun(r)).length} not allowed)`)
    expect(chips.length + runs.length).toBeGreaterThanOrEqual(0)
  })

  it('every chip of a status, severity, verification or handling comes from the status components', () => {
    const bad = chips.filter((h) => !allowedChip(h)).map((h) => `${h.file}:${h.line} ${h.what} ${h.key} (${h.concept})`)
    expect(bad, `Use <StatusBadge>, <SeverityBadge>, <VerificationLine> or <HandledLine> (components/common/status), or add a named exception:\n${bad.join('\n')}`).toEqual([])
  })

  it('every list of CVEs goes through <CveList>', () => {
    const bad = runs.filter((r) => !allowedRun(r)).map((r) => `${r.file}:${r.line} ${r.text}`)
    expect(bad, `Render the CVEs with <CveList> (components/common/status), or add a named exception:\n${bad.join('\n')}`).toEqual([])
  })

  it('every exception is still used', () => {
    expect(ALLOWED.filter((a) => !chips.some((h) => h.file === a.file && h.key === a.key)).map((a) => `${a.file} ${a.key}`), 'stale ALLOWED entries: remove them').toEqual([])
    expect(ALLOWED_RUNS.filter((a) => !runs.some((r) => r.file === a.file && r.text.includes(a.text))).map((a) => `${a.file} ${a.text}`), 'stale ALLOWED_RUNS entries: remove them').toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    const loc: Locales = { feeds: { dash: { inKev: 'In CISA KEV', open: 'Open' }, sev: { high: 'High', low: 'Low' } }, common: { severity: { high: 'High' }, ok: 'Saved' } }
    const one = (text: string) => scanChips([{ file: 'features/x/X.tsx', text }], loc).map((h) => `${h.key}:${h.concept}`)
    expect(one("const { t } = useTranslation('feeds')\n<Chip tone=\"danger\">{t('dash.inKev')}</Chip>")).toEqual(['dash.inKev:finding status'])
    expect(one("useTranslation('feeds')\n<Chip tone={v >= 7 ? 'danger' : 'off'}>{t(`sev.${s}`)}</Chip>")).toEqual(['sev.:severity'])
    expect(one("useTranslation('feeds')\n<Chip tone=\"off\">{t('common:severity.high')}</Chip>")).toEqual(['common:severity.high:severity'])
    expect(one("useTranslation('feeds')\n<Chip tone=\"off\">{t(v >= 7 ? 'sev.high' : 'sev.low', { score })}</Chip>")).toEqual(['sev.high:severity', 'sev.low:severity'])
    expect(one("import { SeverityChip, StatusChip } from '@/components/common/StatusChip'\n<SeverityChip severity=\"high\" /><StatusChip status=\"confirmed\" />")).toEqual(['SeverityChip:drawn its own way', 'StatusChip:drawn its own way'])
    expect(one("import { RiskChip } from './parts'\n<RiskChip risk=\"high\" />")).toEqual([])
    expect(one("useTranslation('feeds')\n<Chip tone=\"ok\">{t('dash.open')}</Chip><Chip tone=\"ok\">{t('ok')}</Chip><Chip tone=\"off\" />")).toEqual([])
    const run = (text: string) => scanRuns([{ file: 'features/x/X.tsx', text }]).map((r) => r.text)
    expect(run("{p.cves.join(', ')}")).toEqual(['cves.join('])
    expect(run('{r.cves.map((c) => <Link key={c}>{c}</Link>)}')).toEqual(['cves.map((c) => <'])
    expect(run('{a.cves.map((c, i) => (\n  <li key={c}>{c}</li>))}')).toHaveLength(1)
    expect(run("accessorFn: (r) => r.cves.join(' '), new Set(items.flatMap((i) => i.cves.map((c) => c.cve)))")).toEqual([])
  })
})
