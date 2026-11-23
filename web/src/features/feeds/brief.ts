// Reading a CVE brief (GET /feeds/cve/{id}) for the screens that show it: the CVE page and the summary card of a finding. Every
// value comes from the brief; these helpers only pick, group and word it, they never compare versions or work out a fact.
import type { TFunction } from 'i18next'
import { OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import type { OpenStatus, Reason } from '@/features/findings/types'
import type { CveBrief, CveRange, CveRefGroup } from './types'

const web = (u: string) => /^https?:\/\//i.test(u)

/** The urgency layer of a signal kind; other kinds (new sources) are shown with their source but give no layer. */
const LAYER: Record<string, number> = { exploited: 2, public_exploit: 3 }

/**
 * Why the CVE is urgent, as the status reasons line reads them: each qualifying signal with its source, date and link, and each
 * exploited-list entry (its due date with it) when no signal of that list says so already. Most urgent first.
 */
export function briefReasons(b: CveBrief): Reason[] {
  const due = new Map(b.lists.map((l) => [l.source, l.due_date]))
  const out: Reason[] = b.signals.filter((s) => s.qualifies && LAYER[s.kind]).map((s) => ({
    layer: LAYER[s.kind]!, source: s.source, name: s.source_name, date: s.first_seen, url: s.url,
    detail: typeof s.detail?.stars === 'number' ? `${s.detail.stars} stars` : null, due: s.kind === 'exploited' ? due.get(s.source) ?? null : null,
  }))
  for (const l of b.lists) {
    if (out.some((r) => r.layer === 2 && r.source === l.source)) continue
    out.push({ layer: 2, source: l.source, name: l.source_name, date: l.date_added, url: null, detail: null, due: l.due_date })
  }
  return out.sort((a, c) => a.layer - c.layer || a.date.localeCompare(c.date))
}

/** The status the CVE has by its own signals (no device): the most urgent layer; null when no list or signal gives one. */
export function briefStatus(b: CveBrief): OpenStatus | null {
  const layers = briefReasons(b).map((r) => r.layer)
  return layers.length ? OPEN_FINDING_STATUSES[Math.min(...layers) - 1]! : null
}

/** A range's product in words: "vmware esxi" (the CPE's words, as the brief's `products` gives them). */
export const rangeProduct = (r: Pick<CveRange, 'vendor' | 'product'>) => `${r.vendor} ${r.product}`.replace(/_/g, ' ').trim()

export type FixRow = { key: string; product: string; train: string; versions: string; fixed: string; origin: CveRange['origin'] }

/**
 * The releases that fix the CVE: first the brief's fixes, one per product and release train as the product's version scheme
 * reads them ("8.0 U3" → "8.0 U3d (build 24585383)"), then the other ranges that end at a release, once per product and release:
 * the release the range names as fixed, else the version it ends before (NVD's "before 2.4.58" gives 2.4.58), printed as the
 * range states it. `key`: "vendor|product", with `train` the row a device's own fix is matched to.
 */
export function fixRows(b: CveBrief): FixRow[] {
  const seen = new Set<string>()
  const rows: FixRow[] = []
  const push = (r: FixRow) => {
    const key = `${r.product}\n${r.train}\n${r.fixed}`
    if (seen.has(key)) return
    seen.add(key)
    rows.push(r)
  }
  const trained = new Set(b.fixes.map((f) => `${f.vendor}|${f.product}|${f.train}`))
  for (const f of b.fixes) {
    const range = b.ranges.find((r) => r.vendor === f.vendor && r.product === f.product && r.train === f.train && r.fixed_release === f.release)
    push({ key: `${f.vendor}|${f.product}`, product: rangeProduct(f), train: f.train, versions: range?.versions ?? '', fixed: f.release, origin: f.origin })
  }
  for (const r of b.ranges) {
    const fixed = r.fixed_release || r.fixed || r.end_excluding
    if (!fixed) continue
    if (r.train && trained.has(`${r.vendor}|${r.product}|${r.train}`)) continue
    push({ key: `${r.vendor}|${r.product}`, product: rangeProduct(r), train: r.train, versions: r.versions, fixed, origin: r.origin })
  }
  return rows
}

export type AffectedGroup = { product: string; origin: CveRange['origin']; counts: boolean; versions: string[] }

/** Every affected-versions row, grouped by who stated it and the product: "vmware esxi: 7.0, 7.0 update_1, …". */
export function affectedGroups(b: CveBrief): AffectedGroup[] {
  const groups = new Map<string, AffectedGroup>()
  for (const r of b.ranges) {
    const product = rangeProduct(r) || r.cpe
    const key = `${r.origin}\n${product}`
    const g = groups.get(key) ?? { product, origin: r.origin, counts: r.counts, versions: [] }
    if (!g.versions.includes(r.versions)) g.versions.push(r.versions)
    groups.set(key, g)
  }
  return [...groups.values()]
}

export type SourceLink = { url: string; group: CveRefGroup }

/** The order references are shown in, as the brief orders them. */
export const REF_GROUPS: readonly CveRefGroup[] = ['vendor-advisory', 'patch', 'mitigation', 'release-notes', 'exploit', 'government-resource',
  'third-party-advisory', 'technical-description', 'issue-tracking', 'mailing-list', 'vdb-entry', 'media-coverage', 'other']

/** Every reference with its group, then the exploited lists' own links the references do not hold (http(s) only), grouped. */
export function briefSources(b: CveBrief): { group: CveRefGroup; links: SourceLink[] }[] {
  const seen = new Set<string>()
  const all: SourceLink[] = []
  const add = (url: string, group: CveRefGroup) => { if (web(url) && !seen.has(url)) { seen.add(url); all.push({ url, group }) } }
  for (const r of b.references) add(r.url, r.group)
  for (const l of b.lists) for (const u of l.links) add(u, 'other')
  return REF_GROUPS.map((group) => ({ group, links: all.filter((s) => s.group === group) })).filter((g) => g.links.length)
}

/** The page that names the fix: the vendor's advisory, else a patch, else release notes; null when the brief has none. */
export function fixLink(b: CveBrief): string | null {
  for (const g of ['vendor-advisory', 'patch', 'release-notes'] as const) {
    const r = b.references.find((x) => x.group === g && web(x.url))
    if (r) return r.url
  }
  return null
}

/**
 * The CVE in one sentence, from fields only: the product, the weakness (CWE name), the attack conditions of the CVSS reading and
 * the status. "VMware ESXi hypervisor has an Out-of-bounds Write weakness (CWE-787) that an attacker can use with local access,
 * with high privileges and with no user action; attackers use it in real attacks."
 */
export function briefSentence(t: TFunction<'feeds'>, b: CveBrief, known?: string | null): string {
  // `known`: the product as the page already knows it (a finding's software line), before the generic "The product"
  const product = b.display ?? b.products[0] ?? known ?? t('brief.theProduct')
  const cwe = b.cwe.find((c) => c.name)
  const weakness = cwe ? t('brief.weakness', { name: cwe.name, id: cwe.id }) : t('brief.flaw')
  const r = b.cvss?.reading
  // CVSS 2.0 has no user interaction metric: the clause is left out, never guessed
  const how = !r ? '' : r.user_interaction === null
    ? t('brief.howNoUser', { vector: t(`brief.vector.${r.attack_vector}`), privileges: t(`brief.privileges.${r.privileges_required}`) })
    : t('brief.how', {
      vector: t(`brief.vector.${r.attack_vector}`),
      privileges: t(`brief.privileges.${r.privileges_required}`),
      user: t(r.user_interaction === 'none' ? 'brief.user.none' : 'brief.user.needed'),
    })
  const status = briefStatus(b)
  const urgency = status === 'exploited' ? t('brief.status.exploited') : status === 'public_exploit' ? t('brief.status.public_exploit') : ''
  return t('brief.sentence', { product, weakness, how, urgency })
}
