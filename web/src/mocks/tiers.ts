// Sample tier data (D-613, D-615; S-TIER-1, S-TIER-2), shared by the findings mock (GET /findings/plan) and the feeds mock
// (GET /feeds/cve/{id}/tier): CVEs on no exploited list, from the feeds epss-all and nvd-recent of the box. The CVE ids are
// sample ids (not real CVEs), like the rest of the sample data. Every string shown is English (D-28).
import { collection } from './db'

export type TierSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none'
export interface TierFact {
  cve: string; published: string; last_modified: string; nvd_status: string; severity: TierSeverity | null; score: number | null
  epss: number | null; percentile: number | null; products: string[]; ranges: boolean
}
export type PlanBasis = 'scan' | 'agent' | 'distro' | 'version'
export interface PlanSeed {
  asset_id: string; software_id: string; software: string; version: string; fixed: string; kind: 'fixed' | 'distro' | 'windows' | 'esu'
  cves: { cve: string; basis: PlanBasis }[]
}
export type FeedReady = 'module_off' | 'off' | 'loading' | 'ready'
/** What the box would say about its tier feeds; tests and the sample switch set it (`compared` false = slice 2's box, D-616). */
export interface TierState { epss: FeedReady; recent: FeedReady; compared: boolean }

const day = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10)

/** EPSS 10 % or more (FIRST's example threshold, D-613): tier 2 when published in the last 12 months. */
export const EPSS_LIKELY = 0.1
export const YEAR_DAYS = 365

function fact(cve: string, ago: number, severity: TierSeverity | null, score: number | null, epss: number | null, products: string[], ranges = true, status = 'Analyzed'): TierFact {
  return { cve, published: day(ago), last_modified: day(Math.max(0, ago - 20)), nvd_status: status, severity, score, epss, percentile: epss === null ? null : Math.min(0.999, 0.5 + epss), products, ranges }
}

/** The tier CVEs the sample knows: published dates relative to today, so they stay inside (or outside) the 12 months. */
export const tierFacts: TierFact[] = [
  fact('CVE-2026-31001', 40, 'high', 7.5, 0.342, ['F5 nginx']),
  fact('CVE-2026-31002', 75, 'medium', 5.3, 0.018, ['F5 nginx']),
  fact('CVE-2026-31003', 190, 'medium', 6.1, 0.004, ['F5 nginx']),
  fact('CVE-2026-32010', 25, 'critical', 9.8, 0.271, ['Microsoft Windows Server 2022', 'Microsoft Windows 11']),
  fact('CVE-2026-32011', 25, 'high', 8.8, 0.126, ['Microsoft Windows Server 2022']),
  fact('CVE-2026-32012', 55, 'high', 7.8, 0.031, ['Microsoft Windows Server 2022']),
  fact('CVE-2026-32013', 55, 'medium', 6.5, 0.009, ['Microsoft Windows Server 2022']),
  fact('CVE-2026-32014', 120, 'high', 7.0, 0.002, ['Microsoft Windows Server 2022']),
  fact('CVE-2026-33100', 60, 'high', 7.5, 0.011, ['OpenSSL OpenSSL']),
  fact('CVE-2026-33101', 160, 'low', 3.7, 0.003, ['OpenSSL OpenSSL']),
  fact('CVE-2026-34500', 30, null, null, 0.021, ['Synology DiskStation Manager'], true, 'Awaiting Analysis'),
  // older than 12 months: listed only because a scan engine found it (D-615 (4))
  fact('CVE-2024-28870', 520, 'critical', 9.1, 0.416, ['Synology DiskStation Manager']),
  // in the data but on no device: its CVE page still answers (S-TIER-1)
  fact('CVE-2026-35999', 12, 'high', 8.1, 0.152, ['Ivanti Endpoint Manager'], false, 'Awaiting Analysis'),
]

const seed: PlanSeed[] = [
  { asset_id: 'a-srvacc', software_id: 's-srvacc', software: 'Windows Server 2022', version: '10.0.20348.2700', fixed: '10.0.20348.4405', kind: 'windows',
    cves: ['CVE-2026-32010', 'CVE-2026-32011', 'CVE-2026-32012', 'CVE-2026-32013', 'CVE-2026-32014'].map((cve) => ({ cve, basis: 'agent' as const })) },
  { asset_id: 'a-web01', software_id: 's-web01-nginx', software: 'nginx', version: '1.18.0', fixed: '1.28.1', kind: 'fixed',
    cves: ['CVE-2026-31001', 'CVE-2026-31002', 'CVE-2026-31003'].map((cve) => ({ cve, basis: 'version' as const })) },
  { asset_id: 'a-web01', software_id: 's-web01-openssl', software: 'OpenSSL', version: '3.0.2-0ubuntu1.18', fixed: '', kind: 'distro',
    cves: ['CVE-2026-33100', 'CVE-2026-33101'].map((cve) => ({ cve, basis: 'distro' as const })) },
  { asset_id: 'a-nas01', software_id: 's-nas01', software: 'Synology NAS (DSM)', version: '7.2', fixed: '7.2.2-72806', kind: 'fixed',
    cves: [{ cve: 'CVE-2026-34500', basis: 'version' }, { cve: 'CVE-2024-28870', basis: 'scan' }] },
]

export const planSeed = collection<PlanSeed[]>('fnd_plan', () => seed, () => [])
export const tierState = collection<TierState>('fnd_plan_state', () => ({ epss: 'ready', recent: 'ready', compared: true }))
export const tierFact = (cve: string) => tierFacts.find((f) => f.cve === cve)
/** likely = EPSS ≥ 0.1; recent otherwise (a KEV CVE is never here). Age is shown by the published date. */
export const tierOf = (f: TierFact): 'likely' | 'recent' => (f.epss ?? 0) >= EPSS_LIKELY ? 'likely' : 'recent'
export const withinYear = (f: TierFact) => f.published >= day(YEAR_DAYS)
export const epssDate = () => day(1)
export const recentSince = () => day(YEAR_DAYS)

/** D-615: NVD's published day of a few sample KEV CVEs (the KEV fixture has none); null = not answered, counts as recent. One table for
 *  the findings and feeds mocks and the mock matcher (match.ts), which drops product-only matches of older ones like the box (D-616). */
const KEV_PUBLISHED: Record<string, string> = { 'CVE-2015-5477': '2015-07-29', 'CVE-2024-27834': '2024-05-14', 'CVE-2025-61624': '2025-10-02' }
export const kevPublished = (cve: string): string | null => KEV_PUBLISHED[cve] ?? (/^CVE-2026-/.test(cve) ? '2026-06-01' : null)
/** D-615, D-616: older than 12 months from the LATER of the published day and the day the list added it (KEV news is never
 *  hidden; an unknown day is never old). */
export const kevAged = (cve: string, dateAdded: string | null) => { const d = kevPublished(cve); return d !== null && !!dateAdded && d < day(YEAR_DAYS) && dateAdded < day(YEAR_DAYS) }
