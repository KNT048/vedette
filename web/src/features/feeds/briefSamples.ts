// Sample CVE briefs for the GUI mock (GET /feeds/cve/{id}). CVE-2025-22225 is a full brief written from its public CVE record and NVD
// record (the same CVE the Go fixture test reads: modules/feeds/testdata/brief): weaknesses with MITRE's names, NVD's 55 affected
// entries, VMware's fixed build of each release train (kept in its own notation, read by the ESXi version scheme), the tagged
// references, NVD's score read into words, CISA's list entry and SSVC. Every other sample brief is built from the
// mock's exploited-list entries (briefOfVuln) or tier facts (briefOfTier).
import type { CveBrief, CveRange, Vuln } from './types'
import { displayOf } from './slug'

const esxiReleases = [
  '7.0:-', '7.0:beta', '7.0:update_1', '7.0:update_1a', '7.0:update_1b', '7.0:update_1c', '7.0:update_1d', '7.0:update_1e', '7.0:update_2', '7.0:update_2a',
  '7.0:update_2c', '7.0:update_2d', '7.0:update_2e', '7.0:update_3', '7.0:update_3c', '7.0:update_3d', '7.0:update_3e', '7.0:update_3f', '7.0:update_3g',
  '7.0:update_3i', '7.0:update_3j', '7.0:update_3k', '7.0:update_3l', '7.0:update_3m', '7.0:update_3n', '7.0:update_3o', '7.0:update_3p', '7.0:update_3q',
  '7.0:update_3r', '8.0:-', '8.0:a', '8.0:b', '8.0:c', '8.0:update_1', '8.0:update_1a', '8.0:update_1c', '8.0:update_1d', '8.0:update_2', '8.0:update_2b',
  '8.0:update_2c', '8.0:update_3', '8.0:update_3b', '8.0:update_3c',
]
const otherProducts = [
  'cloud_foundation:-', 'telco_cloud_infrastructure:2.2', 'telco_cloud_infrastructure:2.5', 'telco_cloud_infrastructure:2.7', 'telco_cloud_infrastructure:3.0',
  'telco_cloud_platform:2.0', 'telco_cloud_platform:2.5', 'telco_cloud_platform:2.7', 'telco_cloud_platform:3.0', 'telco_cloud_platform:4.0',
  'telco_cloud_platform:4.0.1', 'telco_cloud_platform:5.0',
]

const nvdRow = (part: 'a' | 'o', product: string, version: string, update: string): CveRange => ({
  origin: 'nvd', counts: true, part, vendor: 'vmware', product, cpe: `cpe:2.3:${part}:vmware:${product}:${version}:${update}:*:*:*:*:*:*`,
  start_including: '', start_excluding: '', end_including: '', end_excluding: '', fixed: '', version_type: '', default_status: '', platforms: [],
  versions: version === '-' || version === '*' ? 'every version' : update === '-' || update === '*' ? version : `${version} ${update}`,
  train: '', fixed_release: '',
})

// VMware's rows: the fixed build of each ESXi train, as the record states it ("8.0" lessThan "ESXi80U3d-24585383")
const esxiFixes: [string, string, string, string][] = [
  ['8.0', 'ESXi80U3d-24585383', '8.0 U3', '8.0 U3d (build 24585383)'],
  ['8.0', 'ESXi80U2d-24585300', '8.0 U2', '8.0 U2d (build 24585300)'],
  ['7.0', 'ESXi70U3s-24585291', '7.0 U3', '7.0 U3s (build 24585291)'],
]
const vendorRow = ([start, end, train, release]: [string, string, string, string]): CveRange => ({
  origin: 'cna', counts: false, part: '', vendor: 'vmware', product: 'esxi', cpe: '', start_including: start, start_excluding: '', end_including: '',
  end_excluding: end, fixed: end, version_type: 'vendor:custom', default_status: 'unaffected', platforms: [], versions: `from ${start} before ${release}`,
  train, fixed_release: release,
})

const ADVISORY = 'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390'

export const esxiBrief: CveBrief = {
  cve: 'CVE-2025-22225',
  title: null,
  description: 'VMware ESXi contains an arbitrary write vulnerability. A malicious actor with privileges within the VMX process may trigger an arbitrary kernel write leading to an escape of the sandbox.',
  display: 'VMware ESXi hypervisor',
  products: ['vmware cloud foundation', 'vmware esxi', 'vmware telco cloud infrastructure', 'vmware telco cloud platform'],
  published: '2025-03-04', modified: '2026-08-04', nvd_status: 'Analyzed',
  nvd_checked_at: '2026-11-21T00:10:00Z', record_read_at: '2026-11-21T00:05:00Z',
  cwe: [{ id: 'CWE-787', name: 'Out-of-bounds Write' }, { id: 'CWE-123', name: 'Write-what-where Condition' }],
  cvss: {
    source: 'nvd', version: '3.1', score: 8.2, vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', severity: 'high',
    reading: {
      attack_vector: 'local', attack_complexity: 'low', attack_requirements: null, privileges_required: 'high', user_interaction: 'none', scope: 'changed',
      confidentiality: 'high', integrity: 'high', availability: 'high', subsequent: null,
      summary: 'Attacker needs local access, low complexity, high privileges needed, no user action; high impact on confidentiality, integrity and availability; can reach beyond the vulnerable component.',
    },
  },
  scores: [
    { source: 'nvd', version: '3.1', score: 8.2, vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H' },
    { source: 'cna', version: '3.1', score: 8.2, vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H' },
  ],
  lists: [{
    list: 'cisa', source: 'cisa-kev', source_name: 'CISA KEV', vendor: 'VMware', product: 'ESXi', display: 'VMware ESXi hypervisor',
    name: 'VMware ESXi Arbitrary Write Vulnerability',
    description: 'VMware ESXi contains an arbitrary write vulnerability. Successful exploitation allows an attacker with privileges within the VMX process to trigger an arbitrary kernel write leading to an escape of the sandbox.',
    required_action: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.',
    links: [ADVISORY], date_added: '2025-03-04', due_date: '2025-03-25', ransomware: true,
  }],
  signals: [{ kind: 'exploited', source: 'cisa-kev', source_name: 'CISA KEV', first_seen: '2025-03-04T00:00:00Z', last_seen: '2026-11-21T00:00:00Z', qualifies: true,
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', detail: null }],
  ranges: [
    ...esxiReleases.map((r) => { const [v = '', u = ''] = r.split(':'); return nvdRow('o', 'esxi', v, u) }),
    ...otherProducts.map((r) => { const [p = '', v = ''] = r.split(':'); return nvdRow('a', p, v, '*') }),
    ...esxiFixes.map(vendorRow),
  ],
  fixes: esxiFixes.map(([, , train, release]) => ({ vendor: 'vmware', product: 'esxi', origin: 'cna' as const, train, release })),
  ranges_from: 'nvd', ranges_complete: false,
  references: [
    { url: ADVISORY, tags: ['vendor-advisory'], source: 'nvd', group: 'vendor-advisory' },
    { url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-22225', tags: ['government-resource'], source: 'nvd', group: 'government-resource' },
  ],
  solution: null, workaround: null,
  ssvc: { exploitation: 'active', automatable: 'no', technical_impact: 'total' },
  epss: { score: 0.0412, percentile: 0.884, day: '2026-11-20', week_ago: 0.0398, history: [{ day: '2026-11-13', score: 0.0398 }, { day: '2026-11-20', score: 0.0412 }] },
  nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-22225', record_url: 'https://www.cve.org/CVERecord?id=CVE-2025-22225',
}

const ids = (cve: string) => ({ nvd_url: `https://nvd.nist.gov/vuln/detail/${cve}`, record_url: `https://www.cve.org/CVERecord?id=${cve}` })

/** The brief of an exploited-list entry of the mock: the list's words, its signals, its links as untagged references, its EPSS. */
export function briefOfVuln(v: Vuln, published: string | null): CveBrief {
  const display = displayOf(v.vendor, v.product)
  const links = v.links.filter((l) => /^https?:\/\//i.test(l))
  return {
    cve: v.cve, title: null, description: v.description, display, products: [], published, modified: null, nvd_status: null, nvd_checked_at: null,
    record_read_at: null, cwe: [], cvss: null, scores: [],
    lists: [{ list: 'cisa', source: v.source ?? 'cisa-kev', source_name: 'CISA KEV', vendor: v.vendor, product: v.product, display, name: v.name,
      description: v.description, required_action: v.required_action, links, date_added: v.date_added, due_date: v.due_date, ransomware: v.ransomware }],
    signals: [
      { kind: 'exploited', source: 'cisa-kev', source_name: 'CISA KEV', first_seen: `${v.date_added}T00:00:00Z`, last_seen: `${v.date_added}T00:00:00Z`, qualifies: true, url: null, detail: null },
      ...(v.has_template ? [{ kind: 'public_exploit', source: 'nuclei-templates', source_name: 'nuclei-templates', first_seen: `${v.date_added}T00:00:00Z`, last_seen: `${v.date_added}T00:00:00Z`, qualifies: true, url: null, detail: null }] : []),
    ],
    ranges: [], fixes: [], ranges_from: null, ranges_complete: false,
    references: links.map((url) => ({ url, tags: [], source: 'cna' as const, group: 'other' as const })),
    solution: null, workaround: null, ssvc: { exploitation: null, automatable: null, technical_impact: null },
    epss: v.epss === null ? null : { score: v.epss, percentile: Math.min(0.999, 0.5 + v.epss), day: null, week_ago: v.epss_7d_ago, history: [] },
    ...ids(v.cve),
  }
}

/** The brief of a CVE on no exploited list that the catalogue holds (published in the last 12 months), from a tier fact. */
export function briefOfTier(f: { cve: string; published: string; last_modified: string; nvd_status: string; epss: number | null; percentile: number | null; products: string[] }): CveBrief {
  return {
    cve: f.cve, title: null, description: '', display: f.products[0] ?? null, products: f.products.map((p) => p.toLowerCase()), published: f.published,
    modified: f.last_modified, nvd_status: f.nvd_status, nvd_checked_at: null, record_read_at: null, cwe: [], cvss: null, scores: [], lists: [], signals: [],
    ranges: [], fixes: [], ranges_from: null, ranges_complete: false, references: [], solution: null, workaround: null,
    ssvc: { exploitation: null, automatable: null, technical_impact: null },
    epss: f.epss === null ? null : { score: f.epss, percentile: f.percentile ?? 0, day: null, week_ago: null, history: [] },
    ...ids(f.cve),
  }
}
