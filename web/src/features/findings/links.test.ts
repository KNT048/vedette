import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import i18n from '@/lib/i18n'
import { linkLabels } from './links'

const t = i18n.getFixedT('en', 'findings')
const label = (links: string[]) => linkLabels(t, links)

/** The links of an entry as the box keeps them: the list's own `links`, or its "notes" split like the feed does (https only, ";" or space). */
function entryLinks(v: { links?: string[]; notes?: string }): string[] {
  if (v.links) return v.links
  const out: string[] = []
  for (const p of (v.notes ?? '').split(/[;\s]+/)) if (/^https:\/\//i.test(p) && !out.includes(p)) out.push(p)
  return out.slice(0, 10)
}

describe('reference link labels', () => {
  // KEV_FILE=/path/to/known_exploited_vulnerabilities.json runs the same check over the whole published catalog.
  it('no two links of one entry read the same, over every entry of the exploited list', () => {
    const file = process.env.KEV_FILE ?? join(import.meta.dirname, '../../mocks/fixtures/kev.json')
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { vulns?: { cve: string; links: string[] }[]; vulnerabilities?: { cveID: string; notes: string }[] }
    const entries = doc.vulns?.map((v) => ({ cve: v.cve, links: entryLinks(v) })) ?? doc.vulnerabilities!.map((v) => ({ cve: v.cveID, links: entryLinks(v) }))
    const repeated = entries.filter((e) => new Set(label(e.links)).size !== e.links.length).map((e) => e.cve)
    expect(entries.filter((e) => e.links.length > 1).length).toBeGreaterThan(0)
    expect(repeated).toEqual([])
  })

  it('the two pages of a CISA directive: the directive, and its implementation guidance', () => {
    expect(label([
      'https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk',
      'https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk',
    ])).toEqual(['CISA directive BOD 26-04', 'CISA directive BOD 26-04: implementation guidance'])
    expect(label([
      'https://www.cisa.gov/news-events/directives/ed-26-03-mitigate-vulnerabilities-cisco-sd-wan-systems',
      'https://www.cisa.gov/news-events/directives/supplemental-direction-ed-26-03-hunt-and-hardening-guidance-cisco-sd-wan-systems',
    ])).toEqual(['CISA directive ED 26-03: mitigate vulnerabilities', 'CISA directive ED 26-03: supplemental direction hunt and hardening guidance'])
  })

  it('CISA pages are named by what they are; a link alone keeps its plain label', () => {
    expect(label([
      'https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a.',
      'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching',
      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762',
      'https://www.cisa.gov/eviction-strategies-tool/create-from-template',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
      'https://www.fortiguard.com/psirt/FG-IR-24-015',
    ])).toEqual([
      'CISA ICS advisory ICSA-23-236-01', 'CISA cybersecurity advisory AA23-158A', 'CISA alert', 'CISA catalog entry of exploited vulnerabilities', 'CISA notice',
      'NVD entry (affected versions)', 'Vendor advisory (fortiguard.com)',
    ])
  })

  it('several advisories of one vendor are told apart by their id or their page, never by a number when the address says more', () => {
    expect(label([
      'https://support.apple.com/en-us/121752,', 'https://support.apple.com/en-us/121753,', 'https://support.apple.com/en-us/121754',
    ])).toEqual(['Vendor advisory (support.apple.com): 121752', 'Vendor advisory (support.apple.com): 121753', 'Vendor advisory (support.apple.com): 121754'])
    expect(label([
      'https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v',
      'https://github.com/ray-project/ray/commit/70e7c72780bdec075dba6cad1afe0832772bfe09',
    ])).toEqual([
      'Vendor advisory (github.com): security / advisories / GHSA-q279-jhrf-cc6v',
      'Vendor advisory (github.com): commit / 70e7c72780bdec075dba6cad1afe0832772bfe09',
    ])
    expect(label([
      'https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P46#Security_Fixes',
      'https://wiki.zimbra.com/wiki/Zimbra_Releases/10.0.7#Security_Fixes',
    ])).toEqual(['Vendor advisory (wiki.zimbra.com): 8.8.15 / P46', 'Vendor advisory (wiki.zimbra.com): 10.0.7'])
    expect(label([
      'https://roundcube.net/news/2023/10/16/security-update-1.6.4-released,',
      'https://roundcube.net/news/2023/10/16/security-updates-1.5.5-and-1.4.15',
    ])).toEqual(['Vendor advisory (roundcube.net): update 1.6.4 released', 'Vendor advisory (roundcube.net): updates 1.5.5 and 1.4.15'])
  })

  it('two NVD links name their CVE; addresses nothing tells apart are numbered', () => {
    expect(label(['https://nvd.nist.gov/vuln/detail/CVE-2025-1', 'https://nvd.nist.gov/vuln/detail/CVE-2025-2']))
      .toEqual(['NVD entry (affected versions): CVE-2025-1', 'NVD entry (affected versions): CVE-2025-2'])
    expect(label(['https://example.com/a', 'https://example.com/a,'])).toEqual(['Vendor advisory (example.com)', 'Vendor advisory (example.com) (2)'])
  })
})
