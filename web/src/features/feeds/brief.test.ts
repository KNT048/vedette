// Reading a CVE brief: the sentence is built from fields only, the status comes from the brief's own signals, fixed releases are
// listed once per product, and the exploited lists' own links join the references.
import { describe, expect, it } from 'vitest'
import i18n from '@/lib/i18n'
import { briefOfVuln, esxiBrief } from './briefSamples'
import { briefSentence, briefSources, briefStatus, fixRows } from './brief'
import type { CveBrief } from './types'

const t = i18n.getFixedT('en', 'feeds')
const vuln = { cve: 'CVE-2026-20001', vendor: 'Acme', product: 'Widget', name: 'n', description: 'd', required_action: 'a', links: ['https://acme.example.com/sa-1'], date_added: '2026-11-03', due_date: null, ransomware: false, epss: null, epss_7d_ago: null, has_template: false }

describe('the CVE brief, read for the screens', () => {
  it('words the attack conditions of the CVSS reading; a CVE with no signal is only an update', () => {
    const b: CveBrief = { ...esxiBrief, display: 'Acme Widget', lists: [], signals: [], cwe: [{ id: 'CWE-78', name: 'OS Command Injection' }],
      cvss: { ...esxiBrief.cvss!, reading: { ...esxiBrief.cvss!.reading!, attack_vector: 'network', privileges_required: 'none', user_interaction: 'required' } } }
    expect(briefSentence(t, b)).toBe('Acme Widget has a flaw of type “OS Command Injection” (CWE-78) that an attacker can use over the network, without logging in and when a user takes an action.')
    expect(briefStatus(b)).toBeNull() // no list and no signal: no status without a device
  })

  it('a CVSS 2.0 reading has no user interaction: the clause is left out, no raw key', () => {
    const b: CveBrief = { ...esxiBrief, display: 'Acme Widget', lists: [], signals: [], cwe: [],
      cvss: { ...esxiBrief.cvss!, version: '2.0', reading: { ...esxiBrief.cvss!.reading!, attack_vector: 'network', privileges_required: 'none', user_interaction: null, scope: null } } }
    expect(briefSentence(t, b)).toBe('Acme Widget has a flaw that an attacker can use over the network and without logging in.')
  })

  it('a CVE with no score or weakness still gets a sentence; a public exploit alone is layer 3', () => {
    const b = briefOfVuln({ ...vuln, has_template: true }, null)
    const exploitOnly: CveBrief = { ...b, lists: [], signals: b.signals.filter((s) => s.kind === 'public_exploit') }
    expect(briefStatus(exploitOnly)).toBe('public_exploit')
    expect(briefSentence(t, exploitOnly)).toBe('Acme Widget has a flaw; working exploit code is public.')
    expect(briefStatus(b)).toBe('exploited')
  })

  it('lists each fixed release once per product, and the list\'s links join the references', () => {
    // the brief's fixes give one row per product and train; ranges of a train they cover are not repeated
    expect(fixRows(esxiBrief).map((r) => [r.train, r.fixed])).toEqual([['8.0 U3', '8.0 U3d (build 24585383)'], ['8.0 U2', '8.0 U2d (build 24585300)'], ['7.0 U3', '7.0 U3s (build 24585291)']])
    expect(fixRows(esxiBrief)[0]!.key).toBe('vmware|esxi')
    // without a scheme: each range that names a fixed release, once per product and release
    const row = { ...esxiBrief.ranges[0]!, origin: 'cna' as const, fixed: '2.4.58', versions: 'from 2.0 before 2.4.58' }
    expect(fixRows({ ...esxiBrief, fixes: [], ranges: [row, { ...row, versions: '2.4.57' }] })).toEqual([{ key: 'vmware|esxi', product: 'vmware esxi', train: '', versions: 'from 2.0 before 2.4.58', fixed: '2.4.58', origin: 'cna' }])
    // NVD states no fixed release, only the version a range ends before: that version is the row's fix, as written
    const nvd = { ...esxiBrief.ranges[0]!, vendor: 'apache', product: 'http_server', end_excluding: '2.4.58', versions: 'from 2.0 before 2.4.58' }
    expect(fixRows({ ...esxiBrief, fixes: [], ranges: [nvd] }).map((r) => [r.product, r.fixed])).toEqual([['apache http server', '2.4.58']])
    // Junos: "before 20.4", then 20.4R1 and 20.4R2 listed one by one: 20.4 is no fix, as the finding page says (end_listed)
    const base = { ...esxiBrief.ranges[0]!, vendor: 'juniper', product: 'junos', origin: 'nvd' as const, counts: true, fixed: '', fixed_release: '', train: '', start_including: '', start_excluding: '', end_including: '', end_excluding: '' }
    const before = { ...base, end_excluding: '20.4', versions: 'before 20.4' }
    const r1 = { ...base, cpe: 'cpe:2.3:o:juniper:junos:20.4:r1:*:*:*:*:*:*', versions: '20.4 r1' }
    const after = { ...base, end_excluding: '21.2', start_including: '21.1', versions: 'from 21.1 before 21.2' }
    expect(fixRows({ ...esxiBrief, fixes: [], ranges: [before, r1, after] }).map((r) => r.fixed)).toEqual(['21.2'])
    const b = briefOfVuln(vuln, null)
    b.references = []
    b.lists[0]!.links = ['https://acme.example.com/sa-1', 'javascript:alert(1)']
    expect(briefSources(b)).toEqual([{ group: 'other', links: [{ url: 'https://acme.example.com/sa-1', group: 'other' }] }])
    expect(briefSources(esxiBrief).map((g) => g.group)).toEqual(['vendor-advisory', 'government-resource'])
  })
})
