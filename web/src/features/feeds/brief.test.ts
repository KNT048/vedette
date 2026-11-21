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
    expect(briefStatus(b)).toBe('update_recommended')
  })

  it('a CVE with no score or weakness still gets a sentence; a public exploit alone is layer 3', () => {
    const b = briefOfVuln({ ...vuln, has_template: true }, null)
    const exploitOnly: CveBrief = { ...b, lists: [], signals: b.signals.filter((s) => s.kind === 'public_exploit') }
    expect(briefStatus(exploitOnly)).toBe('public_exploit')
    expect(briefSentence(t, exploitOnly)).toBe('Acme Widget has a flaw; working exploit code is public.')
    expect(briefStatus(b)).toBe('exploited')
  })

  it('lists each fixed release once per product, and the list\'s links join the references', () => {
    const row = { ...esxiBrief.ranges[0]!, origin: 'cna' as const, fixed: '8.0 U3d', versions: '8.0 before 8.0 U3d' }
    expect(fixRows({ ...esxiBrief, ranges: [row, { ...row, versions: '8.0 U2' }, ...esxiBrief.ranges] })).toEqual([{ product: 'vmware esxi', versions: '8.0 before 8.0 U3d', fixed: '8.0 U3d', origin: 'cna' }])
    expect(fixRows(esxiBrief)).toEqual([])
    const b = briefOfVuln(vuln, null)
    b.references = []
    b.lists[0]!.links = ['https://acme.example.com/sa-1', 'javascript:alert(1)']
    expect(briefSources(b)).toEqual([{ group: 'other', links: [{ url: 'https://acme.example.com/sa-1', group: 'other' }] }])
    expect(briefSources(esxiBrief).map((g) => g.group)).toEqual(['vendor-advisory', 'government-resource'])
  })
})
