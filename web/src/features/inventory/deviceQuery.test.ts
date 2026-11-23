import { describe, expect, it } from 'vitest'
import '@/lib/i18n'
import { feedsOfRow, filterDevices, fromOldUrl } from './deviceQuery'
import type { DeviceRow } from './types'

// #849: the Devices search runs in the client over the loaded list (MaxListed = 2000).
const NOW = Date.parse('2026-11-16T10:00:00Z')
const obs = (value: string, source: DeviceRow['kind_source'] & string) => ({ value, source, confidence: 0.9, seen_at: '2026-11-16T09:00:00Z' })
function row(p: Partial<DeviceRow> & { id: string }): DeviceRow {
  return {
    site: 's', ip: '192.168.1.1', mac: null, hostname: null, kind: 'unknown', kind_source: null, guess: null, vendor: null, model: null, os: null,
    software_count: 0, service_count: 0, product: null, first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-16T09:00:00Z', approved: true, fragile: false, origin: 'discovered',
    is_box: false, first_scan_at: null, regular_scan: 'follow', approved_at: null, suspicious: false, findings_count: 0, summary: null, sources: [], ...p,
  } as DeviceRow
}
const SW = row({ id: 'sw', hostname: 'SW-CORE', ip: '192.168.1.3', mac: 'F8:7B:20:30:33:03', kind: 'switch', kind_source: 'snmp', vendor: obs('Cisco', 'snmp'), model: obs('CBS350-24P', 'snmp'), sources: ['passive', 'snmp'] })
const SRV = row({ id: 'srv', hostname: 'SRV-AD', ip: '192.168.1.10', kind: 'server', vendor: obs('Dell', 'passive'), os: obs('Windows Server 2016', 'agent'),
  software_count: 1, findings_count: 2, risk: { code: 'exploited', count: 1 }, sources: ['passive', 'osquery'] })
const CAM = row({ id: 'cam', hostname: 'CAM-GATE', ip: '192.168.2.11', kind: 'camera', fragile: true, findings_count: 3, risk: null, service_count: 2, vendor: obs('Hikvision', 'passive'), approved_at: '2026-11-16T08:00:00Z', sources: ['passive'] })
const MAN = row({ id: 'man', hostname: 'branch-fw', ip: '192.168.3.1', origin: 'manual', findings_count: 1, risk: { code: 'needs_input', count: 1 }, kind: 'firewall', kind_source: 'manual', sources: ['manual'] })
const ALL = [SW, SRV, CAM, MAN]
// what GET /inventory/devices?software= answers: the lines of each device that hold the words
const OFFICE = { id: 's1', display: 'Microsoft Office', vendor: 'Microsoft', product: 'Office', version: '2019', kev: [], source: 'agent' as const, confidence: 1, not_installed: false }
const MATCHES = new Map([['srv', [OFFICE]]])
const ids = (q: string) => filterDevices(ALL, q, NOW, undefined, MATCHES).map((d) => d.id)

describe('Devices search (#849)', () => {
  it('free text matches name, IP, MAC (any separators), maker, model and OS; every word must match', () => {
    expect(ids('cisco')).toEqual(['sw'])
    expect(ids('192.168.1.1')).toEqual(['srv']) // a part of 192.168.1.10
    expect(ids('192.168.1.3')).toEqual(['sw'])
    expect(ids('f87b2030')).toEqual(['sw'])
    expect(ids('f8-7b-20')).toEqual(['sw'])
    expect(ids('windows 2016')).toEqual(['srv'])
    expect(ids('dell cisco')).toEqual([])
  })
  it('type: takes a type id, a category or a label; source: reads every feed; same key = either, different keys = both', () => {
    expect(ids('type:switch')).toEqual(['sw'])
    expect(ids('type:network')).toEqual(['sw']) // the category
    expect(ids('type:switch type:camera')).toEqual(['sw', 'cam'])
    expect(ids('source:snmp')).toEqual(['sw'])
    expect(ids('source:osquery')).toEqual(['srv']) // an agent value
    expect(ids('source:manual')).toEqual(['man'])
    expect(ids('source:passive type:camera')).toEqual(['cam'])
  })
  it('fragile, has:findings, software:, approved:24h', () => {
    expect(ids('fragile')).toEqual(['cam'])
    // open findings only: the camera's findings are all closed, the firewall only waits for an answer
    expect(ids('has:findings')).toEqual(['srv'])
    expect(ids('software:office')).toEqual(['srv'])
    expect(ids('software:excel')).toEqual([]) // the server's lines are read again: a stale answer never keeps a row
    expect(filterDevices(ALL, 'software:office', NOW).map((d) => d.id)).toEqual([]) // no answer yet: no row
    expect(ids('has:software')).toEqual(['srv'])
    expect(ids('has:ports')).toEqual(['cam'])
    expect(ids('approved:24h')).toEqual(['cam'])
  })
  it('feedsOfRow is the box\'s own list (#855): osquery and Wazuh are told apart', () => {
    expect([...feedsOfRow(SRV)].sort()).toEqual(['osquery', 'passive'])
    expect(ids('source:wazuh')).toEqual([])
  })
})

describe('old Devices URLs (#849)', () => {
  const to = (s: string) => fromOldUrl(new URLSearchParams(s))?.toString() ?? null
  it('?show= and ?cat= become the query; ?tab=add opens the dialog; the Software and All tabs are gone', () => {
    expect(to('tab=all&show=recent')).toBe('q=approved%3A24h')
    expect(to('show=manual')).toBe('q=source%3Amanual')
    expect(to('show=agent')).toBe('q=source%3Aosquery+source%3Awazuh')
    expect(to('tab=all&show=fragile&cat=security')).toBe('q=fragile+type%3Asecurity')
    expect(to('tab=add&show=recent')).toBe('q=approved%3A24h&add=manual')
    expect(to('tab=software')).toBe('q=has%3Asoftware')
    expect(to('tab=review')).toBeNull()
    expect(to('q=cisco')).toBeNull()
  })
})

describe('SNMP credential label (#849)', () => {
  it('shows the version once, whatever the name says', async () => {
    const { credentialLabel } = await import('./kinds')
    expect(credentialLabel('Core switches', 'v3', 'v3')).toBe('Core switches (v3)')
    expect(credentialLabel('Core switches (v3)', 'v3', 'v3')).toBe('Core switches (v3)')
    expect(credentialLabel('Printers V2C', 'v2c', 'v2c')).toBe('Printers V2C')
    expect(credentialLabel('Lab [v3]', 'v3', 'v3')).toBe('Lab [v3]')
    expect(credentialLabel('v3-lab printers', 'v3', 'v3')).toBe('v3-lab printers (v3)') // the version only counts at the end
    expect(credentialLabel('Branch v2c', 'v3', 'v3')).toBe('Branch v2c (v3)') // another version is not this one
  })
})
