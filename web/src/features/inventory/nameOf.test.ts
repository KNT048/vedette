import { describe, expect, it } from 'vitest'
import { displayName, osProduct } from './nameOf'

const seen = (value: string, software_id?: string) => ({ value, source: 'manual' as const, confidence: 1, seen_at: '2026-11-17T08:00:00.000Z', ...(software_id ? { software_id } : {}) })

describe('displayName: one name for a device on every page', () => {
  it('leaves out a maker or model read from a declared OS row, as the backend naming rule does', () => {
    const a = { hostname: null, ip: '192.168.1.20', origin: 'discovered' as const, vendor: seen('Fortinet'), model: seen('FortiGate', 's-1') }
    expect(displayName(a)).toBe('Fortinet')
    expect(displayName({ ...a, vendor: seen('Fortinet', 's-1') })).toBe('192.168.1.20')
    expect(displayName({ ...a, model: seen('FGT60F') })).toBe('Fortinet FGT60F')
  })
})

describe('displayName: the maker of the network card is a weak name', () => {
  const by = (value: string, source: 'nmap' | 'passive' | 'snmp', basis?: 'guess' | 'stated_web') => ({ value, source, confidence: 0.6, seen_at: '2026-11-17T08:00:00.000Z', ...(basis ? { basis } : {}) })
  const found = { hostname: null, ip: '192.0.2.10', origin: 'discovered' as const, model: null }
  it('names a device after the OS it states, else "<maker> device", as the backend naming rule does', () => {
    expect(displayName({ ...found, vendor: by('Hewlett Packard', 'nmap'), os: by('VMware ESXi 8.0 Update 3 (build 24022510)', 'nmap', 'stated_web') })).toBe('VMware ESXi')
    expect(displayName({ ...found, vendor: by('Fortinet', 'nmap') })).toBe('Fortinet device')
    expect(displayName({ ...found, vendor: by('Routerboard.com', 'nmap'), os: by('MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)', 'nmap', 'guess') })).toBe('Routerboard.com device')
    expect(displayName({ ...found, vendor: by('Juniper Networks', 'passive'), model: by('EX4200-48T', 'passive') })).toBe('Juniper Networks EX4200-48T')
    expect(displayName({ ...found, vendor: by('Fortinet', 'snmp') })).toBe('Fortinet')
    expect(displayName({ ...found, hostname: 'fw-branch', vendor: by('Fortinet', 'nmap') })).toBe('fw-branch')
  })
  it('osProduct drops the release', () => {
    expect(osProduct('MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)')).toBe('MikroTik RouterOS')
    expect(osProduct('JUNOS 15.1R7.9')).toBe('JUNOS')
    expect(osProduct('8.0.3')).toBe('')
  })
})

describe('displayName: never a raw key on another feature\'s screen', () => {
  it('names "<maker> device" and "<product> (no device)" while the inventory words are not loaded', async () => {
    const i18n = (await import('@/lib/i18n')).default
    const bundle = i18n.getResourceBundle('en', 'inventory') as Record<string, unknown> | undefined
    i18n.removeResourceBundle('en', 'inventory')
    try {
      const card = { value: 'Fortinet', source: 'nmap' as const, confidence: 0.6, seen_at: '2026-11-17T08:00:00.000Z' }
      expect(displayName({ hostname: null, ip: '192.0.2.251', origin: 'discovered', model: null, vendor: card })).toBe('Fortinet device')
      expect(displayName({ hostname: null, ip: '', origin: 'manual', vendor: null, model: null, product: { display: 'Microsoft Office' } })).toBe('Microsoft Office (no device)')
    } finally {
      if (bundle) i18n.addResourceBundle('en', 'inventory', bundle)
    }
  })
})
