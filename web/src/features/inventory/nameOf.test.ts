import { describe, expect, it } from 'vitest'
import { displayName } from './nameOf'

const seen = (value: string, software_id?: string) => ({ value, source: 'manual' as const, confidence: 1, seen_at: '2026-11-17T08:00:00.000Z', ...(software_id ? { software_id } : {}) })

describe('displayName: one name for a device on every page', () => {
  it('leaves out a maker or model read from a declared OS row, as the backend naming rule does', () => {
    const a = { hostname: null, ip: '192.168.1.20', origin: 'discovered' as const, vendor: seen('Fortinet'), model: seen('FortiGate', 's-1') }
    expect(displayName(a)).toBe('Fortinet')
    expect(displayName({ ...a, vendor: seen('Fortinet', 's-1') })).toBe('192.168.1.20')
    expect(displayName({ ...a, model: seen('FGT60F') })).toBe('Fortinet FGT60F')
  })
})
