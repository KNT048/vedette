import { describe, expect, it } from 'vitest'
import { auditStore, sessionStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'

// #842/#850: the mock of "+ New range" and "+ New exclusion" answers as the backend does (modules/inventory safety.go AddRange,
// AddExclusion), so the inline dialogs can be built on `make dev`.

const BASE = `${location.origin}/api/v1/scanning/safety`
async function post(path: string, body: unknown, user = 'u-admin') {
  sessionStore.set({ userId: user })
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, json: (await res.json()) as Record<string, any> } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const audits = () => auditStore.get().filter((a) => a.action === 'inventory.settings').length

describe('inline adds of Settings › Scanning (#842)', () => {
  it('adds one range with the attestation, normalizes it, and changes nothing for a range already covered', async () => {
    expect((await post('/ranges', { range: '192.168.30.0/24', confirm: true }, 'u-op')).status).toBe(403)
    expect((await post('/ranges', { range: '192.168.30.0/24', confirm: false })).json.error.code).toBe('scope_not_confirmed')
    expect((await post('/ranges', { range: '8.8.8.0/24', confirm: true })).json.error.code).toBe('public_range')
    expect((await post('/ranges', { range: '192.168.30.7', confirm: true })).json.error.code).toBe('no_prefix')
    expect((await post('/ranges', { range: '192.168.0.0/16', confirm: true })).json.error.code).toBe('overlap_range')
    const before = audits()
    const added = await post('/ranges', { range: '192.168.30.7/24', confirm: true })
    expect(added.status).toBe(200)
    expect(added.json.scope.lan_ranges).toContain('192.168.30.0/24')
    expect(added.json.adjusted).toEqual([{ from: '192.168.30.7/24', to: '192.168.30.0/24' }])
    expect(added.json.scope.confirmed_by).toBe('admin@acme.example')
    expect(audits()).toBe(before + 1)
    const again = await post('/ranges', { range: '192.168.30.128/25', confirm: true })
    expect(again.status).toBe(200)
    expect(again.json.scope.lan_ranges).toEqual(added.json.scope.lan_ranges)
    expect(audits()).toBe(before + 1)
  })

  it('adds one exclusion, idempotent, and refuses the 201st', async () => {
    expect((await post('/exclusions', { entry: '192.168.10.9' }, 'u-view')).status).toBe(403)
    expect((await post('/exclusions', { entry: '192.168.10.5/28' })).json.error.code).toBe('bad_exclusion')
    const added = await post('/exclusions', { entry: '192.168.10.64/28' })
    expect(added.status).toBe(200)
    expect(added.json.exclusions).toContain('192.168.10.64/28')
    expect((await post('/exclusions', { entry: '192.168.10.70' })).json.exclusions).toEqual(added.json.exclusions)
    const st = inventorySettingsStore.get()
    inventorySettingsStore.set({ ...st, active: { ...st.active, exclusions: Array.from({ length: 200 }, (_, i) => `10.1.${Math.floor(i / 250)}.${i % 250}`) } })
    const full = await post('/exclusions', { entry: '192.168.10.9' })
    expect(full.status).toBe(409)
    expect(full.json.error.code).toBe('too_many_exclusions')
  })
})
