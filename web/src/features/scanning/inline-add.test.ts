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
    const shown_ranges = inventorySettingsStore.get().lan_ranges
    const shown_confirmed_at = inventorySettingsStore.get().scope_confirmed_at
    expect((await post('/ranges', { range: '192.168.30.0/24', confirm: true, shown_ranges, shown_confirmed_at }, 'u-op')).status).toBe(403)
    expect((await post('/ranges', { range: '192.168.30.0/24', confirm: false, shown_ranges, shown_confirmed_at })).json.error.code).toBe('scope_not_confirmed')
    expect((await post('/ranges', { range: '8.8.8.0/24', confirm: true, shown_ranges, shown_confirmed_at })).json.error.code).toBe('public_range')
    expect((await post('/ranges', { range: '192.168.30.7', confirm: true, shown_ranges, shown_confirmed_at })).json.error.code).toBe('no_prefix')
    expect((await post('/ranges', { range: '192.168.0.0/16', confirm: true, shown_ranges, shown_confirmed_at })).json.error.code).toBe('overlap_range')
    const stale = await post('/ranges', { range: '192.168.30.0/24', confirm: true, shown_ranges: shown_ranges.slice(1), shown_confirmed_at })
    expect(stale.status).toBe(409)
    expect(stale.json.error.code).toBe('scope_changed')
    expect(stale.json.error.safety.scope.lan_ranges).toEqual(shown_ranges)
    const before = audits()
    const v0 = (await (await fetch(`${location.origin}/api/v1/scanning`)).json()).safety.version
    const added = await post('/ranges', { range: '192.168.30.7/24', confirm: true, shown_ranges, shown_confirmed_at })
    expect(added.status).toBe(200)
    expect(added.json.scope.lan_ranges).toContain('192.168.30.0/24')
    expect(added.json.adjusted).toEqual([{ from: '192.168.30.7/24', to: '192.168.30.0/24' }])
    expect(added.json.scope.confirmed_by).toBe('admin@acme.example')
    expect(added.json.version).not.toBe(v0)
    expect(audits()).toBe(before + 1)
    const again = await post('/ranges', { range: '192.168.30.128/25', confirm: true, shown_ranges: [], shown_confirmed_at: null })
    expect(again.status).toBe(200)
    expect(again.json.scope.lan_ranges).toEqual(added.json.scope.lan_ranges)
    expect(audits()).toBe(before + 1)
    // r2 M1: the same list, but the scope was unconfirmed since the dialog showed it confirmed: refused
    const st = inventorySettingsStore.get()
    inventorySettingsStore.set({ ...st, scope_confirmed_at: null, scope_confirmed_by: null })
    const withdrawn = await post('/ranges', { range: '192.168.40.0/24', confirm: true, shown_ranges: st.lan_ranges, shown_confirmed_at: st.scope_confirmed_at })
    expect(withdrawn.status).toBe(409)
    expect(withdrawn.json.error.code).toBe('scope_changed')
    expect(inventorySettingsStore.get().scope_confirmed_at).toBeNull()
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
    expect(full.status).toBe(400)
    expect(full.json.error.code).toBe('too_many_exclusions')
  })

  it('refuses a full save built on an older version, so it never drops an inline add (review #860 M1)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const page = (await (await fetch(`${location.origin}/api/v1/scanning`)).json()).safety
    expect((await post('/exclusions', { entry: '192.168.10.41' })).status).toBe(200)
    const save = { scope: { lan_ranges: page.scope.lan_ranges, confirmed: true }, window: { days: page.window.days, from: page.window.from, to: page.window.to }, speed: page.speed, exclusions: page.exclusions, fragile: { kinds: page.fragile.kinds, regular_scan_kinds: page.fragile.regular_scan_kinds } }
    const res = await fetch(BASE, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...save, version: page.version }) })
    const out = await res.json() as { error: { code: string; safety: { exclusions: string[]; version: string } } }
    expect(res.status).toBe(409)
    expect(out.error.code).toBe('safety_changed')
    expect(out.error.safety.exclusions).toContain('192.168.10.41')
    const ok = await fetch(BASE, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...save, exclusions: out.error.safety.exclusions, version: out.error.safety.version }) })
    expect(ok.status).toBe(200)
  })
})
