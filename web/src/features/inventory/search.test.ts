import { beforeEach, describe, expect, it } from 'vitest'
import { sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// #849: the mock of the Devices search and of SNMP Read now answers as the backend does (modules/inventory devicesquery.go,
// modules/sensor-active snmp_read.go), so the page can be built on it.
beforeEach(() => ensureBox())

const BASE = `${location.origin}/api/v1/inventory`
async function call(method: string, path: string, user = 'u-admin') {
  sessionStore.set({ userId: user })
  const res = await fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json' } })
  const text = await res.text()
  return { status: res.status, text, json: (text && res.headers.get('Content-Type')?.includes('json') ? JSON.parse(text) : null) as Record<string, any> | null } // eslint-disable-line @typescript-eslint/no-explicit-any
}

describe('Devices search (#849)', () => {
  it('filters the list, keeps the counts over every device and says each device\'s sources', async () => {
    const all = (await call('GET', '/devices')).json!
    const approved = (await call('GET', '/devices?approved=true')).json!
    expect(approved.items.length).toBeGreaterThan(0)
    expect(approved.items.every((d: { approved: boolean }) => d.approved)).toBe(true)
    expect(approved.counts).toEqual(all.counts)
    expect(all.items.every((d: { sources: unknown }) => Array.isArray(d.sources))).toBe(true)
    const manual = (await call('GET', '/devices?source=manual')).json!
    expect(manual.items.every((d: { origin: string; sources: string[] }) => d.origin === 'manual' && d.sources.includes('manual'))).toBe(true)
    const box = all.items.find((d: { is_box: boolean }) => d.is_box)
    const byIP = (await call('GET', `/devices?q=${encodeURIComponent(box.ip)}`)).json!
    expect(byIP.items.map((d: { id: string }) => d.id)).toContain(box.id)
    expect((await call('GET', '/devices?approved=true&approved=true&q=nothing-like-this')).json!.items).toEqual([])
  })

  it('refuses unknown words like the backend', async () => {
    expect((await call('GET', '/devices?type=toaster')).json!.error.code).toBe('bad_filter')
    expect((await call('GET', '/devices?source=nmap')).json!.error.code).toBe('bad_filter')
    expect((await call('GET', '/devices?approved=maybe')).status).toBe(400)
    expect((await call('GET', '/export.csv?source=bogus')).status).toBe(400)
  })

  it('reads the approved devices of a credential\'s scope now, for administrators only', async () => {
    expect((await call('POST', '/snmp/snmp-1/read', 'u-op')).status).toBe(403)
    expect((await call('GET', '/snmp/snmp-1/read')).json).toBeNull()
    const run = await call('POST', '/snmp/snmp-1/read')
    expect(run.status).toBe(202)
    expect(run.json!.status).toBe('running')
    await new Promise<void>((r) => queueMicrotask(r))
    const done = (await call('GET', '/snmp/snmp-1/read')).json!
    expect(done.status).toBe('done')
    expect(done.done).toBe(done.total)
    expect(done.results.every((r: { device_id: string | null }) => r.device_id)).toBe(true)
  })
})
