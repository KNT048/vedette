// The target-tree API of the mock: tree placement, proof through ancestors, scope choice, scans as runs and issue
// handling, each answer checked against the contract schema.
import { describe, expect, it } from 'vitest'
import type { z } from 'zod'
import { sessionStore, usersStore } from '@/mocks/stores'
import { Issue, NOTICE_VERSION, Scan, TargetNode, TargetTree, TERMS_VERSION } from './contract'

const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
async function call(method: string, path: string, body?: unknown, role: keyof typeof USER = 'admin') {
  sessionStore.set({ userId: USER[role] })
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  return { status: res.status, json: (await res.json().catch(() => null)) as unknown }
}
function parsed<T extends z.ZodType>(schema: T, v: unknown): z.infer<T> {
  const r = schema.safeParse(v)
  expect(r.success ? [] : r.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`)).toEqual([])
  return r.data as z.infer<T>
}
const tree = async () => parsed(TargetTree, (await call('GET', '/exposure/tree')).json).items
const withTwoStep = () => usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: true } : x)))

describe('exposure tree', () => {
  it('lists each node right after its parent; a name of a proven apex is covered by its proof', async () => {
    const items = await tree()
    expect(items.map((n) => n.value)).toEqual(['198.51.100.2', '198.51.100.3', 'example.com', 'git.example.com', 'shop.example.net'])
    const git = items.find((n) => n.value === 'git.example.com')!
    expect(git).toMatchObject({ parent_id: 'xt-11', schedule_key: 'exposure.target:xt-12' })
    expect(git.proof).toMatchObject({ state: 'covered', method: null, covered_by: { id: 'xt-11', value: 'example.com' }, dns: null })
    expect(items.find((n) => n.value === 'shop.example.net')).toMatchObject({ blocked: 'proof', proof: { state: 'missing', dns: { zone: 'example.net', alt_host: '_vedette-verify.shop' } } })
    expect(items.find((n) => n.value === '198.51.100.3')!.proof.file?.content).toBeTruthy()
    const hosts = (await call('GET', '/exposure/tree/xt-11/hosts')).json as { items: { name: string; child: unknown }[] }
    expect(hosts.items.find((h) => h.name === 'git.example.com')!.child).toEqual({ id: 'xt-12', value: 'git.example.com' })
  })

  it('an apex added after its names takes them under it, and deleting it moves them back up', async () => {
    withTwoStep()
    const sub = parsed(TargetNode, (await call('POST', '/exposure/tree', { value: 'api.example.org' })).json)
    expect(sub.parent_id).toBeNull()
    const apex = await call('POST', '/exposure/tree', { value: 'example.org', scope_mode: 'self' })
    expect(apex.status).toBe(201)
    const a = parsed(TargetNode, apex.json)
    expect(a).toMatchObject({ parent_id: null, scope_mode: 'self', blocked: 'proof' })
    expect(parsed(TargetNode, (await call('GET', `/exposure/tree/${sub.id}`)).json).parent_id).toBe(a.id)
    // Proving the apex covers the name under it.
    await call('POST', `/exposure/tree/${a.id}/verify`)
    const v = (await call('POST', `/exposure/tree/${a.id}/verify`)).json as { verified: boolean }
    expect(v.verified).toBe(true)
    expect(parsed(TargetNode, (await call('GET', `/exposure/tree/${sub.id}`)).json).proof.covered_by?.value).toBe('example.org')
    expect((await call('DELETE', `/exposure/tree/${a.id}`)).status).toBe(204)
    expect(parsed(TargetNode, (await call('GET', `/exposure/tree/${sub.id}`)).json)).toMatchObject({ parent_id: null, proof: { state: 'missing' } })
  })

  it('refuses a scope on an IP and a choice of names outside the selected scope', async () => {
    expect((await call('POST', '/exposure/tree', { value: '198.51.100.9', scope_mode: 'all' })).status).toBe(400)
    expect((await call('PATCH', '/exposure/tree/xt-11', { selected: ['xh-2'] })).status).toBe(400)
    expect((await call('PATCH', '/exposure/tree/xt-13', { selected: ['xh-2'] })).status).toBe(400)
    const ok = await call('PATCH', '/exposure/tree/xt-13', { selected: ['xh-8'] })
    expect(ok.status).toBe(200)
    const hosts = (await call('GET', '/exposure/tree/xt-13/hosts')).json as { items: { id: string; selected: boolean }[] }
    expect(hosts.items.filter((h) => h.selected).map((h) => h.id)).toEqual(['xh-8'])
    expect((await call('PATCH', '/exposure/tree/xt-13', { enabled: false }, 'operator')).status).toBe(403)
  })

  it('Scan now queues a run; an operator cannot run the first scan; a second Scan now is busy', async () => {
    withTwoStep()
    expect((await call('POST', '/exposure/tree/xt-12/scan', {}, 'operator')).status).toBe(202)
    expect((await call('POST', '/exposure/tree/xt-12/scan', {}, 'operator')).json).toMatchObject({ error: { code: 'busy' } })
    expect((await call('POST', '/exposure/tree/xt-13/scan', {}, 'operator')).status).toBe(409)
    await call('POST', '/exposure/tree/xt-13/verify')
    await call('POST', '/exposure/tree/xt-13/verify')
    expect((await call('POST', '/exposure/tree/xt-13/scan', {}, 'operator')).json).toMatchObject({ error: { code: 'commitment_required' } })
    const first = await call('POST', '/exposure/tree/xt-13/scan', { notice_version: NOTICE_VERSION })
    expect(first.status).toBe(202)
    expect(parsed(Scan, first.json)).toMatchObject({ status: 'queued', mode: 'surface', trigger: 'manual' }) // the scan of xt-12 runs
    const node = parsed(TargetNode, (await call('GET', '/exposure/tree/xt-13')).json)
    expect(node).toMatchObject({ blocked: null, commitment_notice: null, last_scan: { status: 'queued' } })
  })

  it('terms make scans deep; withdrawing them makes them surface again', async () => {
    withTwoStep()
    const n = parsed(TargetNode, (await call('PUT', '/exposure/tree/xt-12/terms', { version: TERMS_VERSION, disruptive: false })).json)
    expect(n.deep).toBe(true)
    expect(n.terms?.text).toContain('git.example.com')
    expect(parsed(TargetNode, (await call('DELETE', '/exposure/tree/xt-12/terms')).json).deep).toBe(false)
  })

  it('handles open issues with the shared resolutions and reopens handled ones', async () => {
    const issues = async () => ((await call('GET', '/exposure/tree/xt-11/issues')).json as { items: unknown[] }).items.map((i) => parsed(Issue, i))
    expect((await issues()).map((i) => i.severity)).toEqual(['high', 'medium', 'medium', 'low'])
    const git = ((await call('GET', '/exposure/tree/xt-12/issues')).json as { items: unknown[] }).items.map((i) => parsed(Issue, i))
    expect(git.find((i) => i.id === 'xi-5')!.cves).toEqual([{ cve: 'CVE-2025-26791', severity: expect.objectContaining({ band: 'medium' }) }])
    const code = async (b: unknown) => ((await call('POST', '/exposure/issues/handle', b)).json as { error: { code: string } }).error.code
    expect(await code({ ids: ['xi-1'], resolution: 'accepted', note: 'Behind the VPN only', accepted_until: '2020-01-01' })).toBe('bad_until')
    expect(await code({ ids: ['xi-1'], resolution: 'mitigated', note: 'x', accepted_until: '2099-01-01' })).toBe('bad_until')
    for (const resolution of ['accepted', 'false_positive', 'not_relevant']) expect(await code({ ids: ['xi-1'], resolution, note: '  ' })).toBe('note_required')
    expect((await call('POST', '/exposure/issues/handle', { ids: ['xi-1'], resolution: 'wontfix', note: '' })).status).toBe(400)
    const r = await call('POST', '/exposure/issues/handle', { ids: ['xi-1', 'xi-3', 'xi-4'], resolution: 'mitigated', note: 'CSP set at the proxy' }, 'operator')
    expect(r.json).toEqual({ handled: 1, skipped: 2 })
    expect((await issues()).find((i) => i.id === 'xi-1')).toMatchObject({ state: 'handled', resolution: 'mitigated', resolved_by: 'it@acme.example', note: 'CSP set at the proxy' })
    expect((await call('POST', '/exposure/issues/reopen', { ids: ['xi-1', 'xi-2'] }, 'operator')).json).toEqual({ reopened: 1, skipped: 1 })
    expect((await issues()).find((i) => i.id === 'xi-1')).toMatchObject({ state: 'open', resolution: null, resolved_by: null })
    expect((await call('POST', '/exposure/issues/reopen', { ids: ['xi-1'] }, 'viewer')).status).toBe(403)
  })
})
