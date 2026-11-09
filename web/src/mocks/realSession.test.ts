// make dev-api with core real: the mocked modules take the signed-in user and role from the real backend.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { server } from '@/test/server'
import { realModules } from '@/lib/apiModules'
import { realSessionHandler, setRealSession } from './realSession'

const isReal = realModules('core,exposure')
const url = (p: string) => `http://localhost/api/v1${p}`
const feedsHot = () => fetch(url('/feeds/hot?window=24h'))
const noContent = async () => new Response(null, { status: 204 })

type Me = { id: string; name: string; email: string; role: string }
const op: Me = { id: 'u1', name: 'Op', email: 'o@acme.example', role: 'operator' }

/** The signed-in user of the "real backend"; null = signed out. */
let me: Me | null = null
let meCalls = 0
/** `send` is what the "real backend" does with a write that goes to it. */
function useRealCore(send: (r: Request) => Promise<Response> = noContent) {
  setRealSession(true, async () => { meCalls++; return me }, send)
  server.use(realSessionHandler(isReal)) // prepended: runs before the mocked handlers
}
afterEach(() => { setRealSession(false); me = null; meCalls = 0 })

describe('mocked modules while core is real', () => {
  it('answer 401 when nobody is signed in on the real backend', async () => {
    useRealCore()
    expect((await feedsHot()).status).toBe(401)
  })

  it('answer for the real session, and keep checking its role', async () => {
    useRealCore()
    me = { id: 'u-real', name: 'Real Viewer', email: 'v@acme.example', role: 'viewer' }
    expect((await feedsHot()).status).toBe(200)
    expect((await fetch(url('/feeds/weekly'))).status).toBe(200)
    // a viewer is not an operator: the role of the real session is what the mock enforces, not admin
    const denied = await fetch(url('/feeds/weekly/x'), { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })
    expect(denied.status).toBe(403)
  })

  it('reads /me once for a burst of requests and again after a sign-out', async () => {
    useRealCore()
    me = op
    await Promise.all([feedsHot(), fetch(url('/feeds/weekly')), fetch(url('/feeds/status'))])
    expect(meCalls).toBe(1)
    me = null
    await fetch(url('/auth/logout'), { method: 'POST' })
    expect((await feedsHot()).status).toBe(401)
    expect(meCalls).toBe(2)
  })

  it('reads /me again after a sign-in', async () => {
    useRealCore()
    expect((await feedsHot()).status).toBe(401) // signed out: not kept
    me = op
    await fetch(url('/auth/login'), { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })
    expect((await feedsHot()).status).toBe(200)
    expect(meCalls).toBe(2)
  })

  it('reads /me again after a role change, so a downgrade takes effect at once', async () => {
    useRealCore()
    me = op
    expect((await fetch(url('/feeds/weekly/x'), { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status).not.toBe(403)
    me = { ...op, role: 'viewer' }
    await fetch(url('/core/users/u1'), { method: 'PATCH', body: '{"role":"viewer"}', headers: { 'content-type': 'application/json' } })
    expect((await fetch(url('/feeds/weekly/x'), { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status).toBe(403)
  })

  it('drops a /me answer that was still in flight when the user signed out', async () => {
    let release: ((v: Me | null) => void) | undefined
    let signedOut = false
    setRealSession(true, () => (signedOut ? Promise.resolve(null) : new Promise((r) => { release = r })), noContent)
    server.use(realSessionHandler(isReal))
    const before = feedsHot() // a mocked module asks who is signed in: /me is on the wire
    await vi.waitFor(() => expect(release).toBeDefined())
    signedOut = true
    await fetch(url('/auth/logout'), { method: 'POST' })
    release!(op) // the backend had answered /me before it handled the sign-out
    await before
    expect((await feedsHot()).status).toBe(401) // not the old user
  })

  it('does not keep a /me read made while the sign-out was still being handled by the backend', async () => {
    let finishLogout: (() => void) | undefined
    useRealCore(() => new Promise<Response>((resolve) => { finishLogout = () => { me = null; resolve(new Response(null, { status: 204 })) } }))
    me = op
    const logout = fetch(url('/auth/logout'), { method: 'POST' })
    await vi.waitFor(() => expect(finishLogout).toBeDefined())
    expect((await feedsHot()).status).toBe(200) // still signed in at this moment: right
    finishLogout!()
    expect((await logout).status).toBe(204)
    expect((await feedsHot()).status).toBe(401) // the answer read just before is not served on
  })
})
