// make dev-api with core real: the mocked modules take the signed-in user and role from the real backend.
import { afterEach, describe, expect, it } from 'vitest'
import { server } from '@/test/server'
import { realModules } from '@/lib/apiModules'
import { realSessionHandler, setRealSession } from './realSession'

const isReal = realModules('core,exposure')
const url = (p: string) => `http://localhost/api/v1${p}`

/** The signed-in user of the "real backend"; null = signed out. */
let me: { id: string; name: string; email: string; role: string } | null = null
let meCalls = 0
function useRealCore() {
  setRealSession(true, async () => { meCalls++; return me })
  server.use(realSessionHandler(isReal)) // prepended: runs before the mocked handlers
}
afterEach(() => { setRealSession(false); me = null; meCalls = 0 })

describe('mocked modules while core is real', () => {
  it('answer 401 when nobody is signed in on the real backend', async () => {
    useRealCore()
    expect((await fetch(url('/feeds/hot?window=24h'))).status).toBe(401)
  })

  it('answer for the real session, and keep checking its role', async () => {
    useRealCore()
    me = { id: 'u-real', name: 'Real Viewer', email: 'v@acme.example', role: 'viewer' }
    expect((await fetch(url('/feeds/hot?window=24h'))).status).toBe(200)
    expect((await fetch(url('/feeds/weekly'))).status).toBe(200)
    // a viewer is not an operator: the role of the real session is what the mock enforces, not admin
    const denied = await fetch(url('/feeds/weekly/x'), { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })
    expect(denied.status).toBe(403)
  })

  it('reads /me once for a burst of requests and again after a sign-in or sign-out', async () => {
    useRealCore()
    me = { id: 'u1', name: 'Op', email: 'o@acme.example', role: 'operator' }
    await Promise.all([fetch(url('/feeds/hot?window=24h')), fetch(url('/feeds/weekly')), fetch(url('/feeds/status'))])
    expect(meCalls).toBe(1)
    me = null
    await fetch(url('/auth/logout'), { method: 'POST' }).catch(() => {})
    expect((await fetch(url('/feeds/hot?window=24h'))).status).toBe(401)
    expect(meCalls).toBe(2)
  })
})
