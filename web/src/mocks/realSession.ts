// `make dev-api` with `core` in VITE_API_REAL: the sign-in is the real backend's, so the mock's own session store
// stays empty and the mocked modules (feeds, inventory, ...) would answer every request with 401. While core is
// real, the mock layer asks the real backend who is signed in (GET /api/v1/me, sent past MSW with bypass()) and
// takes the user and role from that: role checks keep working, nobody is granted admin.
//
// The answer is kept for a few seconds. Every write to a real module (sign-in, sign-out, setup, a role change) is
// sent to the backend by this layer itself; when the backend has answered, a generation counter is bumped and the
// held answer dropped. A /me read is stored only if no write finished since it started (otherwise it is read
// again), so an answer read before a sign-out never outlives it. A signed-out answer is never kept.
import { bypass, http, type HttpHandler } from 'msw'
import { moduleOf } from '@/lib/apiModules'
import type { Role } from '@/lib/session'
import type { User } from './stores'

const TTL_MS = 3000
const ROLES: readonly string[] = ['viewer', 'operator', 'admin']

type FetchMe = () => Promise<unknown>

let enabled = false
let fetchMe: FetchMe = defaultFetchMe
type Send = (request: Request) => Promise<Response>

let send: Send = (request) => fetch(bypass(request))
let gen = 0 // bumped after every write to a real module
let cached: { user: User; at: number } | null = null
let inflight: Promise<void> | null = null

async function defaultFetchMe(): Promise<unknown> {
  const r = await fetch(bypass(new Request(new URL('/api/v1/me', location.origin))))
  return r.ok ? r.json() : null
}

/** Turn the real-session lookup on (core is real) or off. `fetcher` replaces the network call (tests). */
export function setRealSession(on: boolean, fetcher: FetchMe = defaultFetchMe, sender?: Send) {
  enabled = on
  fetchMe = fetcher
  send = sender ?? ((request) => fetch(bypass(request)))
  gen++
  cached = null
  inflight = null
}

export const realSessionOn = () => enabled

/** The signed-in user of the real backend as last read, or undefined (not signed in, or not read yet). */
export function realUser(): User | undefined {
  return cached && Date.now() - cached.at < TTL_MS ? cached.user : undefined
}

function toUser(me: unknown): User | null {
  const m = me as { id?: unknown; name?: unknown; email?: unknown; role?: unknown; twofa?: unknown } | null
  if (!m || typeof m.id !== 'string' || typeof m.email !== 'string' || typeof m.role !== 'string' || !ROLES.includes(m.role)) return null
  return { id: m.id, name: String(m.name ?? ''), email: m.email, role: m.role as Role, password: '', twofa: m.twofa === true, created_at: '', last_login: null }
}

/** Read /me now unless a fresh answer is held. Never throws: a backend that does not answer means signed out. */
export async function syncRealSession(): Promise<void> {
  if (!enabled || realUser()) return
  inflight ??= (async () => {
    try {
      let u: User | null = null
      for (let attempt = 0; attempt < 3; attempt++) {
        const started = gen
        try { u = toUser(await fetchMe()) } catch { u = null }
        if (started === gen) { cached = u ? { user: u, at: Date.now() } : null; return }
      }
      cached = null // writes kept coming: keep nothing, the next request reads again
    } finally {
      inflight = null
    }
  })()
  await inflight
}

function modulePath(url: string): string {
  return new URL(url).pathname.replace(/^\/api\/v1/, '')
}

/** First MSW handler: before a mocked module answers, fetch who is signed in; a write to a real module is sent on by this handler and forgets the answer once the backend has answered. A read of a real module, and every request after the lookup, returns nothing, so it goes on to the next handler (or to the network). */
export function realSessionHandler(isReal: (module: string) => boolean): HttpHandler {
  return http.all('*/api/v1/*', async ({ request }) => {
    if (isReal(moduleOf(modulePath(request.url)))) {
      if (request.method === 'GET' || request.method === 'HEAD') return
      // Send the write ourselves so the held answer is dropped after the backend acted, not before.
      const res = await send(request)
      gen++
      cached = null
      return res
    }
    await syncRealSession()
  })
}
