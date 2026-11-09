// `make dev-api` with `core` in VITE_API_REAL: the sign-in is the real backend's, so the mock's own session store
// stays empty and the mocked modules (feeds, inventory, ...) would answer every request with 401. While core is
// real, the mock layer asks the real backend who is signed in (GET /api/v1/me, sent past MSW with bypass()) and
// takes the user and role from that: role checks keep working, nobody is granted admin.
//
// The answer is kept for a few seconds and dropped when a request that can change it (any write to a real
// module: sign-in, sign-out, setup, a role change) goes by. A signed-out answer is never kept.
import { bypass, http, type HttpHandler } from 'msw'
import { moduleOf } from '@/lib/apiModules'
import type { Role } from '@/lib/session'
import type { User } from './stores'

const TTL_MS = 3000
const ROLES: readonly string[] = ['viewer', 'operator', 'admin']

type FetchMe = () => Promise<unknown>

let enabled = false
let fetchMe: FetchMe = defaultFetchMe
let cached: { user: User; at: number } | null = null
let inflight: Promise<void> | null = null

async function defaultFetchMe(): Promise<unknown> {
  const r = await fetch(bypass(new Request(new URL('/api/v1/me', location.origin))))
  return r.ok ? r.json() : null
}

/** Turn the real-session lookup on (core is real) or off. `fetcher` replaces the network call (tests). */
export function setRealSession(on: boolean, fetcher: FetchMe = defaultFetchMe) {
  enabled = on
  fetchMe = fetcher
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
      const u = toUser(await fetchMe())
      cached = u ? { user: u, at: Date.now() } : null
    } catch {
      cached = null
    } finally {
      inflight = null
    }
  })()
  await inflight
}

function modulePath(url: string): string {
  return new URL(url).pathname.replace(/^\/api\/v1/, '')
}

/** First MSW handler: before a mocked module answers, fetch who is signed in; a write to a real module forgets the answer. It returns nothing, so the request goes on to the next handler (or to the network). */
export function realSessionHandler(isReal: (module: string) => boolean): HttpHandler {
  return http.all('*/api/v1/*', async ({ request }) => {
    if (isReal(moduleOf(modulePath(request.url)))) {
      if (request.method !== 'GET' && request.method !== 'HEAD') { cached = null }
      return
    }
    await syncRealSession()
  })
}
