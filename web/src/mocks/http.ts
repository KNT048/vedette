// Shared helpers for mock handlers: the standard error {error:{code,message}}, permission checks, validation at the edge (SYS-2).
import { HttpResponse } from 'msw'
import { sessionStore, usersStore, type User } from './stores'
import { realSessionOn, realUser } from './realSession'
import type { Role } from '@/lib/session'

export const API = '*/api/v1'

/** `extra` is spread into `error` next to `code` and `message`, so `field` or any other detail reaches the client. */
export function fail(status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
  return HttpResponse.json({ error: { code, message, ...extra } }, { status })
}

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** The signed-in person: the mock session, or (when core runs for real in `make dev-api`) the real backend's user (`mocks/realSession.ts`). */
export function currentUser(): User | undefined {
  if (realSessionOn()) return realUser()
  const s = sessionStore.get()
  return s.userId ? usersStore.get().find((x) => x.id === s.userId) : undefined
}

/** Returns a 401/403 error if the permission is missing, or null if allowed. `allowLimited`: also lets a session that is limited because of a temporary password through. */
export function guard(min: Role, allowLimited = false) {
  const u = currentUser()
  if (!u) return fail(401, 'unauthenticated', 'Your session has ended. Sign in again.')
  if (rank[u.role] < rank[min]) return fail(403, 'forbidden', 'Your account is not allowed to do this.')
  // after the role, like the server: a session opened with an administrator-set password may only read /me, change the password and sign out (those pass allowLimited).
  if (u.temp_password_expires_at && !allowLimited) return fail(403, 'password_change_required', 'Choose a new password before you continue.')
  return null
}

export async function body<T>(req: Request): Promise<Partial<T>> {
  try { return (await req.json()) as Partial<T> } catch { return {} }
}

export const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/
export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export const CIDR_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/
export const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** Write an audit entry for every mutation (SYS-3). The core module shows it in Settings → Audit log. */
export { audit } from './stores'

/** The product is English only. Keep the signature so old code runs; new code uses English strings directly. */
export const langOf = (_req: Request): 'en' => 'en'
/** @deprecated use English strings directly. Returns the English text. */
export const msg = (_req: Request, _vi: string, en: string) => en
