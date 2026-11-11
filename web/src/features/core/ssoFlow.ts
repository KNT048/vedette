// D-194: what the sign-in page keeps between "Sign in with SSO" and /sso/callback. Session storage of this tab only (not a
// cookie, legal.md), removed as soon as the callback page reads it.
const KEY = 'vedette-sso-flow'

export interface SsoFlow { binding: string; next: string }

/** A path inside the app, never another site (`//host` or a full URL). */
export const safeNext = (next: string | null | undefined): string => (next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/')

export function saveSsoFlow(f: SsoFlow) {
  try { sessionStorage.setItem(KEY, JSON.stringify(f)) } catch { /* storage blocked: the callback says to start again */ }
}

/** Reads and removes the flow; null when this tab did not start one. */
export function takeSsoFlow(): SsoFlow | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    sessionStorage.removeItem(KEY)
    if (!raw) return null
    const f = JSON.parse(raw) as Partial<SsoFlow>
    return typeof f.binding === 'string' ? { binding: f.binding, next: safeNext(f.next) } : null
  } catch {
    return null
  }
}
