// Helpers of the two-step sign-in specs (twofa.spec.ts, twofa-channel.global.spec.ts): the TOTP calculation, a GUI sign-in, a throwaway user.
import { createHmac } from 'node:crypto'
import { expect, request, type APIRequestContext, type Page } from '@playwright/test'
import { authFile, box, createUser, password, uniq } from './box'

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function b32decode(s: string) {
  let bits = 0, v = 0
  const out: number[] = []
  for (const c of s.toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8 } }
  return Buffer.from(out)
}
/** TOTP written independently in the test (node:crypto), RFC 6238, SHA-1, 6 digits, 30 s (verbatim from e2e/qa/twofa.spec.ts). */
export function totp(secret: string, at = Date.now()) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(at / 30000)))
  const h = createHmac('sha1', b32decode(secret)).update(c).digest()
  const o = h[19]! & 15
  const n = ((h[o]! & 127) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!
  return String(n % 1_000_000).padStart(6, '0')
}
export const step = (at = Date.now()) => Math.floor(at / 30000)

/** A code the box has not seen yet: the box refuses a step at or before the last one it accepted (replay protection), so wait for the next
 *  30 s window if this one is used, and return the code of the step after `used` (the box accepts one step ahead of its clock). */
export async function codeAfter(key: string, used: number): Promise<{ code: string; step: number }> {
  while (step() < used) await new Promise((ok) => setTimeout(ok, 1000))
  return { code: totp(key, Date.now() + 30000), step: step() + 1 }
}

/** A six-digit string that is none of `not`. */
export const wrongCode = (...not: string[]) => ['000000', '111111', '222222'].find((c) => !not.includes(c))!

export const masked = (email: string) => `${email[0]}•••${email.slice(email.indexOf('@'))}`

export const adminApi = () => request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
export const fresh = () => request.newContext({ baseURL: box().base_url })

/** A throwaway viewer with the run's password, made the way a person gets one (temporary password, then a change), and the admin's API context. */
export async function newUser(prefix = 'tf') {
  const tag = uniq(prefix)
  const who = { name: `Person ${tag}`, email: `${tag}@e2e.test`, role: 'viewer' as const }
  const admin = await adminApi()
  const tmp = await fresh()
  await createUser(admin, tmp, who)
  await tmp.dispose()
  return { ...who, pw: password(), admin }
}

/** Opens the sign-in page and submits email and password; the page is left on whatever the box answers. */
export async function submitSignIn(page: Page, email: string, pw: string) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(pw)
  await page.getByRole('button', { name: 'Sign in' }).click()
}

/** Signs in with a password alone and waits for the first page after the login. */
export async function signIn(page: Page, email: string, pw: string) {
  await submitSignIn(page, email, pw)
  await expect(page).not.toHaveURL(/\/login/, { timeout: 30_000 })
}
