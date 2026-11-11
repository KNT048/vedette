// Shared by exposure.spec.ts and exposure.global.spec.ts (WP-30, D-170): what the box says about the exposure module, read through the API,
// and the texts of the page worked out from it, so a test never guesses what is on the box.
// Nothing here (or in the two specs) makes the box reach the internet: Detect now, Verify again, the DNS Check of a domain and auto-detect
// being turned on all call the public IP services or real DNS from the box, and the box has no setting that points them at loopback
// (cmd/vedette/exposure.go builds the real prober and net.DefaultResolver), so no test presses them. See .ai/deferred/feat-e2e-real-exposure.md.
import { expect, request, type APIRequestContext } from '@playwright/test'
import { api, authFile, box, type Role } from './box'

export const as = (role: Role) => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
/** A client with no session. The state must be given empty on purpose: `request.newContext` of the test runner takes the `storageState` of the test's `use` otherwise. */
export const anon = () => request.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] } })

export interface Check { at: string; ok: boolean; message: string }
export interface Tgt {
  id: string; kind: 'domain' | 'ip'; value: string; status: 'verified' | 'unverified' | 'expired'; method: string | null; token: string
  verified_at: string | null; expires_at: string | null; validity: string | null; last_check: Check | null; commitment: { by: string; at: string } | null
  scannable: boolean; blocked_reason: string | null; created_at: string; last_scan_at: string | null; latest: { admin_panels: number; ports: number; certs_expiring: number } | null
}
export interface BoxIp { auto: boolean; interval_min: number; last_run: Check | null; retry_in_min: number | null }
export interface List { items: Tgt[]; box_ip: BoxIp; ignored: { value: string; ignored_by: string; ignored_at: string }[] }
export interface AuditRow { id: string; user: string; action: string; target: string; detail?: string }
export interface ApiErr { error: { code: string; message: string } }

/** The error answer of the API as one object: status, code and the exact message. */
export const refused = (status: number, code: string, message: string) => ({ status, body: { error: { code, message } } })

export async function list(c: APIRequestContext): Promise<List> {
  const r = await api<List>(c, 'GET', '/exposure/targets')
  expect(r.status, `GET /exposure/targets: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}
export async function target(c: APIRequestContext, id: string): Promise<Tgt> {
  const r = await api<Tgt>(c, 'GET', `/exposure/targets/${id}`)
  expect(r.status, `GET /exposure/targets/${id}: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}
/** Everything a refusal must leave alone: the whole list, the ignored list and the settings. */
export const snapshot = async (c: APIRequestContext) => JSON.stringify(await list(c))

/** The audit rows of the exposure module that mention `q` (the box searches action, target and detail). */
export async function audit(c: APIRequestContext, q: string): Promise<AuditRow[]> {
  const r = await api<{ items: AuditRow[] }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)
  expect(r.status, `GET /core/audit?q=${q}`).toBe(200)
  return r.body.items
}
export const auditIds = async (c: APIRequestContext, q: string) => new Set((await audit(c, q)).map((r) => r.id))

let counter = 0
/** A domain no other test uses: process id and a counter, never the time. Valid for the box (labels of letters, digits and dashes; a letter-only last label). */
export const domain = (): string => `exp${process.pid.toString(36)}-${(counter++).toString(36)}.e2e.example`

/** Domains a test made, removed by name after it through the API, and the status of each removal checked (a failed test leaves nothing on the box). */
export const made: string[] = []
export async function sweep() {
  if (!made.length) return
  const admin = await as('admin')
  try {
    const items = (await list(admin)).items
    for (const value of made.splice(0)) {
      const t = items.find((i) => i.value === value)
      if (t) expect((await api(admin, 'DELETE', `/exposure/targets/${t.id}`)).status, `cleanup of ${value}`).toBe(204)
    }
  } finally { await admin.dispose() }
}

const PRESET = new Set([1, 5, 10, 15, 30, 60, 120, 360, 720, 1440])
const EVERY: Record<number, string> = { 1: 'every minute', 5: 'every 5 minutes', 10: 'every 10 minutes', 15: 'every 15 minutes', 30: 'every 30 minutes', 60: 'every hour', 120: 'every 2 hours', 360: 'every 6 hours', 720: 'every 12 hours', 1440: 'every 24 hours' }
export const every = (n: number) => (PRESET.has(n) ? EVERY[n]! : `every ${n} minutes`)
/** The line over the controls of the Public IPs panel (boxIp.state). */
export const autoLine = (b: BoxIp) => (b.auto ? `Auto-detect is on: the box checks its public IPs ${every(b.interval_min)}.` : 'Auto-detect is off: the box checks only when you select Detect now.')

/** The headline of the page (ExposurePage title), worked out from what the API says now. */
export function headline(items: Tgt[]): string {
  const scanned = items.filter((x) => x.latest)
  const admin = scanned.reduce((n, x) => n + (x.latest?.admin_panels ?? 0), 0)
  const pending = items.filter((x) => !x.scannable).length
  const plural = (n: number, one: string, other: string) => (n === 1 ? one : other)
  if (items.length === 0) return 'No domain or verified public IP yet'
  if (scanned.length === 0) {
    return pending > 0
      ? plural(pending, `${pending} item cannot be scanned yet: it needs ownership proof or your confirmation`, `${pending} items cannot be scanned yet: they need ownership proof or your confirmation`)
      : plural(items.length, `${items.length} target is verified and confirmed, ready for the first scan`, `${items.length} targets are verified and confirmed, ready for the first scan`)
  }
  if (admin > 0) return plural(admin, `${admin} admin interface is exposed to the Internet`, `${admin} admin interfaces are exposed to the Internet`)
  if (pending > 0) return plural(pending, `No exposed admin interface in the targets scanned so far. ${pending} target cannot be scanned yet`, `No exposed admin interface in the targets scanned so far. ${pending} targets cannot be scanned yet`)
  return 'No admin interface is exposed to the Internet'
}

/** The "Ownership" chip of a target (OwnerChip), without the day count of an expiring IP (an IP only comes from the public IP services, which no test reaches). */
export const ownerText = (t: Pick<Tgt, 'status'>) => ({ unverified: 'Awaiting ownership proof', expired: 'Verification expired', verified: 'Ownership verified' })[t.status]
/** The "Scan" cell of a target: the blocked label, or "Ready to scan". */
export const blockedLabel: Record<string, string> = { unverified: 'Needs ownership proof', expired: 'Verification expired', txt_missing: 'TXT record missing', ip_not_current: 'Paused', no_commitment: 'Needs your confirmation' }
export const scanCell = (t: Pick<Tgt, 'blocked_reason'>) => (t.blocked_reason ? blockedLabel[t.blocked_reason]! : 'Ready to scan')
