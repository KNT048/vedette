// Shared by notify.spec.ts and notify.global.spec.ts (WP-30, D-170): the shapes of the notify API, the texts the page derives from them, small helpers.
// Nothing here talks to the internet. The one send that can be tried on a box with no internet is an email channel pointed at a closed port on loopback
// (SMTP to an internal host is allowed, INV-8); a webhook cannot point at loopback (D-86), and Telegram, Slack and Zalo have fixed internet addresses.
// DEPENDENCY: a production box refuses a loopback SMTP server like a webhook (walk 3, INV-8); the e2e box (TestE2EBox) is built by the tests of cmd/vedette,
// which set notify's test-only Config.SMTPLoopback (notify_wiring_test.go), so the email tests here still reach loopback.
// Not covered: DNS rebinding of a webhook name (the dial-time check needs a resolver seam); only the spelled-out addresses are tested.
import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { networkInterfaces } from 'node:os'
import { expect, type Locator, type Page } from '@playwright/test'
import { api } from './box'
export { as } from './findings-seed'

export type ChannelType = 'telegram' | 'slack' | 'zalo' | 'zalo-personal' | 'email' | 'webhook'
export const TYPES: ChannelType[] = ['telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook']
export const NAME: Record<ChannelType, string> = { telegram: 'Telegram', slack: 'Slack', zalo: 'Zalo OA', 'zalo-personal': 'Zalo personal', email: 'Email', webhook: 'Webhook' }
export const SEV: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

export interface Ch {
  type: ChannelType; configured: boolean; enabled: boolean; fields: Record<string, string>; secret_last4: string | null; min_severity: string
  last_test: { at: string; ok: boolean; detail: string } | null; approvals: boolean; approvers: { user_id: string; address: string }[]
  approval_last4: { app_token: string | null; bot_token: string | null }
}
export interface Quiet { enabled: boolean; from: string; to: string; allow_critical: boolean }
export interface Grouping { enabled: boolean; window_min: number }
export interface Rules { quiet: Quiet; grouping: Grouping }
export interface Channels extends Rules { channels: Ch[]; email_code_users: number }
export interface Hist { id: string; at: string; channel: ChannelType; to: string; ok: boolean; error?: string; kind: 'incident' | 'vuln' | 'approval'; what: string; link: string }
export interface History { items: Hist[]; suppressed: { count: number; days: number } }
export interface AuditRow { id: string; user: string; action: string; target: string; detail?: string }
export interface ApiErr { error: { code: string; message: string } }
export interface Incident { id: string; status: string; title: string }

export const ERR_UNREACHABLE = 'The message could not be sent. The server could not be reached or answered something unexpected.'

/** The error answers of the API, as (status, code, message) in one object so a test compares all three. */
export const refused = (status: number, code: string, message?: string) => ({ status, body: { error: message === undefined ? { code, message: expect.any(String) } : { code, message } } })

export async function getChannels(c: Parameters<typeof api>[0]): Promise<Channels> {
  const r = await api<Channels>(c, 'GET', '/notify/channels')
  expect(r.status, `GET /notify/channels: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}
export async function getHistory(c: Parameters<typeof api>[0]): Promise<History> {
  const r = await api<History>(c, 'GET', '/notify/history')
  expect(r.status, `GET /notify/history: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}

/** The summary line under the quiet hours fields, from the form values (ChannelsSettings.tsx), or null when the page shows none. */
export function quietSummary(q: Quiet): string | null {
  if (!q.enabled || !q.from || !q.to || q.from === q.to) return null
  return q.from > q.to ? `Quiet from ${q.from} this evening until ${q.to} the next morning.` : `Quiet from ${q.from} to ${q.to} on the same day.`
}
/** The line over the History table (history.meta*), from the count of vulnerabilities that matched no device. */
export function historyMeta(s: { count: number; days: number }): string {
  if (s.count === 0) return `Vedette only alerts for products you own. In the last ${s.days} days no new vulnerability was skipped for matching none of your devices. The first download of the vulnerability lists is not counted.`
  if (s.count === 1) return `Vedette only alerts for products you own. 1 new vulnerability in the last ${s.days} days matches none of your devices, so nothing was sent. The first download of the vulnerability lists is not counted.`
  return `Vedette only alerts for products you own. ${s.count} new vulnerabilities in the last ${s.days} days match none of your devices, so nothing was sent. The first download of the vulnerability lists is not counted.`
}
/** "Sent to" cell of a channel row (dest() in ChannelsSettings.tsx). */
export function destText(c: Ch): string {
  if (!c.configured) return ''
  switch (c.type) {
    case 'zalo-personal': return `Zalo, recipient ${c.fields.user_id}`
    case 'telegram': return `Chat ${c.fields.chat_id}`
    case 'slack': return c.fields.label || 'Slack webhook'
    case 'zalo': return `OA ${c.fields.oa_id}, recipient ${c.fields.user_id}`
    case 'email': return c.fields.to ?? ''
    case 'webhook': return c.fields.url ?? ''
  }
}
export const statusText = (c: Ch) => (!c.configured ? 'Not set up' : c.enabled ? 'On' : 'Off')

/** The row of one channel in the Alert channels table, found through its own button (Set up X when it is not configured, Edit X when it is). */
export const chanRow = (page: Page, c: Pick<Ch, 'type' | 'configured'>): Locator =>
  page.getByRole('row').filter({ has: page.getByRole('button', { name: `${c.configured ? 'Edit' : 'Set up'} ${NAME[c.type]}`, exact: true }) })

/** Server errors (5xx) the page saw on the API while a test ran: a test ends with `expect(server).toEqual([])`. */
export function watch5xx(page: Page): string[] {
  const seen: string[] = []
  page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) seen.push(`${r.request().method()} ${r.url()} ${r.status()}`) })
  return seen
}

/** A loopback port nothing listens on: a connection to it is refused at once, on this machine only. */
export async function closedPort(): Promise<number> {
  const s = createServer()
  await new Promise<void>((ok) => s.listen(0, '127.0.0.1', ok))
  const port = (s.address() as AddressInfo).port
  await new Promise<void>((ok) => s.close(() => ok()))
  return port
}

/** An IPv4 address of one of this machine's own network interfaces that is not loopback: the box is this machine, so it is "the box itself". */
export function ownAddress(): string | undefined {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) if (a.family === 'IPv4' && !a.internal) return a.address
  }
  return undefined
}

/** The new audit rows of notify since `before` (a set of ids), as `action|target|detail|user` lines, sorted. */
export async function newAudit(c: Parameters<typeof api>[0], before: Set<string>): Promise<string[]> {
  const r = await api<{ items: AuditRow[] }>(c, 'GET', '/core/audit?q=notify.')
  expect(r.status, 'GET /core/audit').toBe(200)
  return r.body.items.filter((i) => !before.has(i.id) && i.action.startsWith('notify.')).map((i) => `${i.action}|${i.target}|${i.detail ?? ''}|${i.user}`).sort()
}
export async function auditIds(c: Parameters<typeof api>[0]): Promise<Set<string>> {
  const r = await api<{ items: AuditRow[] }>(c, 'GET', '/core/audit?q=notify.')
  expect(r.status, 'GET /core/audit').toBe(200)
  return new Set(r.body.items.map((i) => i.id))
}
/** The audit log never holds a secret: searching for it finds nothing. */
export async function auditHasNo(c: Parameters<typeof api>[0], secret: string) {
  // positive control: the search works, so an empty answer below means "not there", not "search broken"
  const known = await api<{ items: AuditRow[] }>(c, 'GET', '/core/audit?q=notify.channel_save')
  expect(known.status, 'GET /core/audit?q=notify.channel_save').toBe(200)
  expect(known.body.items.length, 'positive control: a q= search finds the channel saves').toBeGreaterThan(0)
  for (const part of [secret, secret.slice(0, -4)]) {
    const r = await api<{ items: AuditRow[]; total: number }>(c, 'GET', `/core/audit?q=${encodeURIComponent(part)}`)
    expect(r.status, 'GET /core/audit?q=<secret>').toBe(200)
    expect(r.body.items, 'a secret (or all but its last 4 characters) found in the audit log').toEqual([])
  }
}
/** What the page shows in the Last test cell: `Tested <time>: failed|success`, the time formatted the way the GUI does (fmtDateTime: en-GB, the page's time zone). */
export function testedText(t: { at: string; ok: boolean }): string {
  const when = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Ho_Chi_Minh' }).format(new Date(t.at))
  return `Tested ${when}: ${t.ok ? 'success' : 'failed'}`
}
