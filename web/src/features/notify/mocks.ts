// Mock API module notify (S-ALERT-1, S-ALERT-3, S-NOT-1). Incidents (D-52): trap, bad address, log anomaly, unknown device. Vulnerability notices stay with the finding.
// Bí mật (token, mật khẩu) chỉ lưu phía mock và không bao giờ trả ra: API chỉ trả 4 ký tự cuối (SYS-4). Mọi văn bản người dùng thấy bằng tiếng Anh (D-28).
// Không hỗ trợ nhiều site/MSP (quyết định của chủ dự án): không có tin gộp nhiều khách.
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, currentUser, DOMAIN_RE, EMAIL_RE, fail, guard, IPV4_RE } from '@/mocks/http'
import { assetsStore, boxInfo, emailCodeUserCount, usersStore } from '@/mocks/stores'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import type { Severity } from '@/lib/types'
import { isInternalHost } from '@/features/feeds/defaults'
import { chatLinkSenders, newLinkToken } from '@/features/response/identity'
import { identityStore, isLinked } from '@/features/response/state'
import { CHANNEL_TYPES, FIELDS, OWN_TEXT, ROUTE_SEVERITIES, forbiddenHost, ownHost } from './types'
import { OAUTH_HOST, emailBinding, emailProvider, isOAuth, isUserSignin, savedFor } from './emailProviders'
import type { Approver, Channel, ChannelInput, ChannelType, EmailSignin, Grouping, HistoryItem, Incident, IncidentDetail, IncidentStatus, Preview, Quiet, SendRecord, TestResult, ZaloApprover, ZaloContact, ZaloLogin } from './types'

const SEV: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

// approvals: module khác (response) đọc bằng peek('notify_channels'): mỗi kênh có approvals?: boolean và approvers?: {user_id, address}[]. Giữ nguyên hình dạng này (D-46).
interface StoredChannel extends Omit<Channel, 'secret_last4' | 'approvals' | 'approvers' | 'approval_last4'> { secret: string; url?: string; approvals?: boolean; approvers?: Approver[]; app_token?: string; bot_token?: string }
const blank = (type: ChannelType): StoredChannel => ({ type, configured: false, enabled: false, fields: {}, secret: '', min_severity: 'medium', last_test: null })
// The webhook URL is a bearer secret (SYS-4): the mock keeps it apart from `fields`, as the backend seals it, and shows only scheme://host/… and its last 4 characters.
const SAVED_FIELDS: Record<ChannelType, string[]> = { ...FIELDS, slack: ['label', 'channel_id'], 'zalo-personal': ['user_id', 'group', 'name'], webhook: [] }

const channels = collection<StoredChannel[]>('notify_channels', () => [
  { type: 'telegram', configured: true, enabled: true, fields: { chat_id: '-1002145678901' }, secret: '123456789:EXAMPLE_not_a_real_token_0000000000', min_severity: 'medium', last_test: { at: daysAgo(2), ok: true, detail: 'Telegram received the test message (chat -1002145678901).' } },
  { type: 'slack', configured: true, enabled: true, fields: { label: '#it-alerts', channel_id: 'C04VEDETTE1' }, secret: 'https://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/EXAMPLEnotarealwebhook', min_severity: 'high', approvals: true, approvers: [{ user_id: 'u-admin', address: 'U04ABCD1234' }, { user_id: 'u-op', address: 'U04OPS00001' }], app_token: 'xapp-EXAMPLE-not-a-real-app-token', bot_token: 'xoxb-EXAMPLE-not-a-real-bot-token', last_test: { at: daysAgo(1), ok: true, detail: 'Slack accepted the test message (#it-alerts).' } },
  blank('zalo'),
  blank('zalo-personal'),
  { type: 'email', configured: true, enabled: true, fields: { host: 'smtp.acme.example', port: '587', security: 'starttls', username: 'alerts@acme.example', from: 'alerts@acme.example', to: 'it@acme.example, director@acme.example' }, secret: 'MatKhauMau-m3Tz', min_severity: 'high', approvals: true, approvers: [{ user_id: 'u-admin', address: 'admin@acme.example' }], last_test: { at: daysAgo(6), ok: true, detail: 'Test email sent to it@acme.example, director@acme.example.' } },
  blank('webhook'),
], () => CHANNEL_TYPES.map(blank))
const rules = collection<{ quiet: Quiet; grouping: Grouping }>('notify_rules', () => ({
  quiet: { enabled: true, from: '22:00', to: '06:30', allow_critical: true },
  grouping: { enabled: true, window_min: 60 },
}))

// Vulnerability notices (D-52): messages about a finding. They are not incidents; the finding page shows them (slot finding.panels) and Settings, Alert channels, History lists them.
interface Notice { id: string; finding_ids: string[]; cves: string[]; product: string; created_at: string; sends: SendRecord[] }
const s = (id: string, channel: ChannelType, to: string, at: string, ok = true, error?: string): SendRecord => ({ id, channel, to, at, ok, error })
const plus = (iso: string, sec: number) => new Date(new Date(iso).getTime() + sec * 1000).toISOString()
const notices = collection<Notice[]>('notify_alerts', () => {
  const t1 = daysAgo(0, 4), t2 = daysAgo(3), t3 = daysAgo(24)
  return [
    { id: 'al-1', finding_ids: ['f-1'], cves: ['CVE-2022-27593'], product: 'QNAP Photo Station', created_at: t1,
      sends: [s('sd-1', 'telegram', 'chat -1002145678901', plus(t1, 40)), s('sd-2', 'email', 'it@acme.example, director@acme.example', plus(t1, 45))] },
    { id: 'al-2', finding_ids: ['f-2'], cves: ['CVE-2026-119977'], product: 'WordPress', created_at: t2,
      sends: [s('sd-3', 'telegram', 'chat -1002145678901', plus(t2, 38)), s('sd-4', 'email', 'it@acme.example, director@acme.example', plus(t2, 41), false, 'The SMTP server rejected the login (code 535). Check the SMTP username and password in Settings, Alert channels.')] },
    { id: 'al-3', finding_ids: ['f-3'], cves: ['CVE-2026-96951'], product: 'Microsoft Windows Server', created_at: t3,
      sends: [s('sd-5', 'telegram', 'chat -1002145678901', plus(t3, 36)), s('sd-6', 'email', 'it@acme.example, director@acme.example', plus(t3, 39))] },
  ]
}, () => [])
// Approval requests sent to chat (module response): listed in the history only.
const approvalSends = collection<{ id: string; at: string; send: SendRecord; what: string }[]>('notify_approval_sends', () => {
  const t = daysAgo(1, 2)
  return [{ id: 'ap-1', at: t, what: 'Approval request: block 185.220.101.47 on the firewall', send: s('sd-12', 'slack', '#it-alerts', t) }]
}, () => [])

interface StoredIncident extends Omit<Incident, 'devices'> { asset_ids: string[] }
const incidents = collection<StoredIncident[]>('notify_incidents', () => {
  const p = (iso: string, h: number) => new Date(new Date(iso).getTime() + h * 36e5).toISOString()
  const t4 = daysAgo(1, 1), t5 = daysAgo(4), t6 = daysAgo(0, 0.2), t7 = daysAgo(0, 1), t8 = daysAgo(2)
  return [
    { id: 'al-4', kind: 'trap', attempt: false, link: '/honeypot/hits/hit-seed-1', title: 'PC-HR-01 touched the SMB trap on FILESRV-OLD', asset_ids: ['a-pc07'], severity: 'critical', status: 'new', first_seen: t4, last_seen: p(t4, 0.4), count: 3,
      what: 'PC-HR-01 (192.168.10.107) opened an SMB connection to the trap machine FILESRV-OLD (192.168.10.240) 3 times. Nobody uses this trap, so it usually means the machine is infected or someone is probing the network.',
      action: 'Take the machine off the network (unplug the cable, turn off Wi-Fi), then ask its user what they were doing. Do not change passwords from that machine.',
      sends: [s('sd-7', 'telegram', 'chat -1002145678901', plus(t4, 5))], handled_by: null, handled_at: null, note: null },
    { id: 'al-5', kind: 'trap', attempt: false, link: '/honeypot/hits/hit-seed-2', title: '192.168.10.157 touched the RDP trap on FILESRV-OLD', asset_ids: ['a-unk01'], severity: 'critical', status: 'resolved', first_seen: t5, last_seen: t5, count: 1,
      what: 'Unknown device 192.168.10.157 (not in the inventory) tried to sign in over Remote Desktop to the trap machine FILESRV-OLD (192.168.10.240).',
      action: 'Take the device off the network, then find out who brought it into the company.',
      sends: [s('sd-8', 'telegram', 'chat -1002145678901', plus(t5, 5)), s('sd-9', 'email', 'it@acme.example, director@acme.example', plus(t5, 9))], handled_by: 'it@acme.example', handled_at: daysAgo(3), note: "A visitor's phone joined the internal network by mistake. Guest Wi-Fi password changed." },
    { id: 'al-6', kind: 'bad_address', attempt: false, link: '/logs', title: 'PC-SALES-02 connected to 185.220.101.47, a known-bad address', asset_ids: ['a-pc05'], severity: 'high', status: 'new', first_seen: p(t6, -23), last_seen: t6, count: 14,
      what: 'PC-SALES-02 (192.168.10.105) connected 14 times in 24 hours to 185.220.101.47, a Tor exit node on the malicious address list (Tor exit list, IPsum). This is usually unknown software on that machine calling out.',
      action: 'Open the logs to see whether that machine is still connecting, then run an antivirus scan on it. If you cannot explain it, take the machine off the network.',
      sends: [s('sd-10', 'telegram', 'chat -1002145678901', plus(t6, 20)), s('sd-11', 'email', 'it@acme.example, director@acme.example', plus(t6, 24), false, 'The SMTP server rejected the login (code 535). Check the SMTP username and password in Settings, Alert channels.')], handled_by: null, handled_at: null, note: null },
    { id: 'in-7', kind: 'log_anomaly', attempt: false, link: '/logs', title: 'WEB01 logged far more failed sign-ins than usual', asset_ids: ['a-web01'], severity: 'medium', status: 'new', first_seen: t7, last_seen: p(t7, 0.8), count: 1,
      what: 'WEB01 wrote 1,240 failed sign-in lines in 10 minutes. On a normal day it writes fewer than 20. Someone may be guessing passwords.',
      action: 'Open the logs for WEB01 and check the source addresses. If they are not yours, block them and change the passwords of the accounts that were tried.',
      sends: [s('sd-13', 'slack', '#it-alerts', plus(t7, 12))], handled_by: null, handled_at: null, note: null },
    { id: 'in-8', kind: 'unknown_device', attempt: false, link: '/devices/a-unk01', title: 'A new unknown device appeared: 192.168.10.157', asset_ids: ['a-unk01'], severity: 'medium', status: 'acknowledged', first_seen: t8, last_seen: t8, count: 1,
      what: 'A device that is not in your inventory joined the network at 192.168.10.157.',
      action: 'Find out whose device it is. Add it to the inventory if it belongs to you, otherwise remove it from the network.',
      sends: [s('sd-14', 'telegram', 'chat -1002145678901', plus(t8, 6))], handled_by: 'it@acme.example', handled_at: daysAgo(1, 5), note: 'Asking the office manager.' },
  ]
}, () => [])

const withDevices = (a: StoredIncident): Incident => {
  const { asset_ids, ...rest } = a
  return { ...rest, devices: asset_ids.map((id) => { const x = assetsStore.get().find((y) => y.id === id); return { id, name: x ? (x.hostname ?? x.ip) : id } }) }
}

function compose(a: Incident, type: ChannelType): Preview {
  const { what, action } = a
  const dev = a.devices.map((d) => { const x = assetsStore.get().find((y) => y.id === d.id); return x ? `${d.name} (${x.ip})` : d.name }).join(', ')
  const link = `https://${boxInfo().ip ?? '<VEDETTE_BOX_IP>'}/incidents/${a.id}`
  const head = `${SEV[a.severity]}: ${a.title}`
  const lines = [head, `Device: ${dev}`, what, `What to do first: ${action}`, `Details: ${link}`]
  if (type === 'email') return { channel: type, subject: `[Vedette] ${head}`, text: ['Hello,', '', ...lines.slice(1), '', 'This email was sent automatically by Vedette on your company box.'].join('\n') }
  if (type === 'webhook') return { channel: type, text: JSON.stringify({ event: 'incident.created', kind: a.kind, id: a.id, severity: a.severity, title: a.title, devices: a.devices, what, action, url: link }, null, 2) }
  if (type === 'slack') return { channel: type, text: [`*${head}*`, ...lines.slice(1, -1), `<${link}|Open in Vedette>`].join('\n') }
  return { channel: type, text: lines.join('\n') }
}
const detail = (a: StoredIncident): IncidentDetail => {
  const pub = withDevices(a)
  const types = [...new Set(a.sends.map((x) => x.channel))]
  return { incident: pub, previews: types.map((t) => compose(pub, t)) }
}

const kevData = kev as { generated_at: string; vulns: { cve: string; date_added: string }[] }
function suppressed(all: Notice[]) {
  // New vulnerabilities in the last 7 days of KEV data with no notice match none of your devices, so nothing was sent.
  const since = new Date(kevData.generated_at).getTime() - 7 * 864e5
  const sent = new Set(all.flatMap((a) => a.cves))
  return { count: kevData.vulns.filter((v) => new Date(`${v.date_added}T23:59:59Z`).getTime() >= since && !sent.has(v.cve)).length, days: 7 }
}
function history(): HistoryItem[] {
  const inc = incidents.get().flatMap((i) => i.sends.map((x): HistoryItem => ({ ...x, kind: 'incident', what: i.title, link: `/incidents/${i.id}` })))
  const vul = notices.get().flatMap((n) => n.sends.map((x): HistoryItem => ({ ...x, kind: 'vuln', what: `${n.product} is being exploited (${n.cves.join(', ')})`, link: `/findings/${n.finding_ids[0]}` })))
  const apr = approvalSends.get().map((x): HistoryItem => ({ ...x.send, kind: 'approval', what: x.what, link: '/response' }))
  return [...inc, ...vul, ...apr].sort((a, b) => b.at.localeCompare(a.at))
}

const last4 = (v?: string) => (v ? v.slice(-4) : null)
const shownUrl = (u?: string) => { try { const x = new URL(u ?? ''); return `${x.protocol}//${x.host}/…${(u as string).slice(-4)}` } catch { return '' } }
const pub = (c: StoredChannel): Channel => { const { secret, url, app_token, bot_token, approvals, approvers, ...r } = c; return { ...r, fields: c.type === 'webhook' && url ? { url: shownUrl(url) } : r.fields, secret_last4: last4(secret), approvals: approvals === true, approvers: approvers ?? [], approval_last4: { app_token: last4(app_token), bot_token: last4(bot_token) } } }
const HM = /^([01]\d|2[0-3]):[0-5]\d$/

// Quy tắc kênh (đối chiếu 2026-11): Telegram Bot API (token <số bot>:<chuỗi>; chat_id số, nhóm/kênh siêu nhóm bắt đầu -100, kênh công khai @tên);
// SMTP: 465 = TLS ngầm (SSL/TLS), 587 = STARTTLS; Zalo OA API: gửi tin tới user_id của người đã quan tâm hoặc nhắn OA, kèm OA access token.
const ADDRESS: Record<string, { re: RegExp; msg: string }> = {
  slack: { re: /^[UW][A-Z0-9]{8,12}$/, msg: 'A Slack member ID looks like U04ABCD1234 (Profile, More, Copy member ID).' },
  telegram: { re: /^\d{5,15}$/, msg: 'A Telegram user ID is a number of 5 to 15 digits. A bot such as @userinfobot can show it.' },
  email: { re: EMAIL_RE, msg: 'An approver email is not valid, for example name@company.com.' },
  // D-242: the user ID, never a phone number (a reply carries the user ID, so a phone number would never match).
  'zalo-personal': { re: /^(?!(?:\+?84\d{9}|0\d{9})$)\d{6,25}$/, msg: "Enter the approver's Zalo user ID, not a phone number: a reply in Zalo carries the sender's user ID, never the phone number, so a phone number would never match. The user ID is the long number of the Zalo account, for example 2938475610293847561." },
}
function checkApprovers(type: ChannelType, b: Partial<ChannelInput>) {
  if (b.approvals !== true) return null
  const rule = ADDRESS[type]
  if (!rule) return fail(400, 'approvals_unsupported', 'This channel cannot take approvals. It sends a link that opens Vedette instead.')
  const list = b.approvers ?? []
  if (!list.length) return fail(400, 'approvers_required', 'Add at least one approver, or turn off "Approve actions from this channel".')
  // S-NOT-1 (review of #172, L1): approvals need the numeric chat; a public @name is fine for alerts only.
  if (type === 'telegram' && !/^-?\d{5,20}$/.test((b.fields?.chat_id ?? '').trim())) return fail(400, 'bad_chat_id', 'To approve actions in Telegram, Chat ID must be the number of the chat (groups look like -1001234567890), not a public @channel_name: anyone can join a public channel, and a name that is given up can be taken by someone else.')
  const seen = new Set<string>()
  const addrs = new Map<string, string>() // address → email of the user it belongs to (D-242: one address is one approver)
  for (const a of list) {
    const u = usersStore.get().find((x) => x.id === a.user_id && !x.disabled)
    if (!u) return fail(400, 'no_such_user', 'One of the approvers does not exist or is disabled.')
    if (u.role === 'viewer') return fail(400, 'viewer_not_allowed', `${u.email} is a viewer. Only operators and administrators can approve actions.`)
    if (seen.has(u.id)) return fail(400, 'duplicate_user', `${u.email} is listed twice.`)
    seen.add(u.id)
    const addr = (a.address ?? '').trim()
    if (!rule.re.test(addr)) return fail(400, 'bad_approver_address', `${u.email}: ${rule.msg}`)
    const key = type === 'email' ? addr.toLowerCase() : addr
    const other = addrs.get(key)
    if (other) return fail(400, 'duplicate_address', `${u.email}: ${addr} is already the address of ${other}. One address can belong to one approver only.`)
    addrs.set(key, u.email)
  }
  return null
}

/** The URL a save means: an empty one, or the masked one the API showed, keeps the saved URL. The mock keeps the URL in clear, so it
 * never answers the box's 400 `url_unreadable` (a sealed URL that cannot be opened, channels.go SaveChannel). */
const webhookUrl = (f: Record<string, string>, cur: StoredChannel) => {
  const given = (f.url ?? '').trim()
  return given && given !== shownUrl(cur.url) ? given : cur.url ?? ''
}

/** The box's rule for a webhook or an SMTP server (channel/webhook.go ownAddr, forbiddenAddr; D-446): never Vedette itself (loopback: in a
 * container that is core itself), link-local (cloud metadata), multicast or unspecified. The mock knows none of the machine's addresses. */
/** The recipient named in `bad_to` (smtp.go badRecipient): one line, control and format characters dropped, cut to 60 characters. */
const shownRecipient = (x: string) => {
  const r = [...x.replace(/[\t\n\u0085\u2028\u2029]/g, ' ').replace(/[\p{Cc}\p{Cf}]/gu, '').trim()]
  return r.length > 60 ? `${r.slice(0, 59).join('')}…` : r.join('')
}

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const BAD_KEY = 'This is not a service account key file from Google Cloud. In the Google Cloud console open IAM & Admin, Service accounts, the account, Keys, Add key, JSON, and choose the downloaded file.'
/** The box's reading of a Google service account key file (smtpauth.go parseGoogleKey), minus the RSA parse: the mock cannot read the key itself. */
const googleKeyOk = (raw: string) => {
  if (raw.length > 16384) return false
  try {
    const k = JSON.parse(raw) as Record<string, unknown>
    return k.type === 'service_account' && typeof k.client_email === 'string' && EMAIL_RE.test(k.client_email) && typeof k.private_key === 'string' && /^-----BEGIN (RSA )?PRIVATE KEY-----/.test(k.private_key)
  } catch { return false }
}
const SECRET_NAME: Record<string, string> = { password: 'Enter the password or API key', token_as_user: 'Enter the server API token', microsoft_oauth: 'Enter the client secret', google_oauth: 'Choose the service account key', microsoft_user: 'Sign in with Microsoft', google_user: 'Sign in with Google' }
// eslint-disable-next-line no-control-regex
const ONE_LINE = /^[^\u0000-\u001f\u007f]+$/

const GOOGLE_CLIENT_RE = /^[0-9]{6,30}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com$/
const TENANT_OK = (t: string) => ['organizations', 'common', 'consumers'].includes(t) || GUID_RE.test(t) || DOMAIN_RE.test(t)
/** The tenant and client checks of a user sign-in (smtpsignin.go StartMicrosoftDevice, StartGoogleConsent; smtp.go NewEmail). */
function signinFieldError(provider: string, tenant: string, client: string) {
  if (provider === 'microsoft365-user' && !TENANT_OK(tenant.trim())) return fail(400, 'bad_tenant_id', 'The tenant ID is the Directory (tenant) ID of the app registration, a domain such as company.onmicrosoft.com, organizations, or consumers for Outlook.com.')
  if (provider !== 'gmail-oauth' && !GUID_RE.test(client.trim())) return fail(400, 'bad_client_id', 'The client ID is the Application (client) ID of the app registration, for example 0a1b2c3d-4e5f-6789-abcd-ef0123456789.')
  if (provider === 'gmail-oauth' && !GOOGLE_CLIENT_RE.test(client.trim())) return fail(400, 'bad_client_id', 'The client ID of a Google OAuth client ends with .apps.googleusercontent.com. Copy it from Google Auth Platform, Clients.')
  return null
}

// D-480 user sign-ins: in the mock, a device sign-in finishes at the second check; a Google one when a fitting address is pasted.
interface MockSignin extends EmailSignin { by: string; client: string; tenant: string; checks: number; state?: string; redirect?: string }
const signins = new Map<string, MockSignin>()
const SIGNED_IN_AS = 'alerts@acme.example'
const publicSignin = ({ by: _b, client: _c, tenant: _t, checks: _k, state: _s, redirect: _r, ...v }: MockSignin): EmailSignin => v

/** The box's reading of the pasted address (smtpsignin.go pastedCode): loopback at this sign-in's port, its state, then code. */
function pastedCode(si: MockSignin, pasted: string) {
  const notOurs = fail(400, 'bad_url', `Paste the whole address your browser shows after you approved, starting with ${si.redirect}/?`)
  let u: URL
  try { u = new URL(pasted.trim()) } catch { return { err: notOurs } }
  if (pasted.length > 4096 || u.protocol !== 'http:' || u.username || !['127.0.0.1', 'localhost'].includes(u.hostname) || `http://127.0.0.1:${u.port}` !== si.redirect || !['', '/'].includes(u.pathname)) return { err: notOurs }
  if (u.searchParams.get('state') !== si.state) return { err: fail(400, 'bad_state', 'This address belongs to another sign-in. Press Sign in with Google again and paste the address of that sign-in.') }
  if (u.searchParams.get('error')) return { declined: true }
  if (!/^[\x21-\x7e]{1,2048}$/.test(u.searchParams.get('code') ?? '')) return { err: fail(400, 'bad_url', 'The address has no sign-in code. Paste the whole address from the browser after you approved.') }
  return {}
}

/** The email checks of the box in its order (channels.go emailFields, newSender, then channel/smtp.go NewEmail; D-449 presets). */
function validateEmail(f: Record<string, string>, secret: string, cur: StoredChannel) {
  const prov = emailProvider(f.provider)
  if (!prov) return fail(400, 'bad_provider', 'Choose an email provider from the list, or Custom SMTP.')
  // a saved secret goes only where it was saved for (D-449 review): another method, server or port needs it again
  const rebind = !secret && !!cur.secret && savedFor(cur.fields) !== emailBinding(f)
  const needSecret = (msg: string) => fail(400, 'secret_required', rebind ? `${SECRET_NAME[prov.auth]} again: the sign-in method, the server or the port changed, and a saved secret is only sent where it was saved for.` : msg)
  // SaveChannel reads the port and the recipients before the adapter checks the rest (channels.go newSender).
  const portText = (f.port ?? '').trim()
  if (!/^[+-]?\d+$/.test(portText)) return fail(400, 'bad_port', 'The SMTP port is a number from 1 to 65535 (usually 587 or 465).')
  const to = (f.to ?? '').split(/[,;]/).map((x) => x.trim()).filter(Boolean)
  if (!to.length || to.length > 20) return fail(400, 'bad_to', 'Enter between 1 and 20 recipient emails, separated by commas.')
  const badTo = to.find((x) => !EMAIL_RE.test(x))
  const named = badTo === undefined ? '' : shownRecipient(badTo)
  if (badTo !== undefined) return fail(400, 'bad_to', named ? `${named} is not a valid email address. Separate several recipients with commas.` : 'A recipient email is not valid. Separate several recipients with commas.')
  const host = (f.host ?? '').trim()
  if (!(IPV4_RE.test(host) || DOMAIN_RE.test(host))) return fail(400, 'bad_host', 'The SMTP server must be a domain name or an IP address, for example smtp.company.com.')
  const port = Number(portText)
  if (port < 1 || port > 65535) return fail(400, 'bad_port', 'The SMTP port is a number from 1 to 65535 (usually 587 or 465).')
  if (ownHost(host)) return fail(400, 'bad_host', OWN_TEXT) // D-446
  if (forbiddenHost(host)) return fail(400, 'bad_host', 'The SMTP server cannot be a link-local or multicast address, a cloud metadata service, or an unspecified address.')
  if (!['starttls', 'ssl', 'none'].includes(f.security ?? '')) return fail(400, 'bad_security', 'Choose an encryption type: STARTTLS, SSL/TLS or none.')
  if (f.security === 'ssl' && port === 587) return fail(400, 'port_mismatch', 'Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS.')
  if (f.security === 'starttls' && port === 465) return fail(400, 'port_mismatch', 'Port 465 uses SSL/TLS, not STARTTLS. Choose SSL/TLS, or change the port to 587 for STARTTLS.')
  const has = !!secret || (!!cur.secret && !rebind)
  const pinned = OAUTH_HOST[prov.id]
  if (f.security === 'none') {
    if (prov.auth !== 'password') return fail(400, 'bad_security', 'This provider signs in, so the connection must be encrypted. Choose STARTTLS or SSL/TLS.')
    // the adapter's insecure_smtp, which the API answers as bad_security (channels.go apiConfigCode); no login without encryption
    if (!isInternalHost(host)) return fail(400, 'bad_security', 'Unencrypted SMTP is only allowed for a server on your internal network. Choose STARTTLS or SSL/TLS.')
  } else if (isUserSignin(prov.auth)) {
    if (pinned && host.toLowerCase().replace(/\.$/, '') !== pinned) return fail(400, 'bad_host', `This sign-in sends its token only to ${pinned}. Enter ${pinned} as the SMTP server.`)
    if (!EMAIL_RE.test((f.username ?? '').trim())) return fail(400, 'bad_username', 'Sign in first: the mailbox is the account that signs in.')
    const bad = signinFieldError(prov.id, f.tenant_id ?? '', f.client_id ?? ''); if (bad) return bad
    if (!has) return needSecret(prov.auth === 'google_user' ? 'Sign in with Google first.' : 'Sign in with Microsoft first.')
  } else if (isOAuth(prov.auth)) {
    if (pinned && host.toLowerCase().replace(/\.$/, '') !== pinned) return fail(400, 'bad_host', `This sign-in sends its token only to ${pinned}. Enter ${pinned} as the SMTP server.`)
    if (!EMAIL_RE.test((f.username ?? '').trim())) return fail(400, 'bad_username', 'Enter the mailbox Vedette sends as, for example alerts@company.com.')
    if (prov.auth === 'microsoft_oauth') {
      const tenant = (f.tenant_id ?? '').trim()
      if (!GUID_RE.test(tenant) && !DOMAIN_RE.test(tenant)) return fail(400, 'bad_tenant_id', 'The tenant ID is the Directory (tenant) ID of the app registration, for example 72f988bf-86f1-41af-91ab-2d7cd011db47, or your domain such as company.onmicrosoft.com.')
      if (!GUID_RE.test((f.client_id ?? '').trim())) return fail(400, 'bad_client_id', 'The client ID is the Application (client) ID of the app registration, for example 0a1b2c3d-4e5f-6789-abcd-ef0123456789.')
      if (!has) return needSecret('Enter the client secret of the app registration.')
      if (secret && (secret.length > 256 || !ONE_LINE.test(secret))) return fail(400, 'bad_secret', 'The client secret is the Value of a secret under Certificates & secrets of the app registration (not its Secret ID). Copy it again.')
    } else {
      if (!has) return needSecret('Choose the JSON key file of the service account.')
      if (secret && !googleKeyOk(secret)) return fail(400, 'bad_secret', BAD_KEY)
    }
  } else {
    if (prov.auth !== 'token_as_user' && (!f.username?.trim() || !ONE_LINE.test(f.username))) return fail(400, 'bad_username', 'Enter the SMTP username (usually the email address).')
    if (!has) return needSecret('Enter the SMTP password. This channel has no saved key yet.')
    if (secret && (secret.length > 1024 || !ONE_LINE.test(secret))) return fail(400, 'bad_secret', prov.auth === 'token_as_user' ? "The server API token is one line of letters, digits and dashes. Copy it again from the server's API Tokens tab in Postmark." : 'The password has a control character (such as a line break) or is too long. Copy it again.')
  }
  if (!EMAIL_RE.test((f.from ?? '').trim())) return fail(400, 'bad_from', 'The sender email is not valid, for example alerts@company.com.')
  return null
}

function validate(type: ChannelType, b: Partial<ChannelInput>, cur: StoredChannel) {
  const f = b.fields ?? {}
  const secret = (b.secret ?? '').trim()
  const need = (label: string) => (!cur.secret && !secret ? fail(400, 'secret_required', `Enter the ${label}. This channel has no saved key yet.`) : null)
  if (!ROUTE_SEVERITIES.includes(b.min_severity as never)) return fail(400, 'bad_severity', 'Choose a minimum severity: Critical, High, Medium or Low.')
  const badApprovers = checkApprovers(type, b); if (badApprovers) return badApprovers
  // Each type checks in the order of its adapter (modules/notify/channel/*.go, then SaveChannel), so one input gets the same code from both.
  if (type === 'telegram') {
    const bad = need('bot token'); if (bad) return bad
    if (secret && !/^\d{6,12}:[A-Za-z0-9_-]{30,}$/.test(secret)) return fail(400, 'bad_token', 'A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces.')
    if (!/^(-?\d{5,20}|@[A-Za-z0-9_]{5,32})$/.test((f.chat_id ?? '').trim())) return fail(400, 'bad_chat_id', 'Chat ID is a number (groups look like -1001234567890) or a public @channel_name. Send the bot a message, then open getUpdates to see the number.')
    return null
  }
  if (type === 'slack') {
    let u: URL | null = null
    try { u = new URL(secret) } catch { /* không phải URL */ }
    if (!cur.secret && !secret) return fail(400, 'secret_required', 'Enter the Incoming Webhook URL.')
    if (secret && (!u || u.protocol !== 'https:' || u.hostname !== 'hooks.slack.com' || !u.pathname.startsWith('/services/'))) return fail(400, 'bad_webhook', 'A Slack Incoming Webhook URL starts with https://hooks.slack.com/services/. Copy it again from your Slack app.')
    if ((f.label ?? '').trim().length > 80) return fail(400, 'bad_label', 'The channel label can be at most 80 characters.')
    const app = (b.app_token ?? '').trim(), bot = (b.bot_token ?? '').trim()
    if (app && !/^xapp-[\w-]{10,}$/.test(app)) return fail(400, 'bad_app_token', 'The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information.')
    if (bot && !/^xoxb-[\w-]{10,}$/.test(bot)) return fail(400, 'bad_bot_token', 'The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app.')
    if (b.approvals === true) {
      if (!/^[CGD][A-Z0-9]{8,12}$/.test((f.channel_id ?? '').trim())) return fail(400, 'bad_channel_id', 'A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom.')
      if (!app && !cur.app_token) return fail(400, 'secret_required', 'Enter the app-level token (xapp-…). Approving in Slack needs Socket Mode.')
      if (!bot && !cur.bot_token) return fail(400, 'secret_required', 'Enter the bot token (xoxb-…). Approving in Slack needs it to read button presses and reply.')
    }
    return null
  }
  if (type === 'zalo') {
    if (!/^\d{6,20}$/.test((f.oa_id ?? '').trim())) return fail(400, 'bad_oa_id', 'OA ID is a string of digits, shown in the Official Account management page.')
    if (!/^\d{6,25}$/.test((f.user_id ?? '').trim())) return fail(400, 'bad_user_id', 'The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA.')
    const bad = need('access token'); if (bad) return bad
    if (secret && secret.length < 20) return fail(400, 'bad_token', 'The Zalo access token is too short. Copy the whole string from Zalo Developers.')
    return null
  }
  if (type === 'zalo-personal') {
    if (b.zalo_login === true && zaloSignedIn() === null) return fail(400, 'login_required', 'The Zalo sign-in has ended. Sign in with a new QR code, then save.')
    if (!/^\d{6,25}$/.test((f.user_id ?? '').trim())) return fail(400, 'bad_user_id', 'The recipient is the numeric Zalo ID of a user or a group (6 to 25 digits).')
    return !cur.secret && !secret && b.zalo_login !== true ? fail(400, 'secret_required', 'Scan the QR code with the Zalo app first. This channel has no saved session yet.') : null
  }
  if (type === 'email') return validateEmail(f, secret, cur)
  let u: URL | null = null
  try { u = new URL(webhookUrl(f, cur)) } catch { /* không phải URL */ }
  if (!u || !/^https?:$/.test(u.protocol)) return fail(400, 'bad_url', 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.')
  // The API answers the adapter's blocked_host and insecure_url as bad_url (channels.go apiConfigCode); blocked_host comes first (webhook.go).
  if (ownHost(u.hostname)) return fail(400, 'bad_url', OWN_TEXT) // D-446
  if (forbiddenHost(u.hostname)) return fail(400, 'bad_url', 'The webhook cannot point at a link-local or multicast address, a cloud metadata service, or an unspecified address.')
  if (u.protocol === 'http:' && !isInternalHost(u.hostname)) return fail(400, 'bad_url', 'Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.')
  if (secret && secret.length < 16) return fail(400, 'bad_secret', 'The signing key needs at least 16 characters. Press Generate random if you want a random one.')
  return need('webhook signing key')
}

/** Mô phỏng một lần gửi: host đuôi .invalid/.test không tới được; token Telegram/Zalo chứa "invalid" bị từ chối. Các trường hợp còn lại thành công. */
function deliver(c: StoredChannel): { ok: boolean; detail: string } {
  const host = c.type === 'email' ? c.fields.host ?? '' : c.type === 'webhook' ? (() => { try { return new URL(c.url ?? '').hostname } catch { return '' } })() : ''
  if (/\.(invalid|test)$/.test(host)) return { ok: false, detail: `Could not connect to ${host}. Check the host name, the port and any firewall between the box and that machine.` }
  if ((c.type === 'telegram' || c.type === 'zalo') && /invalid/i.test(c.secret)) {
    return { ok: false, detail: c.type === 'telegram'
      ? 'Telegram returned 401 Unauthorized: the bot token is wrong or was revoked. Get a new token from @BotFather and save it.'
      : 'Zalo refused the message (code -220): the access token is invalid or expired (OA tokens last 25 hours). Get a new token in Zalo Developers and save it.' }
  }
  switch (c.type) {
    case 'zalo-personal': return { ok: true, detail: `Zalo personal sent the test message to ${c.fields.user_id}.` }
    case 'telegram': return { ok: true, detail: `Telegram received the test message (chat ${c.fields.chat_id}).` }
    case 'slack': return { ok: true, detail: `Slack accepted the test message${c.fields.label ? ` (${c.fields.label})` : ''}.` }
    case 'zalo': return { ok: true, detail: `Zalo OA ${c.fields.oa_id} sent the test message to recipient ${c.fields.user_id}.` }
    case 'email': return { ok: true, detail: `Test email sent to ${c.fields.to}.` }
    case 'webhook': return { ok: true, detail: 'The webhook returned HTTP 200.' }
  }
}
const destOf = (c: StoredChannel) => (c.type === 'telegram' ? `chat ${c.fields.chat_id}` : c.type === 'slack' ? (c.fields.label || 'Slack webhook') : c.type === 'zalo' ? `OA ${c.fields.oa_id}` : c.type === 'zalo-personal' ? `Zalo ${c.fields.user_id}` : c.type === 'email' ? (c.fields.to ?? '') : (c.url ? new URL(c.url).origin : ''))
const isType = (v: unknown): v is ChannelType => CHANNEL_TYPES.includes(v as ChannelType)

// Zalo personal set-up (D-447): the QR sign-in walks one state per poll (waiting → scanned → signed in), the contact list is fixed, and an
// approver is sent a confirm link (made by the response mock, kept in zaloMessages) and is linked once they confirm it signed in.
const ZALO_QR = { size: 29, path: 'M4 4h7v1h-7zM4 5h1v1h-1zM10 5h1v1h-1zM4 6h1v1h-1zM6 6h3v1h-3zM10 6h1v1h-1zM4 7h1v1h-1zM6 7h3v1h-3zM10 7h1v1h-1zM4 8h1v1h-1zM6 8h3v1h-3zM10 8h1v1h-1zM4 9h1v1h-1zM10 9h1v1h-1zM4 10h7v1h-7zM14 14h1v1h-1z' }
let zaloLogin: { owner: string; state: ZaloLogin['state']; polls: number } | null = null
const zaloCodes = new Map<string, { address: string; at: string; error: string }>()
const zaloMessages: { to: string; text: string }[] = []
/** The messages the box's Zalo account sent (tests read the confirm link from them). */
export const zaloMessagesForTest = () => zaloMessages
function sendZaloLink(a: Approver) {
  const made = newLinkToken(a.user_id, 'zalo-personal', a.address)
  if (!('token' in made)) { zaloCodes.set(a.user_id, { address: a.address, at: nowIso(), error: `No link was made: ${made.message}` }); return made }
  const who = usersStore.get().find((u) => u.id === a.user_id)?.name ?? a.user_id
  const link = `https://${boxInfo().ip ?? 'vedette.local'}/link/zalo?c=${encodeURIComponent(made.token)}`
  zaloMessages.push({ to: a.address, text: `Vedette: open this link and sign in to Vedette as ${who} to link this Zalo account to ${who}: ${link} It works once, within 10 minutes. If you are not ${who}, ignore this message.` })
  zaloCodes.set(a.user_id, { address: a.address, at: nowIso(), error: '' })
  audit('notify.zalo_link_code', 'zalo-personal', `a confirm link was sent to Zalo ${a.address}`)
  return made
}
const zaloSignedIn = () => (zaloLogin?.state === 'signed_in' && zaloLogin.owner === currentUser()?.id ? 'Vedette Box' : null)
const ZALO_GROUPS: ZaloContact[] = [{ id: '8000000001', name: 'IT team', group: true, members: 5 }, { id: '8000000002', name: 'Night shift', group: true, members: 12 }]
/** The uid of the mock's signed-in Zalo account (the box's own account): only your own row with it confirms without a message. */
export const ZALO_BOX_UID = '1000000000000000001'
const ZALO_FRIENDS: ZaloContact[] = [{ id: '3847561029384756102', name: 'Lan Pham', group: false, members: 0 }, { id: '2938475610293847561', name: 'Minh Tran', group: false, members: 0 }]
const zaloView = (): ZaloLogin => {
  const l = zaloLogin
  if (!l || l.owner !== currentUser()?.id) return { state: 'none', qr: null, name: '', error: '', expires_at: null }
  const live = l.state === 'waiting' || l.state === 'scanned'
  return { state: l.state, qr: live ? ZALO_QR : null, name: l.state === 'scanned' ? 'Vedette Alerts' : l.state === 'signed_in' ? 'Vedette Box' : '', error: '', expires_at: live ? new Date(Date.now() + 100_000).toISOString() : null }
}
const zaloSession = () => zaloSignedIn() !== null || !!channels.get().find((c) => c.type === 'zalo-personal' && c.configured && c.secret)
const NO_SESSION = () => fail(409, 'no_session', 'Sign in with the QR code first: finding groups and people needs the Zalo account.')
const BAD_QUERY = 'Enter a group invite link (https://zalo.me/g/…), a phone number such as 0912345678, or a Zalo ID.'
// Telegram approvers (D-414): the bot sends each a confirm link privately (made by the response mock, kept in tgMessages) and they are
// linked once they confirm it signed in, as on Zalo. The mock's bot may always write to the person; the real box, when it may not, posts a
// note without the link in the approval chat asking them to press Start, and answers send_failed.
const tgCodes = new Map<string, { address: string; at: string; error: string }>()
const tgMessages: { to: string; text: string }[] = []
/** The messages the Telegram bot sent (tests read the confirm link from them). */
export const telegramMessagesForTest = () => tgMessages
function sendTelegramLink(a: Approver) {
  const made = newLinkToken(a.user_id, 'telegram', a.address)
  if (!('token' in made)) { tgCodes.set(a.user_id, { address: a.address, at: nowIso(), error: `No link was made: ${made.message}` }); return made }
  const who = usersStore.get().find((u) => u.id === a.user_id)?.name ?? a.user_id
  const link = `https://${boxInfo().ip ?? 'vedette.local'}/link/telegram?c=${encodeURIComponent(made.token)}`
  tgMessages.push({ to: a.address, text: `Info: ${who}: open this link to link your Telegram account to Vedette.\nSign in to Vedette as ${who}, then press Confirm. It works once, within 10 minutes. If you are not ${who}, ignore this message.\nDetails: ${link}` })
  tgCodes.set(a.user_id, { address: a.address, at: nowIso(), error: '' })
  audit('notify.telegram_link_code', 'telegram', `a confirm link was sent to Telegram ${a.address} privately`)
  return made
}
const zaloApprover = (a: Approver) => linkApprover('zalo-personal', a)
function linkApprover(type: 'zalo-personal' | 'telegram', a: Approver): ZaloApprover {
  const rec = (type === 'telegram' ? tgCodes : zaloCodes).get(a.user_id)
  const base = { user_id: a.user_id, address: a.address, name: a.name ?? '', sent_at: rec?.address === a.address ? rec.at : null, error: '', self: a.user_id === currentUser()?.id, box_account: type === 'zalo-personal' && a.address === ZALO_BOX_UID }
  if (isLinked(a.user_id, type, a.address)) return { ...base, state: 'linked' }
  if (!rec || rec.address !== a.address) return { ...base, state: 'not_sent' }
  if (rec.error) return { ...base, state: 'not_sent', error: rec.error }
  return Date.now() - new Date(rec.at).getTime() < 600_000 ? { ...base, state: 'waiting' } : { ...base, state: 'not_sent', error: 'The link expired. Send a new one.' }
}

export const handlers = [
  http.post(`${API}/notify/zalo/login`, () => {
    const denied = guard('admin'); if (denied) return denied
    const me = currentUser()!.id
    if (zaloLogin && zaloLogin.owner !== me && zaloLogin.state !== 'expired' && zaloLogin.state !== 'declined' && zaloLogin.state !== 'failed') return fail(409, 'login_busy', 'Another administrator is signing in to Zalo now. Try again in a few minutes.')
    zaloLogin = { owner: me, state: 'waiting', polls: 0 }
    return HttpResponse.json(zaloView())
  }),

  http.get(`${API}/notify/zalo/login`, () => {
    const denied = guard('admin'); if (denied) return denied
    const l = zaloLogin
    if (l && l.owner === currentUser()!.id && (l.state === 'waiting' || l.state === 'scanned')) {
      l.polls++
      l.state = l.polls >= 2 ? 'signed_in' : 'scanned'
      if (l.state === 'signed_in') audit('notify.zalo_login', 'zalo-personal', 'QR sign-in: signed in as Vedette Box')
    }
    return HttpResponse.json(zaloView())
  }),

  http.delete(`${API}/notify/zalo/login`, () => {
    const denied = guard('admin'); if (denied) return denied
    if (zaloLogin?.owner === currentUser()!.id) zaloLogin = null
    return new HttpResponse(null, { status: 204 })
  }),

  // The box answers 409 no_session without a session; the page asks only once it has one (ZaloRecipient canLook), so the mock always
  // answers the demo list (the contract test reads every GET of the module).
  http.get(`${API}/notify/zalo/contacts`, () => {
    const denied = guard('admin'); if (denied) return denied
    return HttpResponse.json({ friends: ZALO_FRIENDS, groups: ZALO_GROUPS })
  }),

  http.post(`${API}/notify/zalo/resolve`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const q = String((await body<{ query: string }>(request)).query ?? '').trim()
    const link = /^(https?:\/\/)?zalo\.me\/g\/[A-Za-z0-9]{6,40}\/?$/i.test(q)
    const phone = /^(\+?84\d{9}|0\d{9})$/.test(q.replace(/[\s.-]/g, ''))
    if (!q || q.length > 200) return fail(400, 'bad_query', BAD_QUERY)
    if (!link && !phone && /^\d{6,25}$/.test(q)) return HttpResponse.json({ id: q, name: '', group: false, members: 0, member: true })
    if (!link && !phone) return fail(400, 'bad_query', BAD_QUERY)
    if (!zaloSession()) return NO_SESSION()
    if (link) return HttpResponse.json({ id: '8000000009', name: 'Support group', group: true, members: 7, member: false })
    if (q.endsWith('000')) return fail(404, 'not_found', "Nothing was found. Check the link or the number; a person can hide from search by phone number in Zalo's privacy settings.")
    return HttpResponse.json({ id: '4756102938475610293', name: 'Hoa Le', group: false, members: 0, member: true })
  }),

  http.get(`${API}/notify/zalo/approvers`, () => {
    const denied = guard('admin'); if (denied) return denied
    const c = channels.get().find((x) => x.type === 'zalo-personal')
    return HttpResponse.json({ items: (c?.approvers ?? []).map(zaloApprover) })
  }),

  http.post(`${API}/notify/zalo/approvers/:user_id/code`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const c = channels.get().find((x) => x.type === 'zalo-personal')
    if (!c?.configured || !c.enabled || !c.approvals) return fail(409, 'channel_not_ready', 'Save the Zalo (personal) channel turned on, with "Approve actions from this channel", first.')
    const a = (c.approvers ?? []).find((x) => x.user_id === params.user_id)
    if (!a) return fail(404, 'not_listed', 'This person is not an approver on the Zalo channel. Save the channel first.')
    if (a.user_id === currentUser()!.id && a.address === ZALO_BOX_UID) { // the box's own account: no message, confirm it now in this session
      const made = newLinkToken(a.user_id, 'zalo-personal', a.address)
      if (!('token' in made)) return fail(made.status, made.code, made.message)
      audit('notify.zalo_link_code', 'zalo-personal', `a confirm link was made for the administrator's own Zalo ${a.address} (no message sent)`)
      return HttpResponse.json({ ...zaloApprover(a), link: `/link/zalo?c=${encodeURIComponent(made.token)}` })
    }
    const made = sendZaloLink(a)
    if (!('token' in made)) return fail(made.status, made.code, made.message)
    return HttpResponse.json(zaloApprover(a))
  }),

  http.get(`${API}/notify/telegram/approvers`, () => {
    const denied = guard('admin'); if (denied) return denied
    const c = channels.get().find((x) => x.type === 'telegram')
    return HttpResponse.json({ items: (c?.approvers ?? []).map((a) => linkApprover('telegram', a)) })
  }),

  http.post(`${API}/notify/telegram/approvers/:user_id/code`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = telegramLinkFor(String(params.user_id))
    return 'status' in r ? fail(r.status, r.code, r.message) : HttpResponse.json(r)
  }),

  http.get(`${API}/notify/incidents`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ incidents: [...incidents.get()].sort((a, b) => b.last_seen.localeCompare(a.last_seen)).map(withDevices) })
  }),

  http.get(`${API}/notify/incidents/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const a = incidents.get().find((x) => x.id === params.id)
    if (!a) return fail(404, 'not_found', 'No such incident. It may have been removed.')
    return HttpResponse.json(detail(a))
  }),

  http.patch(`${API}/notify/incidents/:id`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const id = String(params.id)
    if (!incidents.get().some((x) => x.id === id)) return fail(404, 'not_found', 'No such incident.')
    const b = await body<{ status: IncidentStatus; note: string }>(request)
    if (!['new', 'acknowledged', 'resolved'].includes(String(b.status))) return fail(400, 'bad_status', 'Status must be new, acknowledged or resolved.')
    const note = (b.note ?? '').trim()
    if (note.length > 500) return fail(400, 'note_too_long', 'A note can be at most 500 characters.')
    const reopen = b.status === 'new'
    let out!: StoredIncident
    incidents.update((l) => l.map((x) => (x.id === id ? (out = { ...x, status: b.status!, handled_by: reopen ? null : (currentUser()?.email ?? null), handled_at: reopen ? null : nowIso(), note: reopen ? null : note || null }) : x)))
    audit('notify.incident_status', out.title, `${b.status}${note ? `: ${note}` : ''}`)
    return HttpResponse.json(detail(out))
  }),

  http.get(`${API}/notify/history`, () => {
    const denied = guard('admin'); if (denied) return denied
    return HttpResponse.json({ items: history(), suppressed: suppressed(notices.get()) })
  }),

  http.post(`${API}/notify/history/:id/resend`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const id = String(params.id)
    const old = history().find((x) => x.id === id)
    if (!old) return fail(404, 'not_found', 'No such message in the history.')
    const c = channels.get().find((x) => x.type === old.channel)
    if (!c || !c.configured || !c.enabled) return fail(409, 'channel_not_ready', 'This channel is not set up or is turned off. An administrator can turn it on in Settings, Alert channels.')
    const r = deliver(c)
    const rec: SendRecord = { id: newId('sd'), channel: c.type, to: destOf(c), at: nowIso(), ok: r.ok, error: r.ok ? undefined : r.detail }
    if (old.kind === 'incident') incidents.update((l) => l.map((x) => (x.sends.some((y) => y.id === id) ? { ...x, sends: [...x.sends, rec] } : x)))
    else if (old.kind === 'vuln') notices.update((l) => l.map((x) => (x.sends.some((y) => y.id === id) ? { ...x, sends: [...x.sends, rec] } : x)))
    else approvalSends.update((l) => [...l, { id: newId('ap'), at: rec.at, what: old.what, send: rec }])
    audit('notify.resend', old.what, c.type)
    return HttpResponse.json({ ...rec, kind: old.kind, what: old.what, link: old.link })
  }),

  http.get(`${API}/notify/findings/:id/notices`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const sends = notices.get().filter((n) => n.finding_ids.includes(String(params.id))).flatMap((n) => n.sends).sort((a, b) => a.at.localeCompare(b.at))
    return HttpResponse.json({ sends })
  }),

  http.get(`${API}/notify/alerts/:id/target`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const id = String(params.id)
    const n = notices.get().find((x) => x.id === id)
    if (n) return HttpResponse.json({ to: `/findings/${n.finding_ids[0]}` })
    if (incidents.get().some((x) => x.id === id)) return HttpResponse.json({ to: `/incidents/${id}` })
    return fail(404, 'not_found', 'No such alert. It may have been removed from the log.')
  }),

  http.get(`${API}/notify/channels`, () => {
    const denied = guard('admin'); if (denied) return denied
    const cur = channels.get()
    return HttpResponse.json({ channels: CHANNEL_TYPES.map((t) => pub(cur.find((c) => c.type === t) ?? blank(t))), ...rules.get(), email_code_users: emailCodeUserCount() })
  }),

  http.put(`${API}/notify/channels/:type`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const type = params.type
    if (!isType(type)) return fail(404, 'not_found', 'No such channel type.')
    const b = await body<ChannelInput>(request)
    const cur = channels.get().find((c) => c.type === type) ?? blank(type)
    if (type === 'email' && b.signin) { // D-480: the box takes the sign-in's refresh token and mailbox (channels.go takeSignin)
      const si = signins.get(b.signin)
      const f = b.fields ?? {}
      if (!si || si.by !== (currentUser()?.email ?? '') || si.status !== 'signed_in' || si.provider !== f.provider || si.client !== (f.client_id ?? '').trim() ||
        (si.provider === 'microsoft365-user' && si.tenant !== (f.tenant_id ?? '').trim())) return fail(400, 'secret_required', 'The sign-in is over or does not match these settings. Sign in again, then save.')
      b.secret = `{"refresh_token":"mock-${si.id}"}`
      b.fields = { ...f, username: si.mailbox!, ...(si.provider === 'outlook' ? { tenant_id: 'consumers' } : {}) }
      signins.delete(si.id)
    }
    const bad = validate(type, b, cur); if (bad) return bad
    const fields = Object.fromEntries(SAVED_FIELDS[type].filter((k) => !(type === 'slack' && k === 'channel_id' && b.approvals !== true)).map((k) => [k, String(b.fields?.[k] ?? '').trim()]))
    if (type === 'email') {
      fields.to = fields.to!.split(/[,;]/).map((x) => x.trim()).filter(Boolean).join(', ')
      // only the fields the provider uses (channels.go emailFields): tenant and client IDs are Microsoft 365's; Postmark's username is its token
      const auth = emailProvider(fields.provider)!.auth
      if (!fields.provider) delete fields.provider
      if (auth !== 'microsoft_oauth' && auth !== 'microsoft_user') delete fields.tenant_id
      if (!['microsoft_oauth', 'microsoft_user', 'google_user'].includes(auth)) delete fields.client_id
      if (auth === 'token_as_user') delete fields.username
    }
    const zalo = type === 'zalo-personal'
    if (zalo) {
      if (fields.group !== 'true') delete fields.group
      if (!fields.name) delete fields.name
      const account = b.zalo_login === true ? zaloSignedIn() : cur.fields.account
      if (account) fields.account = account
    }
    const secret = zalo && b.zalo_login === true ? 'zl-session-from-qr-sign-in' : (b.secret ?? '').trim()
    if (zalo && b.zalo_login === true) zaloLogin = null
    const approvals = b.approvals === true
    const approvers = approvals ? (b.approvers ?? []).map((a) => ({ user_id: a.user_id, address: a.address.trim(), ...(zalo && a.name ? { name: a.name } : {}) })) : []
    // email: the saved secret stays only for the method, server and port it was saved for; a save that needs none deletes it (D-449 review)
    const kept = type !== 'email' || savedFor(cur.fields) === emailBinding(fields) ? cur.secret : ''
    if (type === 'email' && (secret || kept)) fields.secret_for = emailBinding(fields)
    const byLink = zalo || type === 'telegram' // the confirm-link channels (D-447, D-414)
    const same = (a: Approver, x: Approver) => x.user_id === a.user_id && x.address === a.address
    const fresh = byLink ? approvers.filter((a) => !(cur.approvers ?? []).some((x) => same(a, x))) : []
    const gone = byLink ? (cur.approvers ?? []).filter((x) => !approvers.some((a) => same(a, x)) && isLinked(x.user_id, type, x.address)) : []
    const next: StoredChannel = { ...cur, configured: true, enabled: b.enabled === true, fields, secret: secret ? secret : kept, ...(type === 'webhook' ? { url: webhookUrl(b.fields ?? {}, cur) } : {}), min_severity: b.min_severity!, last_test: null, approvals, approvers,
      app_token: type === 'slack' ? (b.app_token?.trim() || cur.app_token) : undefined, bot_token: type === 'slack' ? (b.bot_token?.trim() || cur.bot_token) : undefined }
    channels.update((l) => [...l.filter((c) => c.type !== type), next])
    // your own row with the box's own account confirms in your session; every other Zalo, yours too, gets the link by message
    for (const g of gone) { // a linked approver removed or given another ID: the old proof ends, so naming it again needs a new confirm
      identityStore.update((l) => l.filter((x) => !(x.channel === type && same(g, x))))
      const who = usersStore.get().find((u) => u.id === g.user_id)?.email ?? g.user_id
      audit(zalo ? 'notify.zalo_unlink' : 'notify.telegram_unlink', type, `${who}: ${zalo ? 'Zalo' : 'Telegram'} ${g.address} is no longer their approver address; its link no longer counts`)
    }
    if (next.enabled && approvals && zalo) for (const a of fresh) if (!(a.user_id === currentUser()!.id && a.address === ZALO_BOX_UID)) sendZaloLink(a)
    if (next.enabled && approvals && type === 'telegram') for (const a of fresh) sendTelegramLink(a)
    audit('notify.channel_save', type, `${next.enabled ? 'on' : 'off'}${approvals ? `, approvals on (${approvers.length} approver${approvers.length === 1 ? '' : 's'})` : ''}`)
    return HttpResponse.json(pub(next))
  }),

  http.delete(`${API}/notify/channels/:type`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const type = params.type
    if (!isType(type)) return fail(404, 'not_found', 'No such channel type.')
    const gone = channels.get().find((c) => c.type === type)?.approvers ?? []
    channels.update((l) => [...l.filter((c) => c.type !== type), blank(type)])
    // the approvers' proofs end with the channel (D-447): a recreated channel does not show them linked
    identityStore.update((l) => l.filter((x) => !(x.channel === type && gone.some((a) => a.user_id === x.user_id && a.address === x.address))))
    audit('notify.channel_remove', type, 'configuration and saved key deleted')
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${API}/notify/channels/:type/test`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const type = params.type
    if (!isType(type)) return fail(404, 'not_found', 'No such channel type.')
    const c = channels.get().find((x) => x.type === type)
    if (!c?.configured) return fail(400, 'not_configured', 'This channel has no saved configuration. Enter and save it before sending a test.')
    const r = deliver(c)
    const result: TestResult = { at: nowIso(), ok: r.ok, detail: r.detail }
    channels.update((l) => l.map((x) => (x.type === type ? { ...x, last_test: result } : x)))
    audit('notify.channel_test', type, r.ok ? 'ok' : 'failed')
    return HttpResponse.json(result)
  }),

  http.post(`${API}/notify/email-signin`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ provider: string; tenant_id?: string; client_id: string; client_secret?: string }>(request)
    const provider = b.provider ?? '', client = (b.client_id ?? '').trim()
    if (!['microsoft365-user', 'outlook', 'gmail-oauth'].includes(provider)) return fail(400, 'bad_provider', 'Only Microsoft 365, Outlook.com and Gmail sign in this way.')
    const tenant = provider === 'outlook' ? 'consumers' : (b.tenant_id ?? '').trim()
    const bad = signinFieldError(provider, tenant, client); if (bad) return bad
    if (provider === 'gmail-oauth' && !(b.client_secret ?? '').trim()) return fail(400, 'bad_secret', 'Enter the client secret of the Desktop OAuth client (Google Auth Platform, Clients).')
    const id = newId('si')
    const base = { id, provider: provider as EmailSignin['provider'], status: 'waiting' as const, expires_at: new Date(Date.now() + 15 * 60_000).toISOString(), by: currentUser()?.email ?? '', client, tenant, checks: 0 }
    let si: MockSignin
    if (provider === 'gmail-oauth') {
      const state = 'S'.repeat(43), redirect = 'http://127.0.0.1:53121'
      si = { ...base, flow: 'paste', state, redirect, consent_url: `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({ client_id: base.client, redirect_uri: redirect, response_type: 'code', scope: 'https://mail.google.com/ openid email', state, code_challenge_method: 'S256' })}` }
    } else {
      si = { ...base, flow: 'device', user_code: 'WDJB-MJHT', verification_uri: 'https://microsoft.com/devicelogin', interval: 5 }
    }
    for (const [k, o] of signins) if (o.by === si.by) signins.delete(k)
    signins.set(id, si)
    return HttpResponse.json(publicSignin(si))
  }),

  http.post(`${API}/notify/email-signin/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const si = signins.get(String(params.id))
    if (!si || si.by !== (currentUser()?.email ?? '')) return fail(404, 'not_found', 'This sign-in is over or belongs to another administrator. Start the sign-in again.')
    if (si.status !== 'waiting') return HttpResponse.json(publicSignin(si))
    if (si.flow === 'device') {
      si.checks++
      if (si.checks >= 2) { si.status = 'signed_in'; si.mailbox = SIGNED_IN_AS }
      return HttpResponse.json(publicSignin(si))
    }
    const r = pastedCode(si, (await body<{ url?: string }>(request)).url ?? '')
    if (r.err) return r.err
    if (r.declined) si.status = 'declined'
    else { si.status = 'signed_in'; si.mailbox = SIGNED_IN_AS }
    return HttpResponse.json(publicSignin(si))
  }),

  http.put(`${API}/notify/rules`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ quiet: Quiet; grouping: Grouping }>(request)
    const q = b.quiet, g = b.grouping
    if (!q || !HM.test(q.from) || !HM.test(q.to)) return fail(400, 'bad_time', 'Enter quiet hours like 22:00.')
    if (q.enabled === true && q.from === q.to) return fail(400, 'bad_quiet', 'The start and end times must not be the same.')
    if (!g || ![15, 60, 240].includes(g.window_min)) return fail(400, 'bad_window', 'The grouping window must be 15, 60 or 240 minutes.')
    const next = { quiet: { enabled: q.enabled === true, from: q.from, to: q.to, allow_critical: q.allow_critical === true }, grouping: { enabled: g.enabled === true, window_min: g.window_min } }
    rules.set(next)
    audit('notify.rules_save', 'quiet hours and grouping')
    return HttpResponse.json(next)
  }),
]

type Refusal = { status: number; code: string; message: string }
/** Send again for a Telegram approver (the channel dialog, and My account through response, D-414). */
function telegramLinkFor(userId: string): ZaloApprover | Refusal {
  const c = channels.get().find((x) => x.type === 'telegram')
  if (!c?.configured || !c.enabled || !c.approvals) return { status: 409, code: 'channel_not_ready', message: 'Save the Telegram channel turned on, with "Approve actions from this channel", first.' }
  const a = (c.approvers ?? []).find((x) => x.user_id === userId)
  if (!a) return { status: 404, code: 'not_listed', message: 'This person is not an approver on the Telegram channel. Save the channel first.' }
  const made = sendTelegramLink(a)
  return 'token' in made ? linkApprover('telegram', a) : made
}
// My account, Send again (response's Config.LinkSender on the real box): the same sends as the channel dialog.
chatLinkSenders.telegram = (userId) => { const r = telegramLinkFor(userId); return 'status' in r ? r : {} }
chatLinkSenders['zalo-personal'] = (userId) => {
  const c = channels.get().find((x) => x.type === 'zalo-personal')
  if (!c?.configured || !c.enabled || !c.approvals) return { status: 409, code: 'channel_not_ready', message: 'Save the Zalo (personal) channel turned on, with "Approve actions from this channel", first.' }
  const a = (c.approvers ?? []).find((x) => x.user_id === userId)
  if (!a) return { status: 404, code: 'not_listed', message: 'This person is not an approver on the Zalo channel. Save the channel first.' }
  // your own row with the box's own account confirms in this session, for an administrator only (D-414 review: an operator never)
  if (a.address === ZALO_BOX_UID && usersStore.get().find((u) => u.id === userId)?.role === 'admin') {
    const made = newLinkToken(a.user_id, 'zalo-personal', a.address)
    return 'token' in made ? { link: `/link/zalo?c=${encodeURIComponent(made.token)}` } : made
  }
  const made = sendZaloLink(a)
  return 'token' in made ? {} : made
}
