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
import { CHANNEL_TYPES, FIELDS, ROUTE_SEVERITIES, forbiddenHost } from './types'
import type { Approver, Channel, ChannelInput, ChannelType, Grouping, HistoryItem, Incident, IncidentDetail, IncidentStatus, Preview, Quiet, SendRecord, TestResult } from './types'

const SEV: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

// approvals: module khác (response) đọc bằng peek('notify_channels'): mỗi kênh có approvals?: boolean và approvers?: {user_id, address}[]. Giữ nguyên hình dạng này (D-46).
interface StoredChannel extends Omit<Channel, 'secret_last4' | 'approvals' | 'approvers' | 'approval_last4'> { secret: string; url?: string; approvals?: boolean; approvers?: Approver[]; app_token?: string; bot_token?: string }
const blank = (type: ChannelType): StoredChannel => ({ type, configured: false, enabled: false, fields: {}, secret: '', min_severity: 'medium', last_test: null })
// The webhook URL is a bearer secret (SYS-4): the mock keeps it apart from `fields`, as the backend seals it, and shows only scheme://host/… and its last 4 characters.
const SAVED_FIELDS: Record<ChannelType, string[]> = { ...FIELDS, slack: ['label', 'channel_id'], webhook: [] }

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

/** The box's rule for a webhook or an SMTP server (channel/webhook.go forbiddenAddr): never this machine (loopback: in a container that is core
 * itself), link-local (cloud metadata), multicast or unspecified. The mock knows none of the box's own LAN addresses. */
/** The recipient named in `bad_to` (smtp.go badRecipient): one line, control and format characters dropped, cut to 60 characters. */
const shownRecipient = (x: string) => {
  const r = [...x.replace(/[\t\n\u0085\u2028\u2029]/g, ' ').replace(/[\p{Cc}\p{Cf}]/gu, '').trim()]
  return r.length > 60 ? `${r.slice(0, 59).join('')}…` : r.join('')
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
    if (!/^\d{6,25}$/.test((f.user_id ?? '').trim())) return fail(400, 'bad_user_id', 'The recipient is the numeric Zalo ID of a user or a group (6 to 25 digits).')
    return !cur.secret && !secret ? fail(400, 'secret_required', 'Scan the QR code with the Zalo app first. This channel has no saved session yet.') : null
  }
  if (type === 'email') {
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
    if (forbiddenHost(host)) return fail(400, 'bad_host', "The SMTP server cannot be this machine, a link-local or multicast address, a cloud metadata service, or an unspecified address. For a mail server on the computer that runs Vedette, enter that computer's LAN address.")
    const port = Number(portText)
    if (port < 1 || port > 65535) return fail(400, 'bad_port', 'The SMTP port is a number from 1 to 65535 (usually 587 or 465).')
    if (!['starttls', 'ssl', 'none'].includes(f.security ?? '')) return fail(400, 'bad_security', 'Choose an encryption type: STARTTLS, SSL/TLS or none.')
    if (f.security === 'ssl' && port === 587) return fail(400, 'port_mismatch', 'Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS.')
    if (f.security === 'starttls' && port === 465) return fail(400, 'port_mismatch', 'Port 465 uses SSL/TLS, not STARTTLS. Choose SSL/TLS, or change the port to 587 for STARTTLS.')
    if (f.security === 'none') {
      // the adapter's insecure_smtp, which the API answers as bad_security (channels.go apiConfigCode); no login without encryption
      if (!isInternalHost(host)) return fail(400, 'bad_security', 'Unencrypted SMTP is only allowed for a server on your internal network. Choose STARTTLS or SSL/TLS.')
    } else {
      if (!f.username?.trim()) return fail(400, 'bad_username', 'Enter the SMTP username (usually the email address).')
      const bad = need('SMTP password'); if (bad) return bad
    }
    if (!EMAIL_RE.test((f.from ?? '').trim())) return fail(400, 'bad_from', 'The sender email is not valid, for example alerts@company.com.')
    return null
  }
  let u: URL | null = null
  try { u = new URL(webhookUrl(f, cur)) } catch { /* không phải URL */ }
  if (!u || !/^https?:$/.test(u.protocol)) return fail(400, 'bad_url', 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.')
  // The API answers the adapter's blocked_host and insecure_url as bad_url (channels.go apiConfigCode); blocked_host comes first (webhook.go).
  if (forbiddenHost(u.hostname)) return fail(400, 'bad_url', 'The webhook cannot point at this machine, a link-local or multicast address, a cloud metadata service, or an unspecified address.')
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

export const handlers = [
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
    const bad = validate(type, b, cur); if (bad) return bad
    const fields = Object.fromEntries(SAVED_FIELDS[type].filter((k) => !(type === 'slack' && k === 'channel_id' && b.approvals !== true)).map((k) => [k, String(b.fields?.[k] ?? '').trim()]))
    if (type === 'email') fields.to = fields.to!.split(/[,;]/).map((x) => x.trim()).filter(Boolean).join(', ')
    const secret = (b.secret ?? '').trim()
    const approvals = b.approvals === true
    const approvers = approvals ? (b.approvers ?? []).map((a) => ({ user_id: a.user_id, address: a.address.trim() })) : []
    const next: StoredChannel = { ...cur, configured: true, enabled: b.enabled === true, fields, secret: secret ? secret : cur.secret, ...(type === 'webhook' ? { url: webhookUrl(b.fields ?? {}, cur) } : {}), min_severity: b.min_severity!, last_test: null, approvals, approvers,
      app_token: type === 'slack' ? (b.app_token?.trim() || cur.app_token) : undefined, bot_token: type === 'slack' ? (b.bot_token?.trim() || cur.bot_token) : undefined }
    channels.update((l) => [...l.filter((c) => c.type !== type), next])
    audit('notify.channel_save', type, `${next.enabled ? 'on' : 'off'}${approvals ? `, approvals on (${approvers.length} approver${approvers.length === 1 ? '' : 's'})` : ''}`)
    return HttpResponse.json(pub(next))
  }),

  http.delete(`${API}/notify/channels/:type`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const type = params.type
    if (!isType(type)) return fail(404, 'not_found', 'No such channel type.')
    channels.update((l) => [...l.filter((c) => c.type !== type), blank(type)])
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
