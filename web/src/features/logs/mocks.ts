// Mock API module logs (S-LOG-1/2/3). Nguồn log, digest "mới / tăng đột biến / kết nối xấu", tìm sự kiện, lưu giữ, chuyển tiếp SIEM.
// Dòng log và digest là dữ liệu mẫu cố định; thiết bị nguồn tra theo IP trong assetsStore (kiểm kê). Mọi văn bản người dùng thấy bằng tiếng Anh (D-28).
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard, IPV4_RE, NAME_RE } from '@/mocks/http'
import { assetsStore, boxInfo, modulesStore } from '@/mocks/stores'
import { collection, daysAgo, dataMode, newId, nowIso } from '@/mocks/db'
import { iocListed } from '@/features/feeds/sourcesMock'
import { CATALOG } from './catalog'
import { KIND_IDS } from './kinds'
import { syslogHeader } from './syslog'
import { SIEM_EVENTS } from './types'
import type { Digest, IocHit, EventWindow, LogEvent, LogSource, NewItem, Proto, SiemConfig, SiemInput, SourceInput, SourceKind, SpikeItem, UnknownSender } from './types'

type Stored = Omit<LogSource, 'asset_id' | 'asset_name' | 'state'>

const sources = collection<Stored[]>('logs_sources', () => [
  { id: 'ls-1', kind: 'fortigate', name: 'FW-HQ', sender_ip: '192.168.10.1', proto: 'udp', port: 514, last_received: new Date(Date.now() - 20e3).toISOString(), lines_per_hour: 1840, created_at: daysAgo(30), client_cert_sha256: null },
  { id: 'ls-2', kind: 'mikrotik', name: 'RT-BACKUP', sender_ip: '192.168.10.2', proto: 'udp', port: 514, last_received: new Date(Date.now() - 120e3).toISOString(), lines_per_hour: 310, created_at: daysAgo(30), client_cert_sha256: null },
  { id: 'ls-3', kind: 'windows', name: 'SRV-AD', sender_ip: '192.168.10.10', proto: 'udp', port: 514, last_received: new Date(Date.now() - 240e3).toISOString(), lines_per_hour: 95, created_at: daysAgo(20), client_cert_sha256: null },
  { id: 'ls-4', kind: 'windows', name: 'SRV-FILE', sender_ip: '192.168.10.11', proto: 'udp', port: 514, last_received: daysAgo(3), lines_per_hour: 0, created_at: daysAgo(20), client_cert_sha256: null },
], () => [])
// IOC detections (S-LOG-2, S-LOG-4, D-43): metadata from a SPAN port (DNS query, TLS SNI, HTTP host, flow) or syslog matched against the feeds.
// Stored shape is read by the response module with peek('logs_ioc_hits'); like the box (INV-7) it does not hold the device: asset_id and
// asset_name are resolved from the inventory when the digest is read. Clean install: empty.
type StoredIoc = Omit<IocHit, 'asset_id' | 'asset_name'>
const iocHits = collection<StoredIoc[]>('logs_ioc_hits', () => {
  return [
    { id: 'b-1', ts: daysAgo(0, 0.2), src_ip: '192.168.10.105', dest: '185.220.101.47', dest_kind: 'ip', seen_via: 'span_flow', feeds: ['Tor exit list', 'IPsum'], confidence: 0.9, blocked: false, listed_as: null },
    { id: 'b-2', ts: daysAgo(0, 1.6), src_ip: '192.168.10.20', dest: 'a7k2q.update-dsm-synology.com', dest_kind: 'domain', seen_via: 'span_dns', feeds: ['hagezi TIF'], confidence: 0.95, blocked: false, listed_as: 'update-dsm-synology.com' },
    { id: 'b-3', ts: daysAgo(0, 3), src_ip: '192.168.10.157', dest: '45.148.10.95', dest_kind: 'ip', seen_via: 'syslog:FW-HQ', feeds: ['ET Open compromised', 'IPsum'], confidence: 0.6, blocked: true, listed_as: null },
  ]
}, () => [])
// Senders whose syslog the box dropped because no source declares them (S-LOG-1, FORBID-5): kept in memory on the box, so a clean install has none.
const unknownSenders = collection<UnknownSender[]>('logs_unknown_senders', () => [
  { ip: '192.168.10.3', proto: 'udp', count: 418, last_seen: new Date(Date.now() - 45e3).toISOString() },
], () => [])
const retention = collection<{ days: number }>('logs_retention', () => ({ days: 30 }))
const siem = collection<Omit<SiemConfig, 'secret_last4'> & { secret: string }>('logs_siem', () => ({
  enabled: false, format: 'syslog', host: '', port: 514, proto: 'udp', url: '', secret: '', events: ['findings', 'alerts'], last_test: null,
}))

// What a device must trust for the box's syslog TLS port (D-434): on a default box the box's own CA (the 8443 leaf is signed by it and re-issued
// on renewal), so the sample is that.
const BOX_TLS = {
  kind: 'box_ca' as const, issuer: 'CN=Vedette box CA', port: 6514,
  fingerprint_sha256: 'c3a1f0e29d4b7a86510e3fb2c8d94a7e61b05f3d2a98c47e0b1d6f5a3c2e8d91', subject: 'CN=Vedette box CA', not_after: daysAgo(-7000),
  pem: '-----BEGIN CERTIFICATE-----\nU2FtcGxlIGNlcnRpZmljYXRlIGZvciB0aGUgbW9jayBib3gu\n-----END CERTIFICATE-----\n',
}

const toSource = (s: Stored): LogSource => {
  const a = assetsStore.get().find((x) => x.ip === s.sender_ip)
  const age = s.last_received ? Date.now() - new Date(s.last_received).getTime() : Infinity
  return { ...s, asset_id: a?.id ?? null, asset_name: a ? (a.hostname ?? a.ip) : null, state: !s.last_received ? 'never' : age > 3600e3 ? 'silent' : 'receiving' }
}
const nameOf = (id: string) => sources.get().find((s) => s.id === id)?.name ?? id

// Sự kiện mẫu: sinh một lần (giả ngẫu nhiên có hạt giống) rồi lưu, nên tải lại trang vẫn thấy cùng dòng.
type StoredEvent = Omit<LogEvent, 'host' | 'app' | 'message'>

function seedEvents(): StoredEvent[] {
  let seed = 20261106
  const rnd = () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
  const pick = <T,>(l: T[]): T => l[Math.floor(rnd() * l.length)]!
  const pcs = Array.from({ length: 12 }, (_, i) => `192.168.10.${101 + i}`)
  const out: StoredEvent[] = []
  const add = (source_id: string, minutesAgo: number, line: string) => out.push({ id: newId('le'), ts: new Date(Date.now() - minutesAgo * 60e3).toISOString(), source_id, source_name: nameOf(source_id), line })
  for (let i = 0; i < 90; i++) {
    const m = Math.floor(rnd() * 7 * 24 * 60)
    const kind = rnd()
    if (kind < 0.5) {
      const deny = rnd() < 0.25
      add('ls-1', m, `type="traffic" subtype="forward" level="${deny ? 'warning' : 'notice'}" srcip=${pick(pcs)} dstip=${deny ? `45.${Math.floor(rnd() * 200)}.${Math.floor(rnd() * 200)}.${Math.floor(rnd() * 200)}` : pick(['142.250.66.78', '13.107.42.14', '157.240.15.35'])} dstport=${deny ? pick([23, 445, 3389]) : 443} action="${deny ? 'deny' : 'accept'}" policyid=${deny ? 0 : 3}`)
    } else if (kind < 0.7) {
      add('ls-2', m, `firewall,info input: in:ether1 out:(unknown 0), proto TCP (SYN), ${Math.floor(rnd() * 200)}.${Math.floor(rnd() * 200)}.${Math.floor(rnd() * 200)}.9:${40000 + Math.floor(rnd() * 20000)}->192.168.10.2:${pick([8291, 22, 8728])}, len 60`)
    } else {
      add('ls-3', m, pick([
        `4624: An account was successfully logged on. Account Name: ${pick(['accounts1', 'hr2', 'admin.it'])} Logon Type: ${pick([2, 3])} Source Network Address: ${pick(pcs)}`,
        `4625: An account failed to log on. Account Name: ${pick(['accounts1', 'administrator', 'sale3'])} Logon Type: 3 Source Network Address: ${pick(pcs)}`,
        '4634: An account was logged off.',
      ]))
    }
  }
  // Các dòng khớp digest, để tìm theo IP trong digest thấy đúng dòng.
  add('ls-1', 12, 'type="traffic" subtype="forward" level="warning" srcip=192.168.10.105 dstip=185.220.101.47 dstport=443 action="accept" policyid=3')
  add('ls-1', 95, 'type="traffic" subtype="forward" level="warning" srcip=192.168.10.20 dstip=104.21.55.9 dstport=443 hostname="update-dsm-synology.com" action="accept" policyid=3')
  add('ls-1', 180, 'type="traffic" subtype="forward" level="warning" srcip=192.168.10.157 dstip=45.148.10.95 dstport=8080 action="accept" policyid=3')
  add('ls-3', 130, '4720: A user account was created. Subject Account Name: admin.it Target Account Name: support_tmp')
  return out.sort((a, b) => b.ts.localeCompare(a.ts))
}
const events = collection<StoredEvent[]>('logs_events', seedEvents, () => [])
// The box reads the syslog header of each line it lists (W1-22, D-485).
const shown = (l: StoredEvent[]): LogEvent[] => l.map((e) => ({ ...e, ...syslogHeader(e.line) }))

function digest(): Digest {
  const lines = sources.get().reduce((n, s) => n + s.lines_per_hour * 24, 0)
  // Like the box (historyDays): whole days since the first line of the oldest source, at most 7. The mock has no first-line time: a source that
  // received something counts from when it was added.
  const history = Math.min(7, Math.max(0, ...sources.get().filter((s) => s.last_received).map((s) => Math.floor((Date.now() - new Date(s.created_at).getTime()) / 86400e3))))
  const feedsOff = modulesStore.get().find((m) => m.id === 'feeds')?.enabled === false // PRE-3: with Feeds off the list is empty (the page says why)
  const matching = !feedsOff && iocListed() // like the box: false when no switched-on feed lists an indicator
  // Cài sạch: chưa có log thật nên digest rỗng (digest mẫu nhắc IP và thiết bị không tồn tại trong cài đặt này).
  if (dataMode() === 'clean') return { generated_at: nowIso(), lines_24h: lines, baseline_days: 7, history_days: history, new: [], spikes: [], bad_connections: [], ioc_matching: matching }
  const fresh: NewItem[] = [
    { id: 'n-1', signature: 'Blocked access to port 3389 (Remote Desktop) from the Internet', source_id: 'ls-1', source_name: nameOf('ls-1'), count: 212, first_seen: daysAgo(0, 6), sample: 'type="traffic" level="warning" srcip=45.9.148.20 dstip=192.168.10.1 dstport=3389 action="deny"' },
    { id: 'n-2', signature: '4720: A new user account was created', source_id: 'ls-3', source_name: nameOf('ls-3'), count: 1, first_seen: daysAgo(0, 2), sample: 'Subject Account Name: admin.it Target Account Name: support_tmp' },
    { id: 'n-3', signature: 'Winbox login from a machine that never logged in before', source_id: 'ls-2', source_name: nameOf('ls-2'), count: 3, first_seen: daysAgo(0, 9), sample: 'system,info,account user admin logged in from 192.168.10.113 via winbox' },
  ]
  const spikes: SpikeItem[] = [
    { id: 's-1', signature: '4625: Failed logon (network type)', source_id: 'ls-3', source_name: nameOf('ls-3'), count: 340, baseline_per_day: 22, sample: 'Account Name: administrator Logon Type: 3 Source Network Address: 192.168.10.113' },
    { id: 's-2', signature: 'Blocked DNS to 8.8.8.8 (forcing internal DNS)', source_id: 'ls-1', source_name: nameOf('ls-1'), count: 96, baseline_per_day: 9, sample: 'type="traffic" srcip=192.168.10.108 dstip=8.8.8.8 dstport=53 action="deny"' },
  ]
  const assets = assetsStore.get()
  // Like the box (INV-7, iochits.go): the hits of the last 24 hours, newest first, at most 20, and the device resolved from the inventory when read, so
  // removing or renaming a device is reflected.
  const since = Date.now() - 86400e3
  const bad: IocHit[] = feedsOff ? [] : iocHits.get().filter((r) => new Date(r.ts).getTime() >= since).sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 20)
    .map((r) => { const a = assets.find((x) => x.ip === r.src_ip); return { ...r, asset_id: a?.id ?? null, asset_name: a ? (a.hostname ?? a.ip) : null } })
  return { generated_at: nowIso(), lines_24h: lines, baseline_days: 7, history_days: history, new: fresh, spikes, bad_connections: bad, ioc_matching: matching }
}

function validateSource(b: Partial<SourceInput>, selfId?: string) {
  const name = String(b.name ?? '').trim()
  if (!KIND_IDS.includes(b.kind as SourceKind)) return fail(400, 'bad_kind', 'Choose a device type from the list.')
  if (!NAME_RE.test(name)) return fail(400, 'bad_name', 'The name may only contain letters without accents, digits, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: FW-HQ.')
  if (!IPV4_RE.test(String(b.sender_ip ?? ''))) return fail(400, 'bad_ip', 'The IP address of the sending device is not valid. Enter it like 192.168.10.1.')
  if (!CATALOG[b.kind as SourceKind].protos.includes(b.proto as Proto)) return fail(400, 'bad_proto', 'This device type cannot send logs with the chosen protocol. Pick another protocol from the list.')
  if (!Number.isInteger(b.port) || b.port! < 1 || b.port! > 65535) return fail(400, 'bad_port', 'The port must be a number from 1 to 65535. Usually 514 (UDP or TCP) or 6514 (TLS).')
  if (b.client_cert_sha256) {
    if (b.proto !== 'tls') return fail(400, 'bad_client_cert', 'Only a TLS source can have a client certificate, given as its SHA-256 fingerprint: 64 hexadecimal characters.')
    if (!/^[0-9a-f]{64}$/.test(b.client_cert_sha256)) return fail(400, 'bad_client_cert', 'Only a TLS source can have a client certificate, given as its SHA-256 fingerprint: 64 hexadecimal characters.')
  }
  if (sources.get().some((s) => s.id !== selfId && s.sender_ip === b.sender_ip)) return fail(409, 'duplicate', 'There is already a log source with this IP address. Edit that one instead of adding a new one: a UDP source also takes lines from its IP over TCP.')
  return null
}

const WINDOW_MS: Record<EventWindow, number> = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 }

// The checks of the box (modules/logs/siem.go SetSiem), in its order: format, then the destination (URL or host, port, protocol, and an address
// that no SIEM may be at), then the events, then the signing key; a webhook with no saved key and none sent is refused last.
const SIEM_HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/
const NUMERIC_LABEL_RE = /^(0x[0-9a-f]+|[0-9]+)$/
const SIEM_METADATA = ['100.100.100.200', '192.0.0.192', 'fd00:ec2::254'] // cloud metadata endpoints that are not link-local
const BAD_HOST = 'The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.'
const BAD_URL = 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://siem.company.com/hooks/vedette.'
// SYS-7: link-local, multicast, unspecified, broadcast and a metadata endpoint are never a destination; nor is Vedette itself (D-446): loopback
// and localhost on every port, the box's own address on Vedette's own ports. A name that is an address in disguise (2130706433, 0x7f.1) is
// not a host name. Names are resolved only on the box's socket.
const VEDETTE_PORTS = [514, 6514, 8443, 8444, 8765]
const OWN_TEXT = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."
function siemHostProblem(raw: string, port: number) {
  const host = raw.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  const blocked = fail(400, 'blocked_host', 'The SIEM cannot be a link-local, multicast or unspecified address, or a cloud metadata service.')
  const own = fail(400, 'blocked_host', OWN_TEXT)
  if (IPV4_RE.test(host)) {
    const [a = 0, b = 0] = host.split('.').map(Number)
    if (a === 127 || (host === boxInfo().ip && VEDETTE_PORTS.includes(port))) return own
    return host === '0.0.0.0' || (a >= 224 && a <= 239) || (a === 169 && b === 254) || host === '255.255.255.255' || SIEM_METADATA.includes(host) ? blocked : null
  }
  if (host === '::1') return own
  if (host.includes(':')) return host === '::' || /^fe[89ab]/.test(host) || /^ff/.test(host) || SIEM_METADATA.includes(host) ? blocked : null
  if (NUMERIC_LABEL_RE.test(host.split('.').at(-1) ?? '')) return fail(400, 'bad_host', BAD_HOST)
  return host === 'localhost' || host.endsWith('.localhost') ? own : null
}
function validateSiem(b: Partial<SiemInput>, saved: { secret: string }) {
  if (!['syslog', 'cef', 'json'].includes(String(b.format))) return fail(400, 'bad_format', 'Choose a format: syslog, CEF or JSON webhook.')
  if (b.format === 'json') {
    const raw = String(b.url ?? '').trim()
    let u: URL | null = null
    try { u = new URL(raw) } catch { /* not a URL */ }
    // eslint-disable-next-line no-control-regex
    if (!u || raw.length > 2048 || !/^https?:$/.test(u.protocol) || u.hostname === '' || u.username || u.password || u.hash || u.port === '0' || /[^\x21-\x7e]/.test(raw)) return fail(400, 'bad_url', BAD_URL)
    const problem = siemHostProblem(u.hostname, Number(u.port || (u.protocol === 'http:' ? 80 : 443))); if (problem) return problem
  } else {
    const host = String(b.host ?? '').trim()
    if (host.length > 253 || !(IPV4_RE.test(host) || SIEM_HOST_RE.test(host))) return fail(400, 'bad_host', BAD_HOST)
    if (!Number.isInteger(b.port) || b.port! < 1 || b.port! > 65535) return fail(400, 'bad_port', 'The port must be a number from 1 to 65535.')
    if (!['udp', 'tcp', 'tls'].includes(String(b.proto))) return fail(400, 'bad_proto', 'Choose UDP, TCP or TLS.')
    const problem = siemHostProblem(host, b.port!); if (problem) return problem
  }
  const ev = Array.isArray(b.events) ? b.events : []
  if (ev.length === 0 || ev.length > SIEM_EVENTS.length || ev.some((e) => !SIEM_EVENTS.includes(e)) || new Set(ev).size !== ev.length) return fail(400, 'bad_events', 'Choose at least one event type to forward.')
  if (b.secret && [...b.secret].length < 16) return fail(400, 'bad_secret', 'The signing key needs at least 16 characters. Press Generate random if you want a random one.')
  // eslint-disable-next-line no-control-regex
  if (b.secret && (new TextEncoder().encode(b.secret).length > 512 || b.secret !== b.secret.trim() || /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/.test(b.secret))) {
    return fail(400, 'bad_secret', 'The signing key can be at most 512 bytes, with no control characters and no space at either end.')
  }
  if (b.format === 'json' && !b.secret && !saved.secret) return fail(400, 'secret_required', 'Enter the webhook signing key.')
  return null
}
const publicSiem = (c: ReturnType<typeof siem.get>): SiemConfig => { const { secret, ...rest } = c; return { ...rest, secret_last4: secret ? secret.slice(-4) : null } }

export const handlers = [
  http.get(`${API}/logs/sources`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ box: { ...boxInfo(), tls: BOX_TLS }, sources: sources.get().map(toSource), retention_days: retention.get().days })
  }),

  http.post(`${API}/logs/sources`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<SourceInput>(request)
    const bad = validateSource(b); if (bad) return bad
    const s: Stored = { id: newId('ls'), kind: b.kind!, name: b.name!.trim(), sender_ip: b.sender_ip!, proto: b.proto!, port: b.port!, last_received: null, lines_per_hour: 0, created_at: nowIso(), client_cert_sha256: b.client_cert_sha256 || null }
    sources.update((l) => [...l, s])
    audit('logs.source_add', s.name, `${s.kind} ${s.sender_ip} ${s.proto}/${s.port}`)
    return HttpResponse.json(toSource(s), { status: 201 })
  }),

  http.put(`${API}/logs/sources/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    if (!sources.get().some((s) => s.id === id)) return fail(404, 'not_found', 'No such log source.')
    const b = await body<SourceInput>(request)
    const bad = validateSource(b, id); if (bad) return bad
    let out: Stored | undefined
    sources.update((l) => l.map((s) => (s.id === id ? (out = { ...s, kind: b.kind!, name: b.name!.trim(), sender_ip: b.sender_ip!, proto: b.proto!, port: b.port!, client_cert_sha256: b.client_cert_sha256 || null }) : s)))
    audit('logs.source_edit', out!.name)
    return HttpResponse.json(toSource(out!))
  }),

  http.delete(`${API}/logs/sources/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = sources.get().find((x) => x.id === params.id)
    if (!s) return fail(404, 'not_found', 'No such log source.')
    sources.update((l) => l.filter((x) => x.id !== s.id))
    audit('logs.source_delete', s.name, 'logs already received are kept for the retention period')
    return new HttpResponse(null, { status: 204 })
  }),

  http.get(`${API}/logs/unknown-senders`, () => {
    const denied = guard('operator'); if (denied) return denied
    // Like the box: a sender a source now takes over the protocol it used is left out (a UDP source takes TCP too, D-444); the 10 seen most recently.
    const declared = sources.get()
    const items = unknownSenders.get().filter((u) => !declared.some((s) => s.sender_ip === u.ip && (s.proto === u.proto || (s.proto === 'udp' && u.proto === 'tcp')))).sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 10)
    return HttpResponse.json({ items })
  }),

  http.get(`${API}/logs/digest`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(digest())
  }),

  http.get(`${API}/logs/events`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const p = new URL(request.url).searchParams
    const w = p.get('window') as EventWindow
    if (!(w in WINDOW_MS)) return fail(400, 'bad_window', 'The time range must be 1h, 24h or 7d.')
    const src = p.get('source') ?? ''
    const q = (p.get('q') ?? '').trim().slice(0, 200).toLowerCase()
    const since = Date.now() - Math.min(WINDOW_MS[w], retention.get().days * 86400e3)
    const all = events.get().filter((e) => new Date(e.ts).getTime() >= since && (!src || e.source_id === src) && (!q || e.line.toLowerCase().includes(q) || e.source_name.toLowerCase().includes(q)))
    // A keyword search answers 200 matches at most and, when older lines may remain, `next_cursor` (the id of the last line shown) that
    // `cursor` continues from (D-441); the real box also stops at a time budget, which a mock has no reason to imitate.
    const cursor = p.get('cursor')
    if (cursor && !q) return fail(400, 'bad_cursor', 'That search position is not valid. Search again from the start.')
    if (q) {
      const from = cursor ? all.findIndex((e) => e.id === cursor) + 1 : 0
      if (cursor && from === 0) return fail(400, 'bad_cursor', 'That search position is not valid. Search again from the start.')
      const page = all.slice(from, from + 200)
      const more = from + 200 < all.length
      return HttpResponse.json({ events: shown(page), total: page.length, next_cursor: more ? page[page.length - 1]!.id : null, ...(more ? { searched_back_to: page[page.length - 1]!.ts } : {}) })
    }
    return HttpResponse.json({ events: shown(all.slice(0, 200)), total: all.length, next_cursor: null })
  }),

  http.put(`${API}/logs/retention`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ days: number }>(request)
    if (![7, 30, 90, 180].includes(Number(b.days))) return fail(400, 'bad_days', 'Retention must be 7, 30, 90 or 180 days.')
    retention.set({ days: Number(b.days) })
    audit('logs.retention', `${b.days} days`)
    return HttpResponse.json({ retention_days: Number(b.days) })
  }),

  http.get(`${API}/logs/siem`, () => {
    const denied = guard('admin'); if (denied) return denied
    return HttpResponse.json(publicSiem(siem.get()))
  }),

  http.put(`${API}/logs/siem`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<SiemInput>(request)
    const cur = siem.get()
    const bad = validateSiem(b, cur); if (bad) return bad
    const next = { ...cur, enabled: b.enabled === true, format: b.format!, host: b.format === 'json' ? '' : b.host!.trim(), port: b.format === 'json' ? 514 : b.port!, proto: b.format === 'json' ? 'udp' as const : b.proto!, url: b.format === 'json' ? b.url!.trim() : '', events: b.events!, secret: b.secret ? b.secret : cur.secret, last_test: null }
    siem.set(next)
    audit('logs.siem_save', b.format === 'json' ? next.url : `${next.host}:${next.port}`, `${next.format}, ${next.enabled ? 'on' : 'off'}`)
    return HttpResponse.json(publicSiem(next))
  }),

  http.post(`${API}/logs/siem/test`, () => {
    const denied = guard('admin'); if (denied) return denied
    const c = siem.get()
    const target = c.format === 'json' ? c.url : c.host
    if (!target) return fail(400, 'not_configured', 'No SIEM destination is saved. Enter and save the configuration before sending a test.')
    const unreachable = /\.(invalid|test)\b/.test(target)
    const result = unreachable
      ? { at: nowIso(), ok: false, detail: `Could not connect to ${target}. Check the name or IP address, the port and any firewall between the box and the SIEM.` }
      : { at: nowIso(), ok: true, detail: c.format === 'json' ? 'The destination returned HTTP 200.' : `Sent 1 test record to ${c.host}:${c.port}/${c.proto}.` }
    siem.set({ ...c, last_test: result })
    audit('logs.siem_test', target, result.ok ? 'ok' : 'failed')
    return HttpResponse.json(result)
  }),
]
