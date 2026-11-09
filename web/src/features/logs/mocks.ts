// Mock API module logs (S-LOG-1/2/3). Nguồn log, digest "mới / tăng đột biến / kết nối xấu", tìm sự kiện, lưu giữ, chuyển tiếp SIEM.
// Dòng log và digest là dữ liệu mẫu cố định; thiết bị nguồn tra theo IP trong assetsStore (kiểm kê). Mọi văn bản người dùng thấy bằng tiếng Anh (D-28).
import { http, HttpResponse } from 'msw'
import { API, audit, body, DOMAIN_RE, fail, guard, IPV4_RE, NAME_RE } from '@/mocks/http'
import { assetsStore, boxInfo } from '@/mocks/stores'
import { collection, daysAgo, dataMode, newId, nowIso } from '@/mocks/db'
import { CATALOG } from './catalog'
import { KIND_IDS } from './kinds'
import { SIEM_EVENTS } from './types'
import type { Digest, IocHit, EventWindow, LogEvent, LogSource, NewItem, Proto, SiemConfig, SiemInput, SourceInput, SourceKind, SpikeItem } from './types'

type Stored = Omit<LogSource, 'asset_id' | 'asset_name' | 'state'>

const sources = collection<Stored[]>('logs_sources', () => [
  { id: 'ls-1', kind: 'fortigate', name: 'FW-HQ', sender_ip: '192.168.10.1', proto: 'udp', port: 514, last_received: new Date(Date.now() - 20e3).toISOString(), lines_per_hour: 1840, created_at: daysAgo(30) },
  { id: 'ls-2', kind: 'mikrotik', name: 'RT-BACKUP', sender_ip: '192.168.10.2', proto: 'udp', port: 514, last_received: new Date(Date.now() - 120e3).toISOString(), lines_per_hour: 310, created_at: daysAgo(30) },
  { id: 'ls-3', kind: 'windows', name: 'SRV-AD', sender_ip: '192.168.10.10', proto: 'udp', port: 514, last_received: new Date(Date.now() - 240e3).toISOString(), lines_per_hour: 95, created_at: daysAgo(20) },
  { id: 'ls-4', kind: 'windows', name: 'SRV-FILE', sender_ip: '192.168.10.11', proto: 'udp', port: 514, last_received: daysAgo(3), lines_per_hour: 0, created_at: daysAgo(20) },
], () => [])
// IOC detections (S-LOG-2, S-LOG-4, D-43): metadata from a SPAN port (DNS query, TLS SNI, HTTP host, flow) or syslog matched against the feeds.
// Stored shape is read by the response module with peek('logs_ioc_hits'). Clean install: empty.
type StoredIoc = Omit<IocHit, 'asset_name'>
const iocHits = collection<StoredIoc[]>('logs_ioc_hits', () => {
  const id = (ip: string) => assetsStore.get().find((x) => x.ip === ip)?.id ?? null
  return [
    { id: 'b-1', ts: daysAgo(0, 0.2), asset_id: id('192.168.10.105'), src_ip: '192.168.10.105', dest: '185.220.101.47', dest_kind: 'ip', seen_via: 'span_flow', feeds: ['Tor exit list', 'IPsum'], confidence: 0.9 },
    { id: 'b-2', ts: daysAgo(0, 1.6), asset_id: id('192.168.10.20'), src_ip: '192.168.10.20', dest: 'update-dsm-synology.com', dest_kind: 'domain', seen_via: 'span_dns', feeds: ['hagezi TIF', 'Phishing.Database'], confidence: 0.95 },
    { id: 'b-3', ts: daysAgo(0, 3), asset_id: id('192.168.10.157'), src_ip: '192.168.10.157', dest: '45.148.10.95', dest_kind: 'ip', seen_via: 'syslog:FW-HQ', feeds: ['ET Open compromised', 'IPsum'], confidence: 0.6 },
  ]
}, () => [])
const retention = collection<{ days: number }>('logs_retention', () => ({ days: 30 }))
const siem = collection<Omit<SiemConfig, 'secret_last4'> & { secret: string }>('logs_siem', () => ({
  enabled: false, format: 'syslog', host: '', port: 514, proto: 'udp', url: '', secret: '', events: ['findings', 'alerts'], last_test: null,
}))

const toSource = (s: Stored): LogSource => {
  const a = assetsStore.get().find((x) => x.ip === s.sender_ip)
  const age = s.last_received ? Date.now() - new Date(s.last_received).getTime() : Infinity
  return { ...s, asset_id: a?.id ?? null, asset_name: a ? (a.hostname ?? a.ip) : null, state: !s.last_received ? 'never' : age > 3600e3 ? 'silent' : 'receiving' }
}
const nameOf = (id: string) => sources.get().find((s) => s.id === id)?.name ?? id

// Sự kiện mẫu: sinh một lần (giả ngẫu nhiên có hạt giống) rồi lưu, nên tải lại trang vẫn thấy cùng dòng.
function seedEvents(): LogEvent[] {
  let seed = 20261106
  const rnd = () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
  const pick = <T,>(l: T[]): T => l[Math.floor(rnd() * l.length)]!
  const pcs = Array.from({ length: 12 }, (_, i) => `192.168.10.${101 + i}`)
  const out: LogEvent[] = []
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
const events = collection<LogEvent[]>('logs_events', seedEvents, () => [])

function digest(): Digest {
  const lines = sources.get().reduce((n, s) => n + s.lines_per_hour * 24, 0)
  // Cài sạch: chưa có log thật nên digest rỗng (digest mẫu nhắc IP và thiết bị không tồn tại trong cài đặt này).
  if (dataMode() === 'clean') return { generated_at: nowIso(), lines_24h: lines, baseline_days: 7, new: [], spikes: [], bad_connections: [] }
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
  // Device resolved from the inventory when read, so removing a device is reflected.
  const bad: IocHit[] = iocHits.get().map((r) => { const a = assets.find((x) => x.ip === r.src_ip); return { ...r, asset_id: a?.id ?? null, asset_name: a ? (a.hostname ?? a.ip) : null } })
  return { generated_at: nowIso(), lines_24h: lines, baseline_days: 7, new: fresh, spikes, bad_connections: bad }
}

function validateSource(b: Partial<SourceInput>, selfId?: string) {
  const name = String(b.name ?? '').trim()
  if (!KIND_IDS.includes(b.kind as SourceKind)) return fail(400, 'bad_kind', 'Choose a device type from the list.')
  if (!NAME_RE.test(name)) return fail(400, 'bad_name', 'The name may only contain letters without accents, digits, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: FW-HQ.')
  if (!IPV4_RE.test(String(b.sender_ip ?? ''))) return fail(400, 'bad_ip', 'The IP address of the sending device is not valid. Enter it like 192.168.10.1.')
  if (!CATALOG[b.kind as SourceKind].protos.includes(b.proto as Proto)) return fail(400, 'bad_proto', 'This device type cannot send logs with the chosen protocol. Pick another protocol from the list.')
  if (!Number.isInteger(b.port) || b.port! < 1 || b.port! > 65535) return fail(400, 'bad_port', 'The port must be a number from 1 to 65535. Usually 514 (UDP or TCP) or 6514 (TLS).')
  if (sources.get().some((s) => s.id !== selfId && s.sender_ip === b.sender_ip)) return fail(409, 'duplicate', 'There is already a log source with this IP address. Edit that one instead of adding a new one.')
  return null
}

const WINDOW_MS: Record<EventWindow, number> = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 }

function validateSiem(b: Partial<SiemInput>) {
  if (!['syslog', 'cef', 'json'].includes(String(b.format))) return fail(400, 'bad_format', 'Choose a format: syslog, CEF or JSON webhook.')
  if (b.format === 'json') {
    let u: URL | null = null
    try { u = new URL(String(b.url ?? '')) } catch { /* không phải URL */ }
    if (!u || !/^https?:$/.test(u.protocol)) return fail(400, 'bad_url', 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://siem.company.com/hooks/vedette.')
    if (b.secret && b.secret.length < 16) return fail(400, 'bad_secret', 'The signing key needs at least 16 characters. Press Generate if you want a random one.')
  } else {
    if (!(IPV4_RE.test(String(b.host ?? '')) || DOMAIN_RE.test(String(b.host ?? '')))) return fail(400, 'bad_host', 'The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com.')
    if (!Number.isInteger(b.port) || b.port! < 1 || b.port! > 65535) return fail(400, 'bad_port', 'The port must be a number from 1 to 65535.')
    if (!['udp', 'tcp', 'tls'].includes(String(b.proto))) return fail(400, 'bad_proto', 'Choose UDP, TCP or TLS.')
  }
  if (!Array.isArray(b.events) || b.events.length === 0 || b.events.some((e) => !SIEM_EVENTS.includes(e))) return fail(400, 'bad_events', 'Choose at least one event type to forward.')
  return null
}
const publicSiem = (c: ReturnType<typeof siem.get>): SiemConfig => { const { secret, ...rest } = c; return { ...rest, secret_last4: secret ? secret.slice(-4) : null } }

export const handlers = [
  http.get(`${API}/logs/sources`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ box: boxInfo(), sources: sources.get().map(toSource), retention_days: retention.get().days })
  }),

  http.post(`${API}/logs/sources`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<SourceInput>(request)
    const bad = validateSource(b); if (bad) return bad
    const s: Stored = { id: newId('ls'), kind: b.kind!, name: b.name!.trim(), sender_ip: b.sender_ip!, proto: b.proto!, port: b.port!, last_received: null, lines_per_hour: 0, created_at: nowIso() }
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
    sources.update((l) => l.map((s) => (s.id === id ? (out = { ...s, kind: b.kind!, name: b.name!.trim(), sender_ip: b.sender_ip!, proto: b.proto!, port: b.port! }) : s)))
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
    return HttpResponse.json({ events: all.slice(0, 200), total: all.length })
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
    const bad = validateSiem(b); if (bad) return bad
    const next = { ...cur, enabled: b.enabled === true, format: b.format!, host: b.format === 'json' ? '' : b.host!, port: b.format === 'json' ? 514 : b.port!, proto: b.format === 'json' ? 'udp' as const : b.proto!, url: b.format === 'json' ? b.url! : '', events: b.events!, secret: b.secret ? b.secret : cur.secret, last_test: null }
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
