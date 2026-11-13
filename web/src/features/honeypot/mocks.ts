// Mock API of module honeypot (S-HP-1, S-HP-2, D-466). Tables: hp_config, hp_trap_ips, hp_hits, hp_tokens. The response module reads hp_hits with peek; core's
// network mock reads hp_trap_ips with peek. Traps only listen, they never hit back (LEGAL §3).
// Services/ports follow OpenCanary (presets.ts SERVICE_PORT; SMB is Samba-based; D-467 added the other modules that work in the image). Each Trap IP answers
// only its own services (D-466).
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard, IPV4_RE } from '@/mocks/http'
import { assetsStore, boxInfo } from '@/mocks/stores'
import { boxAddress, networkStore } from '@/mocks/network'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import { PRESETS, SERVICE_PORT, VENDORS } from './presets'
import { HP_SERVICES, type Hit, type HitDetail, type HitEvent, type HitKind, type HpOverview, type HpService, type Token, type TokenType, type Trap, type TrapIP, type TrapIPInput, type TrapPreset, type TrapState, type TrapSuggestion, type TrapVendor } from './types'

// as modules/honeypot ServiceName.Label
const LABEL: Record<HpService, string> = {
  smb: 'SMB', rdp: 'RDP', ssh: 'SSH', mssql: 'MSSQL', http: 'HTTP', https: 'HTTPS', ftp: 'FTP', telnet: 'Telnet', mysql: 'MySQL', mongodb: 'MongoDB',
  redis: 'Redis', vnc: 'VNC', git: 'Git', httpproxy: 'HTTP proxy', tcpbanner: 'SMTP', tftp: 'TFTP', ntp: 'NTP', sip: 'SIP',
}
const WINDOW_MINUTES = 60
const MAX_TRAP_IPS = 32

// settle: per Trap IP, the reads left until a change shows its final state (see settleOneRead).
interface Config { ignored_7d: number; settle?: Record<string, { kind: 'starting' | 'stopping'; left: number }> }
// kind, source_ip, label, token_id: S-HP-2. Rows written before S-HP-2 lack them, so every read falls back (kind = service).
interface Stored { id: string; ts: string; kind?: HitKind; service: HpService | null; label?: string; token_id?: string; port: number | null; src_ip: string; source_ip?: string; src_asset_id: string | null; is_test: boolean; excerpt: string; events: HitEvent[]; trap_ip: string; trap_hostname: string; seed?: { srcName: string | null; lan: [string, string] } }
interface StoredTrapIP { id: string; name: string; ip: string; preset: TrapPreset; vendor: TrapVendor | null; services: HpService[]; enabled: boolean; created_at: string; fail?: string }
type StoredToken = Omit<Token, 'last_triggered_at' | 'triggers'>

const SESSION: Partial<Record<HpService, { first: string; excerpt: string }>> = {
  smb: { first: 'request to list shares (IPC$, ADMIN$)', excerpt: 'NTLM negotiate, account "administrator" tried a password 3 times, listed shares IPC$ and ADMIN$' },
  rdp: { first: 'remote login started, user name "admin"', excerpt: 'X.224 connection request, cookie "mstshash=admin", login failed' },
  ssh: { first: 'SSH login attempt, account "root"', excerpt: 'SSH-2.0-OpenSSH_9.6, tried a password for "root" 2 times' },
  mssql: { first: 'SQL Server login attempt, account "sa"', excerpt: 'TDS prelogin, login "sa" failed' },
  http: { first: 'request GET /admin', excerpt: 'GET /admin HTTP/1.1, User-Agent: curl/8.4.0' },
}

/** Log lines around a sample hit, generated when read. */
function makeEvents(ts: string, src_ip: string, srcName: string, service: HpService, trapIp: string, lanTargets: [string, string]): HitEvent[] {
  const t = new Date(ts).getTime()
  const at = (min: number) => new Date(t + min * 60_000).toISOString()
  const p = SERVICE_PORT[service]
  const fw = (dst: string) => `Firewall: ${src_ip} to ${dst} port ${p} allowed`
  return [
    { ts: at(-27), source: 'dhcp', text: `DHCP: ${srcName} (${src_ip}) renewed its lease`, mark: false },
    { ts: at(-14), source: 'ad', text: `AD: successful logon on ${srcName}`, mark: false },
    { ts: at(-4), source: 'firewall', text: fw(lanTargets[0]), mark: false },
    { ts: at(0), source: 'honeypot', text: `${LABEL[service]} trap: ${src_ip} connected to ${trapIp}:${p}`, mark: true },
    // INV-9: only the hit's own line is marked, not the later lines folded into it
    { ts: at(1), source: 'honeypot', text: `${LABEL[service]} trap: ${SESSION[service]?.first ?? 'new connection'}`, mark: false },
    { ts: at(8), source: 'firewall', text: fw(lanTargets[1]), mark: false },
    { ts: at(21), source: 'honeypot', text: `${LABEL[service]} trap: session closed, no more traffic from ${src_ip}`, mark: false },
  ]
}

const config = collection<Config>('hp_config', () => ({ ignored_7d: 14 }), () => ({ ignored_7d: 0 }))

const trapIps = collection<StoredTrapIP[]>('hp_trap_ips', () => [
  { id: 'tip-1', name: 'FILESRV-OLD', ip: '192.168.10.240', preset: 'file_server', vendor: 'dell', services: ['smb', 'rdp'], enabled: true, created_at: daysAgo(20) },
  { id: 'tip-2', name: 'NAS-ARCHIVE', ip: '192.168.10.241', preset: 'nas', vendor: 'synology', services: ['http', 'smb'], enabled: true, created_at: daysAgo(9) },
  { id: 'tip-3', name: 'PRN-FLOOR2', ip: '192.168.10.242', preset: 'printer', vendor: 'hp', services: ['http'], enabled: true, created_at: daysAgo(9) },
  // One Trap IP the host could not set up, so the failed state can be walked on `make dev`; one switched off.
  { id: 'tip-4', name: 'CAM-DOCK', ip: '192.168.10.243', preset: 'camera', vendor: 'hikvision', services: ['http'], enabled: true, created_at: daysAgo(2), fail: 'the host could not do it' },
  { id: 'tip-5', name: 'BUILD-SRV-02', ip: '192.168.10.244', preset: 'linux', vendor: 'vmware', services: ['ssh'], enabled: false, created_at: daysAgo(1) },
], () => [])

const hitsStore = collection<Stored[]>('hp_hits', () => {
  const t1 = daysAgo(1, 1), t2 = daysAgo(4)
  return [
    { id: 'hit-seed-1', ts: t1, kind: 'service', source_ip: '192.168.10.107', service: 'smb', port: 445, src_ip: '192.168.10.107', src_asset_id: 'a-pc07', is_test: false, excerpt: '', trap_ip: '192.168.10.240', trap_hostname: 'FILESRV-OLD', events: [], seed: { srcName: 'PC-HR-01', lan: ['192.168.10.11', '192.168.10.10'] } },
    { id: 'hit-seed-2', ts: t2, kind: 'service', source_ip: '192.168.10.157', service: 'rdp', port: 3389, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false, excerpt: '', trap_ip: '192.168.10.240', trap_hostname: 'FILESRV-OLD', events: [], seed: { srcName: null, lan: ['192.168.10.13', '192.168.10.10'] } },
    // A hit on another Trap IP carries that Trap IP's name (D-466).
    { id: 'hit-seed-5', ts: daysAgo(5), kind: 'service', source_ip: '192.168.10.157', service: 'http', port: 80, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false, excerpt: '', trap_ip: '192.168.10.241', trap_hostname: 'NAS-ARCHIVE', events: [], seed: { srcName: null, lan: ['192.168.10.13', '192.168.10.10'] } },
    // The same unknown device, later: used a planted credential, then swept the Trap IPs.
    { id: 'hit-seed-3', ts: daysAgo(3), kind: 'token', source_ip: '192.168.10.157', service: null, label: 'Credential token svc-backup-old', token_id: 'tok-2', port: null, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false,
      excerpt: 'SMB logon attempt for "svc-backup-old" on SRV-FILE. This account exists only as bait.', trap_ip: 'svc-backup-old', trap_hostname: 'Credential token svc-backup-old',
      events: [
        { ts: daysAgo(3, 0.2), source: 'ad', text: 'AD: failed logon for svc-backup-old from 192.168.10.157 (account does not exist)', mark: true },
        { ts: daysAgo(3), source: 'honeypot', text: 'Credential token svc-backup-old was used from 192.168.10.157', mark: true },
        { ts: daysAgo(3, -0.1), source: 'firewall', text: 'Firewall: 192.168.10.157 to 192.168.10.10 port 445 allowed', mark: false },
      ] },
    // W1-13: one source touching two or more Trap IPs within a minute is one scan hit (ingest.go sweep).
    { id: 'hit-seed-4', ts: daysAgo(2), kind: 'scan', source_ip: '192.168.10.157', service: null, label: 'Scan across the Trap IPs', port: null, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false,
      excerpt: 'Touched FILESRV-OLD (192.168.10.240), NAS-ARCHIVE (192.168.10.241), PRN-FLOOR2 (192.168.10.242) within a minute', trap_ip: '192.168.10.240, 192.168.10.241, 192.168.10.242', trap_hostname: 'FILESRV-OLD, NAS-ARCHIVE, PRN-FLOOR2',
      events: [
        { ts: daysAgo(2, 0.02), source: 'honeypot', text: '192.168.10.157 touched FILESRV-OLD (192.168.10.240)', mark: true },
        { ts: daysAgo(2), source: 'honeypot', text: '192.168.10.157 touched NAS-ARCHIVE (192.168.10.241)', mark: true },
        { ts: daysAgo(2, -0.1), source: 'firewall', text: 'Firewall: 192.168.10.157 to 192.168.10.13 port 3389 allowed', mark: false },
      ] },
  ]
}, () => [])

const tokens = collection<StoredToken[]>('hp_tokens', () => [
  { id: 'tok-1', type: 'file', name: 'Payroll-2026-Q4', value: 'Payroll-2026-Q4.xlsx', password: null, plant_at: '\\\\SRV-FILE\\HR', created_at: daysAgo(9) },
  { id: 'tok-2', type: 'credential', name: 'svc-backup-old', value: 'svc-backup-old', password: 'Bk!7mQ2xv-Lr9', plant_at: 'Password manager, shared folder "IT"', created_at: daysAgo(9) },
  { id: 'tok-3', type: 'url', name: 'Wiki intranet link', value: 'https://192.168.10.250:8443/t/q8f2k1m7xz', password: null, plant_at: 'Intranet wiki, page "Admin links"', created_at: daysAgo(9) },
  { id: 'tok-4', type: 'dns', name: 'Backup script host', value: 'backup-7k2q.vedette.internal', password: null, plant_at: 'Backup script config', created_at: daysAgo(9) },
], () => [])

const NETBIOS_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$/
const TOKEN_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/
const TOKEN_LABEL: Record<TokenType, string> = { file: 'File token', credential: 'Credential token', url: 'URL token', dns: 'DNS token' }

const toInt = (ip: string) => ip.split('.').reduce((n, x) => n * 256 + Number(x), 0)
// Mạng của hộp: dữ liệu mẫu 192.168.10.0/24; cài sạch theo dải LAN người dùng khai (boxInfo).
function inLan(ip: string) {
  const lan = boxInfo().lan
  if (!lan) return false
  const [base = '0.0.0.0', bits = '24'] = lan.split('/')
  const size = 2 ** (32 - Number(bits))
  return toInt(ip) >= toInt(base) && toInt(ip) < toInt(base) + size
}
const assetName = (a: { hostname: string | null; ip: string }) => a.hostname ?? a.ip
const deviceAt = (ip: string) => assetsStore.get().find((a) => a.ip === ip)
const byAge = (l: StoredTrapIP[]) => [...l].sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))

// The real box takes minutes to bring an address up or down; the mock shows the same states for the answer to a change and the read right
// after it, and the read after that has settled (S-HP-1). Counted in reads, not in time. Kept in the config row, so it resets with the store.
const settlingNow = (id: string) => { const x = config.get().settle?.[id]; return x && x.left > 0 ? x.kind : undefined }
const settle = (id: string, kind: 'starting' | 'stopping') => config.update((c) => ({ ...c, settle: { ...c.settle, [id]: { kind, left: 1 } } }))
/** A read of the overview or the list has been answered: whatever was settling is one read closer to done. */
function settleOneRead() {
  const s = config.get().settle
  if (!s || !Object.values(s).some((x) => x.left > 0)) return
  config.update((c) => ({ ...c, settle: Object.fromEntries(Object.entries(c.settle ?? {}).map(([k, x]) => [k, { ...x, left: Math.max(0, x.left - 1) }])) }))
}

// The mock host always succeeds at once (except a seeded failure); the MAC carries the vendor's OUI, else a stable locally administered one.
const hex2 = (n: number) => n.toString(16).padStart(2, '0')
function macOf(t: StoredTrapIP) {
  const tail = t.ip.split('.').slice(1).map((n) => hex2(Number(n))).join(':')
  const oui = VENDORS.find((v) => v.id === t.vendor)?.oui.toLowerCase()
  return oui ? `${oui}:${tail}` : `06:b7:36:${tail}`
}

function stateOf(t: StoredTrapIP): { state: TrapState; reason: string | null } {
  const s = settlingNow(t.id)
  if (!t.enabled) return { state: s === 'stopping' ? 'stopping' : 'off', reason: null }
  if (deviceAt(t.ip)) return { state: 'conflict', reason: 'a device of the inventory has this address' }
  if (t.fail) return { state: 'failed', reason: t.fail }
  if (s === 'starting') return { state: 'starting', reason: null }
  return { state: 'listening', reason: null }
}
// What the D-83 OUI table says for each vendor's prefix (modules/honeypot reads content/oui).
const MAC_VENDOR: Record<TrapVendor, string> = {
  dell: 'Dell Inc.', hp: 'Hewlett Packard', vmware: 'VMware, Inc.', hyperv: 'Microsoft Corporation', supermicro: 'Super Micro Computer, Inc.', synology: 'Synology Incorporated',
  qnap: 'QNAP Systems, Inc.', brother: 'Brother industries, LTD.', canon: 'CANON INC.', hikvision: 'Hangzhou Hikvision Digital Technology Co.,Ltd.', dahua: 'Zhejiang Dahua Technology Co., Ltd.', axis: 'Axis Communications AB',
}
const linkOf = (ip: string) => `vdh${ip.split('.').map((n) => hex2(Number(n))).join('')}`

function trapIpView(t: StoredTrapIP): TrapIP {
  const { fail: _f, ...rest } = t
  const st = stateOf(t)
  const held = st.state === 'listening'
  const services = HP_SERVICES.filter((s) => t.services.includes(s))
  const last = hitsStore.get().filter((h) => !h.is_test && (h.kind ?? 'service') === 'service' && h.trap_ip === t.ip).sort((a, b) => b.ts.localeCompare(a.ts))[0]
  const dev = deviceAt(t.ip)
  return {
    ...rest, services, ...st, mac: held ? macOf(t) : null, mac_vendor: held && t.vendor ? MAC_VENDOR[t.vendor] : null,
    attachment: held ? { kind: 'macvlan', link: linkOf(t.ip), parent: 'eth0' } : null, open_services: held ? services : [],
    last_hit_at: last?.ts ?? null, device_id: dev?.id ?? null, device_name: dev ? assetName(dev) : null,
  }
}

const maskPassword = (pw: string) => '•'.repeat(8) + (pw.length >= 8 ? pw.slice(-4) : '')

function tokenView(t: StoredToken): Token {
  const own = hitsStore.get().filter((h) => h.token_id === t.id).sort((a, b) => b.ts.localeCompare(a.ts))
  return { ...t, last_triggered_at: own[0]?.ts ?? null, triggers: own.filter((h) => !h.is_test).length }
}

/** Device types that really exist in the inventory, so a Trap IP of that type blends in. */
function suggestions(): TrapSuggestion[] {
  const assets = assetsStore.get()
  const out: TrapSuggestion[] = []
  for (const p of PRESETS) {
    const m = assets.filter((a) => (p.id === 'file_server' ? a.kind === 'server' && /windows/i.test(a.os?.value ?? '') || a.services.some((s) => s.port === 445 && a.kind === 'server')
      : p.id === 'linux' ? a.kind === 'server' && /linux|ubuntu|debian/i.test(a.os?.value ?? '')
      : p.id === 'database' ? a.kind === 'server' && a.services.some((s) => s.port === 1433)
      : p.kinds.includes(a.kind)))
    if (m.length) out.push({ preset: p.id, count: m.length, examples: m.slice(0, 3).map(assetName) })
  }
  return out
}

/** Addresses near the top of the /24 of the box that nothing uses yet. ponytail: assumes a /24, ranges wider than that still get .230-.249 of the first block. */
function spareIps(): string[] {
  const lan = boxInfo().lan
  if (!lan) return []
  const prefix = (lan.split('/')[0] ?? '').split('.').slice(0, 3).join('.')
  const used = new Set([...assetsStore.get().map((a) => a.ip), ...trapIps.get().map((d) => d.ip), boxInfo().ip])
  return Array.from({ length: 20 }, (_, i) => `${prefix}.${230 + i}`).filter((ip) => !used.has(ip) && inLan(ip)).slice(0, 5)
}

function hitView(h: Stored): Hit {
  const a = h.src_asset_id ? assetsStore.get().find((x) => x.id === h.src_asset_id) : undefined
  const kind = h.kind ?? 'service'
  return {
    id: h.id, ts: h.ts, kind, service: h.service, label: h.label ?? (h.service ? LABEL[h.service] : ''), port: h.port, src_ip: h.src_ip, src_asset_id: a ? a.id : null, src_name: a ? assetName(a) : null, is_test: h.is_test,
    excerpt: h.seed && h.service ? (SESSION[h.service]?.excerpt ?? h.excerpt) : h.excerpt, trap_ip: h.trap_ip, trap_hostname: h.trap_hostname,
  }
}

const RANK: Record<TrapState, number> = { listening: 5, starting: 4, stopping: 3, failed: 2, conflict: 1, off: 0 }

function overview(): HpOverview {
  const real = hitsStore.get().filter((h) => !h.is_test).sort((x, y) => y.ts.localeCompare(x.ts))
  const weekAgo = Date.now() - 7 * 864e5
  const all = byAge(trapIps.get())
  const on = all.filter((t) => t.enabled)
  const views = new Map(all.map((t) => [t.id, trapIpView(t)]))
  const traps: Trap[] = HP_SERVICES.map((service) => {
    const own = real.filter((h) => (h.kind ?? 'service') === 'service' && h.service === service)
    const serving = on.filter((t) => t.services.includes(service))
    const stopping = all.some((t) => !t.enabled && t.services.includes(service) && views.get(t.id)?.state === 'stopping')
    const state = serving.length ? serving.map((t) => views.get(t.id)!.state).reduce((a, b) => (RANK[b] > RANK[a] ? b : a)) : stopping ? 'stopping' : 'off'
    return {
      service, port: SERVICE_PORT[service], enabled: serving.length > 0, state, trap_ips: serving.map((t) => t.name),
      hits_7d: own.filter((h) => new Date(h.ts).getTime() >= weekAgo).length,
      last_hit_at: own[0]?.ts ?? null,
    }
  })
  const firstSmb = on.find((t) => t.services.includes('smb'))
  const firstHttp = on.find((t) => t.services.includes('http'))
  const today = new Date().toDateString()
  const last = real[0]
  return {
    problem: null, lan: boxInfo().lan, box: { ip: boxInfo().ip, name: boxInfo().hostname }, ignored_7d: config.get().ignored_7d,
    trap_ips: { total: all.length, enabled: on.length, listening: [...views.values()].filter((v) => v.state === 'listening').length, failing: [...views.values()].filter((v) => v.enabled && (v.state === 'failed' || v.state === 'conflict')).length },
    smb_name: firstSmb?.name ?? null, http_page: firstHttp ? (firstHttp.preset === 'nas' ? 'nas' : 'login') : null, traps,
    summary: { today: real.filter((h) => new Date(h.ts).toDateString() === today).length, week: real.filter((h) => new Date(h.ts).getTime() >= weekAgo).length, last_hit_at: last?.ts ?? null, last_src: last ? (hitView(last).src_name ?? last.src_ip) : null },
    updated_at: nowIso(),
  }
}

/** The checks of POST and PUT /honeypot/trap-ips, in the backend's order (mutate.go checkTrapIP). self = the id being changed. */
function checkInput(b: Partial<TrapIPInput>, self?: string): Response | { name: string; ip: string; preset: TrapPreset; vendor: TrapVendor | null; services: HpService[] } {
  const preset = b.preset as TrapPreset
  if (!PRESETS.some((p) => p.id === preset)) return fail(400, 'bad_preset', 'Choose what the Trap IP looks like.')
  const vendor = (b.vendor ?? null) as TrapVendor | null
  if (vendor !== null && !VENDORS.some((v) => v.id === vendor)) return fail(400, 'bad_vendor', 'Choose a vendor from the list, or none.')
  const example = PRESETS.find((p) => p.id === preset)!.example
  const name = String(b.name ?? '').trim()
  if (!name) return fail(400, 'bad_name', `Enter a name for the Trap IP, for example ${example}.`)
  if (!NETBIOS_RE.test(name) || /^\d+$/.test(name)) return fail(400, 'bad_name', `The name may only contain letters, digits and hyphens, up to 15 characters, not all digits, and must not start or end with a hyphen. Example ${example}.`)
  const others = trapIps.get().filter((x) => x.id !== self)
  if (assetsStore.get().some((a) => a.hostname?.toLowerCase() === name.toLowerCase()) || others.some((x) => x.name.toLowerCase() === name.toLowerCase())) return fail(409, 'name_in_use', `The name ${name} is already used by a device or another Trap IP. Pick another name.`)
  const ip = String(b.ip ?? '').trim()
  if (!ip) return fail(400, 'bad_ip', 'Enter an address for the Trap IP, for example 192.168.10.240. Pick an address no device uses.')
  if (!IPV4_RE.test(ip) || /(^|\.)0\d/.test(ip)) return fail(400, 'bad_ip', 'The address is not valid. Use the form 192.168.10.240, each number 0 to 255, no leading zeros.')
  if (!boxInfo().lan) return fail(400, 'no_lan', 'Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network the Trap IPs go on.')
  if (!inLan(ip) || ip.endsWith('.0') || ip.endsWith('.255')) return fail(400, 'ip_outside_lan', `The Trap IP must be inside the box's network (${boxInfo().lan}), not the network or broadcast address.`)
  if (ip === boxInfo().ip) return fail(400, 'ip_is_box', 'This is the Vedette box\'s own IP. Pick an unused IP.')
  const clash = deviceAt(ip)
  if (clash) return fail(409, 'ip_in_use', `IP ${ip} belongs to device ${assetName(clash)} in the inventory. Pick an unused IP.`)
  if (others.some((x) => x.ip === ip)) return fail(409, 'ip_in_use', `IP ${ip} is already another Trap IP.`)
  const raw = Array.isArray(b.services) ? b.services : null
  if (!raw || raw.length === 0) return fail(400, 'bad_services', 'Pick at least one service for the Trap IP to answer on.')
  if (raw.some((s) => !HP_SERVICES.includes(s)) || new Set(raw).size !== raw.length) return fail(400, 'bad_services', 'Pick services from the list, each once.')
  // After the form's own checks, as the box asks the host for its gateway last (trapips.go gatewayRefusal).
  if (ip === networkStore.get().mgmt.gateway) return fail(400, 'ip_is_gateway', 'This is the address of your router (the box\'s default gateway). Pick an unused IP.')
  return { name, ip, preset, vendor, services: HP_SERVICES.filter((s) => raw.includes(s)) }
}

/** The source of a real hit, for Respond on a trap incident (response D-509); null for a test hit or an unknown id. A scan's source
 * may be forged: it is confirmed only by a service hit (a completed connection) of the same source within the hour around it. */
export function hitSource(id: string): { ip: string; asset_id: string | null; kind: HitKind; confirmed: boolean } | null {
  const h = hitsStore.get().find((x) => x.id === id)
  if (!h || h.is_test) return null
  const kind = h.kind ?? 'service', at = Date.parse(h.ts)
  const confirmed = kind !== 'scan' || hitsStore.get().some((x) => !x.is_test && (x.kind ?? 'service') === 'service' && x.src_ip === h.src_ip && Math.abs(Date.parse(x.ts) - at) <= 36e5)
  return { ip: h.src_ip, asset_id: h.src_asset_id, kind, confirmed }
}

export const handlers = [
  http.get(`${API}/honeypot`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const b = overview()
    settleOneRead()
    return HttpResponse.json(b)
  }),

  http.get(`${API}/honeypot/hits`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const asset = new URL(request.url).searchParams.get('asset')
    const items = hitsStore.get().filter((h) => !asset || h.src_asset_id === asset).sort((a, b) => b.ts.localeCompare(a.ts)).map(hitView)
    return HttpResponse.json({ items })
  }),

  http.get(`${API}/honeypot/hits/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const h = hitsStore.get().find((x) => x.id === params.id)
    if (!h) return fail(404, 'not_found', 'No such trap hit. The list may have been cleaned up.')
    const a = h.src_asset_id ? assetsStore.get().find((x) => x.id === h.src_asset_id) : undefined
    const events = h.seed && h.service ? makeEvents(h.ts, h.src_ip, h.seed.srcName ?? `unknown device ${h.src_ip}`, h.service, h.trap_ip, h.seed.lan) : h.events
    const detail: HitDetail = { ...hitView(h), asset: a ? { id: a.id, kind: a.kind, ip: a.ip, approved: a.approved } : null, events, window_minutes: WINDOW_MINUTES }
    return HttpResponse.json(detail)
  }),

  // "Thử chạm bẫy": lần chạm có nhãn thử trên Trap IP đầu tiên đang bật có dịch vụ đó, đi từ chính hộp (bình thường bị loại trừ), không tính vào số liệu, không gửi cảnh báo.
  http.post(`${API}/honeypot/test-hit`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ service: HpService }>(request)
    const service = b.service as HpService
    if (!HP_SERVICES.includes(service)) return fail(400, 'bad_service', 'Choose a service from the list.')
    const on = byAge(trapIps.get()).filter((t) => t.enabled && t.services.includes(service))
    if (!on.length) return fail(409, 'trap_off', `No Trap IP that is on has ${LABEL[service]}. Add ${LABEL[service]} to a Trap IP, or turn one on, before testing.`)
    const t = on.find((x) => !deviceAt(x.ip))
    if (!t) return fail(409, 'ip_in_use', `Every Trap IP with ${LABEL[service]} clashes with a device, so the trap cannot listen. Change the address before testing.`)
    const ts = nowIso()
    const h: Stored = {
      id: newId('hit'), ts, kind: 'service', source_ip: boxInfo().ip ?? '0.0.0.0', service, port: SERVICE_PORT[service], src_ip: boxInfo().ip ?? '0.0.0.0', src_asset_id: null, is_test: true,
      excerpt: `[test] The Vedette box connected to ${LABEL[service]} port ${SERVICE_PORT[service]} on ${t.name} itself to check the trap`, trap_ip: t.ip, trap_hostname: t.name,
      events: [{ ts, source: 'vedette', text: `Test started by a user selecting "Test trap" for ${LABEL[service]}. Not an attacker.`, mark: true }],
    }
    hitsStore.update((l) => [h, ...l])
    audit('honeypot.test_hit', LABEL[service])
    return HttpResponse.json(hitView(h))
  }),

  // --- D-466: Trap IPs ---
  http.get(`${API}/honeypot/trap-ips`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const items = byAge(trapIps.get()).map(trapIpView)
    settleOneRead()
    return HttpResponse.json({ items, suggestions: suggestions(), spare_ips: spareIps(), spare_checked: assetsStore.get().some((a) => a.ip !== boxInfo().ip && inLan(a.ip)) })
  }),

  // Trap IPs = system scope → admin.
  http.post(`${API}/honeypot/trap-ips`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const v = checkInput(await body<Partial<TrapIPInput>>(request))
    if (v instanceof Response) return v
    if (trapIps.get().length >= MAX_TRAP_IPS) return fail(409, 'limit_reached', `The box can hold ${MAX_TRAP_IPS} Trap IPs. Delete one before adding another.`)
    const t: StoredTrapIP = { id: newId('tip'), ...v, enabled: true, created_at: nowIso() }
    trapIps.update((l) => [...l, t])
    settle(t.id, 'starting')
    audit('honeypot.trap_ip_add', t.ip, `${t.preset} ${t.name}: ${t.services.join(', ')}`)
    return HttpResponse.json(trapIpView(t), { status: 201 })
  }),

  http.put(`${API}/honeypot/trap-ips/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = trapIps.get().find((x) => x.id === params.id)
    if (!cur) return fail(404, 'not_found', 'No such Trap IP.')
    const v = checkInput(await body<Partial<TrapIPInput>>(request), cur.id)
    if (v instanceof Response) return v
    const next: StoredTrapIP = { ...cur, ...v }
    trapIps.update((l) => l.map((x) => (x.id === cur.id ? next : x)))
    if (next.enabled) settle(next.id, 'starting')
    audit('honeypot.trap_ip_edit', next.ip, `${next.preset} ${next.name}: ${next.services.join(', ')}`)
    return HttpResponse.json(trapIpView(next))
  }),

  http.patch(`${API}/honeypot/trap-ips/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'bad_body', 'enabled must be true or false.')
    let out: StoredTrapIP | undefined
    trapIps.update((l) => l.map((d) => (d.id === params.id ? (out = { ...d, enabled: b.enabled! }) : d)))
    if (!out) return fail(404, 'not_found', 'No such Trap IP.')
    settle(out.id, b.enabled ? 'starting' : 'stopping')
    audit(b.enabled ? 'honeypot.trap_ip_enable' : 'honeypot.trap_ip_disable', out.ip, out.name)
    return HttpResponse.json(trapIpView(out))
  }),

  http.delete(`${API}/honeypot/trap-ips/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const d = trapIps.get().find((x) => x.id === params.id)
    if (!d) return fail(404, 'not_found', 'No such Trap IP.')
    trapIps.update((l) => l.filter((x) => x.id !== d.id))
    audit('honeypot.trap_ip_delete', d.ip, d.name)
    return new HttpResponse(null, { status: 204 })
  }),

  // "Test scan": one labelled test alert as if a sweep touched the Trap IPs; from the box itself, not counted, no alert.
  http.post(`${API}/honeypot/test-scan`, () => {
    const denied = guard('operator'); if (denied) return denied
    const ips = byAge(trapIps.get()).filter((d) => d.enabled).map((d) => d.ip)
    if (ips.length < 2) return fail(409, 'need_decoys', 'Scan detection needs at least two Trap IPs that are on. Add a Trap IP first.')
    const ts = nowIso()
    const src = boxInfo().ip ?? '0.0.0.0'
    const h: Stored = {
      id: newId('hit'), ts, kind: 'scan', source_ip: src, service: null, label: `Port scan across ${ips.length} decoy IPs`, port: null, src_ip: src, src_asset_id: null, is_test: true,
      excerpt: `[test] The Vedette box simulated a sweep across ${ips.length} Trap IPs`, trap_ip: ips.join(', '), trap_hostname: 'Decoy sweep',
      events: [{ ts, source: 'vedette', text: 'Test started by a user selecting "Test scan". Not an attacker.', mark: true }],
    }
    hitsStore.update((l) => [h, ...l])
    audit('honeypot.test_scan', `${ips.length} decoys`)
    return HttpResponse.json(hitView(h))
  }),

  // --- S-HP-2: honey tokens ---
  http.get(`${API}/honeypot/tokens`, () => {
    const denied = guard('viewer'); if (denied) return denied
    // D-189 (WP-31 L14): the bait password is in full for an operator and an administrator; a viewer sees the last 4 characters, as the backend does.
    const role = currentUser()?.role
    const reveal = role === 'operator' || role === 'admin' // fail closed, as the backend does for an unknown role
    return HttpResponse.json({ items: tokens.get().map(tokenView).map((k) => (reveal || k.password === null ? k : { ...k, password: maskPassword(k.password) })) })
  }),

  http.post(`${API}/honeypot/tokens`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ type: TokenType; name: string; plant_at: string; ext?: 'docx' | 'xlsx' }>(request)
    // D-468: the box runs no DNS server, so a DNS token could never alert; the seeded one (tok-4) still lists, a new one is refused.
    if (b.type === 'dns') return fail(409, 'dns_unavailable', 'A DNS token cannot alert: the box runs no DNS server, so nothing would record a lookup of its name. Use a URL token or fake credentials instead.')
    if (!['file', 'credential', 'url'].includes(String(b.type))) return fail(400, 'bad_type', 'Choose a token type: decoy file, fake credentials or URL.')
    const name = String(b.name ?? '').trim()
    const plant = String(b.plant_at ?? '').trim().slice(0, 120)
    if (!TOKEN_NAME_RE.test(name)) return fail(400, 'bad_name', 'The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: Payroll-2026-Q4.')
    if (!plant) return fail(400, 'bad_plant_at', 'Say where you will plant it, for example \\\\SRV-FILE\\HR or "Password manager". This reminds you where to look when it fires.')
    if (b.type === 'file' && b.ext !== 'docx' && b.ext !== 'xlsx') return fail(400, 'bad_ext', 'Choose the file type: .docx or .xlsx.')
    if (tokens.get().some((x) => x.type === b.type && x.name.toLowerCase() === name.toLowerCase())) return fail(409, 'duplicate', 'A token of this type with this name already exists.')
    const rnd = Math.random().toString(36).slice(2, 12).padEnd(10, 'x')
    const box = boxAddress() ?? boxInfo().ip // D-465: the Box address, else the box's IP (as the box does), never its host name
    if (b.type === 'url' && !box) return fail(409, 'no_box_address', 'The box does not know an address other machines can reach yet. Set the Box address in Settings → Box network, then try again.')
    const value = b.type === 'file' ? `${name.replace(/\s+/g, '-')}.${b.ext}` : b.type === 'credential' ? name.replace(/\s+/g, '-').toLowerCase() : `https://${box}:8443/t/${rnd}`
    const password = b.type === 'credential' ? `Bk!${rnd.slice(0, 4)}-${rnd.slice(4).toUpperCase()}x9` : null
    const t: StoredToken = { id: newId('tok'), type: b.type!, name, value, password, plant_at: plant, created_at: nowIso() }
    tokens.update((l) => [t, ...l])
    audit('honeypot.token_add', value, b.type)
    return HttpResponse.json(tokenView(t), { status: 201 })
  }),

  http.delete(`${API}/honeypot/tokens/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = tokens.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    tokens.update((l) => l.filter((x) => x.id !== t.id))
    audit('honeypot.token_delete', t.value, t.type)
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${API}/honeypot/tokens/:id/test`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const t = tokens.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    const ts = nowIso()
    const src = boxInfo().ip ?? '0.0.0.0'
    const label = `${TOKEN_LABEL[t.type]} ${t.name}`
    const h: Stored = {
      id: newId('hit'), ts, kind: 'token', source_ip: src, service: null, label, token_id: t.id, port: null, src_ip: src, src_asset_id: null, is_test: true,
      excerpt: `[test] The Vedette box triggered ${label} to check it`, trap_ip: t.value, trap_hostname: label,
      events: [{ ts, source: 'vedette', text: `Test started by a user selecting "Test token" for ${t.name}. Not an attacker.`, mark: true }],
    }
    hitsStore.update((l) => [h, ...l])
    audit('honeypot.test_token', t.value)
    return HttpResponse.json(hitView(h))
  }),
]
