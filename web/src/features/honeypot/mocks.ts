// Mock API of module honeypot (S-HP-1, S-HP-2). Tables: hp_config, hp_hits, hp_decoys, hp_tokens. The response module reads hp_hits with peek. Traps only listen, they never hit back (LEGAL §3).
// Services/ports follow OpenCanary: SMB 445 (Samba-based), RDP 3389, SSH 22, MSSQL 1433, HTTP 80.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard, IPV4_RE } from '@/mocks/http'
import { assetsStore, boxInfo } from '@/mocks/stores'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import { personalityDef, PERSONALITIES } from './personalities'
import { HP_SERVICES, type Decoy, type DecoySuggestion, type Hit, type HitDetail, type HitEvent, type HitKind, type HpOverview, type HpService, type Personality, type Token, type TokenType, type Trap } from './types'

const PORTS: Record<HpService, number> = { smb: 445, rdp: 3389, ssh: 22, mssql: 1433, http: 80 }
const LABEL: Record<HpService, string> = { smb: 'SMB', rdp: 'RDP', ssh: 'SSH', mssql: 'MSSQL', http: 'HTTP' }
const WINDOW_MINUTES = 60

interface Config { secondary_ip: string | null; hostname: string; traps: Record<HpService, { enabled: boolean; since: string | null }>; ignored_7d: number }
// kind, source_ip, label, token_id: S-HP-2. Rows written before S-HP-2 lack them, so every read falls back (kind = service).
interface Stored { id: string; ts: string; kind?: HitKind; service: HpService | null; label?: string; token_id?: string; port: number | null; src_ip: string; source_ip?: string; src_asset_id: string | null; is_test: boolean; excerpt: string; events: HitEvent[]; trap_ip: string; trap_hostname: string; seed?: { srcName: string | null; lan: [string, string] } }
interface StoredDecoy { id: string; personality: Personality; name: string; ip: string; enabled: boolean; created_at: string }
type StoredToken = Omit<Token, 'last_triggered_at' | 'triggers'>

const SESSION: Record<HpService, { first: string; excerpt: string }> = {
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
  const p = PORTS[service]
  const fw = (dst: string) => `Firewall: ${src_ip} to ${dst} port ${p} allowed`
  return [
    { ts: at(-27), source: 'dhcp', text: `DHCP: ${srcName} (${src_ip}) renewed its lease`, mark: false },
    { ts: at(-14), source: 'ad', text: `AD: successful logon on ${srcName}`, mark: false },
    { ts: at(-4), source: 'firewall', text: fw(lanTargets[0]), mark: false },
    { ts: at(0), source: 'honeypot', text: `${LABEL[service]} trap: ${src_ip} connected to ${trapIp}:${p}`, mark: true },
    { ts: at(1), source: 'honeypot', text: `${LABEL[service]} trap: ${SESSION[service].first}`, mark: true },
    { ts: at(8), source: 'firewall', text: fw(lanTargets[1]), mark: false },
    { ts: at(21), source: 'honeypot', text: `${LABEL[service]} trap: session closed, no more traffic from ${src_ip}`, mark: true },
  ]
}

const config = collection<Config>('hp_config', () => ({
  secondary_ip: '192.168.10.240',
  hostname: 'FILESRV-OLD',
  traps: {
    smb: { enabled: true, since: daysAgo(20) }, rdp: { enabled: true, since: daysAgo(20) }, ssh: { enabled: true, since: daysAgo(12) },
    mssql: { enabled: false, since: null }, http: { enabled: false, since: null },
  },
  ignored_7d: 14,
}), () => ({
  // Cài sạch: chưa có máy giả, mọi bẫy tắt; người dùng đặt IP phụ rồi mới bật.
  secondary_ip: null, hostname: '',
  traps: { smb: { enabled: false, since: null }, rdp: { enabled: false, since: null }, ssh: { enabled: false, since: null }, mssql: { enabled: false, since: null }, http: { enabled: false, since: null } },
  ignored_7d: 0,
}))

const hitsStore = collection<Stored[]>('hp_hits', () => {
  const ip = '192.168.10.240', host = 'FILESRV-OLD'
  const t1 = daysAgo(1, 1), t2 = daysAgo(4)
  return [
    { id: 'hit-seed-1', ts: t1, kind: 'service', source_ip: '192.168.10.107', service: 'smb', port: 445, src_ip: '192.168.10.107', src_asset_id: 'a-pc07', is_test: false, excerpt: '', trap_ip: ip, trap_hostname: host, events: [], seed: { srcName: 'PC-HR-01', lan: ['192.168.10.11', '192.168.10.10'] } },
    { id: 'hit-seed-2', ts: t2, kind: 'service', source_ip: '192.168.10.157', service: 'rdp', port: 3389, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false, excerpt: '', trap_ip: ip, trap_hostname: host, events: [], seed: { srcName: null, lan: ['192.168.10.13', '192.168.10.10'] } },
    // The same unknown device, later: used a planted credential, then swept the decoys.
    { id: 'hit-seed-3', ts: daysAgo(3), kind: 'token', source_ip: '192.168.10.157', service: null, label: 'Credential token svc-backup-old', token_id: 'tok-2', port: null, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false,
      excerpt: 'SMB logon attempt for "svc-backup-old" on SRV-FILE. This account exists only as bait.', trap_ip: 'svc-backup-old', trap_hostname: 'Credential token svc-backup-old',
      events: [
        { ts: daysAgo(3, 0.2), source: 'ad', text: 'AD: failed logon for svc-backup-old from 192.168.10.157 (account does not exist)', mark: true },
        { ts: daysAgo(3), source: 'honeypot', text: 'Credential token svc-backup-old was used from 192.168.10.157', mark: true },
        { ts: daysAgo(3, -0.1), source: 'firewall', text: 'Firewall: 192.168.10.157 to 192.168.10.10 port 445 allowed', mark: false },
      ] },
    { id: 'hit-seed-4', ts: daysAgo(2), kind: 'scan', source_ip: '192.168.10.157', service: null, label: 'Port scan across 3 decoy IPs', port: null, src_ip: '192.168.10.157', src_asset_id: 'a-unk01', is_test: false,
      excerpt: 'Touched 3 decoy IPs (.240, .241, .242) and 14 distinct ports in 38 seconds. Pattern: TCP SYN sweep.', trap_ip: '192.168.10.240-242', trap_hostname: 'Decoy sweep',
      events: [
        { ts: daysAgo(2, 0.02), source: 'honeypot', text: 'First probe: 192.168.10.157 to decoy 192.168.10.240 port 445', mark: true },
        { ts: daysAgo(2), source: 'honeypot', text: 'Scan detected: 3 decoy IPs, 14 ports in 38 seconds', mark: true },
        { ts: daysAgo(2, -0.1), source: 'firewall', text: 'Firewall: 192.168.10.157 to 192.168.10.13 port 3389 allowed', mark: false },
      ] },
  ]
}, () => [])

const decoys = collection<StoredDecoy[]>('hp_decoys', () => [
  { id: 'dec-1', personality: 'nas', name: 'NAS-ARCHIVE', ip: '192.168.10.241', enabled: true, created_at: daysAgo(9) },
  { id: 'dec-2', personality: 'printer', name: 'PRN-FLOOR2', ip: '192.168.10.242', enabled: true, created_at: daysAgo(9) },
], () => [])

const tokens = collection<StoredToken[]>('hp_tokens', () => [
  { id: 'tok-1', type: 'file', name: 'Payroll-2026-Q4', value: 'Payroll-2026-Q4.xlsx', password: null, plant_at: '\\\\SRV-FILE\\HR', created_at: daysAgo(9) },
  { id: 'tok-2', type: 'credential', name: 'svc-backup-old', value: 'svc-backup-old', password: 'Bk!7mQ2xv-Lr9', plant_at: 'Password manager, shared folder "IT"', created_at: daysAgo(9) },
  { id: 'tok-3', type: 'url', name: 'Wiki intranet link', value: 'https://vedette-hq:8443/t/q8f2k1m7xz', password: null, plant_at: 'Intranet wiki, page "Admin links"', created_at: daysAgo(9) },
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
const conflictAsset = (ip: string | null) => (ip ? assetsStore.get().find((a) => a.ip === ip) : undefined)

// The mock host always succeeds at once: a decoy listens when it is on and a trap is on, and has a stable locally administered MAC.
const macOf = (ip: string) => `06:b7:36:${ip.split('.').slice(1).map((n) => Number(n).toString(16).padStart(2, '0')).join(':')}`
function decoyView(d: StoredDecoy): Decoy {
  const anyTrap = Object.values(config.get().traps).some((t) => t.enabled)
  const state: Decoy['state'] = !d.enabled || !anyTrap ? 'off' : conflictAsset(d.ip) ? 'conflict' : 'listening'
  return { ...d, state, reason: d.enabled && !anyTrap ? 'No trap is on, so nothing listens on this address.' : state === 'conflict' ? 'A device of the inventory has this address' : null, mac: state === 'listening' ? macOf(d.ip) : null, services: personalityDef(d.personality).services }
}

const maskPassword = (pw: string) => '\u2022'.repeat(8) + (pw.length >= 8 ? pw.slice(-4) : '')

function tokenView(t: StoredToken): Token {
  const own = hitsStore.get().filter((h) => h.token_id === t.id).sort((a, b) => b.ts.localeCompare(a.ts))
  return { ...t, last_triggered_at: own[0]?.ts ?? null, triggers: own.filter((h) => !h.is_test).length }
}

/** Device types that really exist in the inventory, so a decoy of that type blends in. */
function suggestions(): DecoySuggestion[] {
  const assets = assetsStore.get()
  const label = (a: { hostname: string | null; ip: string }) => a.hostname ?? a.ip
  const out: DecoySuggestion[] = []
  for (const p of PERSONALITIES) {
    const m = assets.filter((a) => (p.id === 'windows_fs' ? a.kind === 'server' && /windows/i.test(a.os?.value ?? '') || a.services.some((s) => s.port === 445 && a.kind === 'server')
      : p.id === 'linux' ? a.kind === 'server' && /linux|ubuntu|debian/i.test(a.os?.value ?? '')
      : p.kinds.includes(a.kind)))
    if (m.length) out.push({ personality: p.id, count: m.length, examples: m.slice(0, 3).map(label) })
  }
  return out
}

/** Unused addresses near the top of the /24 of the box. ponytail: assumes a /24, ranges wider than that still get .230-.249 of the first block. */
function spareIps(): string[] {
  const lan = boxInfo().lan
  if (!lan) return []
  const prefix = (lan.split('/')[0] ?? '').split('.').slice(0, 3).join('.')
  const used = new Set([...assetsStore.get().map((a) => a.ip), ...decoys.get().map((d) => d.ip), config.get().secondary_ip, boxInfo().ip])
  return Array.from({ length: 20 }, (_, i) => `${prefix}.${230 + i}`).filter((ip) => !used.has(ip) && inLan(ip)).slice(0, 5)
}

function hitView(h: Stored): Hit {
  const a = h.src_asset_id ? assetsStore.get().find((x) => x.id === h.src_asset_id) : undefined
  const kind = h.kind ?? 'service'
  return {
    id: h.id, ts: h.ts, kind, service: h.service, label: h.label ?? (h.service ? LABEL[h.service] : ''), port: h.port, src_ip: h.src_ip, src_asset_id: a ? a.id : null, src_name: a ? assetName(a) : null, is_test: h.is_test,
    excerpt: h.seed && h.service ? SESSION[h.service].excerpt : h.excerpt,
  }
}

function overview(): HpOverview {
  const c = config.get()
  const real = hitsStore.get().filter((h) => !h.is_test).sort((x, y) => y.ts.localeCompare(x.ts))
  const weekAgo = Date.now() - 7 * 864e5
  const conflict = conflictAsset(c.secondary_ip)
  const traps: Trap[] = HP_SERVICES.map((service) => {
    const own = real.filter((h) => (h.kind ?? 'service') === 'service' && h.service === service)
    const tr = c.traps[service]
    return {
      service, port: PORTS[service], enabled: tr.enabled, since: tr.since,
      state: !tr.enabled ? 'off' : conflict ? 'conflict' : 'listening',
      hits_7d: own.filter((h) => new Date(h.ts).getTime() >= weekAgo).length,
      last_hit_at: own[0]?.ts ?? null,
    }
  })
  const today = new Date().toDateString()
  const last = real[0]
  return {
    secondary_ip: c.secondary_ip, secondary_mac: c.secondary_ip && traps.some((t) => t.state === 'listening') ? macOf(c.secondary_ip) : null, problem: null, hostname: c.hostname, lan: boxInfo().lan, box: { ip: boxInfo().ip, name: boxInfo().hostname }, ignored_7d: c.ignored_7d,
    conflict_asset: conflict ? { id: conflict.id, name: assetName(conflict) } : null, traps,
    summary: { today: real.filter((h) => new Date(h.ts).toDateString() === today).length, week: real.filter((h) => new Date(h.ts).getTime() >= weekAgo).length, last_hit_at: last?.ts ?? null, last_src: last ? (hitView(last).src_name ?? last.src_ip) : null },
    updated_at: nowIso(),
  }
}

export const handlers = [
  http.get(`${API}/honeypot`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(overview())
  }),

  // Cấu hình bẫy = phạm vi hệ thống → admin.
  http.put(`${API}/honeypot/config`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ secondary_ip: string; hostname: string }>(request)
    const ip = String(b.secondary_ip ?? '').trim()
    const hostname = String(b.hostname ?? '').trim()
    // An empty IP removes the decoy IP, only while every trap is off (a resource in use cannot be released).
    if (!ip && config.get().secondary_ip) {
      if (Object.values(config.get().traps).some((t) => t.enabled)) return fail(409, 'traps_on', 'Turn all traps off before removing the decoy IP.')
      if (!hostname) return fail(400, 'bad_hostname', 'Enter a fake hostname, for example FILESRV-OLD. Pick a name that looks like an old file server in your company.')
      audit('honeypot.config', config.get().secondary_ip!, `decoy IP removed, hostname ${hostname}`)
      config.update((c) => ({ ...c, secondary_ip: null, hostname }))
      return HttpResponse.json(overview())
    }
    if (!ip) return fail(400, 'bad_ip', 'Enter a secondary IP for the decoy, for example 192.168.10.240. Pick an address no device uses.')
    if (!IPV4_RE.test(ip) || /(^|\.)0\d/.test(ip)) return fail(400, 'bad_ip', 'The secondary IP is not valid. Use the form 192.168.10.240, each number 0 to 255, no leading zeros.')
    if (!boxInfo().lan) return fail(400, 'no_lan', 'Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network the box is on.')
    if (!inLan(ip) || ip.endsWith('.0') || ip.endsWith('.255')) return fail(400, 'ip_outside_lan', `The secondary IP must be inside the box's network (${boxInfo().lan}), not the network or broadcast address.`)
    if (ip === boxInfo().ip) return fail(400, 'ip_is_box', 'This is the Vedette box\'s own IP. Pick an unused IP.')
    const clash = conflictAsset(ip)
    if (clash) return fail(409, 'ip_in_use', `IP ${ip} belongs to device ${assetName(clash)} in the inventory. Pick an unused IP.`)
    if (!hostname) return fail(400, 'bad_hostname', 'Enter a fake hostname, for example FILESRV-OLD. Pick a name that looks like an old file server in your company.')
    // NetBIOS: chữ, số, dấu gạch ngang; không dấu chấm, không gạch dưới, không bắt đầu hoặc kết thúc bằng gạch ngang; tối đa 15 ký tự.
    if (!/^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$/.test(hostname) || /^\d+$/.test(hostname)) return fail(400, 'bad_hostname', 'The fake hostname may only contain letters, digits and hyphens, up to 15 characters (NetBIOS limit), not all digits, and must not start or end with a hyphen. Example FILESRV-OLD.')
    const hostClash = assetsStore.get().find((a) => a.hostname?.toLowerCase() === hostname.toLowerCase())
    if (hostClash) return fail(409, 'hostname_in_use', `The name ${hostname} belongs to device ${hostClash.ip} in the inventory. Pick another name.`)
    config.update((c) => ({ ...c, secondary_ip: ip, hostname }))
    audit('honeypot.config', ip, `decoy hostname ${hostname}`)
    return HttpResponse.json(overview())
  }),

  http.patch(`${API}/honeypot/traps/:service`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const service = String(params.service) as HpService
    if (!HP_SERVICES.includes(service)) return fail(404, 'not_found', 'No trap for this service.')
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'bad_body', 'enabled must be true or false.')
    const c = config.get()
    if (b.enabled) {
      if (!c.secondary_ip) return fail(409, 'no_secondary_ip', 'Set a secondary IP for the traps before turning one on.')
      const clash = conflictAsset(c.secondary_ip)
      if (clash) return fail(409, 'ip_in_use', `The secondary IP ${c.secondary_ip} clashes with device ${assetName(clash)}. Change the secondary IP before turning a trap on.`)
    }
    config.update((x) => ({ ...x, traps: { ...x.traps, [service]: { enabled: b.enabled!, since: b.enabled ? nowIso() : null } } }))
    audit(b.enabled ? 'honeypot.trap_enable' : 'honeypot.trap_disable', LABEL[service])
    return HttpResponse.json(overview())
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
    const detail: HitDetail = { ...hitView(h), trap_ip: h.trap_ip, trap_hostname: h.trap_hostname, asset: a ? { id: a.id, kind: a.kind, ip: a.ip, approved: a.approved } : null, events, window_minutes: WINDOW_MINUTES }
    return HttpResponse.json(detail)
  }),

  // "Thử chạm bẫy": lần chạm có nhãn thử, đi từ chính hộp (bình thường bị loại trừ), không tính vào số liệu, không gửi cảnh báo.
  http.post(`${API}/honeypot/test-hit`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ service: HpService }>(request)
    const service = b.service as HpService
    if (!HP_SERVICES.includes(service)) return fail(400, 'bad_service', 'Choose a service: SMB, RDP, SSH, MSSQL or HTTP.')
    const c = config.get()
    if (!c.traps[service].enabled || !c.secondary_ip) return fail(409, 'trap_off', `The ${LABEL[service]} trap is off. Turn it on before testing.`)
    const clash = conflictAsset(c.secondary_ip)
    if (clash) return fail(409, 'ip_in_use', `The secondary IP ${c.secondary_ip} clashes with device ${assetName(clash)}, so the trap cannot listen. Change the secondary IP before testing.`)
    const ts = nowIso()
    const h: Stored = {
      id: newId('hit'), ts, kind: 'service', source_ip: boxInfo().ip ?? '0.0.0.0', service, port: PORTS[service], src_ip: boxInfo().ip ?? '0.0.0.0', src_asset_id: null, is_test: true,
      excerpt: `[test] The Vedette box connected to ${LABEL[service]} port ${PORTS[service]} itself to check the trap`, trap_ip: c.secondary_ip, trap_hostname: c.hostname,
      events: [{ ts, source: 'vedette', text: `Test started by a user selecting "Test trap" for ${LABEL[service]}. Not an attacker.`, mark: true }],
    }
    hitsStore.update((l) => [h, ...l])
    audit('honeypot.test_hit', LABEL[service])
    return HttpResponse.json(hitView(h))
  }),

  // --- S-HP-2: decoy personalities ---
  http.get(`${API}/honeypot/decoys`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: decoys.get().map(decoyView), suggestions: suggestions(), spare_ips: spareIps(), spare_checked: assetsStore.get().some((a) => a.ip !== boxInfo().ip && inLan(a.ip)) })
  }),

  http.post(`${API}/honeypot/decoys`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ personality: Personality; name: string; ip: string }>(request)
    if (!PERSONALITIES.some((p) => p.id === b.personality)) return fail(400, 'bad_personality', 'Choose what the decoy should look like.')
    const ip = String(b.ip ?? '').trim()
    const name = String(b.name ?? '').trim()
    if (!IPV4_RE.test(ip) || /(^|\.)0\d/.test(ip)) return fail(400, 'bad_ip', 'The decoy IP is not valid. Pick a spare address such as 192.168.10.243.')
    if (!boxInfo().lan) return fail(400, 'no_lan', 'Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network the decoys go on.')
    if (!inLan(ip) || ip.endsWith('.0') || ip.endsWith('.255')) return fail(400, 'ip_outside_lan', `The decoy IP must be inside the box's network (${boxInfo().lan}), not the network or broadcast address.`)
    if (ip === boxInfo().ip) return fail(400, 'ip_is_box', 'This is the Vedette box\'s own IP. Pick an unused IP.')
    const clash = conflictAsset(ip)
    if (clash) return fail(409, 'ip_in_use', `IP ${ip} belongs to device ${assetName(clash)} in the inventory. Pick an unused IP.`)
    if (ip === config.get().secondary_ip || decoys.get().some((d) => d.ip === ip)) return fail(409, 'ip_in_use', `IP ${ip} is already used by another decoy.`)
    if (!NETBIOS_RE.test(name) || /^\d+$/.test(name)) return fail(400, 'bad_hostname', 'The decoy name may only contain letters, digits and hyphens, up to 15 characters, not all digits, and must not start or end with a hyphen. Example PRN-FLOOR2.')
    if (assetsStore.get().some((a) => a.hostname?.toLowerCase() === name.toLowerCase()) || decoys.get().some((d) => d.name.toLowerCase() === name.toLowerCase())) return fail(409, 'hostname_in_use', `The name ${name} is already used by a device or another decoy.`)
    const d: StoredDecoy = { id: newId('dec'), personality: b.personality!, name, ip, enabled: true, created_at: nowIso() }
    decoys.update((l) => [...l, d])
    audit('honeypot.decoy_add', ip, `${b.personality} ${name}`)
    return HttpResponse.json(decoyView(d), { status: 201 })
  }),

  http.patch(`${API}/honeypot/decoys/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'bad_body', 'enabled must be true or false.')
    let out: StoredDecoy | undefined
    decoys.update((l) => l.map((d) => (d.id === params.id ? (out = { ...d, enabled: b.enabled! }) : d)))
    if (!out) return fail(404, 'not_found', 'No such decoy.')
    audit(b.enabled ? 'honeypot.decoy_enable' : 'honeypot.decoy_disable', out.ip)
    return HttpResponse.json(decoyView(out))
  }),

  http.delete(`${API}/honeypot/decoys/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const d = decoys.get().find((x) => x.id === params.id)
    if (!d) return fail(404, 'not_found', 'No such decoy.')
    decoys.update((l) => l.filter((x) => x.id !== d.id))
    audit('honeypot.decoy_delete', d.ip, d.name)
    return new HttpResponse(null, { status: 204 })
  }),

  // "Test scan": one labelled test alert as if a sweep touched the decoy IPs; from the box itself, not counted, no alert.
  http.post(`${API}/honeypot/test-scan`, () => {
    const denied = guard('operator'); if (denied) return denied
    const ips = [config.get().secondary_ip, ...decoys.get().filter((d) => d.enabled).map((d) => d.ip)].filter((x): x is string => !!x)
    if (ips.length < 2) return fail(409, 'need_decoys', 'Scan detection needs at least two decoy IPs. Add a decoy first.')
    const ts = nowIso()
    const src = boxInfo().ip ?? '0.0.0.0'
    const h: Stored = {
      id: newId('hit'), ts, kind: 'scan', source_ip: src, service: null, label: `Port scan across ${ips.length} decoy IPs`, port: null, src_ip: src, src_asset_id: null, is_test: true,
      excerpt: `[test] The Vedette box simulated a sweep across ${ips.length} decoy IPs`, trap_ip: ips.join(', '), trap_hostname: 'Decoy sweep',
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
    if (!['file', 'credential', 'url', 'dns'].includes(String(b.type))) return fail(400, 'bad_type', 'Choose a token type: decoy file, fake credentials, URL or DNS name.')
    const name = String(b.name ?? '').trim()
    const plant = String(b.plant_at ?? '').trim().slice(0, 120)
    if (!TOKEN_NAME_RE.test(name)) return fail(400, 'bad_name', 'The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: Payroll-2026-Q4.')
    if (!plant) return fail(400, 'bad_plant_at', 'Say where you will plant it, for example \\\\SRV-FILE\\HR or "Password manager". This reminds you where to look when it fires.')
    if (b.type === 'file' && b.ext !== 'docx' && b.ext !== 'xlsx') return fail(400, 'bad_ext', 'Choose the file type: .docx or .xlsx.')
    if (tokens.get().some((x) => x.type === b.type && x.name.toLowerCase() === name.toLowerCase())) return fail(409, 'duplicate', 'A token of this type with this name already exists.')
    const rnd = Math.random().toString(36).slice(2, 12).padEnd(10, 'x')
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20) || 'token'
    const box = boxInfo().hostname
    const value = b.type === 'file' ? `${name.replace(/\s+/g, '-')}.${b.ext}` : b.type === 'credential' ? name.replace(/\s+/g, '-').toLowerCase() : b.type === 'url' ? `https://${box}:8443/t/${rnd}` : `${slug}-${rnd.slice(0, 4)}.vedette.internal`
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
