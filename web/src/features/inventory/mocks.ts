// Mock API module inventory (S-INV-1..4). Tài sản nằm ở assetsStore dùng chung; bảng riêng của module tiền tố inv_.
// Observation không bao giờ bị ghi đè (ARCHITECTURE §4): sửa tay chỉ thêm một observation nguồn "khai tay".
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, CIDR_RE, currentUser, fail, guard, IPV4_RE } from '@/mocks/http'
import { assetsStore, boxInfo, installStore, isOn, findingsStore } from '@/mocks/stores'
import { matchAssetToKev } from '@/mocks/match'
import { collection, dataMode, daysAgo, newId, nowIso } from '@/mocks/db'
import { networkStore, spanStatusOf } from '@/mocks/network'
import type { Asset, AssetKind, ObsSource, Software } from '@/lib/types'
import { OSQUERY_SCHEDULE } from './agentConfig'
import { linuxInstallScript, NO_BOX_ADDRESS, OSQUERY_VERSION, windowsInstallScript } from './installScripts'
import { sha256Hex } from './kinds'
import { customEntry, findById, findCatalog, searchCatalog, type CatalogEntry } from './catalog'
import type {
  AddDeviceInput, AddDeviceResult, AgentToken, DeviceDetail, DeviceRow, DevicesResponse, ImportResult,
  InventorySettings, ObsField, Observation, RegularScan, Sensor, SettingsInput, SoftwareView, WazuhConnection, WazuhInput,
} from './types'
import { KINDS } from './types'
import { cidrRange, hasHostBits, isPrivateCidr, normalizeRange, overlapping } from './validate'

// Địa chỉ hộp Vedette đưa vào cấu hình agent: Vedette phục vụ cả giao diện lẫn API trên https://<IP hộp>:8443 (TLS). Không biết IP thì để chỗ trống rõ ràng, không bịa.
const serverUrl = () => `https://${boxInfo().ip ?? NO_BOX_ADDRESS}:8443`
const noBoxAddress = () => fail(404, 'no_box_address', "This box knows no address that other machines can reach, so an install script would point nowhere. Open Vedette at its network address; on a container-only install first set VEDETTE_BIND_IP to this machine's LAN address and VEDETTE_HOSTS to that address or a name for it. Then copy the command again.")
const FIELD_ORDER: ObsField[] = ['kind', 'hostname', 'mac', 'vendor', 'model', 'os']

const kevVulns = (kev as { vulns: { cve: string; vendor: string; product: string }[] }).vulns
const cvesFor = (keys: string[]) => kevVulns.filter((v) => keys.includes(`${v.vendor}|${v.product}`.toLowerCase())).map((v) => v.cve)

// ---- bảng riêng ----
interface Meta { suspicious?: boolean; fragile_manual?: boolean; regular_scan?: RegularScan }
export type StoredObs = Omit<Observation, 'current'>
const metaStore = collection<Record<string, Meta>>('inv_meta', () => ({}))
const obsStore = collection<Record<string, StoredObs[]>>('inv_obs', () => ({}))
const notifyStore = collection<{ enabled: boolean }>('inv_notify', () => ({ enabled: true }))
const settingsStore = collection<InventorySettings>('inv_settings', () => ({
  lan_ranges: ['192.168.10.0/24', '192.168.20.0/24'],
  active: { enabled: true, days: [1, 2, 3, 4, 5, 6, 7], from: '23:00', to: '05:00', rate: 50, exclusions: [] },
  fragile_kinds: ['printer', 'camera', 'nvr', 'nas', 'ap', 'iot'], regular_scan_kinds: [],
  scope_confirmed_at: daysAgo(36), scope_confirmed_by: 'admin@acme.example',
}), () => ({
  // Cài sạch: chưa có dải mạng nào, chưa xác nhận phạm vi nên chưa quét chủ động. Người quản trị khai ở trang Phạm vi quét.
  lan_ranges: [],
  active: { enabled: false, days: [1, 2, 3, 4, 5, 6, 7], from: '23:00', to: '05:00', rate: 50, exclusions: [] },
  fragile_kinds: ['printer', 'camera', 'nvr', 'nas', 'ap', 'iot'], regular_scan_kinds: [],
  scope_confirmed_at: null, scope_confirmed_by: null,
}))
// Chỉ cảm biến của chính hộp này (đa site chưa hỗ trợ — chủ dự án, D-28).
type StoredSensor = Omit<Sensor, 'interface' | 'interfaces' | 'span' | 'chosen' | 'span_status' | 'capture_error'>
const sensorsStore = collection<StoredSensor[]>('sp_sensor', () => [
  { id: 'sn-local', name: 'vedette-hq', status: 'online', last_seen: nowIso(), version: '0.1.0', devices_seen: 30 },
], () => [
  // Cài sạch: cảm biến của chính hộp, chưa thấy thiết bị nào.
  { id: 'sn-local', name: boxInfo().hostname, status: 'online', last_seen: nowIso(), version: '0.1.0', devices_seen: 0 },
])
/** Container-only install (D-263, D-387, D-393): the cards the sensor container reported in its heartbeat and the card the admin
 *  chose (null: the default card, D-380), SPAN or not. A clean install has not started the sensor yet (compose.sensors.yaml): no heartbeat, no card. */
type ReportedCard = { name: string; ipv4: string | null; link: boolean }
/** capture_error: what the sensor's heartbeat says about its capture (D-399 (3)); unset = it captures. A rootless container reports no_permission. */
export const containerSensorStore = collection<{ connected: boolean; cards: ReportedCard[]; chosen: string | null; span: boolean; capture_error?: Sensor['capture_error'] }>('sp_container', () => ({
  connected: true, chosen: null, span: false,
  cards: [{ name: 'eno1', ipv4: '192.168.10.20/24', link: true }, { name: 'eno2', ipv4: null, link: true }, { name: 'wlp2s0', ipv4: null, link: false }, { name: 'docker0', ipv4: '172.17.0.1/16', link: true }, { name: 'lo', ipv4: '127.0.0.1/8', link: true }],
}), () => ({ connected: false, cards: [], chosen: null, span: false }))
/** core/sensorlink VirtualIfaceName: a link that is not a network card. */
const VIRTUAL = /^(lo|veth|podman|cni|docker|br|virbr|vdh|bond|tun|tap|wg|dummy|vnet|macvtap|ifb|vedette)|[.@]/
/** GET /inventory/sensors on a container-only install: everything about the cards comes from the heartbeat (D-263); never_connected before the first one. */
function containerSensors() {
  const c = containerSensorStore.get()
  // D-380: of the cards that are up with an address, the one wired card, else the one card; two candidates → none.
  // The backend counts only a global IPv4 (globalIPv4); the fixtures hold no link-local address.
  // D-393: links that are not cards (sensorlink.VirtualIfaceName: loopback, container bridges, veth, VPN) are never the default nor listed.
  const cards = c.cards.filter((x) => !VIRTUAL.test(x.name))
  const withAddress = cards.filter((x) => x.link && x.ipv4)
  const wired = withAddress.filter((x) => !/^w[lw]/.test(x.name))
  const dflt = wired.length === 1 ? wired[0]!.name : wired.length === 0 && withAddress.length === 1 ? withAddress[0]!.name : null
  return sensorsStore.get().map((s) => ({
    ...s, status: c.connected ? s.status : 'never_connected' as const, last_seen: c.connected ? s.last_seen : null, version: c.connected ? s.version : null, devices_seen: c.connected ? s.devices_seen : 0,
    interface: c.chosen ?? dflt, interfaces: cards.map((x) => x.name).sort(), span: c.span, chosen: c.chosen !== null,
    span_status: c.span ? { verdict: 'ok' as const, packets_per_s: 140, other_macs: 12 } : { verdict: 'off' as const, packets_per_s: 0, other_macs: 0 },
    capture_error: c.connected ? (c.capture_error ?? null) : null, // only an online sensor's heartbeat says anything about now
  }))
}
const agentsStore = collection<AgentToken[]>('intake_agent_tokens', () => [
  { id: 'tk-osquery', name: 'osquery on SRV-AD and SRV-FILE', kind: 'osquery', last4: 'k3Pq', created_at: daysAgo(12), last_received: daysAgo(0, 3), hosts: 2, expires_at: new Date(Date.now() + 5 * 864e5).toISOString() },
], () => [])
type StoredWazuh = WazuhConnection & { password: string }
// Chứng chỉ CA của hộp (mock: giá trị giả, nhúng trong script như bản thật sẽ nhúng CA tự ký của hộp).
const MOCK_CA = '-----BEGIN CERTIFICATE-----\nMIIBmockVedetteBoxCA0000000000000000000000000000000000000000000000\n(mock certificate: the real box embeds its own CA here)\n-----END CERTIFICATE-----'
const installers = async () => {
  const box = serverUrl()
  const linux = linuxInstallScript(box, MOCK_CA)
  const windows = windowsInstallScript(box, MOCK_CA)
  return {
    osquery_version: OSQUERY_VERSION,
    linux: { url: `${box}/api/v1/install/osquery.sh`, sha256: await sha256Hex(linux), script: linux },
    windows: { url: `${box}/api/v1/install/osquery.ps1`, sha256: await sha256Hex(windows), script: windows },
  }
}
const expired = (t: AgentToken) => t.expires_at !== null && new Date(t.expires_at).getTime() < Date.now()
const wazuhStore = collection<StoredWazuh | null>('intake_wazuh', () => null, () => null)

// ---- tiện ích ----
const rand = (n: number, alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') => {
  const b = crypto.getRandomValues(new Uint8Array(n))
  return Array.from(b, (x) => alphabet[x % alphabet.length]).join('')
}
// eslint-disable-next-line no-control-regex
const LABEL_RE = /^[^<>\u0000-\u001f]{1,64}$/
const VERSION_RE = /^[\w.\-+() ]{1,40}$/u
const hasIp = (a: Asset) => a.ip !== '' && a.ip !== '—'
/** Đọc cài đặt; dải lưu với bit máy ("192.168.18.5/24") được đưa về địa chỉ mạng. Dải thiếu /prefix giữ nguyên để UI báo lỗi trên dòng đó, không kẹt các thao tác khác. */
function loadSettings(): InventorySettings {
  const cur = settingsStore.get()
  const next = [...new Set(cur.lan_ranges.map((r) => normalizeRange(r).value))]
  if (JSON.stringify(next) === JSON.stringify(cur.lan_ranges)) return cur
  const upd = { ...cur, lan_ranges: next }
  settingsStore.set(upd)
  return upd
}
const policyFragile = (kind: AssetKind) => settingsStore.get().fragile_kinds.includes(kind)

// ---- Chính hộp là thiết bị đầu tiên (D-53, S-INV-5) ----
export const BOX_ID = 'a-box'
const boxSoftware = (key: string, display: string, vendor: string, product: string, version: string, kev: string[]): Software => ({ id: `s-box-${key}`, display, vendor, product, version, kev, source: 'agent', confidence: 1 })
/** Gói trên hộp (dpkg), nguồn "this box" (tác nhân của chính hộp), độ tin cậy 1.0. Phiên bản khớp trạng thái hệ điều hành mẫu ở Settings, Updates. */
const BOX_SOFTWARE: Software[] = [
  boxSoftware('openssh', 'OpenSSH server', 'OpenBSD', 'OpenSSH', '9.6p1', ['openbsd|openssh']),
  boxSoftware('openssl', 'OpenSSL', 'OpenSSL', 'OpenSSL', '3.0.13', ['openssl|openssl']),
  boxSoftware('kernel', 'Linux kernel', 'Linux', 'Kernel', '6.8.0-71', ['linux|kernel']),
  boxSoftware('glibc', 'GNU C Library (libc6)', 'GNU', 'glibc', '2.39', ['gnu|glibc']),
  boxSoftware('curl', 'curl', 'Haxx', 'curl', '8.5.0', ['haxx|curl']),
  boxSoftware('caddy', 'Caddy web server (Vedette web interface)', 'Caddy', 'Caddy', '2.6.2', ['caddyserver|caddy']),
  boxSoftware('python3', 'Python 3 (OpenCanary)', 'Python', 'Python', '3.12.3', ['python|python']),
]
/** Đảm bảo hộp có trong kho, cả dữ liệu mẫu lẫn cài sạch; tên và IP lấy từ boxInfo() mỗi lần (chỉ đọc). Gọi trước mọi đọc/ghi tài sản của module. */
export function ensureBox() {
  const info = boxInfo()
  const ip = info.ip ?? '—'
  const cur = assetsStore.get().find((x) => x.id === BOX_ID)
  if (cur) {
    if (cur.ip !== ip || cur.hostname !== info.hostname) assetsStore.update((l) => l.map((x) => (x.id === BOX_ID ? { ...x, ip, hostname: info.hostname } : x)))
    return
  }
  const now = nowIso()
  const seen = (v: string): Asset['os'] => ({ value: v, source: 'agent', confidence: 1, seen_at: now })
  const a: Asset = {
    id: BOX_ID, site: 'hq', ip, mac: null, hostname: info.hostname, kind: 'server',
    vendor: seen('Vedette'), model: seen('Security box (appliance)'), os: seen('Ubuntu 24.04.3 LTS'),
    software: BOX_SOFTWARE, services: [
      { port: 22, proto: 'tcp', name: 'ssh', product: 'OpenSSH', version: '9.6p1', source: 'agent', confidence: 1 },
      { port: 8443, proto: 'tcp', name: 'https', product: 'Caddy', version: '2.6.2', source: 'agent', confidence: 1 },
    ],
    first_seen: dataMode() === 'sample' ? daysAgo(40) : now, last_seen: now, approved: true, fragile: false, origin: 'discovered',
  }
  assetsStore.update((l) => [a, ...l])
  matchAssetToKev(BOX_ID)
}
function allAssets(): Asset[] { ensureBox(); return assetsStore.get() }
// Hộp có mặt ngay khi mock khởi động, để trang chủ và Findings thấy phát hiện trên hộp mà không cần mở Devices trước. Test tự gọi ensureBox.
if (import.meta.env.MODE !== 'test') ensureBox()

function derive(a: Asset): StoredObs[] {
  const out: StoredObs[] = []
  const push = (field: ObsField, value: string, source: ObsSource, confidence: number, seen_at: string) => out.push({ id: `${a.id}:${field}:${out.length}`, field, value, source, confidence, seen_at })
  const manual = a.origin === 'manual'
  const own = a.id === BOX_ID // the box knows itself: not a passive guess
  const [src, conf]: [ObsSource, number] = own ? ['agent', 1] : manual ? ['manual', 1] : ['passive', 0.7]
  if (a.hostname) push('hostname', a.hostname, src, conf, a.first_seen)
  if (a.mac) push('mac', a.mac, 'passive', 0.99, a.first_seen)
  for (const f of ['vendor', 'model', 'os'] as const) {
    const o = a[f]
    if (!o) continue
    push(f, o.value, o.source, o.confidence, o.seen_at)
    // Lần thấy trước đó yếu hơn: chứng minh giá trị cũ không bị xoá khi có giá trị mới (dữ liệu mẫu).
    if (f === 'os' && o.source !== 'passive' && o.source !== 'manual') push('os', 'Unknown OS (guessed from packet TTL)', 'passive', 0.2, new Date(new Date(o.seen_at).getTime() - 7 * 864e5).toISOString())
  }
  push('kind', a.kind, src, conf, a.first_seen)
  return out
}

function obsOf(a: Asset): StoredObs[] {
  if (!obsStore.get()[a.id]) obsStore.update((m) => ({ ...m, [a.id]: derive(a) }))
  return obsStore.get()[a.id]!
}
function addObs(a: Asset, field: ObsField, value: string, source: ObsSource, confidence: number) {
  const cur = obsOf(a)
  obsStore.update((m) => ({ ...m, [a.id]: [...cur, { id: `${a.id}:${field}:${cur.length}:${Date.now().toString(36)}`, field, value, source, confidence, seen_at: nowIso() }] }))
}
/** Source rank (DATA_MODEL §5.1 (2), ARCHITECTURE §4): manual > agent > snmp > nmap = scan > passive. Unknown sources rank lowest. */
const SOURCE_RANK: Record<string, number> = { manual: 5, agent: 4, snmp: 3, nmap: 2, scan: 2, passive: 1 }
const sourceRank = (s: string) => SOURCE_RANK[s] ?? 0
/** > 0 when `a` wins over `b`: source rank, then higher confidence, then newer seen_at, then smaller id (so the result is deterministic). */
export function compareObs(a: StoredObs, b: StoredObs): number {
  return sourceRank(a.source) - sourceRank(b.source)
    || a.confidence - b.confidence
    || new Date(a.seen_at).getTime() - new Date(b.seen_at).getTime()
    || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0)
}
/** Current value of each field = the winning observation by compareObs. Nothing is overwritten: weaker values stay in the list. */
export function markCurrent(list: StoredObs[]): Observation[] {
  const best = new Map<ObsField, StoredObs>()
  for (const o of list) {
    const b = best.get(o.field)
    if (!b || compareObs(o, b) > 0) best.set(o.field, o)
  }
  return list.map((o) => ({ ...o, current: best.get(o.field)?.id === o.id }))
}

/** A device with no vendor, model or OS (seen only by ARP) takes its current hostname and MAC instead (walk 4: source "–"). */
function summaryOf(a: Asset): DeviceRow['summary'] {
  let f: { source: ObsSource; confidence: number }[] = [a.vendor, a.model, a.os].filter((x): x is NonNullable<typeof x> => x !== null)
  if (!f.length) f = markCurrent(obsOf(a)).filter((o) => o.current && (o.field === 'hostname' || o.field === 'mac'))
  if (!f.length) return null
  const top = f.reduce((m, x) => (x.confidence > m.confidence ? x : m))
  return { source: top.source, confidence: Math.min(...f.map((x) => x.confidence)) }
}
const findingsOf = (id: string) => findingsStore.get().filter((f) => f.asset_id === id).length
/** D-45, D-84: one gentle scan right after a fragile device, a device of unknown kind or one set to "never" is first seen (lowest speed, no service/OS detection); devices declared by hand and the box itself are never scanned. */
const scanInfo = (a: Asset) => ({
  is_box: a.id === BOX_ID,
  first_scan_at: a.origin === 'discovered' && a.id !== BOX_ID && (a.fragile || a.kind === 'unknown' || metaStore.get()[a.id]?.regular_scan === 'never') ? new Date(new Date(a.first_seen).getTime() + 4 * 60_000).toISOString() : null,
  regular_scan: metaStore.get()[a.id]?.regular_scan ?? ('follow' as RegularScan),
})
// Hộp luôn "vừa thấy": nó là máy đang chạy Vedette.
const live = (a: Asset): Asset => (a.id === BOX_ID ? { ...a, last_seen: nowIso() } : a)
const toRow = (a: Asset): DeviceRow => ({ ...live(a), ...scanInfo(a), suspicious: !!metaStore.get()[a.id]?.suspicious, findings_count: findingsOf(a.id), summary: summaryOf(a) })
const find = (id: string) => allAssets().find((x) => x.id === id)
const notFound = (_request?: Request) => fail(404, 'not_found', 'No such device. It may have been removed; go back to the list to see the remaining devices.')

function createManual(entry: CatalogEntry | null, o: { version?: string; name?: string; ip?: string; kind?: AssetKind }): Asset {
  const now = nowIso()
  const kind = o.kind ?? entry?.kind ?? 'unknown'
  const a: Asset = {
    id: newId('a'), site: 'hq', ip: o.ip || '—', mac: null, hostname: o.name || null, kind,
    vendor: entry ? { value: entry.vendor, source: 'manual', confidence: 1, seen_at: now } : null,
    model: null, os: null, services: [], first_seen: now, last_seen: now, approved: true, fragile: policyFragile(kind), origin: 'manual',
    software: entry ? [softwareOf(entry, o.version)] : [],
  }
  assetsStore.update((l) => [a, ...l])
  matchAssetToKev(a.id)
  return a
}
const softwareOf = (e: CatalogEntry, version?: string): Software => ({ id: newId('s'), display: e.display, vendor: e.vendor, product: e.product, version: version || null, kev: e.kev, source: 'manual', confidence: 1 })

const bad = (status: number, code: string, message: string) => ({ status, code, message })
type AddCheck = { err: ReturnType<typeof bad> } | { err?: undefined; entry: CatalogEntry | undefined; version: string; name: string; ip: string }
/** Sản phẩm: chọn trong danh mục (catalog_id) hoặc tự nhập hãng + sản phẩm ("không thấy sản phẩm?"). */
function resolveProduct(b: Partial<AddDeviceInput>): { entry?: CatalogEntry; err?: ReturnType<typeof bad> } {
  if (b.catalog_id) { const e = findById(b.catalog_id); return e ? { entry: e } : { err: bad(400, 'unknown_product', 'That product is not in the list. Pick one from the suggestions, or enter the vendor and product yourself.') } }
  const vendor = typeof b.vendor === 'string' ? b.vendor.trim() : ''
  const product = typeof b.product === 'string' ? b.product.trim() : ''
  if (!vendor && !product) return {}
  if (!vendor || !product) return { err: bad(400, 'incomplete_product', 'Enter both the vendor and the product, for example vendor "Fortinet" and product "FortiGate".') }
  if (!LABEL_RE.test(vendor) || !LABEL_RE.test(product)) return { err: bad(400, 'bad_product', 'Vendor and product are at most 64 characters each and cannot contain < or >.') }
  return { entry: customEntry(vendor, product) }
}
function validateAdd(_request: Request, b: Partial<AddDeviceInput>, requireProduct: boolean): AddCheck {
  const { entry, err } = resolveProduct(b)
  if (err) return { err }
  if (requireProduct && !entry) return { err: bad(400, 'unknown_product', 'Pick a product from the suggestions. Type a vendor or product name, for example "FortiGate".') }
  const version = typeof b.version === 'string' ? b.version.trim() : ''
  if (version && !VERSION_RE.test(version)) return { err: bad(400, 'bad_version', 'The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5.') }
  const name = typeof b.name === 'string' ? b.name.trim() : ''
  if (name && !LABEL_RE.test(name)) return { err: bad(400, 'bad_name', 'The name is at most 64 characters and cannot contain < or >.') }
  const ip = typeof b.ip === 'string' ? b.ip.trim() : ''
  if (ip && !IPV4_RE.test(ip)) return { err: bad(400, 'bad_ip', 'That IP address is not valid. Enter something like 192.168.10.25, or leave it empty if unknown.') }
  if (ip) { const dup = allAssets().find((x) => x.ip === ip); if (dup) return { err: bad(409, 'duplicate_ip', `IP ${ip} is already in the list (${dup.hostname ?? dup.id}). Open that device instead of adding a new one.`) } }
  return { entry, version, name, ip }
}

// ---- CSV ----
function csvCell(v: string | number | boolean | null | undefined): string {
  let s = v === null || v === undefined ? '' : String(v)
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}` // chống CSV injection khi mở bằng Excel
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}
/** Excel tiếng Việt thường lưu CSV phân cách bằng dấu chấm phẩy (hoặc tab): đoán theo dòng tiêu đề. */
function detectDelimiter(text: string): string {
  const first = text.split(/\r\n|\n|\r/).find((l) => l.trim()) ?? ''
  const count = (d: string) => first.split(d).length - 1
  return [';', '\t'].reduce((best, d) => (count(d) > count(best) ? d : best), ',')
}
/** Như bản Go: dấu nháy lạc / không đóng không dừng việc đọc, chỉ đánh dấu dòng (chỉ số dòng → lý do) để báo lỗi theo số dòng. */
function parseCsv(text: string): { rows: string[][]; problems: Map<number, string> } {
  const delim = detectDelimiter(text)
  const rows: string[][] = []
  const problems = new Map<number, string>()
  let row: string[] = []
  let cell = ''
  let q = false, atStart = true, closed = false, openRow = 0
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++ } else { q = false; closed = true } } else cell += c
    } else if (c === '"' && atStart) { q = true; atStart = false; openRow = rows.length }
    else if (c === delim) { row.push(cell); cell = ''; atStart = true; closed = false }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; atStart = true; closed = false }
    else {
      if (c === '"' || closed) problems.set(rows.length, 'A double quote is in the wrong place in this row. Put a whole cell in quotes, or remove the stray quote.')
      atStart = false; cell += c
    }
  }
  if (q) problems.set(openRow, 'A double quote was opened and never closed, so this row runs into the rows below it. Close the quote or remove it.')
  if (cell !== '' || row.length) { row.push(cell); rows.push(row) }
  return { rows, problems }
}
/** Hạ chữ thường, mọi ký tự lạ thành "_": "IP Address" → ip_address. */
const fold = (s: string) => s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')
const HEADER_ALIAS: Record<string, string> = {
  device: 'name', device_name: 'name', hostname: 'name', host_name: 'name', ip_address: 'ip', address: 'ip', software: 'product', application: 'product',
  product_name: 'product', ver: 'version', type: 'kind', device_type: 'kind',
}
// Nhãn loại như hiển thị trong giao diện ("Wi-Fi (AP)", "Camera recorder") cũng được nhận ngoài khoá (firewall, ap, nvr…).
const KIND_LABEL: Record<string, AssetKind> = {
  wi_fi_ap: 'ap', wifi: 'ap', access_point: 'ap', camera_recorder: 'nvr', iot_device: 'iot', website: 'web', laptop: 'pc', computer: 'pc', desktop: 'pc', other: 'unknown',
}
const parseKind = (text: string): AssetKind | undefined => { const k = fold(text); return KINDS.find((x) => x === k) ?? KIND_LABEL[k] }
/** Như rowShapeProblem của Go: nhiều ô có chữ hơn số cột, hoặc một ô duy nhất chứa cả dòng ngăn cách bằng ký tự khác tiêu đề; dòng ngắn thì chấp nhận. */
function rowShapeProblem(cells: string[], columns: number, delim: string): string {
  let n = cells.length
  while (n > 0 && !cells[n - 1]!.trim()) n--
  if (n > columns) return `This row has ${n} columns but the header has ${columns}. Check that every row uses the same separator (comma, semicolon or tab) as the header row.`
  if (cells.length === 1 && columns > 1 && [',', ';', '\t'].some((d) => d !== delim && cells[0]!.split(d).length - 1 >= columns - 1)) {
    return `This row is one cell but the header has ${columns} columns, and the row looks separated by a different character than the header. Use the same separator (comma, semicolon or tab) in every row.`
  }
  return ''
}
/** Như ipNote của Go: IP công cộng hoặc ngoài các dải đã lưu vẫn được thêm nhưng kèm ghi chú (Vedette không quét nó). */
function ipNote(ip: string, ranges: string[]): string {
  const [a, b] = ip.split('.').map(Number) as [number, number]
  const priv = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 127
  if (ranges.some((r) => { const c = cidrRange(r); const n = ip.split('.').reduce((x, y) => x * 256 + Number(y), 0); return n >= c.base && n < c.base + c.size })) return ''
  if (!priv) return `IP ${ip} is a public address. The device was added, but Vedette only scans your own network ranges.`
  if (ranges.length) return `IP ${ip} is outside your saved network ranges. The device was added, but Vedette will not scan it.`
  return ''
}
const MAX_IMPORT_BYTES = 200_000
const MAX_IMPORT_ROWS = 500

function applyFragilePolicy() {
  const meta = metaStore.get()
  const kinds = settingsStore.get().fragile_kinds
  assetsStore.update((l) => l.map((a) => (meta[a.id]?.fragile_manual ? a : { ...a, fragile: kinds.includes(a.kind) })))
}


const publicWazuh = ({ password: _p, ...rest }: StoredWazuh): WazuhConnection => rest
const wazuhAgentCount = () => Math.max(allAssets().filter((a) => a.kind === 'server' || a.kind === 'pc').length, 1)
const INTERVALS = [5, 15, 60, 360, 1440]
/** Kiểm tra form Wazuh như máy chủ thật sẽ làm; mô phỏng các lỗi hay gặp: sai địa chỉ, không tới được, sai mật khẩu. */
function checkWazuhInput(b: Partial<WazuhInput>, prev: StoredWazuh | null): { status: number; code: string; message: string } | null {
  const url = typeof b.url === 'string' ? b.url.trim() : ''
  let u: URL | null = null
  try { u = new URL(url) } catch { /* không phải URL */ }
  if (!u || u.protocol !== 'https:' || !u.hostname || u.username || u.password) return { status: 400, code: 'bad_url', message: 'Enter the Wazuh server API address starting with https://, for example https://wazuh-manager:55000. Do not put the user name or password in it.' }
  const user = typeof b.username === 'string' ? b.username.trim() : ''
  if (!/^[\w.@-]{1,64}$/.test(user)) return { status: 400, code: 'bad_username', message: 'Enter the read-only API user name (letters, digits, dot, dash, underscore; up to 64 characters).' }
  if (!b.password && !prev) return { status: 400, code: 'password_required', message: 'Enter the password of the read-only API user.' }
  if (b.password && b.password.length > 200) return { status: 400, code: 'bad_password', message: 'The password is too long (up to 200 characters).' }
  if (!INTERVALS.includes(Number(b.interval_minutes))) return { status: 400, code: 'bad_interval', message: 'Choose how often to sync: every 5, 15, 60, 360 or 1440 minutes.' }
  if (/unreachable|\.invalid$|(^|\.)down(\.|$)/i.test(u.hostname)) return { status: 502, code: 'wazuh_unreachable', message: `Could not reach ${u.origin}. Check the address and port (55000 by default) and that this box may connect to the Wazuh server.` }
  if (b.password === 'wrong') return { status: 422, code: 'wazuh_auth', message: 'Wazuh refused the user name or password. Check the read-only API user you created.' }
  return null
}
/** Mô phỏng một lần agent/Wazuh báo về: tới 3 máy chủ hoặc máy tính nhận phần mềm nguồn "agent" (tin cậy cao) và một quan sát hệ điều hành. */
function injectSample(): { devices: number; software: number } | { err: string } {
  const targets = allAssets().filter((a) => a.id !== BOX_ID && a.approved && (a.kind === 'server' || a.kind === 'pc')).slice(0, 3)
  if (!targets.length) return { err: 'There is no server or computer in the device list to match yet. Add a device first, then send sample data.' }
  let added = 0
  for (const a of targets) {
    const windows = /windows/i.test(a.os?.value ?? '') || /windows/i.test(a.hostname ?? '') || a.kind === 'pc'
    const picks = (windows ? ['Microsoft Office', 'Microsoft Edge'] : ['OpenSSH', 'Apache HTTP Server']).map((n) => findCatalog(n)).filter((e): e is CatalogEntry => !!e)
    const fresh = picks.filter((e) => !a.software.some((x) => x.product === e.product && x.vendor === e.vendor))
    const sw: Software[] = fresh.map((e, i) => ({ ...softwareOf(e, windows ? ['2021', '122.0'][i] : ['9.6p1', '2.4.58'][i]), source: 'agent' as const, confidence: 0.95 }))
    assetsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, software: [...x.software, ...sw] } : x)))
    matchAssetToKev(a.id)
    addObs(a, 'os', a.os?.value ?? (windows ? 'Windows Server 2019 (build 17763)' : 'Ubuntu 22.04.4 LTS'), 'agent', 0.95)
    added += sw.length
  }
  return { devices: targets.length, software: added }
}

export const handlers = [
  // ---- Danh sách thiết bị ----
  http.get(`${API}/inventory/devices`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const items = allAssets().map(toRow)
    return HttpResponse.json({
      items,
      counts: { all: items.length, pending: items.filter((a) => !a.approved).length, fragile: items.filter((a) => a.fragile).length, manual: items.filter((a) => a.origin === 'manual').length },
      notify_new: notifyStore.get().enabled,
      notify_available: isOn('notify'),
    } satisfies DevicesResponse)
  }),

  http.get(`${API}/inventory/catalog`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const q = (new URL(request.url).searchParams.get('q') ?? '').slice(0, 80)
    const r = searchCatalog(q, 30)
    return HttpResponse.json({
      items: r.items.map((c) => ({ id: c.id, display: c.display, hint: c.hint, category: c.category, vendor: c.vendor, product: c.product, kind: c.kind, version_hint: c.version_hint, kev_cves: c.kev_count })),
      total: r.total,
    })
  }),

  // S-INV-2: ≤3 bấm — Khai thiết bị, chọn gợi ý, Thêm.
  http.post(`${API}/inventory/devices`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const v = validateAdd(request, await body<AddDeviceInput>(request), true)
    if (v.err) return fail(v.err.status, v.err.code, v.err.message)
    const a = createManual(v.entry!, v)
    audit('inventory.add_manual', v.entry!.display, v.ip || undefined)
    return HttpResponse.json({ id: a.id, display: v.entry!.display, kev_cves: v.entry!.kev_count } satisfies AddDeviceResult, { status: 201 })
  }),

  http.get(`${API}/inventory/devices/:id`, ({ params, request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    const software: SoftwareView[] = a.software.map((s) => ({ id: s.id, display: s.display, vendor: s.vendor, product: s.product, version: s.version, source: s.source, confidence: s.confidence, kev_cves: cvesFor(s.kev) }))
    const observations = markCurrent(obsOf(a)).sort((x, y) => FIELD_ORDER.indexOf(x.field) - FIELD_ORDER.indexOf(y.field) || new Date(y.seen_at).getTime() - new Date(x.seen_at).getTime())
    return HttpResponse.json({ asset: { ...live(a), ...scanInfo(a), software }, suspicious: !!metaStore.get()[a.id]?.suspicious, findings_count: findingsOf(a.id), observations, kinds: KINDS } satisfies DeviceDetail)
  }),

  http.patch(`${API}/inventory/devices/:id`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    const b = await body<{ kind: AssetKind; fragile: boolean; regular_scan: RegularScan; notes: string }>(request)
    const patch: Partial<Asset> = {}
    if (b.regular_scan !== undefined) {
      if (!['follow', 'allow', 'never'].includes(b.regular_scan)) return fail(400, 'bad_regular_scan', 'Regular scans must be: follow type setting, allow or never.')
      metaStore.update((m) => ({ ...m, [a.id]: { ...m[a.id], regular_scan: b.regular_scan } }))
      audit('inventory.set_regular_scan', a.hostname ?? a.id, b.regular_scan)
    }
    if (b.kind !== undefined) {
      if (!KINDS.includes(b.kind)) return fail(400, 'bad_kind', `Device type must be one of: ${KINDS.join(', ')}.`)
      if (b.kind !== a.kind) {
        addObs(a, 'kind', b.kind, 'manual', 1)
        patch.kind = b.kind
        if (!metaStore.get()[a.id]?.fragile_manual) patch.fragile = policyFragile(b.kind)
        audit('inventory.set_kind', a.hostname ?? a.id, `${a.kind} → ${b.kind}`)
      }
    }
    if (b.fragile !== undefined) {
      if (typeof b.fragile !== 'boolean') return fail(400, 'bad_fragile', 'fragile must be true or false.')
      patch.fragile = b.fragile
      metaStore.update((m) => ({ ...m, [a.id]: { ...m[a.id], fragile_manual: true } }))
      audit('inventory.set_fragile', a.hostname ?? a.id, String(b.fragile))
    }
    if (b.notes !== undefined) {
      if (typeof b.notes !== 'string' || b.notes.length > 2000) return fail(400, 'bad_notes', 'Notes are at most 2000 characters.')
      patch.notes = b.notes
      audit('inventory.set_notes', a.hostname ?? a.id)
    }
    assetsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, ...patch } : x)))
    return HttpResponse.json({ ok: true })
  }),

  http.delete(`${API}/inventory/devices/:id`, ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    if (a.id === BOX_ID) return fail(409, 'box_device', 'This is the Vedette box itself, so it cannot be deleted. It is always the first device in the list. Its packages come from the box.')
    assetsStore.update((l) => l.filter((x) => x.id !== a.id))
    metaStore.update((m) => { const { [a.id]: _gone, ...rest } = m; return rest })
    obsStore.update((m) => { const { [a.id]: _gone, ...rest } = m; return rest })
    // Phát hiện gắn thiết bị đã xoá không còn nghĩa: gỡ cùng lúc để không còn phát hiện mồ côi (supervisor).
    const orphaned = findingsStore.get().filter((f) => f.asset_id === a.id).length
    if (orphaned) findingsStore.update((l) => l.filter((f) => f.asset_id !== a.id))
    audit('inventory.delete', a.hostname ?? a.ip, orphaned ? `${a.id}; removed ${orphaned} findings of the device` : a.id)
    return new HttpResponse(null, { status: 204 })
  }),

  // S-INV-3
  http.post(`${API}/inventory/devices/:id/approve`, ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    assetsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, approved: true } : x)))
    metaStore.update((m) => ({ ...m, [a.id]: { ...m[a.id], suspicious: false } }))
    audit('inventory.approve', a.hostname ?? a.ip, a.id)
    return HttpResponse.json({ ok: true })
  }),

  http.post(`${API}/inventory/devices/:id/suspicious`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    const b = await body<{ suspicious: boolean }>(request)
    if (typeof b.suspicious !== 'boolean') return fail(400, 'bad_flag', 'suspicious must be true or false.')
    metaStore.update((m) => ({ ...m, [a.id]: { ...m[a.id], suspicious: b.suspicious } }))
    audit(b.suspicious ? 'inventory.mark_suspicious' : 'inventory.unmark_suspicious', a.hostname ?? a.ip, a.id)
    return HttpResponse.json({ ok: true })
  }),

  http.post(`${API}/inventory/devices/:id/software`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    const v = validateAdd(request, { ...(await body<AddDeviceInput>(request)), ip: '' }, true)
    if (v.err) return fail(v.err.status, v.err.code, v.err.message)
    if (a.software.some((s) => s.product === v.entry!.product && s.vendor === v.entry!.vendor && s.display === v.entry!.display)) return fail(409, 'duplicate_software', `${v.entry!.display} is already on this device. To change the version, remove it and add it again.`)
    const sw = softwareOf(v.entry!, v.version)
    assetsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, software: [...x.software, sw] } : x)))
    matchAssetToKev(a.id)
    audit('inventory.add_software', `${a.hostname ?? a.id}: ${sw.display}`)
    return HttpResponse.json({ kev_cves: v.entry!.kev_count }, { status: 201 })
  }),

  http.delete(`${API}/inventory/devices/:id/software/:sid`, ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const a = find(String(params.id))
    if (!a) return notFound(request)
    const sw = a.software.find((s) => s.id === params.sid)
    if (!sw) return fail(404, 'not_found', 'No such software on this device.')
    if (sw.source !== 'manual') return fail(400, 'not_manual', 'Only manually declared software can be removed. Software seen by a sensor or agent updates on the next scan.')
    assetsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, software: x.software.filter((s) => s.id !== sw.id) } : x)))
    audit('inventory.remove_software', `${a.hostname ?? a.id}: ${sw.display}`)
    return new HttpResponse(null, { status: 204 })
  }),

  http.put(`${API}/inventory/notify-new`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'bad_flag', 'enabled must be true or false.')
    notifyStore.set({ enabled: b.enabled })
    audit('inventory.notify_new', b.enabled ? 'on' : 'off')
    return HttpResponse.json({ enabled: b.enabled })
  }),

  // ---- CSV ----
  http.get(`${API}/inventory/export.csv`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const head = ['name', 'ip', 'mac', 'kind', 'vendor', 'model', 'os', 'software', 'approved', 'fragile', 'origin', 'source', 'confidence', 'last_seen']
    const lines = allAssets().map((a) => {
      const s = summaryOf(a)
      return [a.hostname ?? '', hasIp(a) ? a.ip : '', a.mac ?? '', a.kind, a.vendor?.value, a.model?.value, a.os?.value, a.software.map((x) => `${x.display}${x.version ? ` ${x.version}` : ''}`).join('; '), a.approved ? 'yes' : 'no', a.fragile ? 'yes' : 'no', a.origin, s?.source, s ? s.confidence.toFixed(2) : '', a.last_seen].map(csvCell).join(',')
    })
    audit('inventory.export', 'devices.csv', `${lines.length} rows`)
    return new HttpResponse(`﻿${[head.join(','), ...lines].join('\r\n')}\r\n`, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=vedette-devices.csv' } })
  }),

  http.get(`${API}/inventory/import-template.csv`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const text = 'name,ip,product,version,kind\r\nBranch firewall,192.168.30.1,FortiGate,7.2.5,firewall\r\nCompany website,,WordPress,6.5.2,web\r\n'
    return new HttpResponse(`﻿${text}`, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=vedette-devices-template.csv' } })
  }),

  http.post(`${API}/inventory/import`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ filename: string; size: number; text: string }>(request)
    if (typeof b.text !== 'string' || !b.text.trim()) return fail(400, 'empty_file', 'The file is empty. Download the template, fill in your devices and choose it again.')
    if (b.text.length > MAX_IMPORT_BYTES) return fail(400, 'too_large', `The file is too large (max ${MAX_IMPORT_BYTES / 1000} KB). Split it into smaller files.`)
    const csvText = b.text.replace(/^\uFEFF/, '')
    const delim = detectDelimiter(csvText)
    const { rows: table, problems } = parseCsv(csvText)
    const hi = table.findIndex((r) => r.some((c) => c.trim())) // bỏ dòng trống đầu file
    if (problems.has(hi)) return fail(400, 'bad_header', problems.get(hi)!)
    const header = (table[hi] ?? []).map((h) => { const k = fold(h); return HEADER_ALIAS[k] ?? k })
    if (!header.includes('name') && !header.includes('product')) return fail(400, 'bad_header', 'The first row must be column headers with at least a name or product column. Download the template to see the format.')
    const data = table.slice(hi + 1)
    if (!problems.size && !data.some((r) => r.some((c) => c.trim()))) return fail(400, 'no_rows', 'No device rows were found below the column headers. Add at least one row and choose the file again.')
    if (data.length > MAX_IMPORT_ROWS) return fail(400, 'too_many_rows', `At most ${MAX_IMPORT_ROWS} rows per import. This file has ${data.length} rows.`)
    const res: ImportResult = { created: 0, skipped: 0, errors: [], notes: [] }
    const ranges = loadSettings().lan_ranges
    const seenIps = new Set<string>()
    const seenNames = new Set<string>()
    const noIpNames = new Set(allAssets().filter((a) => !hasIp(a) && a.hostname).map((a) => a.hostname!.toLowerCase()))
    data.forEach((cells, i) => {
      const line = hi + i + 2
      if (!problems.has(hi + 1 + i) && cells.every((c) => !c.trim())) return
      // Excel tắt công thức bằng dấu ' đứng trước (xem csvCell khi xuất): bỏ lại khi nhập.
      const err = (message: string) => { res.errors.push({ line, message }); res.skipped++ }
      if (problems.has(hi + 1 + i)) return err(problems.get(hi + 1 + i)!)
      const shape = rowShapeProblem(cells, header.length, delim)
      if (shape) return err(shape)
      const get = (k: string) => (cells[header.indexOf(k)] ?? '').trim().replace(/^'(?=[=+\-@])/, '')
      const productText = get('product')
      const entry = productText ? findCatalog(productText) : undefined
      if (productText && !entry) return err(`Product "${productText.slice(0, 40)}" not recognised. Use a name from the product list of "Add device", for example FortiGate, Synology, WordPress.`)
      if (!productText && !get('name')) return err('This row has neither name nor product. At least one is needed.')
      const kindText = get('kind')
      const kind = kindText ? parseKind(kindText) : undefined
      if (kindText && !kind) return err(`Type "${kindText.slice(0, 20)}" is not valid. Use one of: ${KINDS.join(', ')}.`)
      const v = validateAdd(request, { catalog_id: entry?.id, version: get('version'), name: get('name'), ip: get('ip') }, false)
      if (v.err) return err(v.err.message)
      if (v.ip) { if (seenIps.has(v.ip)) return err(`IP ${v.ip} appears twice in the file.`); seenIps.add(v.ip) }
      else if (v.name) {
        // Nhập lại file vừa xuất: thiết bị chưa có IP không được nhân đôi.
        const key = v.name.toLowerCase()
        if (noIpNames.has(key) || seenNames.has(key)) return err(`A device named "${v.name.slice(0, 40)}" (no IP yet) is already in the list. Add an IP to this row if it is a different device.`)
        seenNames.add(key)
      }
      createManual(entry ?? null, { version: v.version, name: v.name, ip: v.ip, kind })
      res.created++
      const note = v.ip ? ipNote(v.ip, ranges) : ''
      if (note) res.notes.push({ line, message: note })
    })
    audit('inventory.import', b.filename ? String(b.filename).slice(0, 80) : 'csv', `${res.created} devices, ${res.errors.length} errors`)
    return HttpResponse.json(res)
  }),

  // ---- Phạm vi và cảm biến (admin) ----
  http.get(`${API}/inventory/settings`, () => {
    const denied = guard('admin'); if (denied) return denied
    return HttpResponse.json(loadSettings())
  }),

  http.put(`${API}/inventory/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<SettingsInput>(request)
    const adjusted: { from: string; to: string }[] = []
    // "192.168.18.5/24" được đưa về "192.168.18.0/24" (phản hồi nói rõ đã đổi gì); địa chỉ không có /prefix bị từ chối bên dưới, không đoán.
    const ranges = Array.isArray(b.lan_ranges) ? [...new Set(b.lan_ranges.map((x) => { const raw = String(x).trim(); const n = normalizeRange(raw); if (n.value !== raw) adjusted.push({ from: raw, to: n.value }); return n.value }))] : null
    if (!ranges) return fail(400, 'bad_ranges', 'The list of network ranges is missing.')
    if (ranges.length > 16) return fail(400, 'too_many_ranges', 'At most 16 network ranges.')
    for (const r of ranges) {
      if (IPV4_RE.test(r)) return fail(400, 'no_prefix', `"${r}" has no prefix length. Add it so Vedette scans the right size of network, for example ${r}/24 or ${r}/25.`)
      if (!CIDR_RE.test(r)) return fail(400, 'bad_cidr', `"${r.slice(0, 30)}" is not a valid network range. Enter something like 192.168.10.0/24.`)
      if (hasHostBits(r)) return fail(400, 'host_bits', `Range ${r} is not written correctly: the address part must be the first address of the range. Use ${cidrRange(r).network}.`)
      if (!isPrivateCidr(r)) return fail(400, 'public_range', `${r} is not an internal range (10.x, 172.16-31.x, 192.168.x). To scan public addresses, add them under External exposure after verifying ownership.`)
      const clash = overlapping(r, ranges)
      if (clash) return fail(400, 'overlap_range', `Range ${r} overlaps ${clash}. Keep the larger range and drop the smaller one.`)
    }
    const act = b.active
    if (!act || typeof act.enabled !== 'boolean') return fail(400, 'bad_active', 'Active scan settings are missing.')
    if (!Array.isArray(act.days) || act.days.some((d) => !Number.isInteger(d) || d < 1 || d > 7)) return fail(400, 'bad_days', 'Scan days must be Monday to Sunday.')
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(act.from) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(act.to)) return fail(400, 'bad_time', 'Time must look like 23:00.')
    if (act.from === act.to) return fail(400, 'bad_window', 'Start and end time cannot be the same.')
    if (!Number.isInteger(act.rate) || act.rate < 1 || act.rate > 1000) return fail(400, 'bad_rate', 'Scan rate is 1 to 1000 packets per second.')
    const excl = Array.isArray(act.exclusions) ? act.exclusions.map((x) => String(x).trim()) : []
    for (const x of excl) if ((!IPV4_RE.test(x) && !CIDR_RE.test(x)) || (CIDR_RE.test(x) && hasHostBits(x))) return fail(400, 'bad_exclusion', `Exclusion "${x.slice(0, 30)}" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
    if (act.enabled && act.days.length === 0) return fail(400, 'no_days', 'Choose at least one day for the scan window, or turn active scanning off.')
    if (act.enabled && ranges.length === 0) return fail(400, 'no_ranges', 'Active scanning needs at least one network range.')
    if (act.enabled && b.scope_confirmed !== true) return fail(400, 'scope_not_confirmed', 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.')
    const kinds = Array.isArray(b.fragile_kinds) ? b.fragile_kinds : null
    if (!kinds || kinds.some((k) => !KINDS.includes(k))) return fail(400, 'bad_kinds', 'The list of fragile device types is not valid.')
    const regular = Array.isArray(b.regular_scan_kinds) ? b.regular_scan_kinds : []
    if (regular.some((k) => !KINDS.includes(k))) return fail(400, 'bad_kinds', 'The list of device types for regular scans is not valid.')
    const prev = loadSettings()
    const confirmedNow = b.scope_confirmed === true
    const next: InventorySettings = {
      lan_ranges: ranges, fragile_kinds: [...new Set(kinds)], regular_scan_kinds: [...new Set(regular)].filter((k) => kinds.includes(k)),
      active: { enabled: act.enabled, days: [...new Set(act.days)].sort(), from: act.from, to: act.to, rate: act.rate, exclusions: [...new Set(excl)] },
      scope_confirmed_at: confirmedNow ? (prev.scope_confirmed_at && sameSet(prev.lan_ranges, ranges) ? prev.scope_confirmed_at : nowIso()) : null,
      scope_confirmed_by: confirmedNow ? (prev.scope_confirmed_at && sameSet(prev.lan_ranges, ranges) ? prev.scope_confirmed_by : (currentUser()?.email ?? null)) : null,
    }
    settingsStore.set(next)
    applyFragilePolicy()
    audit('inventory.settings', 'scan scope', `${ranges.length} ranges, active scanning ${act.enabled ? 'on' : 'off'}`)
    return HttpResponse.json({ ...next, adjusted })
  }),

  http.get(`${API}/inventory/sensors`, () => {
    const denied = guard('admin'); if (denied) return denied
    if (installStore.get().kind === 'container') return HttpResponse.json({ sensors: containerSensors() })
    // SPAN and the listening port are owned by Settings → Box network (D-56); the sensor row only reflects them.
    const net = networkStore.get()
    const st = spanStatusOf(net)
    const spanOn = net.span.enabled && !!net.span.interface
    const mgmt = net.ifaces.find((i) => i.role === 'management')?.name ?? null
    return HttpResponse.json({ sensors: sensorsStore.get().map((s) => ({ ...s, interface: spanOn ? net.span.interface : mgmt, interfaces: net.ifaces.map((i) => i.name), span: spanOn, chosen: spanOn, span_status: { verdict: st.verdict, packets_per_s: st.packets_per_s, other_macs: st.other_macs }, capture_error: null })) })
  }),

  // D-387: only a container-only install chooses the card here; an appliance sets it in Settings → Box network (D-56, D-118).
  http.patch(`${API}/inventory/sensors/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    if (!sensorsStore.get().some((s) => s.id === params.id)) return fail(404, 'not_found', 'No such sensor. This box has one sensor, sn-local.')
    if (installStore.get().kind !== 'container') return fail(409, 'set_in_box_network', 'On this box the card the sensor listens on is chosen in Settings → Box network.')
    const b = await body<{ interface?: unknown; span?: unknown }>(request)
    if (typeof b.span !== 'boolean' || (b.interface !== null && (typeof b.interface !== 'string' || b.interface.length > 15))) return fail(400, 'invalid', 'Give interface (a card name or null) and span (true or false).')
    const c = containerSensorStore.get()
    const name = b.interface === '' ? null : b.interface as string | null
    if (name && !c.connected) return fail(400, 'bad_interface', 'The sensor has not reported its network cards in the last 90 seconds; check that it runs, wait for its next heartbeat (30 s) and try again.')
    if (name && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(name)) return fail(400, 'bad_interface', `"${name}" is not an interface name.`)
    if (name && VIRTUAL.test(name)) return fail(400, 'bad_interface', `"${name}" is not a network card (loopback, container, bridge or VPN link).`)
    const card = name ? c.cards.find((x) => x.name === name) : undefined
    if (b.span && !name) return fail(400, 'bad_interface', 'A SPAN port needs an interface.')
    if (name && !card) return fail(400, 'bad_interface', `"${name}" is not an interface of this box.`)
    if (b.span && card?.ipv4) return fail(400, 'bad_interface', `"${name}" has an IP address; a SPAN port has none.`)
    containerSensorStore.set({ ...c, chosen: name, span: b.span })
    audit('sensor.interface_set', String(params.id), `interface="${name ?? ''}" span=${b.span}`)
    return HttpResponse.json(containerSensors().find((s) => s.id === params.id))
  }),


  // ---- Agent (S-INV-4) ----
  http.get(`${API}/inventory/agents`, async () => {
    const denied = guard('admin'); if (denied) return denied
    const w = wazuhStore.get()
    return HttpResponse.json({ install: await installers(), tokens: agentsStore.get(), server_url: serverUrl(), wazuh: w ? publicWazuh(w) : null })
  }),

  // Công khai (không bí mật): script do hộp phục vụ; SHA-256 hiện trong giao diện tính đúng trên nội dung này.
  // D-399 (2): no script pinned to the placeholder address: it would pass its SHA-256 check and then fail on every server.
  http.get(`${API}/install/osquery.sh`, () => serverUrl().includes(NO_BOX_ADDRESS) ? noBoxAddress() : new HttpResponse(linuxInstallScript(serverUrl(), MOCK_CA), { headers: { 'Content-Type': 'text/x-shellscript; charset=utf-8' } })),
  http.get(`${API}/install/osquery.ps1`, () => serverUrl().includes(NO_BOX_ADDRESS) ? noBoxAddress() : new HttpResponse(windowsInstallScript(serverUrl(), MOCK_CA), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })),

  // Script cài hỏi trạng thái bằng token trong header (không bao giờ trong URL). Token chỉ cho phép việc này và đăng ký osquery.
  http.post(`${API}/intake/osquery/status`, async ({ request }) => {
    const m = /^Bearer (vdt_osquery_[a-z0-9]{32})$/.exec(request.headers.get('authorization') ?? '')
    const t = m ? agentsStore.get().find((x) => x.last4 === m[1]!.slice(-4)) : undefined
    if (!t) return fail(403, 'invalid_token', 'This enrollment token is not valid. Create a new one in Vedette.')
    if (expired(t)) return fail(403, 'token_expired', 'This enrollment token has expired. Create a new one in Vedette.')
    // The mock keeps no nodes: a named machine counts as enrolled when the token has any machine (the real box matches the name under the token).
    const b = await body<{ host_identifier?: string }>(request)
    const named = typeof b?.host_identifier === 'string' && b.host_identifier.trim().length > 0 && !/[\u0000-\u001f\u007f]/.test(b.host_identifier)
    return HttpResponse.json({ enrolled: t.last_received !== null, hosts: t.hosts, ...(named ? { host_last_seen: t.hosts > 0 ? new Date().toISOString() : null } : {}) })
  }),

  // osquery TLS remote API (D-169): machine to machine, no GUI calls these; the mock answers with the real shapes so the contract tests and OpenAPI cover them.
  // Credential failures are HTTP 200 + node_invalid (osquery does not handle HTTP errors). The mock keeps no nodes: a node key is "mock-node-" + token last4.
  http.post(`${API}/intake/osquery/enroll`, async ({ request }) => {
    const b = await body<{ enroll_secret?: string }>(request)
    const m = /^vdt_osquery_[a-z0-9]{32}$/.test(b.enroll_secret ?? '') ? (b.enroll_secret as string).slice(-4) : null
    const t = m ? agentsStore.get().find((x) => x.last4 === m) : undefined
    if (!t || expired(t)) return HttpResponse.json({ node_invalid: true })
    return HttpResponse.json({ node_key: `mock-node-${t.last4}`, node_invalid: false })
  }),
  http.post(`${API}/intake/osquery/config`, async ({ request }) => {
    const b = await body<{ node_key?: string }>(request)
    if (!/^mock-node-/.test(b.node_key ?? '')) return HttpResponse.json({ node_invalid: true })
    return HttpResponse.json({ ...JSON.parse(OSQUERY_SCHEDULE), node_invalid: false })
  }),
  http.post(`${API}/intake/osquery/log`, async ({ request }) => {
    const b = await body<{ node_key?: string }>(request)
    return HttpResponse.json({ node_invalid: !/^mock-node-/.test(b.node_key ?? '') })
  }),
  http.get(`${API}/intake/ca.pem`, () => new HttpResponse(`${MOCK_CA}\n`, { headers: { 'Content-Type': 'application/x-pem-file' } })),
  // The mock has no package files: only SHA256SUMS exists; the five package names of the real box answer 404 here (they are binaries of 20 to 30 MB).
  http.get(`${API}/install/osquery/:file`, ({ params }) => {
    if (params.file !== 'SHA256SUMS') return fail(404, 'not_found', 'The mock box ships no osquery package files.')
    const names = [`osquery_${OSQUERY_VERSION}-1.linux_amd64.deb`, `osquery-${OSQUERY_VERSION}-1.linux.x86_64.rpm`, `osquery_${OSQUERY_VERSION}-1.linux_arm64.deb`, `osquery-${OSQUERY_VERSION}-1.linux.aarch64.rpm`, `osquery-${OSQUERY_VERSION}.msi`]
    return new HttpResponse(names.map((n) => `${'0'.repeat(64)}  ${n}`).join('\n') + '\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
  }),

  http.post(`${API}/inventory/agents/tokens`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ name: string; kind?: string; expires_in_days?: number }>(request)
    const name = String(b.name ?? '').trim()
    if (!LABEL_RE.test(name)) return fail(400, 'bad_name', 'Name the token so you remember which machines use it, up to 64 characters. Example "osquery on SRV-AD".')
    if (b.kind !== undefined && b.kind !== 'osquery') return fail(400, 'bad_kind', 'Only osquery uses a token. To use Wazuh, connect its API instead.')
    const days = b.expires_in_days === undefined ? 7 : Number(b.expires_in_days)
    if (!Number.isInteger(days) || days < 0 || days > 365) return fail(400, 'bad_expiry', 'Choose how long the token works: 1 to 365 days, or 0 for no expiry.')
    const secret = `vdt_osquery_${rand(32, 'abcdefghijkmnpqrstuvwxyz23456789')}`
    const token: AgentToken = { id: newId('tk'), name, kind: 'osquery', last4: secret.slice(-4), created_at: nowIso(), last_received: null, hosts: 0, expires_at: days === 0 ? null : new Date(Date.now() + days * 864e5).toISOString() }
    agentsStore.update((l) => [...l, token])
    audit('inventory.agent_token_create', name, `osquery, ${days === 0 ? 'no expiry' : `expires in ${days} days`}`)
    return HttpResponse.json({ token, secret }, { status: 201 })
  }),

  http.delete(`${API}/inventory/agents/tokens/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = agentsStore.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    agentsStore.update((l) => l.filter((x) => x.id !== t.id))
    audit('inventory.agent_token_revoke', t.name)
    return new HttpResponse(null, { status: 204 })
  }),

  // CHỈ BẢN XEM THỬ: bản thật có agent báo về. Ở đây giả lập một lần báo về để người dùng thấy tác dụng.
  http.post(`${API}/inventory/agents/tokens/:id/sample-data`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = agentsStore.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    if (expired(t)) return fail(403, 'token_expired', 'This enrollment token has expired. Create a new one and run the install command again.')
    const r = injectSample()
    if ('err' in r) return fail(409, 'no_devices', r.err)
    agentsStore.update((l) => l.map((x) => (x.id === t.id ? { ...x, last_received: nowIso(), hosts: r.devices } : x)))
    audit('inventory.agent_enroll', t.name, `sample data: ${r.devices} devices, ${r.software} software`)
    return HttpResponse.json({ devices: r.devices, software: r.software })
  }),

  http.post(`${API}/inventory/agents/wazuh/test`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<WazuhInput>(request)
    const bad = checkWazuhInput(b, wazuhStore.get())
    if (bad) return fail(bad.status, bad.code, bad.message)
    return HttpResponse.json({ ok: true as const, version: '4.9.2', agents: wazuhAgentCount() })
  }),

  http.put(`${API}/inventory/agents/wazuh`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<Partial<WazuhInput>>(request)
    const prev = wazuhStore.get()
    const bad = checkWazuhInput(b, prev)
    if (bad) return fail(bad.status, bad.code, bad.message)
    const password = b.password ? b.password : prev!.password
    const conn: StoredWazuh = {
      url: (b.url ?? '').trim().replace(/\/+$/, ''), username: (b.username ?? '').trim(), password, password_last4: password.slice(-4), interval_minutes: Number(b.interval_minutes),
      // the check just passed: 'never' until the first pull, else 'connected' (the next pull says more), as the backend does (D-309)
      status: prev?.last_sync ? 'connected' : 'never', last_sync: prev?.last_sync ?? null, agents: prev?.agents ?? 0, packages: prev?.packages ?? 0, error: null,
    }
    wazuhStore.set(conn)
    audit('inventory.wazuh_connect', conn.url, `user ${conn.username}, every ${conn.interval_minutes} min`)
    return HttpResponse.json(publicWazuh(conn))
  }),

  http.delete(`${API}/inventory/agents/wazuh`, () => {
    const denied = guard('admin'); if (denied) return denied
    if (!wazuhStore.get()) return fail(404, 'not_found', 'Wazuh is not connected.')
    wazuhStore.set(null)
    audit('inventory.wazuh_disconnect', 'Wazuh')
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${API}/inventory/agents/wazuh/sample-data`, () => {
    const denied = guard('admin'); if (denied) return denied
    const w = wazuhStore.get()
    if (!w) return fail(404, 'not_found', 'Connect Wazuh first.')
    const r = injectSample()
    if ('err' in r) return fail(409, 'no_devices', r.err)
    wazuhStore.set({ ...w, status: 'connected', last_sync: nowIso(), agents: r.devices, packages: r.software * 40 + 120, error: null })
    audit('inventory.wazuh_sample_data', w.url, `${r.devices} devices, ${r.software} software`)
    return HttpResponse.json({ devices: r.devices, software: r.software })
  }),
]

function sameSet(a: string[], b: string[]) { return a.length === b.length && a.every((x) => b.includes(x)) }

// Dùng chung trong lớp mock (supervisor): module scan đọc dải mạng và xác nhận phạm vi từ đây.
export { settingsStore as inventorySettingsStore }
