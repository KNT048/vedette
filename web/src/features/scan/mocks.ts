// Mock API module scan (S-SCAN-1..5). Trạng thái quét "chạy thật theo thời gian": mỗi lần đọc, mock tính tiến độ từ giờ bắt đầu (timing.stepMs mỗi thiết bị),
// nên UI poll 1 giây là thấy tiến độ và "Dừng ngay" có hiệu lực sau timing.stopMs (≤ 5 s). Chỉ quét mục tiêu trong phạm vi đã xác nhận + ô cam kết (LEGAL §3).
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, CIDR_RE, currentUser, fail, guard, IPV4_RE } from '@/mocks/http'
import { collection, daysAgo, dataMode, newId, nowIso, peek } from '@/mocks/db'
import { assetsStore, findingsStore, isOn } from '@/mocks/stores'
import type { Asset, Finding } from '@/lib/types'
import { BOX_ID, inventorySettingsStore } from '@/features/inventory/mocks'
import { exposureSnapshotsStore, exposureTargetsStore } from '@/features/exposure/mocks'
import type { CredTarget, IdentReason, ProbeEntry, RescanEvent, RunIdentRow, RunResultRow, ScanConfig, ScanConfigResponse, ScanRun, ScanScope, ScanTarget } from './types'


/** Tests đặt nhỏ lại; trình duyệt dùng giá trị thật. */
export const timing = { stepMs: 2000, stopMs: 1000, engineMs: 3000 }
export const RETENTION_DAYS = 90
// Thiết bị mẫu phản hồi chậm: dùng để minh hoạ "tự dừng khi thiết bị không phản hồi" (S-SCAN-4).
const SLOW = new Set(['a-cam03'])

interface Vuln { cve: string; vendor: string; product: string; date_added: string; has_template: boolean }
const vulns = (kev as { vulns: Vuln[] }).vulns
const hasTemplate = (cve: string) => vulns.find((v) => v.cve === cve)?.has_template ?? false
const templateName = (cve: string) => `http/cves/${cve.split('-')[1]}/${cve}.yaml`

// Mọi chuỗi hiển thị bằng tiếng Anh (D-28).
type StoredRow = RunResultRow
interface StoredRun extends ScanRun { target_ids: string[]; stop_requested_at: string | null }
const row = (t: ScanTarget, template: string | null, result: RunResultRow['result'], finding_id: string | null, note: string): StoredRow => ({ target_id: t.id, label: t.label, ip: t.ip, template, result, finding_id, note })
interface ExternalTarget { id: string; value: string; ip: string; verified: boolean; expired: boolean }
const VERIFY_DAYS = 30

// Phạm vi trong = dải LAN ở Thiết bị → Phạm vi và cảm biến (inventory) + ô cam kết đã đánh dấu ở đó (scope_confirmed_at). Không còn văn bản đồng ý.
// Mục tiêu ngoài (exposure): chỉ IP mà chính hộp đi ra Internet bằng và hộp còn thấy trong 30 ngày qua (hộp tự dò và gia hạn; quá hạn = không quét); tên miền xác thực bằng DNS TXT không hết hạn. LEGAL §3.
const scope = {
  get(): ScanScope {
    const s = inventorySettingsStore.get()
    return { networks: s.lan_ranges, commitment: s.scope_confirmed_at ? { confirmed_at: s.scope_confirmed_at, by: s.scope_confirmed_by ?? '—' } : null }
  },
}
const external = {
  get(): ExternalTarget[] {
    const snaps = exposureSnapshotsStore.get()
    return exposureTargetsStore.get().map((t) => {
      // exposure sẽ có expires_at; chưa có thì tính verified_at + 30 ngày.
      const exp = (t as { expires_at?: string | null }).expires_at ?? (t.verified_at ? new Date(Date.parse(t.verified_at) + VERIFY_DAYS * 864e5).toISOString() : null)
      return {
        id: `ext:${t.id}`, value: t.value,
        ip: t.kind === 'ip' ? t.value : (snaps[t.id]?.at(-1)?.hosts.find((h) => h.name === t.value)?.ip ?? snaps[t.id]?.at(-1)?.hosts[0]?.ip ?? '—'),
        verified: !!t.verified_at,
        expired: t.kind === 'ip' && !!exp && Date.parse(exp) < Date.now(),
      }
    })
  },
}
const config = collection<ScanConfig>('scan_config', () => ({
  window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' },
  rate: 5, exclusions: ['192.168.10.250'], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true,
  schedule: { enabled: true, frequency: 'weekly', weekday: 7, at: '23:00' },
}), () => ({
  // Cài sạch: cùng mặc định nhưng chưa loại trừ IP nào (IP hộp mẫu 192.168.10.250 không phải của khách). Chưa có phạm vi/đồng ý thì không quét được.
  window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' },
  rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true,
  schedule: { enabled: true, frequency: 'weekly', weekday: 7, at: '23:00' },
}))
export const runs = collection<StoredRun[]>('scan_runs', seedRuns, () => [])
const probes = collection<ProbeEntry[]>('scan_probes', seedProbes, () => [])
const events = collection<RescanEvent[]>('scan_events', seedEvents, () => [])
const creds = collection<CredTarget[]>('scc_target', () => [])

function seedProbes(): ProbeEntry[] {
  const out: ProbeEntry[] = []
  const rows: [number, string, string, string, string, ProbeEntry['result']][] = [
    [0.1, '192.168.10.21', 'NAS-PHOTOS', 'CVE-2022-27593', 'GET /photo/ HTTP/1.1', 'matched'],
    [0.1, '192.168.10.12', 'WEB01', 'CVE-2026-119977', 'GET /wp-login.php HTTP/1.1', 'banner'],
    [7, '192.168.10.21', 'NAS-PHOTOS', 'CVE-2022-27593', 'GET /photo/ HTTP/1.1', 'matched'],
    [14, '192.168.10.1', 'FW-HQ', 'vedette/fingerprint', 'GET / HTTP/1.1 (read banner)', 'banner'],
    [30, '192.168.10.21', 'NAS-PHOTOS', 'CVE-2022-27593', 'GET /photo/ HTTP/1.1', 'matched'],
    [30, '192.168.20.13', 'CAM-LOBBY', 'vedette/fingerprint', 'GET / HTTP/1.1 (read banner)', 'no_response'],
    [45, '192.168.10.2', 'RT-BACKUP', 'vedette/fingerprint', 'GET / HTTP/1.1 (read banner)', 'banner'],
    [60, '192.168.10.20', 'NAS-BACKUP', 'vedette/fingerprint', 'GET / HTTP/1.1 (read banner)', 'banner'],
    [75, '192.168.10.21', 'NAS-PHOTOS', 'CVE-2022-27593', 'GET /photo/ HTTP/1.1', 'not_matched'],
    [88, '192.168.10.12', 'WEB01', 'vedette/fingerprint', 'GET / HTTP/1.1 (read banner)', 'banner'],
  ]
  rows.forEach(([d, ip, label, tpl, request, result], i) => out.push({ id: `pr-seed${i}`, ts: daysAgo(d), run_id: null, ip, label, template: tpl.startsWith('CVE') ? templateName(tpl) : tpl, request, result }))
  return out.sort((a, b) => b.ts.localeCompare(a.ts))
}

function seedRuns(): StoredRun[] {
  const ts = (d: number, h: number) => daysAgo(d, h)
  const t = targets().filter((x) => x.selectable && x.kind === 'internal' && !SLOW.has(x.id))
  const rowsOf = (list: ScanTarget[]) => list.flatMap((x) => scanOne(x, false).rows)
  const mk = (id: string, trigger: ScanRun['trigger'], note: string | null, started: string, mins: number, list: ScanTarget[], done: number, status: ScanRun['status'], reason: string | null): StoredRun => {
    const rows = [...rowsOf(list.slice(0, done)), ...list.slice(done).map((x) => row(x, null, 'skipped', null, SKIPPED))]
    const identification = trigger === 'manual' ? list.map((x, i) => (i < done ? identOne(x) : identRow(x, [], 'not_scanned', SKIPPED))) : []
    return { id, trigger, trigger_note: note, started_at: started, started_by: trigger === 'manual' ? 'it@acme.example' : 'system', ended_at: new Date(Date.parse(started) + mins * 60_000).toISOString(), status, total: list.length, done, current: null, results: rows, matched: rows.filter((x) => x.result === 'matched').length, stop_reason: reason, target_ids: list.map((x) => x.id), stop_requested_at: null, identification }
  }
  // A scheduled run and a KEV rescan never touch a device that needs a hand pick (D-126 (2)); a manual run may, it was picked.
  const auto = t.filter((x) => !x.pick_only)
  const kevHit = findingsStore.get().find((f) => auto.some((x) => x.id === f.asset_id) && hasTemplate(f.cve) && (f.status === 'confirmed' || f.status === 'suspected'))
  const kevTargets = kevHit ? auto.filter((x) => x.id === kevHit.asset_id) : auto.slice(0, 1)
  return [
    mk('run-seed-1', 'schedule', null, ts(0, 3), 41, auto, auto.length, 'done', null),
    mk('run-seed-2', 'new_kev', `New KEV entry with a scan template: ${kevHit?.cve ?? 'CVE-2024-3400'}`, ts(9, 0), 2, kevTargets, kevTargets.length, 'done', null),
    mk('run-seed-3', 'manual', null, ts(21, 5), 1, t, 4, 'stopped', STOP_NOW),
  ]
}

const SKIPPED = 'Not scanned because the scan was stopped. This device was not touched.'
const NO_RESP = 'No response; scanning stopped so the device is not hung.'
const STOP_NOW = 'You pressed Stop now.'
const STOPPED_MID = 'Stopped while this device was being scanned: no result. The requests on their way are in the probe log as stopped.'

function seedEvents(): RescanEvent[] {
  // Từ KEV thật: CVE có mẫu quét, khớp phần mềm trong kiểm kê mẫu.
  const out: RescanEvent[] = []
  // a rescan only scans devices allowed without a hand pick (D-126 (2)), so a match names only those
  const pickOnly = new Set(targets().filter((x) => x.pick_only).map((x) => x.id))
  for (const v of vulns.filter((x) => x.has_template).slice(0, 40)) {
    const key = `${v.vendor}|${v.product}`.toLowerCase()
    const devices = assetsStore.get().filter((a) => !pickOnly.has(a.id) && a.software.some((s) => s.kev.includes(key))).map((a) => a.hostname ?? a.ip)
    if (!devices.length) continue
    out.push({ id: `ev-${v.cve}`, ts: new Date(`${v.date_added}T09:00:00Z`).toISOString(), cve: v.cve, product: `${v.vendor} ${v.product}`, devices, latency_min: 14 + out.length * 9, run_id: null, result: 'matched' })
    if (out.length >= 4) break
  }
  const unused = () => vulns.find((v) => v.has_template && !out.some((o) => o.cve === v.cve))?.cve
  out.push({ id: 'ev-nomatch', ts: daysAgo(2), cve: unused() ?? 'CVE-2026-0001', product: 'A product you do not use', devices: [], latency_min: null, run_id: null, result: 'no_match' })
  // D-145 (7): every matching device may only be scanned by a hand pick (fragile, unclassified, hand-declared; D-126 (2))
  const pick = targets().filter((x) => x.pick_only).map((x) => x.label).slice(0, 2)
  if (pick.length) out.push({ id: 'ev-pick', ts: daysAgo(4), cve: unused() ?? 'CVE-2026-0002', product: 'A product only on devices that need a hand pick', devices: pick, latency_min: null, run_id: null, result: 'pick_only' })
  // D-261 (2): a rescan that waited 7 days stays in the log, with the reason
  out.push({ id: 'ev-expired', ts: daysAgo(9), cve: unused() ?? 'CVE-2026-0005', product: 'A product whose scan template never arrived', devices: [], latency_min: null, run_id: null, result: 'expired_no_template' })
  return out.sort((a, b) => b.ts.localeCompare(a.ts))
}

// ---- tiện ích địa chỉ / thời gian ----
const ipNum = (ip: string) => ip.split('.').reduce((n, p) => n * 256 + Number(p), 0)
function inCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.includes('/') ? cidr.split('/') as [string, string] : [cidr, '32']
  const mask = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0
  return ((ipNum(ip) & mask) >>> 0) === ((ipNum(base) & mask) >>> 0)
}
const hm = (s: string) => Number(s.slice(0, 2)) * 60 + Number(s.slice(3))
const HM_RE = /^([01]\d|2[0-3]):[0-5]\d$/
const inTimeRange = (at: string, from: string, to: string) => (hm(from) < hm(to) ? hm(at) >= hm(from) && hm(at) < hm(to) : hm(at) >= hm(from) || hm(at) < hm(to))

/** ISO weekday: 1 = Monday … 7 = Sunday (D-57). */
const isoDay = (d: Date) => d.getDay() || 7

/** A slot runs when its window starts on a window day (a window that crosses midnight counts by its start day, so a slot after midnight
 *  belongs to the window of the day before: #164 review M1) and, weekly, on the chosen weekday (the slot's own day). The first
 *  scheduled run (first: none ran yet) takes the next window of any window day (W3-6; modules/scan slotOK). */
function slotOK(c: ScanConfig, d: Date, first = false): boolean {
  const start = new Date(d)
  if (hm(c.window.from) > hm(c.window.to) && hm(c.schedule.at) < hm(c.window.to)) start.setDate(start.getDate() - 1)
  return c.window.days.includes(isoDay(start)) && (first || c.schedule.frequency === 'daily' || isoDay(d) === c.schedule.weekday)
}

export function nextRun(c: ScanConfig, now = new Date(), first = false): string | null {
  if (!c.schedule.enabled) return null
  for (let i = 0; i < 15; i++) {
    const d = new Date(now)
    d.setDate(d.getDate() + i)
    d.setHours(hm(c.schedule.at) / 60 | 0, hm(c.schedule.at) % 60, 0, 0)
    if (d.getTime() > now.getTime() && slotOK(c, d, first)) return d.toISOString()
  }
  return null
}

// ---- mục tiêu ----
function targets(): ScanTarget[] {
  const c = config.get()
  const sc = scope.get()
  const findings = findingsStore.get()
  // D-126 (inventory VulnScanPolicy): the box and a device set to "never scan" are never scanned. Picking a device by hand is the consent for it,
  // so fragile, unclassified and hand-declared devices can be picked (fragile and unclassified at a quarter of the speed); schedule and KEV rescans skip them.
  const meta = peek<Record<string, { regular_scan?: string }>>('inv_meta') ?? {}
  const open = new Map<string, number>()
  for (const f of findings) if (f.status === 'confirmed' || f.status === 'suspected') open.set(f.asset_id, (open.get(f.asset_id) ?? 0) + 1)
  const internal = assetsStore.get().map((a: Asset): ScanTarget => {
    const reason = a.id === BOX_ID ? 'box' : meta[a.id]?.regular_scan === 'never' ? 'regular_scan_never' : !a.approved ? 'unapproved' : !a.ip || a.ip === '—' ? 'no_ip' : c.exclusions.some((e) => inCidr(a.ip, e)) ? 'excluded' : !sc.networks.some((n) => inCidr(a.ip, n)) ? 'out_of_scope' : null
    return { id: a.id, kind: 'internal', device_kind: a.kind, label: a.hostname ?? ([a.vendor?.value, a.model?.value].filter(Boolean).join(' ') || a.ip), ip: a.ip, fragile: a.fragile || a.kind === 'unknown', findings: open.get(a.id) ?? 0, selectable: reason === null, pick_only: reason === null && (a.fragile || a.kind === 'unknown' || a.origin === 'manual'), reason,
      mac: a.mac, vendor: a.vendor?.value ?? null, approved: a.approved, last_seen: a.last_seen }
  })
  // External targets are listed but not scanned by this version yet (the GUI says so); ownership problems are named first, since they are what the user can fix.
  const ext = external.get().map((e): ScanTarget => ({ id: e.id, kind: 'external', device_kind: null, label: e.value, ip: e.ip, fragile: false, findings: 0, selectable: false, pick_only: false, reason: !e.verified ? 'unverified' : e.expired ? 'expired' : 'not_supported', mac: null, vendor: null, approved: false, last_seen: null }))
  return [...internal, ...ext]
}

/** Whether the scanner of the scan container answers (heartbeat, nuclei present). Tests and e2e flip it to see the 503. */
export const scannerStore = collection<{ available: boolean }>('scan_scanner', () => ({ available: true }))
/** Whether the organization time zone can be read. While it cannot, nothing automated starts and the schedule says why (D-261 (3)). Tests flip it. */
export const zoneStore = collection<{ readable: boolean }>('scan_zone', () => ({ readable: true }))
/** Until when the scanner still works on a run that Stop now already closed (D-261 (4)); a new scan is refused until then. Tests set it. */
export const engineStore = collection<{ busyUntil: number }>('scan_engine', () => ({ busyUntil: 0 }))
const engineBusy = () => Date.now() < engineStore.get().busyUntil
const SCANNER_DOWN = "The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again."

const ZONE_DOWN = 'The schedule is on, but the time zone of the organization cannot be read, so no scan starts on its own (rescans for new KEV entries wait too). Check the time zone under Settings, General.'

const REASON: Record<NonNullable<ScanTarget['reason']>, string> = {
  unapproved: 'has not been approved in the inventory',
  excluded: 'is on the exclusion list',
  out_of_scope: 'is outside the confirmed network range',
  no_ip: 'has no IP address in the inventory; add its IP on the device page to scan it',
  box: 'is the Vedette box itself, which is never scanned',
  regular_scan_never: 'is set to never be scanned in the inventory; change that setting first',
  unverified: 'has no verified ownership (do it on the External exposure page)',
  expired: 'verification expired, verify again (on the External exposure page)',
  not_supported: 'is an external target, and this version does not scan external targets yet',
}
const reasonOf = (r: ScanTarget['reason']) => REASON[r ?? 'out_of_scope']

// D-501: Scan now identifies each device first (nmap in the backend). The notes are the backend's words (modules/scan/identify.go identNote).
const IDENT_NOTE: Record<IdentReason | 'identified', string> = {
  identified: 'Recorded on the device page. Software with a version is compared with the CISA list of exploited flaws; an operating system nmap only guessed is not, until you add it with its version there.',
  os_unconfirmed: 'nmap only guessed the operating system and no service gave a version, so nothing is compared with the CISA list yet: a guess would flag every flaw of that system. Add the operating system and its version on the device page to check it.',
  os_no_patch_level: 'Windows named its release (shown above) but not its monthly update level, so nothing is compared with the CISA list yet: that would flag every Windows flaw since that release. Add Windows with its full version (Settings, System, About: OS build, for example 10.0.22631.4317) on the device page, or install the osquery agent on it.',
  host_down: 'Did not answer: it may be switched off, asleep (phones often are) or off the network. Scan it again while it is in use.',
  no_open_ports: 'Answered, but every port tried was closed, so no service could be identified. Add its software on the device page, or install the osquery agent on it.',
  filtered: 'Answered, but a firewall dropped the probes (every port tried was filtered), so nothing could be identified. Add its software on the device page, or install the osquery agent on it.',
  no_version: 'Has open ports, but no service gave its product or version and the operating system could not be told, so there is nothing to compare. Add its software and version on the device page.',
  os_low_confidence: 'No service gave its product or version, and the operating system guess was less than 85% sure, so it was not recorded. Add the operating system and its version on the device page.',
  gentle_only: 'Fragile device: only a gentle port scan ran, without version or operating system detection, so no software was recorded. Add its software on the device page, or allow regular scans for it there.',
  timed_out: 'The identification scan ran out of time before it finished, so nothing new was recorded. Scan it again later.',
  busy: 'Device discovery was scanning at that moment, so this device was not identified in this scan. Scan it again in a few minutes.',
  unavailable: "The network scanner (nmap in the scan container, Active discovery) is not available, so this device was not identified. Check the box's services and that Active discovery is on, then scan again.",
  declared_by_hand: 'Added by hand: Vedette does not port-scan it. The software you entered is what was checked.',
  scanning_off: 'Active scanning is off under Devices, Scope and sensors, so this device was not identified. Only what was already known was checked.',
  not_approved: 'Not approved in the inventory: not scanned, so not identified.',
  out_of_scope: 'Outside the confirmed scope now: not scanned, so not identified.',
  scope_not_confirmed: 'The scan scope commitment is not ticked under Devices, Scope and sensors: not scanned, so not identified.',
  box: 'This address is the Vedette box itself or one of its decoys: it is never scanned.',
  regular_scan_never: 'Set to never be scanned on its device page: not identified. Change that setting to identify it.',
  no_ip: 'No IP address is known for this device, so it could not be scanned or identified.',
  not_scanned: 'Not scanned in this run, so not identified.',
}
const identRow = (t: ScanTarget, found: string[], reason: IdentReason | null, note?: string): RunIdentRow =>
  ({ target_id: t.id, label: t.label, ip: t.ip, found, reason, note: note ?? IDENT_NOTE[reason ?? 'identified'] })
/** What the identification of a picked device says in the mock: the device's known OS and software, else the likeliest reason. */
function identOne(t: ScanTarget): RunIdentRow {
  const a = assetsStore.get().find((x: Asset) => x.id === t.id)
  if (!a) return identRow(t, [], 'not_scanned')
  if (a.origin === 'manual') return identRow(t, [], 'declared_by_hand')
  if (a.fragile && a.kind !== 'unknown') return identRow(t, [], 'gentle_only')
  const found = [...(a.os ? [`Operating system: ${a.os.value}`] : []), ...(a.kind !== 'unknown' ? [`Type: ${a.kind}`] : []), ...a.software.slice(0, 18).map((s) => `Software: ${s.display}`)]
  if (a.software.some((s) => s.version)) return identRow(t, found, null)
  return identRow(t, found, !a.services.length ? 'no_open_ports' : a.os?.value.includes('(build ') ? 'os_no_patch_level' : a.os ? 'os_unconfirmed' : 'no_version')
}

// ---- chạy quét ----
const who = () => currentUser()?.email ?? 'system'
const strip = (r: StoredRun): ScanRun => { const { target_ids: _t, stop_requested_at: _s, ...rest } = r; return rest }
const saveRun = (r: StoredRun) => runs.update((l) => l.map((x) => (x.id === r.id ? r : x)))

function scanOne(t: ScanTarget, stopOnSlow: boolean): { rows: StoredRow[]; probes: Omit<ProbeEntry, 'id' | 'run_id'>[]; unresponsive: boolean } {
  const ts = nowIso()
  if (SLOW.has(t.id) && stopOnSlow) return { rows: [], probes: [], unresponsive: true }
  if (SLOW.has(t.id)) return { rows: [row(t, null, 'no_response', null, 'The device did not respond within the timeout; skipped.')], probes: [{ ts, ip: t.ip, label: t.label, template: 'vedette/fingerprint', request: 'GET / HTTP/1.1 (read banner)', result: 'no_response' }], unresponsive: false }
  const fs = findingsStore.get().filter((f) => f.asset_id === t.id)
  const rows: StoredRow[] = []
  const out: Omit<ProbeEntry, 'id' | 'run_id'>[] = []
  for (const f of fs) {
    if (!hasTemplate(f.cve)) {
      rows.push(row(t, null, 'no_template', f.id, `${f.cve}: no safe scan template yet, still suspected by version.`))
      continue
    }
    const still = f.status === 'confirmed' || f.status === 'suspected'
    rows.push(row(t, templateName(f.cve), still ? 'matched' : 'not_matched', f.id, still ? `${f.cve}: the scan template matches, the flaw is still there.` : `${f.cve}: no match reported by the scan template.`))
    out.push({ ts, ip: t.ip, label: t.label, template: templateName(f.cve), request: 'GET /photo/ HTTP/1.1', result: still ? 'matched' : 'not_matched' })
  }
  if (!rows.length) rows.push(row(t, null, 'not_applicable', null, 'No scan template applies to the software on this device.'))
  out.push({ ts, ip: t.ip, label: t.label, template: 'vedette/fingerprint', request: 'GET / HTTP/1.1 (read banner)', result: 'banner' })
  return { rows, probes: out, unresponsive: false }
}

/** Ghi kết quả vào phát hiện dùng chung: chỉ khớp → xác nhận. Không khớp chỉ là "không báo khớp" (nuclei chỉ in dòng khớp, D-133 (5)): không bao giờ đóng, hạ hay ghi gì lên phát hiện. */
function applyToFindings(rows: StoredRow[]) {
  const ts = nowIso()
  findingsStore.update((l) => l.map((f: Finding) => {
    const r = rows.find((x) => x.finding_id === f.id && x.template)
    if (!r || r.result !== 'matched') return f
    return { ...f, status: 'confirmed', basis: 'scan', confidence: Math.max(f.confidence, 0.95), last_seen: ts,
      evidence: { ...(f.evidence ?? { summary: '' }), summary: f.evidence?.summary || `Safe scan template ${r.template} matched on ${r.label}.`, template: r.template ?? undefined, checked_at: ts },
      history: [...f.history, { ts, user: 'system', action: f.status === 'confirmed' ? 'rescanned' : 'confirmed', note: `Scan of ${r.label}: template matches` }] }
  }))
}

function finalize(r: StoredRun, status: ScanRun['status'], reason: string | null) {
  const all = targets()
  const rows: StoredRow[] = []
  const idents: RunIdentRow[] = []
  const newProbes: ProbeEntry[] = []
  r.target_ids.forEach((id, i) => {
    const t = all.find((x) => x.id === id)
    if (!t) return
    if (r.trigger === 'manual') idents.push(i > r.done ? identRow(t, [], 'not_scanned', SKIPPED) : identOne(t)) // the device a stop came on was identified first
    if (status === 'auto_stopped' && i === r.done) { rows.push(row(t, null, 'no_response', null, NO_RESP)); return }
    // Stop now while a device was being scanned: its requests on the way are logged as stopped, it has no result.
    if (status === 'stopped' && i === r.done) {
      rows.push(row(t, null, 'skipped', null, STOPPED_MID))
      newProbes.push(...scanOne(t, false).probes.map((p) => ({ ...p, id: newId('pr'), run_id: r.id, result: 'stopped' as const })))
      return
    }
    if (i >= r.done) { rows.push(row(t, null, 'skipped', null, SKIPPED)); return }
    const s = scanOne(t, config.get().stop_on_unresponsive)
    if (s.unresponsive) { rows.push(row(t, null, 'no_response', null, NO_RESP)); return }
    rows.push(...s.rows)
    newProbes.push(...s.probes.map((p) => ({ ...p, id: newId('pr'), run_id: r.id })))
  })
  applyToFindings(rows)
  probes.update((l) => [...newProbes.reverse(), ...l])
  if (status === 'stopped') engineStore.set({ busyUntil: Date.now() + timing.engineMs }) // the worker is still finishing the request on its way
  const done: StoredRun = { ...r, status, ended_at: nowIso(), current: null, results: rows, matched: rows.filter((x) => x.result === 'matched').length, stop_reason: reason, identification: idents }
  saveRun(done)
  return done
}

/** Tính tiến độ theo thời gian thực của đồng hồ. */
function advance(r: StoredRun): StoredRun {
  if (r.status === 'done' || r.status === 'stopped' || r.status === 'auto_stopped') return r
  const now = Date.now()
  if (r.status === 'stopping') {
    return now - Date.parse(r.stop_requested_at ?? r.started_at) >= timing.stopMs ? finalize(r, 'stopped', STOP_NOW) : r
  }
  const all = targets()
  const elapsed = now - Date.parse(r.started_at)
  const idx = Math.min(r.total, Math.floor(elapsed / timing.stepMs))
  const stopOnSlow = config.get().stop_on_unresponsive
  const slowAt = r.target_ids.findIndex((id) => SLOW.has(id))
  if (stopOnSlow && slowAt >= 0 && idx > slowAt) {
    const t = all.find((x) => x.id === r.target_ids[slowAt])
    const n = config.get().unresponsive_after
    return finalize({ ...r, done: slowAt }, 'auto_stopped', `${t?.label ?? 'The device'} (${t?.ip ?? ''}) stopped responding after ${n} failed requests. Vedette stopped so the device is not hung.`)
  }
  if (idx >= r.total) return finalize({ ...r, done: r.total }, 'done', null)
  const cur = all.find((x) => x.id === r.target_ids[idx])
  const next: StoredRun = { ...r, done: idx, current: cur ? { label: cur.label, ip: cur.ip } : null }
  saveRun(next)
  return next
}

function startRun(ids: string[], trigger: ScanRun['trigger'], note: string | null, user: string): StoredRun {
  const all = targets()
  const r: StoredRun = { id: newId('run'), trigger, trigger_note: note, started_at: nowIso(), started_by: user, ended_at: null, status: 'running', total: ids.length, done: 0, current: null, results: [], matched: 0, stop_reason: null, target_ids: ids, stop_requested_at: null, identification: [] }
  const t0 = all.find((x) => x.id === ids[0])
  r.current = t0 ? { label: t0.label, ip: t0.ip } : null
  runs.update((l) => [r, ...l].slice(0, 100))
  return r
}

const allRuns = () => runs.get().map(advance)

// ---- validate cấu hình ----
function validateConfig(c: ScanConfig): string | null {
  const w = c.window
  if (!Array.isArray(w.days) || !w.days.length || w.days.some((d) => !Number.isInteger(d) || d < 1 || d > 7)) return 'Choose at least one day for the scan window.'
  if (!HM_RE.test(w.from) || !HM_RE.test(w.to)) return 'Time must look like HH:MM, for example 22:00.'
  if (w.from === w.to) return 'The start and end times must differ. To scan all day, set 00:00 to 23:59.'
  if (!Number.isInteger(c.rate) || c.rate < 1 || c.rate > 20) return 'The rate must be 1 to 20 requests per second. A lower rate is safer for old devices.'
  if (!Array.isArray(c.exclusions) || c.exclusions.length > 200) return 'The exclusion list can have at most 200 lines.'
  for (const [i, e] of c.exclusions.entries()) if (typeof e !== 'string' || (!IPV4_RE.test(e) && !CIDR_RE.test(e))) return `Line ${i + 1}: "${String(e).slice(0, 40)}" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.`
  if (!Number.isInteger(c.unresponsive_after) || c.unresponsive_after < 2 || c.unresponsive_after > 20) return 'The number of non-responses before auto-stop must be 2 to 20.'
  const s = c.schedule
  if (s.frequency !== 'daily' && s.frequency !== 'weekly') return 'The schedule must be daily or weekly.'
  if (!HM_RE.test(s.at)) return 'The schedule time must look like HH:MM.'
  if (!Number.isInteger(s.weekday) || s.weekday < 1 || s.weekday > 7) return 'The schedule day is not valid.'
  if (s.enabled) {
    if (!inTimeRange(s.at, w.from, w.to)) return `The schedule time ${s.at} is outside the ${w.from} to ${w.to} window. Pick a time inside the window or widen the window.`
    if (s.frequency === 'weekly' && !w.days.includes(s.weekday)) return 'The weekly schedule day must be one of the scan window days.'
  }
  return null
}

function configResponse(): ScanConfigResponse {
  const sc = scope.get()
  const c = config.get()
  const up = scannerStore.get().available
  const block = !sc.commitment ? 'The scan scope commitment is not ticked yet. Do it under Devices, Scope and sensors.' : !up ? SCANNER_DOWN : null
  const zoneDown = !zoneStore.get().readable
  const sched = zoneDown && c.schedule.enabled ? ZONE_DOWN : null
  return { config: c, next_run: zoneDown ? null : nextRun(c, new Date(), !runs.get().some((r) => r.trigger === 'schedule')), scope: sc, can_scan: block === null, block_reason: block, dangerous_checks: false, schedule_blocked_reason: sched }
}

// ---- khoá SSH (S-SCAN-5) ----
const KEY_RE = /-----BEGIN (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----([\s\S]+?)-----END (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----/
function keyLast4(raw: string): string | { error: string } {
  if (raw.length > 16_384) return { error: 'The key is longer than 16 KB. Check again: is this really a private key file?' }
  if (/ssh-(rsa|ed25519)|ecdsa-sha2/.test(raw) && !raw.includes('PRIVATE KEY')) return { error: 'This is a public key. Paste the private key, which starts with the line -----BEGIN OPENSSH PRIVATE KEY-----.' }
  const k = KEY_RE.exec(raw.trim())
  if (!k) return { error: 'Could not read the private key. Paste it exactly, from the -----BEGIN ... PRIVATE KEY----- line to the -----END ... PRIVATE KEY----- line.' }
  const bodyB64 = (k[1] ?? '').replace(/\s+/g, '')
  if (bodyB64.length < 40) return { error: 'The key is too short to be valid. Paste the whole content of the key file again.' }
  return bodyB64.slice(-4)
}

const NOT_FOUND = () => fail(404, 'not_found', 'No such item.')

export const handlers = [
  http.get(`${API}/scans/config`, () => { const d = guard('viewer'); return d ?? HttpResponse.json(configResponse()) }),

  // Cấu hình phạm vi/an toàn = admin (spec §4). Nhận một phần, gộp rồi kiểm tra toàn bộ.
  http.put(`${API}/scans/config`, async ({ request }) => {
    const d = guard('admin'); if (d) return d
    const b = await body<Partial<ScanConfig> & { dangerous_checks: boolean }>(request)
    if (b.dangerous_checks === true) return fail(400, 'dangerous_locked', 'Vedette has no dangerous checks: no exploitation, no denial of service. It cannot be turned on.')
    const cur = config.get()
    const next: ScanConfig = {
      ...cur, ...b,
      window: { ...cur.window, ...(b.window ?? {}) },
      schedule: { ...cur.schedule, ...(b.schedule ?? {}) },
    }
    const err = validateConfig(next)
    if (err) return fail(400, 'invalid_config', err)
    config.set(next)
    audit('scan.config', 'scan', JSON.stringify({ rate: next.rate, window: next.window, exclusions: next.exclusions.length, auto_rescan: next.auto_rescan, schedule: next.schedule.enabled }))
    return HttpResponse.json(configResponse())
  }),

  http.get(`${API}/scans/targets`, () => { const d = guard('viewer'); return d ?? HttpResponse.json({ items: targets() }) }),

  http.get(`${API}/scans/runs`, () => { const d = guard('viewer'); return d ?? HttpResponse.json({ items: allRuns().map(strip), engine_busy: engineBusy() }) }),

  http.post(`${API}/scans/runs`, async ({ request }) => {
    const d = guard('operator'); if (d) return d
    const sc = scope.get()
    if (!sc.commitment) return fail(400, 'commitment_required', 'Vedette does not scan until the scope commitment is ticked. Do it under Devices, Scope and sensors.')
    const b = await body<{ targets: string[] }>(request)
    if (!Array.isArray(b.targets) || !b.targets.length) return fail(400, 'no_targets', 'Choose at least one device to scan.')
    if (b.targets.length > 200) return fail(400, 'too_many', 'A scan can include at most 200 devices.')
    if (engineBusy() || allRuns().some((r) => r.status === 'running' || r.status === 'stopping')) return fail(409, 'already_running', 'A scan is already running. Wait for it to finish or press Stop now.')
    const all = targets()
    const ids = [...new Set(b.targets.map(String))]
    for (const id of ids) {
      const t = all.find((x) => x.id === id)
      if (!t) return fail(400, 'unknown_target', `There is no target "${id.slice(0, 40)}" in the scan list.`)
      if (!t.selectable) return fail(400, 'out_of_scope', `${t.label} (${t.ip}) ${reasonOf(t.reason)}, so it cannot be scanned.`)
    }
    // External targets are not scanned yet (not_supported above). When they are, exposure's CheckScannable (INV-13, 409 ip_not_current) runs here, right before the scan.
    if (!scannerStore.get().available) return fail(503, 'scanner_unavailable', SCANNER_DOWN)
    const r = startRun(ids, 'manual', null, who())
    audit('scan.start', r.id, `${ids.length} targets`)
    return HttpResponse.json(strip(r), { status: 201 })
  }),

  // "Dừng ngay" (S-SCAN-4): ngừng gửi yêu cầu mới, trạng thái thành "stopping" rồi "stopped" sau timing.stopMs (≤ 5 s).
  http.post(`${API}/scans/runs/:id/stop`, ({ params }) => {
    const d = guard('operator'); if (d) return d
    const cur = allRuns().find((x) => x.id === params.id)
    if (!cur) return NOT_FOUND()
    if (cur.status !== 'running' && cur.status !== 'stopping') return fail(409, 'not_running', 'This scan has already ended, so there is nothing to stop.')
    const stored = runs.get().find((x) => x.id === cur.id)!
    if (stored.status === 'running') {
      saveRun({ ...stored, status: 'stopping', stop_requested_at: nowIso() })
      audit('scan.stop', stored.id, `scanned ${stored.done}/${stored.total}`)
    }
    return HttpResponse.json(strip(runs.get().find((x) => x.id === cur.id)!))
  }),

  http.get(`${API}/scans/probes.csv`, () => {
    const d = guard('viewer'); if (d) return d
    // Names come from the network (DHCP, mDNS): a cell a spreadsheet would read as a formula gets a leading quote (OWASP CSV injection).
    const esc = (s: string) => `"${(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s).replaceAll('"', '""')}"`
    const text = ['time,target,name,template,request,result', ...probes.get().map((p) => [p.ts, p.ip, esc(p.label), esc(p.template), esc(p.request), p.result].join(','))].join('\n')
    return new HttpResponse(text, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=vedette-probe-log.csv' } })
  }),

  http.get(`${API}/scans/probes`, () => {
    const d = guard('viewer'); if (d) return d
    return HttpResponse.json({ items: probes.get(), retention_days: RETENTION_DAYS })
  }),

  http.get(`${API}/scans/events`, () => {
    const d = guard('viewer'); if (d) return d
    return HttpResponse.json({ items: events.get(), auto_rescan: config.get().auto_rescan })
  }),

  // Quét có tài khoản (module scan-credentialed, S-SCAN-5). Khoá riêng không bao giờ được lưu hay trả lại: chỉ giữ 4 ký tự cuối.
  http.get(`${API}/scans/credentialed`, () => {
    const d = guard('viewer'); if (d) return d
    return HttpResponse.json({ items: creds.get(), enabled: isOn('scan-credentialed') })
  }),

  http.post(`${API}/scans/credentialed`, async ({ request }) => {
    const d = guard('admin'); if (d) return d
    const b = await body<{ asset_id: string; port: number; username: string; private_key: string }>(request)
    const t = targets().find((x) => x.id === b.asset_id && x.kind === 'internal')
    if (!t) return fail(400, 'unknown_host', 'Choose a server from the device list in the inventory.')
    if (!t.selectable) return fail(400, 'out_of_scope', `${t.label} (${t.ip}) ${reasonOf(t.reason)}, so it cannot be scanned.`)
    if (!['server', 'nas', 'web'].includes(t.device_kind ?? '')) return fail(400, 'not_server', `${t.label} is not a server. Scanning with an account over SSH is only for servers, NAS or web machines.`)
    if (!Number.isInteger(b.port) || (b.port ?? 0) < 1 || (b.port ?? 0) > 65535) return fail(400, 'bad_port', 'The SSH port must be 1 to 65535 (usually 22).')
    if (typeof b.username !== 'string' || !/^[a-z_][a-z0-9_-]{0,31}$/.test(b.username)) return fail(400, 'bad_username', 'The account name uses lowercase letters, digits, underscores or hyphens and starts with a letter (for example vedette-scan).')
    if (creds.get().some((c) => c.asset_id === t.id)) return fail(409, 'exists', `${t.label} already has a scan account. Remove the old entry and add it again to change the key.`)
    const k = keyLast4(String(b.private_key ?? ''))
    if (typeof k !== 'string') return fail(400, 'bad_key', k.error)
    const c: CredTarget = { id: newId('cr'), asset_id: t.id, label: t.label, host: t.ip, port: b.port!, username: b.username, key_last4: k, created_at: nowIso(), last_test: null }
    creds.update((l) => [...l, c])
    audit('scan.credentialed.add', t.label, `${b.username}@${t.ip}:${b.port}`)
    return HttpResponse.json(c, { status: 201 })
  }),

  http.delete(`${API}/scans/credentialed/:id`, ({ params }) => {
    const d = guard('admin'); if (d) return d
    const c = creds.get().find((x) => x.id === params.id)
    if (!c) return NOT_FOUND()
    creds.update((l) => l.filter((x) => x.id !== c.id))
    audit('scan.credentialed.remove', c.label)
    return new HttpResponse(null, { status: 204 })
  }),

  // Thử kết nối: mock coi là thành công khi thiết bị có dịch vụ ở đúng cổng trong kiểm kê.
  http.post(`${API}/scans/credentialed/:id/test`, ({ params }) => {
    const d = guard('operator'); if (d) return d
    const c = creds.get().find((x) => x.id === params.id)
    if (!c) return NOT_FOUND()
    const ok = !!assetsStore.get().find((a) => a.id === c.asset_id)?.services.some((s) => s.port === c.port)
    const box = dataMode() === 'clean' ? '' : '192.168.10.250 '
    const message = ok
      ? `Connected as ${c.username}@${c.host}:${c.port}; the target accepted the key ending in ${c.key_last4}.`
      : `Could not connect to ${c.host}:${c.port} (5 second timeout). Check that the SSH service is running and the firewall allows the Vedette box ${box}to reach this port.`
    const next: CredTarget = { ...c, last_test: { ok, ts: nowIso(), message } }
    creds.update((l) => l.map((x) => (x.id === c.id ? next : x)))
    audit('scan.credentialed.test', c.label, ok ? 'ok' : 'failed')
    return HttpResponse.json(next)
  }),
]
