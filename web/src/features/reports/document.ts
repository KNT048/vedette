// Mock of the periodic security report: a fixed sample network, filtered and grouped by the saved options the way the
// server builds the document (one query per section on the shared read models). Clean install: an empty network.
import { dataMode } from '@/mocks/db'
import { orgStore } from '@/mocks/stores'
import { dayOf } from '@/lib/format'
import type {
  CveSeverity, DeviceRef, ExposureTarget, Handled, HandledItem, OpenStatus, ReportDefinition, ReportDocument, ReportFinding, ReportOptions, Reason,
} from './types'
import type { z } from 'zod'
import type * as C from './contract'

type Fix = z.infer<typeof C.Fix>
type Verification = z.infer<typeof C.Verification>

const DAY = 864e5
export const URGENCY: OpenStatus[] = ['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended']
const rank = (s: string) => { const i = URGENCY.indexOf(s as OpenStatus); return i < 0 ? URGENCY.length : i }

export const DEFAULT_OPTIONS: ReportOptions = {
  period: 'last_7_days', grouping: 'device', include_not_added: true, include_not_relevant: false,
  sections: { summary: true, handled: true, open: true, new: true, exposure: true, detections: true, coverage: true },
  charts: true,
}

/** The period a document covers when made at `at` (calendar_month: the last whole month, in UTC for the mock). */
export function periodOf(kind: ReportOptions['period'], at: number) {
  if (kind === 'calendar_month') {
    const d = new Date(at)
    const to = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)
    const from = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1)
    return { kind, from: new Date(from).toISOString(), to: new Date(to).toISOString(), tz: 'UTC' }
  }
  const days = kind === 'last_30_days' ? 30 : 7
  return { kind, from: new Date(at - days * DAY).toISOString(), to: new Date(at).toISOString(), tz: 'UTC' }
}

const dev = (id: string, name: string, added = true): DeviceRef => ({ id, name, added })
const D = {
  ws: dev('a-ws-07', 'ws-accounting-07'), web: dev('a-web-01', 'web-01'), fw: dev('a-fw-01', 'edge-firewall'),
  nas: dev('a-nas-01', 'nas-files-01'), prn: dev('a-prn-02', 'printer-floor2'), rtr: dev('a-rtr-01', 'office-router'), lap: dev('a-lap-12', 'laptop-sales-12', false),
}
const sev = (band: NonNullable<CveSeverity>['band'], score: number): CveSeverity => ({ band, score, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })
const byScan: Verification = { verified: 'scan', basis: 'scan', by: null, at: null }
const byDevice: Verification = { verified: 'device', basis: 'device_version', by: null, at: null }
const banner: Verification = { verified: 'no', basis: 'banner_version', by: null, at: null }
const fix = (kind: Fix['kind'], product: string, version: string | null, ref: string | null = null): Fix =>
  ({ key: `${product.toLowerCase().replace(/[^a-z0-9]+/g, '-')}|${kind}|${version ?? ref ?? ''}`, kind, product, version, ref, url: null })
const day = (end: number, back: number) => dayOf(new Date(end - back * DAY).toISOString())
const KEV_URL = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
const kev = (end: number, back: number): Reason => ({ layer: 2, source: 'cisa-kev', name: 'CISA KEV', date: day(end, back), url: KEV_URL, detail: null, due: day(end, back - 21) })

/** Open findings now; `age` = days since first seen, measured back from the end of the period. */
const OPEN = (end: number): (Omit<ReportFinding, 'first_seen'> & { age: number })[] => [
  { finding_id: 'f-101', cve: 'CVE-2021-41773', device: D.web, product: 'Apache HTTP Server', version: '2.4.49', status: 'under_attack', reasons: [{ layer: 1, source: 'ids', name: 'Intrusion detection', date: day(end, 1), url: null, detail: '192.0.2.77', due: null }, kev(end, 400)], severity: sev('high', 7.5), verification: byScan, fix: fix('update', 'Apache HTTP Server', '2.4.51'), age: 3 },
  { finding_id: 'f-102', cve: 'CVE-2024-21762', device: D.fw, product: 'Fortinet FortiOS', version: '7.2.4', status: 'exploited', reasons: [kev(end, 30)], severity: sev('critical', 9.8), verification: byDevice, fix: fix('update', 'Fortinet FortiOS', '7.2.7'), age: 20 },
  { finding_id: 'f-103', cve: 'CVE-2025-0411', device: D.lap, product: '7-Zip', version: '24.07', status: 'exploited', reasons: [kev(end, 10)], severity: sev('high', 7.0), verification: byDevice, fix: fix('update', '7-Zip', '24.09'), age: 2 },
  { finding_id: 'f-104', cve: 'CVE-2022-27593', device: D.nas, product: 'QNAP Photo Station', version: '6.0.20', status: 'exploited', reasons: [kev(end, 60)], severity: sev('critical', 9.1), verification: banner, fix: fix('update', 'QNAP Photo Station', '6.0.22'), age: 40 },
  { finding_id: 'f-105', cve: 'CVE-2023-1707', device: D.prn, product: 'HP LaserJet firmware', version: '5.6.0.2', status: 'update_recommended', reasons: [], severity: sev('high', 7.5), verification: banner, fix: fix('unknown', 'HP LaserJet firmware', null, 'HPSBPI03838'), age: 5 },
  { finding_id: 'f-106', cve: 'CVE-2024-38063', device: D.ws, product: 'Windows 11 23H2', version: '22631.3880', status: 'update_recommended', reasons: [], severity: sev('critical', 9.8), verification: byDevice, fix: fix('os_update', 'Windows 11 23H2', null, 'KB5041585'), age: 1 },
  { finding_id: 'f-108', cve: 'CVE-2024-41592', device: D.rtr, product: 'DrayTek Vigor firmware', version: '4.3.2', status: 'critical_edge', reasons: [{ layer: 4, source: 'cvss', name: 'CVSS', date: day(end, 9), url: null, detail: 'Critical, needs no login', due: null }], severity: sev('critical', 10), verification: banner, fix: fix('update', 'DrayTek Vigor firmware', '4.3.2.8'), age: 9 },
  { finding_id: 'f-107', cve: 'CVE-2024-6387', device: D.nas, product: 'OpenSSH', version: '8.9p1', status: 'public_exploit', reasons: [{ layer: 3, source: 'github-poc', name: 'GitHub', date: day(end, 12), url: null, detail: '244 stars', due: null }], severity: sev('high', 8.1), verification: byDevice, fix: fix('distro_update', 'OpenSSH', '1:8.9p1-3ubuntu0.10', 'USN-6859-1'), age: 12 },
]

/** `age` = days since it was handled, back from the end of the period; `took` = days from first seen to handled. */
type Row = Omit<HandledItem, 'handled'> & { device: DeviceRef; age: number; took: number; handled: Omit<Handled, 'at' | 'accepted_until'> }
const h = (resolution: Handled['resolution'], via: Handled['via'], by: string, note: string | null = null, from_version: string | null = null, to_version: string | null = null) =>
  ({ resolution, via, by, note, from_version, to_version })
const PERSON = 'it@acme.example'
const HANDLED: Row[] = [
  { device: D.ws, age: 2, took: 3, finding_id: 'f-201', cve: 'CVE-2023-38831', product: 'WinRAR', severity: sev('high', 7.8), handled: h('patched', 'version_moved', 'system', null, '6.24', '7.23') },
  { device: D.ws, age: 2, took: 3, finding_id: 'f-202', cve: 'CVE-2023-40477', product: 'WinRAR', severity: sev('high', 7.8), handled: h('patched', 'version_moved', 'system', null, '6.24', '7.23') },
  { device: D.web, age: 4, took: 9, finding_id: 'f-203', cve: 'CVE-2024-6387', product: 'OpenSSH', severity: sev('high', 8.1), handled: h('patched', 'person', PERSON, 'Updated from the distribution packages.') },
  { device: D.web, age: 5, took: 2, finding_id: 'f-204', cve: 'CVE-2021-44228', product: 'Apache Log4j', severity: sev('critical', 10), handled: h('mitigated', 'person', PERSON, 'JNDI lookups turned off until the vendor update.') },
  { device: D.lap, age: 3, took: 6, finding_id: 'f-205', cve: 'CVE-2023-40031', product: 'Notepad++', severity: sev('high', 7.8), handled: h('patched', 'software_removed', 'system') },
  { device: D.nas, age: 6, took: 14, finding_id: 'f-206', cve: 'CVE-2023-23397', product: 'Microsoft Outlook', severity: sev('critical', 9.8), handled: h('accepted', 'person', PERSON, 'Replaced at the end of the month.') },
  { device: D.prn, age: 1, took: 1, finding_id: 'f-207', cve: 'CVE-2022-3942', product: 'HP LaserJet firmware', severity: sev('medium', 6.1), handled: h('not_relevant', 'data_corrected', 'system') },
]

const TARGETS = (end: number): ExposureTarget[] => [
  { target_id: 't-1', kind: 'domain', value: 'example.com', parent: null, proof: 'proven', last_scan_at: new Date(end - DAY).toISOString(),
    services: [
      { ip: '198.51.100.10', port: 443, proto: 'tcp', name: 'https', product: 'nginx', version: '1.24.0', change: null, cert_expires_at: new Date(end + 12 * DAY).toISOString() },
      { ip: '198.51.100.10', port: 8443, proto: 'tcp', name: 'https', product: 'GitLab', version: null, change: 'new', cert_expires_at: new Date(end + 80 * DAY).toISOString() },
      { ip: '198.51.100.10', port: 21, proto: 'tcp', name: 'ftp', product: 'vsftpd', version: '3.0.5', change: 'closed', cert_expires_at: null },
    ],
    issues: [{ engine: 'zap', severity: 'medium', open: 3, new: 1 }, { engine: 'surface', severity: 'info', open: 2, new: 0 }] },
  { target_id: 't-2', kind: 'domain', value: 'shop.example.com', parent: 'example.com', proof: 'covered', last_scan_at: new Date(end - 2 * DAY).toISOString(),
    services: [{ ip: '198.51.100.11', port: 443, proto: 'tcp', name: 'https', product: 'Apache HTTP Server', version: '2.4.49', change: null, cert_expires_at: new Date(end + 45 * DAY).toISOString() }],
    issues: [{ engine: 'nuclei', severity: 'high', open: 1, new: 1 }] },
  { target_id: 't-3', kind: 'ip', value: '198.51.100.20', parent: null, proof: 'proven', last_scan_at: new Date(end - 3 * DAY).toISOString(),
    services: [{ ip: '198.51.100.20', port: 500, proto: 'udp', name: 'isakmp', product: null, version: null, change: null, cert_expires_at: null }],
    issues: [] },
  { target_id: 't-4', kind: 'ip', value: '198.51.100.30', parent: null, proof: 'proven', last_scan_at: null, services: [], issues: [] },
]

const groupLimit = 100

/** The document of `def` made at `at` (default now). */
export function buildDocument(def: ReportDefinition, at = Date.now()): ReportDocument {
  const o = def.options
  const period = periodOf(o.period, at)
  const from = Date.parse(period.from), end = Date.parse(period.to)
  const clean = dataMode() === 'clean'
  const keep = (d: DeviceRef) => o.include_not_added || d.added
  const open = clean ? [] : OPEN(end).filter((f) => keep(f.device))
    .map(({ age, ...f }): ReportFinding => ({ ...f, first_seen: new Date(end - age * DAY).toISOString() }))
    .sort((a, b) => rank(a.status) - rank(b.status) || (b.severity?.score ?? 0) - (a.severity?.score ?? 0) || a.cve.localeCompare(b.cve))
  const handled = clean ? [] : HANDLED.filter((r) => keep(r.device) && (o.include_not_relevant || r.handled.resolution !== 'not_relevant'))
    .map(({ age, took, ...r }) => ({ ...r, took, handled: { ...r.handled, at: new Date(end - age * DAY).toISOString(), accepted_until: r.handled.resolution === 'accepted' ? day(end, -30) : null } }))
    .filter((r) => Date.parse(r.handled.at) >= from)
  // New = first seen in the period, still open or handled since, so open at the start + new - handled = open now.
  const handledFresh = handled.filter((r) => Date.parse(r.handled.at) - r.took * DAY >= from).map((r): ReportFinding => ({
    finding_id: r.finding_id, cve: r.cve, device: r.device, product: r.product, version: r.handled.from_version, status: r.handled.resolution, reasons: [],
    severity: r.severity, verification: byDevice, fix: fix('update', r.product, r.handled.to_version), first_seen: new Date(Date.parse(r.handled.at) - r.took * DAY).toISOString(),
  }))
  const fresh = [...open.filter((f) => Date.parse(f.first_seen) >= from), ...handledFresh]

  const doc: ReportDocument = {
    definition_id: def.id, title: def.name, org: orgStore.get().name, generated_at: new Date(at).toISOString(), period, options: o, ai_summary: null,
  }
  const s = o.sections
  if (s.summary) {
    const byCve = new Map<string, ReportFinding[]>()
    for (const f of open) byCve.set(`${f.cve}|${f.product}`, [...(byCve.get(`${f.cve}|${f.product}`) ?? []), f])
    doc.summary = {
      open_by_status: URGENCY.map((status) => ({ status, n: open.filter((f) => f.status === status).length })).filter((r) => r.n > 0),
      open_now: open.length, open_before: open.length - fresh.length + handled.length, new: fresh.length, handled: handled.length,
      first: [...byCve.values()].slice(0, 3).map((fs) => {
        const f = fs[0]!
        return { status: f.status as OpenStatus, cve: f.cve, finding_id: f.finding_id, product: f.product, severity: f.severity, fix: f.fix, devices: fs.slice(0, 3).map((x) => x.device), device_count: new Set(fs.map((x) => x.device.id)).size, finding_count: fs.length }
      }),
    }
  }
  if (s.handled) {
    const totals = new Map<string, { resolution: Handled['resolution']; via: Handled['via']; n: number }>()
    for (const { handled: x } of handled) {
      const k = `${x.resolution}|${x.via}`
      totals.set(k, { resolution: x.resolution, via: x.via, n: (totals.get(k)?.n ?? 0) + 1 })
    }
    const devices = new Map<string, { device: DeviceRef; items: HandledItem[] }>()
    for (const { device, took: _took, ...item } of handled.slice(0, groupLimit)) {
      const g = devices.get(device.id) ?? { device, items: [] }
      g.items.push(item)
      devices.set(device.id, g)
    }
    const days = handled.filter((r) => r.handled.resolution === 'patched' || r.handled.resolution === 'mitigated').map((r) => r.took).sort((a, b) => a - b)
    const median = days.length ? (days.length % 2 ? days[(days.length - 1) / 2]! : (days[days.length / 2 - 1]! + days[days.length / 2]!) / 2) : null
    const leftOut = clean || o.include_not_relevant ? 0 : HANDLED.filter((r) => keep(r.device) && r.handled.resolution === 'not_relevant').length
    doc.handled = { totals: [...totals.values()], devices: [...devices.values()], more: Math.max(0, handled.length - groupLimit), median_days: median,
      ...(leftOut ? { not_relevant_left_out: leftOut } : {}) }
  }
  if (s.open) {
    const groups = new Map<string, { key: string; label: string; status: OpenStatus; items: ReportFinding[] }>()
    for (const f of open.slice(0, groupLimit)) {
      const key = o.grouping === 'device' ? f.device.id : f.cve
      const g = groups.get(key) ?? { key, label: o.grouping === 'device' ? f.device.name : f.cve, status: f.status as OpenStatus, items: [] }
      g.items.push(f)
      groups.set(key, g)
    }
    doc.open = { grouping: o.grouping, total: open.length, groups: [...groups.values()], more: Math.max(0, open.length - groupLimit) }
  }
  if (s.new) doc.new = { total: fresh.length, items: fresh.slice(0, groupLimit), more: Math.max(0, fresh.length - groupLimit) }
  if (s.exposure) doc.exposure = { module_on: true, targets: clean ? [] : TARGETS(end) }
  if (s.detections) {
    doc.detections = clean ? { module_on: true, by_kind: [], top: [] } : {
      module_on: true,
      by_kind: [
        { kind: 'intrusion', n: 2, last_at: new Date(end - DAY).toISOString() },
        { kind: 'trap', n: 3, last_at: new Date(end - 2 * DAY).toISOString() },
        { kind: 'log_anomaly', n: 14, last_at: new Date(end - 3 * DAY).toISOString() },
        { kind: 'bad_address', n: 1, last_at: new Date(end - 4 * DAY).toISOString() },
        { kind: 'unknown_device', n: 1, last_at: new Date(end - 5 * DAY).toISOString() },
      ],
      top: [
        { kind: 'intrusion', title: 'Exploit attempt for CVE-2021-41773 against web-01', severity: 'critical', device: D.web, at: new Date(end - DAY).toISOString() },
        { kind: 'trap', title: 'A device touched the SSH trap', severity: 'high', device: keep(D.lap) ? D.lap : null, at: new Date(end - 2 * DAY).toISOString() },
      ],
    }
  }
  if (s.coverage) {
    const devices = clean ? 1 : o.include_not_added ? 8 : 7
    doc.coverage = {
      devices, with_agent: clean ? 0 : 3, not_added: clean || !o.include_not_added ? 0 : 1,
      sources: [{ id: 'sensor-passive', on: true }, { id: 'sensor-active', on: true }, { id: 'agent-intake', on: true }, { id: 'honeypot', on: !clean }, { id: 'logs', on: false }, { id: 'exposure', on: true }, { id: 'ids', on: true }],
      feeds: [
        { id: 'cisa-kev', name: 'CISA KEV', last_ok_at: new Date(at - 3600e3).toISOString(), stale: false },
        { id: 'nvd', name: 'NVD', last_ok_at: new Date(at - 3 * DAY).toISOString(), stale: true },
      ],
    }
  }
  return doc
}
