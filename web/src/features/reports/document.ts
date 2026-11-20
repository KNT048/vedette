// Mock of the periodic security report: a fixed sample network, filtered and grouped by the saved options the way the
// server builds the document (one query per section on the shared read models). Clean install: an empty network.
import { dataMode } from '@/mocks/db'
import type {
  DeviceRef, ExposureTarget, HandledItem, OpenStatus, ReportDefinition, ReportDocument, ReportFinding, ReportOptions, Severity, UrgencyReason,
} from './types'

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
const sev = (band: NonNullable<Severity>['band'], score: number): Severity => ({ band, score })
const byScan = { verified: 'scan' as const, by: null, basis: 'scan' }
const byDevice = { verified: 'device' as const, by: null, basis: 'device_version' }
const banner = { verified: 'no' as const, by: null, basis: 'banner_version' }
const update = (version: string) => ({ kind: 'update', version, ref: null })

/** Open findings now; `age` = days since first seen, measured back from the end of the period. */
const kev = (url: string): UrgencyReason => ({ status: 'exploited', source: 'CISA KEV', at: null, url, detail: null })
const KEV_URL = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
const OPEN: (Omit<ReportFinding, 'first_seen'> & { age: number })[] = [
  { finding_id: 'f-101', cve: 'CVE-2021-41773', device: D.web, product: 'Apache HTTP Server', version: '2.4.49', status: 'under_attack', reasons: [{ status: 'under_attack', source: 'This box', at: null, url: null, detail: 'An exploit attempt was seen against this device' }, kev(KEV_URL)], severity: sev('high', 7.5), verification: byScan, fix: update('2.4.51'), age: 3 },
  { finding_id: 'f-102', cve: 'CVE-2024-21762', device: D.fw, product: 'Fortinet FortiOS', version: '7.2.4', status: 'exploited', reasons: [kev(KEV_URL)], severity: sev('critical', 9.8), verification: byDevice, fix: update('7.2.7'), age: 20 },
  { finding_id: 'f-103', cve: 'CVE-2025-0411', device: D.lap, product: '7-Zip', version: '24.07', status: 'exploited', reasons: [kev(KEV_URL)], severity: sev('high', 7.0), verification: byDevice, fix: update('24.09'), age: 2 },
  { finding_id: 'f-104', cve: 'CVE-2022-27593', device: D.nas, product: 'QNAP Photo Station', version: '6.0.20', status: 'exploited', reasons: [kev(KEV_URL)], severity: sev('critical', 9.1), verification: banner, fix: update('6.0.22'), age: 40 },
  { finding_id: 'f-105', cve: 'CVE-2023-1707', device: D.prn, product: 'HP LaserJet firmware', version: '5.6.0.2', status: 'update_recommended', reasons: [], severity: sev('high', 7.5), verification: banner, fix: { kind: 'unknown', version: null, ref: 'HPSBPI03838' }, age: 5 },
  { finding_id: 'f-106', cve: 'CVE-2024-38063', device: D.ws, product: 'Windows 11 23H2', version: '22631.3880', status: 'update_recommended', reasons: [], severity: sev('critical', 9.8), verification: byDevice, fix: { kind: 'os_update', version: null, ref: 'KB5041585' }, age: 1 },
  { finding_id: 'f-108', cve: 'CVE-2024-41592', device: D.rtr, product: 'DrayTek Vigor firmware', version: '4.3.2', status: 'critical_edge', reasons: [{ status: 'critical_edge', source: 'NVD', at: null, url: null, detail: 'Critical, needs no login' }], severity: sev('critical', 10), verification: banner, fix: update('4.3.2.8'), age: 9 },
  { finding_id: 'f-107', cve: 'CVE-2024-6387', device: D.nas, product: 'OpenSSH', version: '8.9p1', status: 'public_exploit', reasons: [{ status: 'public_exploit', source: 'GitHub', at: null, url: null, detail: 'Working exploit code is public' }], severity: sev('high', 8.1), verification: byDevice, fix: { kind: 'distro_update', version: '1:8.9p1-3ubuntu0.10', ref: 'USN-6859-1' }, age: 12 },
]

type Handled = HandledItem & { device: DeviceRef; age: number }
const vedette = { kind: 'vedette' as const, name: 'Vedette' }
const person = { kind: 'person' as const, name: 'it@acme.example' }
const HANDLED: Handled[] = [
  { device: D.ws, age: 2, finding_id: 'f-201', cve: 'CVE-2023-38831', product: 'WinRAR', severity: sev('high', 7.8), status: 'patched', via: 'version_moved', by: vedette, from_version: '6.24', to_version: '7.23', note: null, accepted_until: null, at: '' },
  { device: D.ws, age: 2, finding_id: 'f-202', cve: 'CVE-2023-40477', product: 'WinRAR', severity: sev('high', 7.8), status: 'patched', via: 'version_moved', by: vedette, from_version: '6.24', to_version: '7.23', note: null, accepted_until: null, at: '' },
  { device: D.web, age: 4, finding_id: 'f-203', cve: 'CVE-2024-6387', product: 'OpenSSH', severity: sev('high', 8.1), status: 'patched', via: 'person', by: person, from_version: null, to_version: null, note: 'Updated from the distribution packages.', accepted_until: null, at: '' },
  { device: D.web, age: 5, finding_id: 'f-204', cve: 'CVE-2021-44228', product: 'Apache Log4j', severity: sev('critical', 10), status: 'mitigated', via: 'person', by: person, from_version: null, to_version: null, note: 'JNDI lookups turned off until the vendor update.', accepted_until: null, at: '' },
  { device: D.lap, age: 3, finding_id: 'f-205', cve: 'CVE-2023-40031', product: 'Notepad++', severity: sev('high', 7.8), status: 'patched', via: 'software_removed', by: vedette, from_version: null, to_version: null, note: null, accepted_until: null, at: '' },
  { device: D.nas, age: 6, finding_id: 'f-206', cve: 'CVE-2023-23397', product: 'Microsoft Outlook', severity: sev('critical', 9.8), status: 'accepted', via: 'person', by: person, from_version: null, to_version: null, note: 'Replaced at the end of the month.', accepted_until: '', at: '' },
  { device: D.prn, age: 1, finding_id: 'f-207', cve: 'CVE-2022-3942', product: 'HP LaserJet firmware', severity: sev('medium', 6.1), status: 'not_relevant', via: 'data_corrected', by: vedette, from_version: null, to_version: null, note: null, accepted_until: null, at: '' },
]

const TARGETS = (end: number): ExposureTarget[] => [
  { target_id: 't-1', kind: 'domain', value: 'example.com', parent: null, proof: 'verified', last_scan_at: new Date(end - DAY).toISOString(),
    services: [
      { ip: '198.51.100.10', port: 443, proto: 'tcp', name: 'https', product: 'nginx', version: '1.24.0', change: null, cert_expires_at: new Date(end + 12 * DAY).toISOString() },
      { ip: '198.51.100.10', port: 8443, proto: 'tcp', name: 'https', product: 'GitLab', version: null, change: 'new', cert_expires_at: new Date(end + 80 * DAY).toISOString() },
      { ip: '198.51.100.10', port: 21, proto: 'tcp', name: 'ftp', product: 'vsftpd', version: '3.0.5', change: 'closed', cert_expires_at: null },
    ],
    issues: [{ engine: 'zap', severity: 'medium', open: 3, new: 1 }, { engine: 'surface', severity: 'info', open: 2, new: 0 }] },
  { target_id: 't-2', kind: 'domain', value: 'shop.example.com', parent: 'example.com', proof: 'covered', last_scan_at: new Date(end - 2 * DAY).toISOString(),
    services: [{ ip: '198.51.100.11', port: 443, proto: 'tcp', name: 'https', product: 'Apache HTTP Server', version: '2.4.49', change: null, cert_expires_at: new Date(end + 45 * DAY).toISOString() }],
    issues: [{ engine: 'nuclei', severity: 'high', open: 1, new: 1 }] },
  { target_id: 't-3', kind: 'ip', value: '198.51.100.20', parent: null, proof: 'verified', last_scan_at: new Date(end - 3 * DAY).toISOString(),
    services: [{ ip: '198.51.100.20', port: 500, proto: 'udp', name: 'isakmp', product: null, version: null, change: null, cert_expires_at: null }],
    issues: [] },
]

const groupLimit = 100

/** The document of `def` made at `at` (default now). */
export function buildDocument(def: ReportDefinition, at = Date.now()): ReportDocument {
  const o = def.options
  const period = periodOf(o.period, at)
  const from = Date.parse(period.from), end = Date.parse(period.to)
  const clean = dataMode() === 'clean'
  const keep = (d: DeviceRef) => o.include_not_added || d.added
  const open = clean ? [] : OPEN.filter((f) => keep(f.device))
    .map(({ age, ...f }): ReportFinding => ({ ...f, first_seen: new Date(end - age * DAY).toISOString() }))
    .sort((a, b) => rank(a.status) - rank(b.status) || (b.severity?.score ?? 0) - (a.severity?.score ?? 0) || a.cve.localeCompare(b.cve))
  const handled = clean ? [] : HANDLED.filter((h) => keep(h.device) && (o.include_not_relevant || h.status !== 'not_relevant'))
    .map((h) => ({ ...h, at: new Date(end - h.age * DAY).toISOString(), accepted_until: h.status === 'accepted' ? new Date(end + 30 * DAY).toISOString().slice(0, 10) : null }))
    .filter((h) => Date.parse(h.at) >= from)
  const fresh = open.filter((f) => Date.parse(f.first_seen) >= from)

  const doc: ReportDocument = {
    definition_id: def.id, title: def.name, generated_at: new Date(at).toISOString(), period, options: o, ai_summary: null,
  }
  const s = o.sections
  if (s.summary) {
    const byCve = new Map<string, ReportFinding[]>()
    for (const f of open) byCve.set(`${f.cve}|${f.product}`, [...(byCve.get(`${f.cve}|${f.product}`) ?? []), f])
    doc.summary = {
      open_by_status: URGENCY.map((status) => ({ status, n: open.filter((f) => f.status === status).length })).filter((r) => r.n > 0),
      open_now: open.length, open_before: Math.max(0, open.length - fresh.length + handled.length), new: fresh.length, handled: handled.length,
      first: [...byCve.values()].slice(0, 3).map((fs) => {
        const f = fs[0]!
        return { status: f.status as OpenStatus, cve: f.cve, finding_id: f.finding_id, product: f.product, severity: f.severity, fix: f.fix, devices: fs.slice(0, 3).map((x) => x.device), device_count: new Set(fs.map((x) => x.device.id)).size, finding_count: fs.length }
      }),
    }
  }
  if (s.handled) {
    const totals = new Map<string, { status: HandledItem['status']; via: string; n: number }>()
    for (const h of handled) {
      const k = `${h.status}|${h.via}`
      totals.set(k, { status: h.status, via: h.via, n: (totals.get(k)?.n ?? 0) + 1 })
    }
    const devices = new Map<string, { device: DeviceRef; items: HandledItem[] }>()
    for (const { device, age: _a, ...item } of handled.slice(0, groupLimit)) {
      const g = devices.get(device.id) ?? { device, items: [] }
      g.items.push(item)
      devices.set(device.id, g)
    }
    doc.handled = { totals: [...totals.values()], devices: [...devices.values()], more: Math.max(0, handled.length - groupLimit) }
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
        { kind: 'failed_logins', n: 14, last_at: new Date(end - 3 * DAY).toISOString() },
        { kind: 'bad_connection', n: 1, last_at: new Date(end - 4 * DAY).toISOString() },
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
      sources: [{ id: 'passive', on: true }, { id: 'active', on: true }, { id: 'agents', on: true }, { id: 'honeypot', on: !clean }, { id: 'logs', on: false }, { id: 'exposure', on: true }],
      feeds: [
        { id: 'cisa_kev', name: 'CISA KEV', last_ok_at: new Date(at - 3600e3).toISOString(), stale: false },
        { id: 'nvd', name: 'NVD', last_ok_at: new Date(at - 3 * DAY).toISOString(), stale: true },
      ],
    }
  }
  return doc
}
