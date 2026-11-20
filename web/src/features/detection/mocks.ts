// Mock API of intrusion detection. Table ids_alert holds the alerts as the ids module stores them (with their CVE ids, the
// ids_alert_cve rows, folded in, and the device ids found when the event arrived); the device names, the linked findings
// and the severity are resolved when read, like the box.
// The overview reads the other modules through their own endpoints, as core reads the modules' ports on the box.
//
// Until the ids module is in the module list, it counts as on in the sample data and off on a clean install (the box
// ships it off). The incident of an alert is kept on the alert here; on the box it is the notify incident of kind
// intrusion, handled with PATCH /notify/incidents/{id}.
import { http, HttpResponse } from 'msw'
import { API, fail, guard } from '@/mocks/http'
import { assetsStore, findingsStore, installStore, isOn, moduleAvailable, modulesStore } from '@/mocks/stores'
import { networkStore, spanStatusOf } from '@/mocks/network'
import { collection, dataMode, daysAgo, nowIso, peek } from '@/mocks/db'
import { containerSensorStore } from '@/features/inventory/mocks'
import { accepted } from '@/features/findings/mocks'
import type { Finding } from '@/lib/types'
import type { HpOverview } from '@/features/honeypot/types'
import type { Incident, IncidentsResponse } from '@/features/notify/types'
import type { IocHit, SourcesResponse } from '@/features/logs/types'
import { DETECTION_KINDS, type Alert, type AlertIncident, type AlertWindow, type DeviceRef, type FindingStatus, type KindCount, type MirrorHit, type Overview, type Severity, type Watcher } from './types'

type Stored = Omit<Alert, 'src_device' | 'dst_device' | 'findings' | 'severity'> & { src_asset_id: string | null; dst_asset_id: string | null; incident: AlertIncident | null }

const at = (d: number, h = 0) => daysAgo(d, h)
const alerts = collection<Stored[]>('ids_alert', () => [
  // A FortiGate IPS event naming a CVE the NAS is affected by: its finding is under attack.
  { id: 'ida-1', source: 'log', sid: 51006, signature: 'QNAP.Photo.Station.Path.Traversal', category: 'Path Traversal', priority: 1, src_ip: '198.51.100.23', dst_ip: '10.0.10.21', dst_port: 443, proto: 'tcp',
    src_asset_id: null, dst_asset_id: 'a-nas02', cves: ['CVE-2022-27593'], first_seen: at(0, 5), last_seen: at(0, 0.5), count: 14, incident: { id: 'in-ids-1', status: 'new' } },
  // Suricata on the firewall: two CVEs, the web server is not affected by either.
  { id: 'ida-2', source: 'log', sid: 2034124, signature: 'ET EXPLOIT Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)', category: 'Attempted Administrator Privilege Gain', priority: 1,
    src_ip: '198.51.100.77', dst_ip: '10.0.10.12', dst_port: 80, proto: 'tcp', src_asset_id: null, dst_asset_id: 'a-web01', cves: ['CVE-2021-41773', 'CVE-2021-42013'], first_seen: at(1, 3), last_seen: at(1, 2), count: 3,
    incident: { id: 'in-ids-2', status: 'acknowledged' } },
  // From inside the network, against the domain controller; handled.
  { id: 'ida-3', source: 'log', sid: 43796, signature: 'MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution', category: '', priority: 1, src_ip: '10.0.10.113', dst_ip: '10.0.10.10', dst_port: 445, proto: 'tcp',
    src_asset_id: null, dst_asset_id: 'a-srvad', cves: ['CVE-2017-0144'], first_seen: at(3, 2), last_seen: at(3, 1), count: 2, incident: { id: 'in-ids-3', status: 'resolved' } },
  // A scan with no CVE.
  { id: 'ida-4', source: 'log', sid: 2009358, signature: 'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)', category: 'Web Application Attack', priority: 3,
    src_ip: '192.0.2.50', dst_ip: '10.0.10.1', dst_port: 443, proto: 'tcp', src_asset_id: null, dst_asset_id: 'a-fw01', cves: [], first_seen: at(0, 0.4), last_seen: at(0, 0.2), count: 40, incident: { id: 'in-ids-4', status: 'new' } },
  // Outside the 7-day window.
  { id: 'ida-5', source: 'log', sid: 2029022, signature: 'ET EXPLOIT FortiOS SSL VPN - Pre-Auth Messages File Path Traversal (CVE-2018-13379)', category: 'Attempted Administrator Privilege Gain', priority: 1,
    src_ip: '198.51.100.9', dst_ip: '10.0.10.1', dst_port: 10443, proto: 'tcp', src_asset_id: null, dst_asset_id: 'a-fw01', cves: ['CVE-2018-13379'], first_seen: at(20, 4), last_seen: at(20, 3), count: 6, incident: { id: 'in-ids-5', status: 'resolved' } },
], () => [])

/** On while it is on in the module list; until it is listed there, on with the sample data and off on a clean install. */
function idsOn(): boolean {
  const m = modulesStore.get().find((x) => (x.id as string) === 'ids')
  return m ? m.enabled : dataMode() !== 'clean'
}
const offFail = () => fail(404, 'not_found', 'Not found.')

const ref = (a: { id: string; hostname: string | null; ip: string } | undefined): DeviceRef | null => (a ? { id: a.id, name: a.hostname ?? a.ip } : null)
const deviceAt = (ip: string) => ref(assetsStore.get().find((x) => x.ip === ip))
const deviceOf = (id: string | null) => (id ? ref(assetsStore.get().find((x) => x.id === id)) : null)
// The new status vocabulary of a finding the alert names: an open one is under attack (the attack is in the alert); a handled one keeps its
// handling. The shared store keeps an accepted risk as not_relevant, with its last day in the findings mock's own table.
const HANDLED: Partial<Record<Finding['status'], FindingStatus>> = { patched: 'patched', mitigated: 'mitigated', not_relevant: 'not_relevant', false_positive: 'false_positive' }
const statusOf = (f: Finding): FindingStatus => (accepted.get()[f.id] ? 'accepted' : HANDLED[f.status] ?? 'under_attack')
const PRIORITY_SEVERITY: Record<number, Severity> = { 1: 'high', 2: 'medium', 3: 'low', 4: 'info' }

function view(s: Stored): Alert {
  const { src_asset_id, dst_asset_id, ...rest } = s
  const dst = deviceOf(dst_asset_id)
  const findings = !dst ? [] : findingsStore.get().filter((f) => f.asset_id === dst.id && s.cves.includes(f.cve))
    .map((f) => ({ id: f.id, cve: f.cve, device: dst, status: statusOf(f) }))
    .sort((a, b) => a.cve.localeCompare(b.cve) || a.id.localeCompare(b.id))
  const affected = findings.some((f) => f.status === 'under_attack')
  return { ...rest, severity: affected ? 'critical' : PRIORITY_SEVERITY[s.priority] ?? 'info', src_device: deviceOf(src_asset_id), dst_device: dst, findings }
}

const WINDOW_MS: Record<AlertWindow, number> = { '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5 }
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i
const inWindow = (s: { last_seen: string }, ms: number) => new Date(s.last_seen).getTime() >= Date.now() - ms

function list(p: URLSearchParams) {
  const w = p.get('window') as AlertWindow
  if (!(w in WINDOW_MS)) return fail(400, 'bad_window', 'The time range must be 24h, 7d or 30d.')
  const cve = (p.get('cve') ?? '').trim()
  if (cve && !CVE_RE.test(cve)) return fail(400, 'invalid_cve', 'A CVE ID looks like CVE-2022-27593.')
  const q = (p.get('q') ?? '').trim().toLowerCase()
  const device = p.get('device') ?? ''
  let rows = alerts.get().filter((s) => inWindow(s, WINDOW_MS[w])).map(view)
  if (device) rows = rows.filter((a) => a.src_device?.id === device || a.dst_device?.id === device)
  if (cve) rows = rows.filter((a) => a.cves.includes(cve.toUpperCase()))
  if (q) rows = rows.filter((a) => [a.signature, a.category, a.src_ip, a.dst_ip, a.src_device?.name, a.dst_device?.name, ...a.cves].some((x) => x?.toLowerCase().includes(q)))
  rows.sort(p.get('sort') === 'count'
    ? (a, b) => b.count - a.count || a.id.localeCompare(b.id)
    : (a, b) => b.last_seen.localeCompare(a.last_seen) || a.id.localeCompare(b.id))
  const offset = Number(p.get('offset') ?? 0) || 0
  const limit = Math.min(200, Math.max(1, Number(p.get('limit') ?? 200) || 200))
  return HttpResponse.json({ items: rows.slice(offset, offset + limit), total: rows.length })
}

// ---- overview ----

async function read<T>(path: string): Promise<T | null> {
  const r = await fetch(new URL(`/api/v1${path}`, location.origin), { headers: { Accept: 'application/json' } })
  return r.ok ? ((await r.json()) as T) : null
}
const newest = (xs: Array<string | null | undefined>) => xs.filter((x): x is string => !!x).sort().at(-1) ?? null
// The log kinds whose device profile reads IPS or IDS events (FortiGate IPS, Suricata or Snort on pfSense and OPNsense).
const IPS_KINDS = ['fortigate', 'pfsense', 'opnsense', 'suricata']

async function traps(): Promise<Watcher> {
  const base = { id: 'traps' as const, module: 'honeypot', last_input_at: null, detections_7d: 0 }
  if (!moduleAvailable('honeypot')) return { ...base, state: 'unavailable', detail: 'This install cannot run traps: they need the system helper of an appliance install.', action: null }
  if (!isOn('honeypot')) return { ...base, state: 'off', detail: 'The Honeypot module is off.', action: 'turn_on' }
  const hp = await read<HpOverview>('/honeypot')
  if (!hp) return { ...base, state: 'failed', detail: 'The trap state could not be read.', action: 'fix' }
  const seen = { last_input_at: newest(hp.traps.map((t) => t.last_hit_at)), detections_7d: hp.traps.reduce((n, t) => n + t.hits_7d, 0) }
  const t = hp.trap_ips
  if (t.enabled === 0) return { ...base, ...seen, state: 'not_set_up', detail: 'No Trap IP is switched on.', action: 'set_up' }
  if (t.listening > 0) return { ...base, ...seen, state: 'watching', detail: `${t.listening} of ${t.enabled} Trap IPs are listening.`, action: t.failing > 0 ? 'fix' : 'view' }
  if (t.failing > 0) return { ...base, ...seen, state: 'failed', detail: hp.problem ?? 'No Trap IP could be set up.', action: 'fix' }
  return { ...base, ...seen, state: 'quiet', detail: 'The Trap IPs are starting.', action: 'view' }
}

async function logs(sources: SourcesResponse | null, incidents: Incident[], ms: number): Promise<Watcher> {
  const base = { id: 'logs' as const, module: 'logs', last_input_at: null, detections_7d: 0 }
  if (!isOn('logs')) return { ...base, state: 'off', detail: 'The Logs module is off.', action: 'turn_on' }
  const list = sources?.sources ?? []
  const detections_7d = incidents.filter((i) => (i.kind === 'bad_address' || i.kind === 'log_anomaly') && inWindow(i, ms)).length
  const last_input_at = newest(list.map((s) => s.last_received))
  if (list.length === 0) return { ...base, detections_7d, state: 'not_set_up', detail: 'No device sends its logs to the box yet.', action: 'set_up' }
  const sending = list.filter((s) => s.state === 'receiving').length
  if (sending === 0) return { ...base, detections_7d, last_input_at, state: 'quiet', detail: `None of the ${list.length} log sources sent anything in the last hour.`, action: 'fix' }
  return { ...base, detections_7d, last_input_at, state: 'watching', detail: `${sending} of ${list.length} log sources are sending.`, action: sending < list.length ? 'fix' : 'view' }
}

function mirrorPort(hits: MirrorHit[]): Watcher {
  const base = { id: 'mirror_port' as const, module: 'sensor-passive', last_input_at: null, detections_7d: hits.length }
  if (!isOn('sensor-passive')) return { ...base, state: 'off', detail: 'The network sensor module is off.', action: 'turn_on' }
  if (installStore.get().kind === 'container') {
    const c = containerSensorStore.get()
    if (!c.connected || !c.span) return { ...base, state: 'not_set_up', detail: 'No network card is set as a mirror port.', action: 'set_up' }
    if (c.capture_error) return { ...base, state: 'failed', detail: 'The sensor cannot capture on the mirror port.', action: 'fix' }
    return { ...base, state: 'watching', detail: 'The sensor reads DNS, TLS and HTTP names from the mirror port.', action: 'view' }
  }
  const st = spanStatusOf(networkStore.get())
  if (st.verdict === 'off') return { ...base, state: 'not_set_up', detail: 'No network card is set as a mirror port.', action: 'set_up' }
  if (st.verdict === 'ok') return { ...base, last_input_at: st.last_packet_at, state: 'watching', detail: `The mirror port on ${st.interface} carries traffic of ${st.other_macs} other devices.`, action: 'view' }
  const why = st.verdict === 'no_link' ? 'has no cable link' : st.verdict === 'own_only' ? 'only sees the box\'s own traffic' : 'carries no traffic'
  return { ...base, last_input_at: st.last_packet_at, state: 'quiet', detail: `The mirror port on ${st.interface} ${why}.`, action: 'fix' }
}

function ipsEvents(sources: SourcesResponse | null, ms: number): Watcher {
  const base = { id: 'ips_events' as const, module: 'ids', last_input_at: null, detections_7d: 0 }
  if (!idsOn()) return { ...base, state: 'off', detail: 'Reading IPS events from firewall logs is off.', action: 'turn_on' }
  const recent = alerts.get().filter((s) => inWindow(s, ms))
  const seen = { last_input_at: newest(alerts.get().map((s) => s.last_seen)), detections_7d: recent.length }
  const ips = isOn('logs') ? (sources?.sources ?? []).filter((s) => IPS_KINDS.includes(s.kind)) : []
  if (ips.length === 0) return { ...base, ...seen, state: 'not_set_up', detail: 'No firewall that writes IPS events sends its logs to the box.', action: 'set_up' }
  const sending = ips.filter((s) => s.state === 'receiving')
  if (sending.length === 0) return { ...base, ...seen, state: 'quiet', detail: `${ips.map((s) => s.name).join(', ')} sent nothing in the last hour.`, action: 'fix' }
  return { ...base, ...seen, state: 'watching', detail: `IPS events are read from ${sending.map((s) => s.name).join(', ')}.`, action: 'view' }
}

async function overview(): Promise<Overview> {
  const ms = 7 * 864e5
  const sources = isOn('logs') ? await read<SourcesResponse>('/logs/sources') : null
  const incidents = isOn('notify') ? (await read<IncidentsResponse>('/notify/incidents'))?.incidents ?? [] : []
  // Bad-address hits seen through the mirror port: the logs module matches them (it reads the feeds).
  let hits: MirrorHit[] = []
  if (isOn('logs') && (await read('/logs/bad-connections?window=7d&limit=1'))) {
    hits = (peek<Array<Omit<IocHit, 'asset_id' | 'asset_name'>>>('logs_ioc_hits') ?? [])
      .filter((h) => h.seen_via.startsWith('span_') && new Date(h.ts).getTime() >= Date.now() - ms)
      .sort((a, b) => b.ts.localeCompare(a.ts) || a.id.localeCompare(b.id))
      .map((h) => ({ ts: h.ts, src_ip: h.src_ip, device: deviceAt(h.src_ip), dest: h.dest, dest_kind: h.dest_kind, seen_via: h.seen_via as MirrorHit['seen_via'], feeds: h.feeds }))
  }
  const recent = idsOn() ? alerts.get().filter((s) => inWindow(s, ms)) : []
  // Intrusion incidents are counted from the alerts that carry them; the other kinds from the notify incidents.
  const intrusion = new Map(recent.filter((s) => s.incident).map((s) => [s.incident!.id, s.incident!.status]))
  const kinds: KindCount[] = DETECTION_KINDS.map((kind) => {
    if (kind === 'intrusion') return { kind, incidents: intrusion.size, new: [...intrusion.values()].filter((s) => s === 'new').length }
    const own = incidents.filter((i) => i.kind === kind && inWindow(i, ms))
    return { kind, incidents: own.length, new: own.filter((i) => i.status === 'new').length }
  })
  return {
    generated_at: nowIso(), window_days: 7,
    watchers: [await traps(), await logs(sources, incidents, ms), mirrorPort(hits), ipsEvents(sources, ms)],
    kinds,
    mirror_port_hits: { total: hits.length, latest: hits.slice(0, 5) },
    alerts: { total: recent.length, affected: recent.map(view).filter((a) => a.findings.some((f) => f.status === 'under_attack')).length },
  }
}

export const handlers = [
  http.get(`${API}/detection/overview`, async () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(await overview())
  }),
  http.get(`${API}/detection/alerts`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!idsOn()) return offFail()
    return list(new URL(request.url).searchParams)
  }),
  http.get(`${API}/detection/alerts/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!idsOn()) return offFail()
    const s = alerts.get().find((x) => x.id === params.id)
    return s ? HttpResponse.json(view(s)) : fail(404, 'not_found', 'This alert no longer exists.')
  }),
]
