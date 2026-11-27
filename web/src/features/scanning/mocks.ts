// Mock of Settings › Scanning (#850): the backend PR writes it so `tsc` and the contract test pass; the UI owner changes it freely.
// The safety block is the inventory's settings store (the one store, as on the box); the check rate of the vulnerability checks has a
// small store of its own here. The engine switches move the module store, inventory's active.enabled and the OpenVAS flag.
import { http, HttpResponse } from 'msw'
import type { z } from 'zod'
import { API, audit, body, CIDR_RE, currentUser, fail, guard, IPV4_RE } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { assetsStore, installStore, isOn, modulesStore } from '@/mocks/stores'
import type { ModuleId } from '@/lib/modules'
import { mockDeviceProgress } from '@/lib/progress'
import { BOX_ID, inventorySettingsStore, SAFETY_CHANGED, safetyVersion, snmpStore } from '@/features/inventory/mocks'
import { cidrRange, isPrivateCidr, LOCAL_RANGE_NAMES, normalizeRange, overlapping } from '@/features/inventory/validate'
import { exposureMockRun, greenboneMock } from '@/features/exposure/mocks'
import { exposureStepRuns } from './runStepsMock'
import { lastScanRun, liveScanRuns, runs as scanRunStore } from '@/features/scan/mocks'
import type { DiscoveryRunInput, Engine, EngineId, EnginePatch, ExclusionAdd, HistoryRun, RangeAdd, Run as RunSchema, RunDetail, RunningJob, RunStatus, Scanning, SafetyInput } from './contract'

type EngineT = z.infer<typeof Engine>
type Id = z.infer<typeof EngineId>
type Run = z.infer<typeof RunningJob>

const checkRate = collection<{ requests_per_s: number }>('scanning_check_rate', () => ({ requests_per_s: 5 }))
// starts_ms/behind: a run a person asked for while another one held the scanner waits behind it (the box's queue), saying so
const runs = collection<Array<Run & { ends_ms: number; starts_ms?: number; behind?: string }>>('scanning_runs', () => [], () => [])
const RUN_MS = 20_000
type HistoryRow = z.infer<typeof HistoryRun>
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
/** GET /scanning/history, as cmd/vedette scanninghistory.go builds it: the LAN jobs and the public scans, newest first. */
export const historyStore = collection<HistoryRow[]>('scanning_history', () => [
  { id: 'saj-h1', kind: 'device', engine: 'nmap-versions', trigger: 'person', label: '192.168.10.21', target_id: null, started_at: ago(3), ended_at: ago(2.98), outcome: 'ok', text: 'Scanned 192.168.10.21: 3 open ports (22 ssh, 80 http, 445 microsoft-ds); OS guess Linux 5.4 - 5.15; nothing changed since the previous check' },
  { id: 'saj-h2', kind: 'sweep', engine: 'nmap-discovery', trigger: 'sweep', label: 'LAN 192.168.10.0/24', target_id: null, started_at: ago(20), ended_at: ago(19.9), outcome: 'ok', text: 'Swept 254 addresses: 12 hosts answered, 2 new devices' },
  { id: 'saj-h3', kind: 'snmp', engine: 'snmp', trigger: 'automatic', label: 'SNMP read', target_id: null, started_at: ago(21), ended_at: ago(20.95), outcome: 'partial', text: '2 of 3 devices answered over SNMP' },
], () => [])
/** What a device check found, in the words cmd/vedette foundText writes: the device's open ports (the mock's check finds what it has). */
const checkText = (ip: string, services: ReadonlyArray<{ port: number; proto: string; name: string }>) => {
  if (services.length === 0) return `Scanned ${ip}: no open port; nothing changed since the previous check`
  const shown = services.slice(0, 8).map((s) => `${s.port}${s.proto === 'udp' ? '/udp' : ''}${s.name ? ` ${s.name}` : ''}`)
  if (services.length > 8) shown.push(`and ${services.length - 8} more`)
  return `Scanned ${ip}: ${services.length} open ${services.length === 1 ? 'port' : 'ports'} (${shown.join(', ')}); nothing changed since the previous check`
}
/** The addresses each mock LAN job reached, as the box keeps them in its probes (History shows only the label or a count): a device
 *  check its address, an SNMP read every address it asked. ?asset= matches on them, for every kind. */
const reached = collection<Record<string, string[]>>('scanning_history_reached', () => ({ 'saj-h1': ['192.168.10.21'], 'saj-h3': ['192.168.10.1', '192.168.10.21', '192.168.10.30'] }), () => ({}))
/** A mock that adds a LAN job to History (a device check, an SNMP read) records the addresses it reached. */
export const markReached = (id: string, ips: string[]) => reached.set({ ...reached.get(), [id]: ips })

interface Def { id: Id; group: EngineT['group']; module: ModuleId & EngineT['module']; follows?: Id; affects?: Id[]; preview?: boolean; cost: EngineT['cost'] }
const DEFS: Def[] = [
  { id: 'passive', group: 'discover', module: 'sensor-passive', cost: { ram_mb: 512, while: 'on', container: null } },
  { id: 'nmap-discovery', group: 'discover', module: 'sensor-active', affects: ['nmap-versions', 'snmp'], cost: { ram_mb: 1024, while: 'on', container: 'scan' } },
  { id: 'nmap-versions', group: 'identify', module: 'sensor-active', follows: 'nmap-discovery', cost: { ram_mb: 1024, while: 'on', container: 'scan' } },
  { id: 'snmp', group: 'identify', module: 'sensor-active', follows: 'nmap-discovery', cost: { ram_mb: 1024, while: 'on', container: 'scan' } },
  { id: 'osquery', group: 'identify', module: 'agent-intake', affects: ['wazuh'], cost: { ram_mb: 0, while: 'on', container: null } },
  { id: 'wazuh', group: 'identify', module: 'agent-intake', affects: ['osquery'], cost: { ram_mb: 0, while: 'on', container: null } },
  { id: 'nuclei', group: 'vuln', module: 'scan', preview: true, cost: { ram_mb: 1024, while: 'on', container: 'scan' } },
  { id: 'zap', group: 'vuln', module: 'exposure', cost: { ram_mb: 1024, while: 'running', container: null } },
  { id: 'openvas', group: 'vuln', module: 'exposure', cost: { ram_mb: 4000, while: 'on', container: null } },
  { id: 'honeypot', group: 'traps', module: 'honeypot', preview: true, cost: { ram_mb: 256, while: 'on', container: null } },
]
const NO_SWITCH: Id[] = ['nmap-versions', 'snmp', 'zap']

/** The discovery runs a person started (POST …/nmap-discovery/run). */
function discoveryRuns(): Run[] {
  const now = Date.now()
  const kept = runs.get().filter((r) => r.ends_ms > now)
  if (kept.length !== runs.get().length) runs.set(kept)
  return kept.map(({ ends_ms, starts_ms, behind, ...r }) => {
    if (starts_ms && behind && now < starts_ms) {
      const p = mockDeviceProgress(now, 0, now)
      return { ...r, queued: true, progress: { ...p, message: `Queued behind “${behind}”; it starts in about ${Math.max(1, Math.ceil((starts_ms - now) / 60000))} minutes` } }
    }
    const started = starts_ms ?? Date.parse(r.started_at)
    return { ...r, queued: false, progress: mockDeviceProgress(started, (now - started) / (ends_ms - started), now) }
  })
}
/** Every run going on (#850 review M7): discovery, the LAN vulnerability checks (scan mock) and the public scan (exposure mock). */
function live(): Run[] {
  const out = discoveryRuns()
  for (const r of liveScanRuns()) out.push({ engine: 'nuclei', id: r.id, label: r.total === 1 && r.current ? `Check ${r.current.label}` : `Vulnerability checks on ${r.total} devices`, target_id: null, started_at: r.started_at, progress: r.progress, queued: false })
  const ex = exposureMockRun()
  if (ex?.status === 'running') out.push({ engine: ex.phase === 'greenbone' ? 'openvas' : 'zap', id: ex.id, label: ex.target_value, target_id: ex.target_id, started_at: ex.started_at, progress: ex.progress, queued: false })
  return out
}

/** Queues a run a person asked for (behind the last one going, saying so) with its History rows; returns its id. */
function queueRun(picked: Array<{ id: string; ip: string; services: Parameters<typeof checkText>[1] }>, ranges: string[]): string {
  const started = nowIso()
  const last = runs.get().filter((r) => r.ends_ms > Date.now()).at(-1)
  const begins = Math.max(Date.parse(started), last?.ends_ms ?? 0)
  const run: Run & { ends_ms: number; starts_ms?: number; behind?: string } = {
    engine: 'nmap-discovery', id: newId('sar'), started_at: started, progress: null, queued: !!last,
    label: picked.length === 0 ? `LAN sweep ${ranges.join(', ')}` : picked.length === 1 ? `Check ${picked[0]!.ip}` : `Check ${picked.length} devices`,
    target_id: picked.length === 1 ? picked[0]!.id : null, ends_ms: begins + RUN_MS * Math.max(1, picked.length),
    ...(last ? { starts_ms: begins, behind: last.label } : {}),
  }
  runs.set([...runs.get(), run])
  // its jobs as History lists them: one per device checked, or the sweep (the mock ends them at once)
  const rows: HistoryRow[] = picked.length
    ? picked.map((a) => ({ id: newId('saj'), kind: 'device' as const, engine: 'nmap-versions' as const, trigger: 'person' as const, label: a.ip, target_id: null, started_at: started, ended_at: started, outcome: 'ok' as const, text: checkText(a.ip, a.services) }))
    : [{ id: newId('saj'), kind: 'sweep', engine: 'nmap-discovery', trigger: 'sweep', label: `LAN sweep of ${ranges.join(', ')}`, target_id: null, started_at: started, ended_at: started, outcome: 'ok', text: `Swept ${ranges.length * 254} addresses: 0 hosts answered, 0 new devices` }]
  historyStore.set([...rows, ...historyStore.get()])
  rows.forEach((r) => { if (r.kind === 'device') markReached(r.id, [r.label]) })
  return run.id
}

function enabled(d: Def): boolean {
  const st = inventorySettingsStore.get()
  if (d.module === 'sensor-active') return isOn('sensor-active') && st.active.enabled
  if (d.id === 'openvas') return isOn('exposure') && greenboneMock.view().enabled
  return isOn(d.module)
}

function nucleiLast(): EngineT['last_run'] {
  const r = lastScanRun()
  return r ? { at: r.ended_at ?? r.started_at, outcome: r.status === 'done' ? 'ok' : 'stopped', text: `${r.total} devices checked, ${r.matched} matched` } : null
}

function engine(d: Def, running: Run[]): EngineT {
  const st = inventorySettingsStore.get()
  const on = enabled(d)
  const appliance = installStore.get().kind === 'appliance'
  let state: EngineT['state'] = on ? 'ready' : 'off'
  let reason: string | null = null
  if (!appliance && (d.id === 'honeypot' || d.id === 'zap' || d.id === 'openvas')) { state = 'unavailable'; reason = 'This install has no operating system helper (container-only install), so it cannot run this.' }
  else if (on && d.module === 'sensor-active' && !st.scope_confirmed_at) { state = 'needs_setup'; reason = 'Confirm the network ranges you may scan.' }
  else if (d.id === 'openvas' && isOn('exposure')) {
    const g = greenboneMock.view()
    if (g.state === 'unavailable') { state = 'unavailable'; reason = g.reason }
    else if (!g.preflight.ok && !g.enabled) { state = 'unavailable'; reason = g.preflight.reason }
    else if (g.state === 'starting' || g.state === 'loading') { state = 'starting'; reason = g.reason ?? 'OpenVAS is loading its feed (first time takes 1 to 3 hours).' }
    else if (g.state === 'error') { state = 'error'; reason = g.reason }
    if (running.some((r) => r.engine === 'openvas')) state = 'running'
  }
  else if (on && running.some((r) => r.engine === d.id)) state = 'running'
  const windowed = d.module === 'sensor-active' || d.id === 'nuclei'
  return {
    id: d.id, group: d.group, module: d.module, enabled: on, can_toggle: !NO_SWITCH.includes(d.id), follows: d.follows ?? null, affects: d.affects ?? [],
    state, reason, preview: d.preview ?? false, cost: d.cost,
    last_run: !on ? null : d.id === 'nuclei' ? nucleiLast() : d.id === 'zap' || d.id === 'openvas' ? null : { at: new Date(Date.now() - 9 * 3600_000).toISOString(), outcome: 'ok', text: d.id === 'nmap-discovery' ? 'Swept 508 addresses, 2 new devices' : 'Last run finished' },
    next_run_at: on && windowed ? new Date(Date.now() + 6 * 3600_000).toISOString() : null,
  }
}

export function scanningView(): z.infer<typeof Scanning> {
  const st = inventorySettingsStore.get()
  const running = live()
  const engines = DEFS.map((d) => engine(d, running))
  const counted = new Set<string>()
  let reserved = 2048
  for (const e of engines) {
    const holds = e.enabled && (e.cost.while === 'on' || e.state === 'running')
    if (!holds || e.cost.ram_mb === null) continue
    if (e.cost.container) { if (counted.has(e.cost.container)) continue; counted.add(e.cost.container) }
    reserved += e.cost.ram_mb
  }
  return {
    safety: {
      scope: { lan_ranges: st.lan_ranges, confirmed_at: st.scope_confirmed_at, confirmed_by: st.scope_confirmed_by },
      window: { days: st.active.days.length ? st.active.days : [1, 2, 3, 4, 5, 6, 7], from: st.active.from, to: st.active.to, time_zone: 'Asia/Ho_Chi_Minh' },
      speed: { packets_per_s: st.active.rate, requests_per_s: checkRate.get().requests_per_s },
      exclusions: st.active.exclusions,
      fragile: { kinds: st.fragile_kinds, regular_scan_kinds: st.regular_scan_kinds, devices: assetsStore.get().filter((a) => a.fragile).length },
      version: safetyVersion(),
    },
    engines, running, box: { memory_mb: 7680, reserved_mb: reserved },
  }
}

const masked = (cidr: string) => {
  const [ip, bits] = cidr.split('/') as [string, string]
  const n = ip.split('.').reduce((a, o) => a * 256 + Number(o), 0)
  const b = Number(bits)
  const m = b === 0 ? 0 : (n - (n % 2 ** (32 - b)))
  return `${[24, 16, 8, 0].map((s) => Math.floor(m / 2 ** s) % 256).join('.')}/${b}`
}

/** What one pass over a scope costs (POST /scanning/safety/estimate), as the box counts it: an address behind a router costs 17
 *  packets (the mock treats every range as routed), one window is from-to, a week has a window per day. */
function scopeCost(ranges: string[], excl: string[], days: number[], from: string, to: string, pps: number) {
  const valid = ranges.filter((r) => CIDR_RE.test(r)).map(masked)
  const size = (c: string) => 2 ** (32 - Number(c.split('/')[1]))
  let addresses = valid.reduce((n, r) => n + size(r), 0)
  for (const x of excl) {
    const c = IPV4_RE.test(x) ? `${x}/32` : CIDR_RE.test(x) ? masked(x) : null
    if (c && coveredBy(c, valid)) addresses -= size(c)
  }
  addresses = Math.max(0, addresses)
  const mins = (t: string) => { const [h, m] = t.split(':').map(Number) as [number, number]; return h * 60 + m }
  let win = (mins(to) - mins(from)) * 60
  if (win < 0) win += 24 * 3600
  const pass = Math.floor((addresses * 17) / Math.max(1, pps))
  const weekWindows = new Set(days).size
  const windows = addresses > 0 && win > 0 ? Math.max(1, Math.ceil(pass / win)) : 0
  return { addresses, pass_seconds: pass, window_seconds: win, windows, week_windows: weekWindows,
    fits_window: windows <= 1, fits_week: addresses === 0 || win === 0 || weekWindows === 0 || windows <= weekWindows }
}
const TOO_LARGE = 'One pass over these ranges does not end within a week of scan windows. Vedette never takes a scope it cannot sweep within a week: raise the scan rate, widen the window or add days, or narrow the ranges.'

/** c (a CIDR or an IPv4 address, its /32) lies inside one of list's ranges or addresses: adding it changes nothing. */
const coveredBy = (c: string, list: string[]) => {
  const r = cidrRange(c.includes('/') ? c : `${c}/32`)
  return list.find((o) => { const q = cidrRange(o.includes('/') ? o : `${o}/32`); return r.base >= q.base && r.base + r.size <= q.base + q.size })
}
const SCOPE_NOT_CONFIRMED = 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.'

// Runs (GET /runs, /runs/{id}, POST /runs/{id}/stop|resume): one model for every engine, as core/run keeps it. The seed holds a
// sweep waiting for its window halfway through a /16, a device check running, one queued behind it in the same lane, finished
// vulnerability checks, an exposure scan with an engine step under it, and an SNMP read a restart stopped.
type RunRow = z.infer<typeof RunDetail>
type RunState = z.infer<typeof RunStatus>
const minAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()
const runBase = (r: Partial<RunRow> & Pick<RunRow, 'id' | 'module' | 'kind' | 'lane' | 'title' | 'status' | 'queued_at'>): RunRow => ({
  trigger: 'manual', trigger_note: null, requested_by: 'admin@acme.example', schedule_id: null, subject: null, parent_id: null,
  waiting_for: null, stop_reason: null, error: null, total: 0, done: 0, started_at: null, ended_at: null, updated_at: r.queued_at,
  can_stop: false, can_resume: false, summary: '', blocked_by: null, steps: [], items: [], items_total: 0, log: [], children: [], ...r,
})
export const runsStore = collection<RunRow[]>('core_runs', () => [
  runBase({ id: 'run-m1', module: 'sensor-active', kind: 'lan_sweep', lane: 'nmap', title: 'LAN sweep of 192.0.2.0/24, 10.20.0.0/16', trigger: 'schedule', requested_by: 'system',
    status: 'waiting', waiting_for: 'the scan window (opens 23:00)', queued_at: minAgo(1500), started_at: minAgo(1499), updated_at: minAgo(1020),
    total: 256 + 65536, done: 256 + 6272,
    steps: [
      { seq: 1, name: '192.0.2.0/24', status: 'done', total: 256, done: 256, note: '12 hosts answered', started_at: minAgo(1499), ended_at: minAgo(1490) },
      { seq: 2, name: '10.20.0.0/16', status: 'waiting', total: 65536, done: 6272, note: 'About 9 more nights at 50 packets/s', started_at: minAgo(1490), ended_at: null },
    ],
    items: [
      { seq: 1, subject_kind: 'device', subject_id: 'a-fw01', label: 'FW-HQ', outcome: 'found', note: null },
      { seq: 2, subject_kind: 'device', subject_id: 'a-nas02', label: 'NAS-PHOTOS', outcome: 'found', note: null },
      { seq: 3, subject_kind: 'host', subject_id: null, label: '10.20.3.17', outcome: 'new', note: 'Answered on 22 and 443' },
    ],
    items_total: 3,
    log: [
      { ts: minAgo(1499), level: 'info', text: 'Started' },
      { ts: minAgo(1490), level: 'info', text: '192.0.2.0/24 swept: 12 hosts answered' },
      { ts: minAgo(1020), level: 'info', text: 'Waiting for the scan window (opens 23:00)' },
    ] }),
  runBase({ id: 'run-m2', module: 'sensor-active', kind: 'device_check', lane: 'nmap', title: 'Check NAS-PHOTOS',
    subject: { kind: 'device', id: 'a-nas02', label: 'NAS-PHOTOS' }, status: 'running', queued_at: minAgo(3), started_at: minAgo(3), updated_at: minAgo(1),
    total: 5, done: 3, steps: [{ seq: 1, name: 'identify services', status: 'running', total: 5, done: 3, note: null, started_at: minAgo(3), ended_at: null }],
    log: [{ ts: minAgo(3), level: 'info', text: 'Started' }] }),
  runBase({ id: 'run-m3', module: 'sensor-active', kind: 'device_check', lane: 'nmap', title: 'Check WEB01',
    subject: { kind: 'device', id: 'a-web01', label: 'WEB01' }, status: 'queued', queued_at: minAgo(2) }),
  runBase({ id: 'run-m4', module: 'scan', kind: 'vuln_check', lane: 'nuclei', title: 'Vulnerability checks of 12 devices', trigger: 'schedule', requested_by: 'system',
    status: 'done', queued_at: minAgo(600), started_at: minAgo(600), ended_at: minAgo(540), updated_at: minAgo(540), total: 12, done: 12,
    steps: [{ seq: 1, name: 'safe checks', status: 'done', total: 12, done: 12, note: '2 findings confirmed', started_at: minAgo(600), ended_at: minAgo(540) }],
    log: [{ ts: minAgo(600), level: 'info', text: 'Started' }, { ts: minAgo(540), level: 'info', text: 'Done' }] }),
  runBase({ id: 'run-m5', module: 'exposure', kind: 'exposure_scan', lane: 'exposure', title: 'Scan of www.example.com',
    subject: { kind: 'target', id: 'et-1', label: 'www.example.com' }, status: 'done', queued_at: minAgo(300), started_at: minAgo(300), ended_at: minAgo(260), updated_at: minAgo(260),
    items: [
      { seq: 1, subject_kind: 'address', subject_id: '203.0.113.10', label: '203.0.113.10', outcome: 'checked_top', note: null },
      { seq: 2, subject_kind: 'port', subject_id: '203.0.113.10:8444', label: '203.0.113.10:8444', outcome: 'checked_top', note: null },
    ],
    items_total: 2 }),
  runBase({ id: 'run-m9', module: 'exposure', kind: 'exposure_scan', lane: 'exposure', title: 'Scan of example.com',
    subject: { kind: 'target', id: 'et-2', label: 'example.com' }, status: 'done', queued_at: minAgo(200), started_at: minAgo(200), ended_at: minAgo(190), updated_at: minAgo(190),
    items: [
      { seq: 1, subject_kind: 'address', subject_id: '203.0.113.10', label: 'example.com 203.0.113.10', outcome: 'deep_scanned', note: null },
      { seq: 2, subject_kind: 'run', subject_id: 'run-m5', label: 'Deep scan of 203.0.113.10 at 09:20', outcome: 'reused',
        note: "Its ports, services and nmap's scripts at 203.0.113.10 were reused by this scan; this scan ran its own web checks there." },
    ],
    items_total: 2 }),
  runBase({ id: 'run-m6', module: 'exposure', kind: 'zap_passive', lane: 'zap', title: 'ZAP passive scan of www.example.com', parent_id: 'run-m5',
    subject: { kind: 'target', id: 'et-1', label: 'www.example.com' }, status: 'done', queued_at: minAgo(290), started_at: minAgo(290), ended_at: minAgo(265), updated_at: minAgo(265) }),
  runBase({ id: 'run-m7', module: 'sensor-active', kind: 'snmp_read', lane: 'snmp', title: 'SNMP read of 3 devices', trigger: 'schedule', requested_by: 'system',
    status: 'stopped', stop_reason: 'Vedette restarted', queued_at: minAgo(2000), started_at: minAgo(2000), ended_at: minAgo(1990), updated_at: minAgo(1990),
    log: [{ ts: minAgo(2000), level: 'info', text: 'Started' }, { ts: minAgo(1990), level: 'warn', text: 'Stopped: Vedette restarted' }] }),
  ...exposureStepRuns(),
].map(withButtons), () => [])
/** The buttons, by the one rule of core/run: stop while queued, waiting or running; resume while waiting, or stopped with a step left. */
function withButtons(r: RunRow): RunRow {
  const workLeft = r.steps.length === 0 || r.steps.some((s) => s.status !== 'done')
  return { ...r, can_stop: ['queued', 'waiting', 'running'].includes(r.status), can_resume: r.status === 'waiting' || (r.status === 'stopped' && workLeft && r.kind === 'lan_sweep') }
}
/**
 * The runs the engines' own mocks hold (a person's discovery run, the vulnerability checks, the public scan, the LAN history), as
 * GET /runs lists them once each engine writes its runs through core/run: under the same ids, so every "Open the run" of the dev
 * data opens its run page. Read only here: Stop and Resume act on the rows of runsStore.
 */
function engineRuns(): RunRow[] {
  const now = nowIso()
  const out: RunRow[] = []
  const ro = (r: RunRow): RunRow => ({ ...r, can_stop: false, can_resume: false })
  for (const j of discoveryRuns()) {
    out.push(ro(runBase({ id: j.id, module: 'sensor-active', kind: j.target_id ? 'device_check' : 'lan_sweep', lane: 'nmap', title: j.label, status: 'running',
      subject: j.target_id ? { kind: 'device', id: j.target_id, label: assetsStore.get().find((a) => a.id === j.target_id)?.hostname ?? j.label } : null,
      queued_at: j.started_at, started_at: j.started_at, updated_at: now })))
  }
  const live = new Map(liveScanRuns().map((r) => [r.id, r]))
  for (const stored of scanRunStore.get()) {
    const r = live.get(stored.id) ?? stored
    out.push(ro(runBase({ id: r.id, module: 'scan', kind: 'vuln_check', lane: 'nuclei', title: `Vulnerability checks of ${r.total} device${r.total === 1 ? '' : 's'}`,
      trigger: r.trigger === 'manual' ? 'manual' : r.trigger === 'schedule' ? 'schedule' : 'event', trigger_note: r.trigger_note, requested_by: r.started_by,
      status: r.status === 'auto_stopped' ? 'stopped' : r.status, stop_reason: r.stop_reason, total: r.total, done: r.done,
      queued_at: r.started_at, started_at: r.started_at, ended_at: r.ended_at, updated_at: r.ended_at ?? now,
      items: r.results.map((x, i) => ({ seq: i + 1, subject_kind: 'device', subject_id: x.target_id, label: x.label, outcome: x.result === 'matched' ? 'found' : 'checked', note: x.note })),
      items_total: r.results.length })))
  }
  const ex = exposureMockRun()
  if (ex) {
    out.push(ro(runBase({ id: ex.id, module: 'exposure', kind: 'exposure_scan', lane: 'exposure', title: `Scan of ${ex.target_value}`, requested_by: ex.by || 'system',
      subject: { kind: 'target', id: ex.target_id, label: ex.target_value }, status: ex.status, error: ex.error?.message ?? null, stop_reason: ex.stop_reason ?? null,
      queued_at: ex.started_at, started_at: ex.status === 'queued' ? null : ex.started_at, ended_at: ex.finished_at, updated_at: ex.finished_at ?? now })))
  }
  const kinds = { sweep: 'lan_sweep', device: 'device_check', snmp: 'snmp_read', external: 'exposure_scan' } as const
  const states = { ok: 'done', partial: 'partial', failed: 'failed', stopped: 'stopped', running: 'running' } as const
  for (const h of historyStore.get()) {
    out.push(ro(runBase({ id: h.id, module: h.kind === 'external' ? 'exposure' : 'sensor-active', kind: kinds[h.kind], lane: h.kind === 'external' ? 'exposure' : 'nmap', title: h.label,
      trigger: h.trigger === 'person' ? 'manual' : 'schedule', requested_by: h.trigger === 'person' ? 'admin@acme.example' : 'system',
      subject: h.target_id ? { kind: 'target', id: h.target_id, label: h.label } : null, status: states[h.outcome],
      error: h.outcome === 'failed' || h.outcome === 'partial' ? h.text : null, stop_reason: h.outcome === 'stopped' ? h.text : null,
      queued_at: h.started_at, started_at: h.started_at, ended_at: h.ended_at, updated_at: h.ended_at ?? now,
      log: [{ ts: h.started_at, level: 'info', text: h.text }] })))
  }
  return out
}
/** Every run GET /runs knows: the runs of runsStore, then the engines' own (an id held by both is runsStore's). */
function allRunRows(): RunRow[] {
  const own = runsStore.get()
  const ids = new Set(own.map((r) => r.id))
  return [...own, ...engineRuns().filter((r) => !ids.has(r.id))]
}
/** What the box adds as it reads a run (core/run summary.go): the line of words, the run a queued one waits for, and the buttons of the
 *  person asking (an operator stops and resumes; a LAN sweep resumes for an administrator only). */
const UNITS: Record<string, string> = { lan_sweep: 'addresses', device_check: 'devices', snmp_read: 'devices', all_ports: 'devices', vuln_check: 'devices', exposure_scan: 'steps' }
const n = (x: number) => x.toLocaleString('en-US')
function present(r: RunRow, all: RunRow[]): RunRow {
  const role = currentUser()?.role
  const operator = role === 'operator' || role === 'admin'
  const holder = r.status === 'queued' ? all.find((x) => x.lane === r.lane && x.id !== r.id && (x.status === 'running' || x.status === 'stopping')) : undefined
  const count = r.total > 0 ? `${n(r.done)} of ${n(r.total)}${UNITS[r.kind] ? ` ${UNITS[r.kind]}` : ''}` : ''
  const join = (...p: string[]) => p.filter(Boolean).join('; ')
  const summary = r.status === 'queued' ? (holder ? `Queued behind “${holder.title}”; it starts when that run ends` : 'Queued; it starts in a moment')
    : r.status === 'waiting' ? join(`Waiting for ${r.waiting_for ?? 'a person to resume it'}`, count)
    : r.status === 'running' ? (count || 'Running')
    : r.status === 'stopping' ? join(`Stopping: ${r.stop_reason ?? 'a stop was asked'}`, count)
    : r.status === 'done' ? (count ? `Done: ${count}` : 'Done')
    : r.status === 'partial' ? join(`Partly done: ${r.error ?? 'part of the work was not done'}`, count)
    : r.status === 'failed' ? `Failed: ${r.error ?? 'the run did not finish'}`
    : join((r.stop_reason ?? '').startsWith('Stopped') ? r.stop_reason! : `Stopped: ${r.stop_reason ?? 'a stop was asked'}`, r.total > 0 && r.done < r.total ? `${count} done` : '')
  return { ...r, summary, blocked_by: holder ? { id: holder.id, title: holder.title } : null,
    can_stop: r.can_stop && operator, can_resume: r.can_resume && operator && (r.kind !== 'lan_sweep' || role === 'admin') }
}
const runSummary = (r: RunRow): z.infer<typeof RunSchema> => {
  const { steps: _s, items: _i, items_total: _t, log: _l, children: _c, ...run } = present(r, allRunRows())
  return run
}
const runDetail = (id: string): RunRow | undefined => {
  const all = allRunRows()
  const r = all.find((x) => x.id === id)
  return r && { ...present(r, all), children: all.filter((x) => x.parent_id === id).map(runSummary) }
}
function setRun(id: string, fn: (r: RunRow) => RunRow) {
  runsStore.update((l) => l.map((r) => (r.id === id ? withButtons({ ...fn(r), updated_at: nowIso() }) : r)))
}
const ENDED: RunState[] = ['done', 'partial', 'failed', 'stopped']
const logLine = (r: RunRow, level: 'info' | 'warn', text: string): RunRow => ({ ...r, log: [...r.log, { ts: nowIso(), level, text }].slice(-200) })

const runHandlers = [
  http.get(`${API}/runs`, ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = new URL(request.url)
    const p = (k: string) => u.searchParams.get(k) ?? ''
    const q = p('q').trim().toLowerCase()
    const rows = allRunRows()
      .filter((r) => (!p('module') || r.module === p('module')) && (!p('kind') || r.kind === p('kind')) && (!p('status') || r.status === p('status')))
      .filter((r) => (!p('subject_kind') || r.subject?.kind === p('subject_kind')) && (!p('subject_id') || r.subject?.id === p('subject_id')))
      .filter((r) => !q || r.title.toLowerCase().includes(q) || (r.subject?.label ?? '').toLowerCase().includes(q) || r.requested_by.toLowerCase().includes(q) || r.id === p('q').trim())
      .sort((a, b) => (b.started_at ?? b.queued_at).localeCompare(a.started_at ?? a.queued_at)) // by when each started, as the box lists them
    const offset = Number(p('offset') || 0)
    const limit = Math.min(200, Math.max(1, Number(p('limit') || 200)))
    return HttpResponse.json({ items: rows.slice(offset, offset + limit).map(runSummary), total: rows.length })
  }),
  http.get(`${API}/runs/:id`, ({ params }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const r = runDetail(String(params.id))
    return r ? HttpResponse.json(r) : fail(404, 'not_found', 'This run does not exist, or it ended more than 400 days ago.')
  }),
  http.post(`${API}/runs/:id/stop`, ({ params }) => {
    const denied = guard('operator')
    if (denied) return denied
    const id = String(params.id)
    const r = runsStore.get().find((x) => x.id === id)
    if (!r) return fail(404, 'not_found', 'This run does not exist, or it ended more than 400 days ago.')
    if (ENDED.includes(r.status)) return fail(409, 'not_running', 'This run has already ended, so there is nothing to stop.')
    const by = currentUser()?.email ?? 'system'
    const reason = `Stopped by ${by}`
    const stop = (x: RunRow): RunRow => (ENDED.includes(x.status) || x.status === 'stopping' ? x
      : logLine({ ...x, status: 'stopped', stop_reason: reason, waiting_for: null, ended_at: nowIso(),
        steps: x.steps.map((s) => (s.status === 'running' || s.status === 'waiting' ? { ...s, status: 'stopped' as const } : s)) }, 'warn', `Stopped: ${reason}`))
    // The mock ends the work at once: a running run would be stopping for a moment on the box.
    for (const x of [r, ...runsStore.get().filter((c) => c.parent_id === id)]) setRun(x.id, stop)
    audit('scanning.run_stop', id, r.title)
    return HttpResponse.json(runSummary(runsStore.get().find((x) => x.id === id)!))
  }),
  http.post(`${API}/runs/:id/resume`, ({ params }) => {
    const denied = guard('operator')
    if (denied) return denied
    const id = String(params.id)
    const r = runsStore.get().find((x) => x.id === id)
    if (!r) return fail(404, 'not_found', 'This run does not exist, or it ended more than 400 days ago.')
    if (!r.can_resume) return fail(409, 'not_resumable', 'This run cannot be resumed: it has no work left, or its engine cannot go on from where it stopped.')
    const by = currentUser()?.email ?? 'system'
    setRun(id, (x) => logLine({ ...x, status: 'queued', waiting_for: null, stop_reason: null, error: null, ended_at: null,
      steps: x.steps.map((s) => (s.status === 'done' ? s : { ...s, status: 'queued' as const, ended_at: null })) }, 'info', `Resumed by ${by}`))
    audit('scanning.run_resume', id, r.title)
    return HttpResponse.json(runSummary(runsStore.get().find((x) => x.id === id)!))
  }),
]

export const handlers = [
  ...runHandlers,
  http.get(`${API}/scanning`, () => guard('viewer') ?? HttpResponse.json(scanningView())),
  http.get(`${API}/scanning/history`, ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    // ?asset= keeps the device's own runs: its checks (at its address now) and, only while SNMP is set up on it, the SNMP reads of
    // its read address
    const asset = new URL(request.url).searchParams.get('asset')
    const ip = asset === null ? null : assetsStore.get().find((a) => a.id === asset)?.ip ?? '—'
    const readFrom = asset === null ? null : snmpStore.get().find((x) => x.device_id === asset)?.read_from ?? null
    const ofDevice = (r: HistoryRow) => r.kind === 'device' ? ip !== '—' && (reached.get()[r.id] ?? []).includes(ip!)
      : r.kind === 'snmp' && readFrom !== null && (reached.get()[r.id] ?? []).includes(readFrom)
    const rows = ip === null ? historyStore.get() : historyStore.get().filter(ofDevice)
    return HttpResponse.json({ items: [...rows].sort((a, b) => b.started_at.localeCompare(a.started_at)) })
  }),

  http.put(`${API}/scanning/safety`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<z.infer<typeof SafetyInput>>(request)
    if (b.version !== safetyVersion()) return fail(409, 'safety_changed', SAFETY_CHANGED, { safety: scanningView().safety })
    const st = inventorySettingsStore.get()
    const ranges = b.scope?.lan_ranges ?? []
    if (ranges.length > 16) return fail(400, 'too_many_ranges', 'At most 16 network ranges.')
    const adjusted: Array<{ from: string; to: string }> = []
    const clean: string[] = []
    for (const r of ranges) {
      if (!CIDR_RE.test(r)) return fail(400, IPV4_RE.test(r) ? 'no_prefix' : 'bad_cidr', `"${r.slice(0, 30)}" is not a valid network range. Enter something like 192.168.10.0/24.`)
      const m = masked(r)
      if (m !== r) adjusted.push({ from: r, to: m })
      if (!clean.includes(m)) clean.push(m)
    }
    const w = b.window
    if (!w?.days?.length) return fail(400, 'no_days', 'Choose at least one day for the scan window.')
    if (w.from === w.to) return fail(400, 'bad_window', 'Start and end time cannot be the same.')
    const pps = b.speed?.packets_per_s ?? 0, rps = b.speed?.requests_per_s ?? 0
    if (pps < 1 || pps > 1000) return fail(400, 'bad_rate', 'Scan rate is 1 to 1000 packets per second.')
    if (rps < 1 || rps > 20) return fail(400, 'bad_rate', 'The vulnerability check rate is 1 to 20 requests per second.')
    const excl = b.exclusions ?? []
    if (excl.length > 200) return fail(400, 'too_many_exclusions', 'The exclusion list can have at most 200 lines.')
    for (const x of excl) if (!IPV4_RE.test(x) && !(CIDR_RE.test(x) && masked(x) === x)) return fail(400, 'bad_exclusion', `Exclusion "${x.slice(0, 30)}" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
    if (st.active.enabled && !b.scope?.confirmed) return fail(400, 'scope_not_confirmed', 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.')
    if (!scopeCost(clean, excl, w.days, w.from!, w.to!, pps).fits_week) return fail(400, 'scope_too_large', TOO_LARGE)
    const same = [...clean].sort().join() === [...st.lan_ranges].sort().join()
    const who = currentUser()?.email ?? null
    inventorySettingsStore.set({
      ...st, lan_ranges: clean,
      active: { ...st.active, days: [...new Set(w.days)].sort(), from: w.from!, to: w.to!, rate: pps, exclusions: [...new Set(excl)] },
      fragile_kinds: b.fragile?.kinds ?? st.fragile_kinds, regular_scan_kinds: (b.fragile?.regular_scan_kinds ?? []).filter((k) => (b.fragile?.kinds ?? st.fragile_kinds).includes(k)),
      scope_confirmed_at: b.scope?.confirmed ? (same && st.scope_confirmed_at ? st.scope_confirmed_at : nowIso()) : null,
      scope_confirmed_by: b.scope?.confirmed ? (same && st.scope_confirmed_by ? st.scope_confirmed_by : who) : null,
    })
    checkRate.set({ requests_per_s: rps })
    audit('inventory.settings', 'scan scope', `${clean.length} ranges`)
    return HttpResponse.json({ ...scanningView().safety, adjusted })
  }),

  http.post(`${API}/scanning/safety/estimate`, async ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const b = await body<{ lan_ranges: string[]; exclusions: string[]; window: { days: number[]; from: string; to: string }; packets_per_s: number }>(request)
    return HttpResponse.json(scopeCost(b.lan_ranges ?? [], b.exclusions ?? [], b.window?.days ?? [], b.window?.from ?? '00:00', b.window?.to ?? '00:00', b.packets_per_s ?? 1))
  }),

  // "+ New range" where the person is (#842): one range added in one step, the same rules as the PUT (inventory POST of the backend)
  http.post(`${API}/scanning/safety/ranges`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<z.infer<typeof RangeAdd>>(request)
    const raw = String(b.range ?? '').trim()
    const { value: r } = normalizeRange(raw)
    const adjusted = r !== raw ? [{ from: raw, to: r }] : []
    if (IPV4_RE.test(r)) return fail(400, 'no_prefix', `"${r}" has no prefix length. Add it so Vedette scans the right size of network, for example ${r}/24 or ${r}/25.`)
    if (!CIDR_RE.test(r)) return fail(400, 'bad_cidr', `"${r.slice(0, 30)}" is not a valid network range. Enter something like 192.168.10.0/24.`)
    if (!isPrivateCidr(r)) return fail(400, 'public_range', `${r} is not an internal range (${LOCAL_RANGE_NAMES}). To scan public addresses, add them under External exposure after verifying ownership.`)
    if (b.confirm !== true) return fail(400, 'scope_not_confirmed', SCOPE_NOT_CONFIRMED)
    const st = inventorySettingsStore.get()
    const covered = coveredBy(r, st.lan_ranges)
    if (covered && st.scope_confirmed_at) return HttpResponse.json({ ...scanningView().safety, adjusted })
    // review #860 H1, r2 M1: the tick covers the ranges and the confirmation the dialog showed, and only those
    const shown = [...new Set((b.shown_ranges ?? []).map((x) => normalizeRange(String(x)).value))].sort()
    const sec = (v: string | null | undefined) => (v ? new Date(v).toISOString().slice(0, 19) : null)
    if (shown.join() !== [...st.lan_ranges].sort().join() || sec(b.shown_confirmed_at) !== sec(st.scope_confirmed_at)) return fail(409, 'scope_changed', 'The network ranges changed since this dialog opened. Check the current list, then confirm again.', { safety: scanningView().safety })
    const ranges = covered ? st.lan_ranges : [...st.lan_ranges, r]
    if (ranges.length > 16) return fail(400, 'too_many_ranges', 'At most 16 network ranges.')
    const clash = overlapping(r, st.lan_ranges)
    if (!covered && clash) return fail(400, 'overlap_range', `Range ${r} overlaps ${clash}. Keep the larger range and drop the smaller one.`)
    inventorySettingsStore.set({ ...st, lan_ranges: ranges, scope_confirmed_at: nowIso(), scope_confirmed_by: currentUser()?.email ?? null })
    const was = st.scope_confirmed_at ? '' : `${st.lan_ranges.join(', ')} were shown`
    const what = covered ? `confirmed the scope, which was not confirmed (${was}; ${r} is inside it)` : `added range ${r}${was && st.lan_ranges.length ? ` and confirmed the scope, which was not confirmed (${was})` : ''}`
    audit('inventory.settings', 'scan scope', `${what}: ${ranges.length} ranges, active scanning ${st.active.enabled ? 'on' : 'off'}`)
    return HttpResponse.json({ ...scanningView().safety, adjusted })
  }),

  // "+ New exclusion" where the person is (#842): one entry added in one step
  http.post(`${API}/scanning/safety/exclusions`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<z.infer<typeof ExclusionAdd>>(request)
    const x = String(b.entry ?? '').trim()
    if (!IPV4_RE.test(x) && !(CIDR_RE.test(x) && masked(x) === x)) return fail(400, 'bad_exclusion', `Exclusion "${x.slice(0, 30)}" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
    const st = inventorySettingsStore.get()
    if (coveredBy(x, st.active.exclusions)) return HttpResponse.json(scanningView().safety)
    if (st.active.exclusions.length >= 200) return fail(400, 'too_many_exclusions', 'The exclusion list can have at most 200 lines. Remove one in Settings, Scanning, or exclude a range that covers several.')
    const exclusions = [...st.active.exclusions, x]
    inventorySettingsStore.set({ ...st, active: { ...st.active, exclusions } })
    audit('inventory.settings', 'scan scope', `added exclusion ${x}: ${exclusions.length} exclusions`)
    return HttpResponse.json(scanningView().safety)
  }),

  http.patch(`${API}/scanning/engines/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const d = DEFS.find((x) => x.id === params.id)
    if (!d) return fail(404, 'not_found', 'This engine no longer exists.')
    if (NO_SWITCH.includes(d.id)) return fail(409, 'not_toggleable', 'This engine has no switch of its own: it follows another engine or runs as a step of another scan.')
    const b = await body<z.infer<typeof EnginePatch>>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'invalid', 'The switch value must be on or off.')
    const setModule = (id: ModuleId, on: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled: on, enabled_at: on ? nowIso() : null } : m)))
    if (d.id === 'nmap-discovery') {
      const st = inventorySettingsStore.get()
      if (b.enabled && !st.scope_confirmed_at) return fail(400, 'scope_not_confirmed', 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.')
      if (b.enabled && !isOn('sensor-active')) {
        if (!b.with_dependencies) return fail(409, 'missing_dependencies', 'Module sensor-active also needs to be on.', { lacking: ['sensor-active'] })
        setModule('sensor-active', true)
      }
      inventorySettingsStore.set({ ...st, active: { ...st.active, enabled: b.enabled } })
      audit('inventory.settings', 'scan scope', `active scanning ${b.enabled ? 'on' : 'off'}`)
    } else if (d.id === 'openvas') {
      if (!isOn('exposure')) return fail(409, 'module_off', 'The External exposure module is off. An admin can turn it on in Settings, Modules.')
      const refused = greenboneMock.set(b.enabled) // the OpenVAS flag of the exposure mock, as PUT /exposure/greenbone (audited there)
      if (refused) return fail(409, refused.code, refused.message)
    } else {
      if (b.enabled && installStore.get().kind !== 'appliance' && d.id === 'honeypot') return fail(409, 'not_appliance', 'This install has no operating system helper (container-only install), so it cannot run the honeypot.')
      setModule(d.module, b.enabled)
      audit('core.module', d.module, b.enabled ? 'on' : 'off')
    }
    return HttpResponse.json(scanningView())
  }),

  http.post(`${API}/scanning/engines/nmap-discovery/run`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<z.infer<typeof DiscoveryRunInput>>(request)
    const st = inventorySettingsStore.get()
    if (!isOn('sensor-active')) return fail(409, 'module_off', 'Active discovery (module sensor-active) is off. An admin can turn it on in Settings, Scanning.')
    if (!st.active.enabled) return fail(409, 'engine_off', 'Network discovery is off. Turn it on in Settings, Scanning first.')
    if (!st.scope_confirmed_at) return fail(400, 'scope_not_confirmed', 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.')
    const targets = b.targets ?? []
    const going = discoveryRuns()
    // never refused because the scanner is busy (the box queues it); a second LAN sweep while one goes on is the one refusal
    if (targets.length === 0 && going.some((r) => r.target_id === null && r.label.startsWith('LAN sweep'))) return fail(409, 'busy', 'A LAN sweep is already going on: it is the answer. Follow it on the Runs tab.')
    const assets = assetsStore.get()
    const picked: typeof assets = []
    for (const t of targets) {
      const a = assets.find((x) => x.id === t || x.ip === t)
      if (!a) return fail(400, 'unknown_device', `No device has the address or id ${t.slice(0, 40)}. Let discovery find it first, or add it under Devices.`, { target: t })
      if (!a.ip || a.ip === '—') return fail(400, 'not_scannable', `${a.hostname ?? a.id} has no IP address, so it cannot be checked.`, { target: t })
      if (a.id === BOX_ID) return fail(400, 'out_of_scope', 'The Vedette box itself is never part of a scan.', { target: t })
      if (st.active.exclusions.includes(a.ip)) return fail(400, 'out_of_scope', `${a.ip} is outside the confirmed scope or excluded.`, { target: t })
      picked.push(a)
    }
    // asked again: the run it already has, nothing new
    const same = picked.length === 1 ? runs.get().find((r) => r.target_id === picked[0]!.id && r.ends_ms > Date.now()) : undefined
    const id = same?.id ?? queueRun(picked, st.lan_ranges)
    return HttpResponse.json(discoveryRuns().find((r) => r.id === id), { status: 202 })
  }),
]
