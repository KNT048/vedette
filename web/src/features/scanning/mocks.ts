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
import { BOX_ID, inventorySettingsStore, SAFETY_CHANGED, safetyVersion } from '@/features/inventory/mocks'
import { cidrRange, isPrivateCidr, LOCAL_RANGE_NAMES, normalizeRange, overlapping } from '@/features/inventory/validate'
import { exposureMockRun, greenboneMock } from '@/features/exposure/mocks'
import { lastScanRun, liveScanRuns } from '@/features/scan/mocks'
import type { DiscoveryRunInput, Engine, EngineId, EnginePatch, ExclusionAdd, HistoryRun, RangeAdd, RunningJob, Scanning, SafetyInput } from './contract'

type EngineT = z.infer<typeof Engine>
type Id = z.infer<typeof EngineId>
type Run = z.infer<typeof RunningJob>

const checkRate = collection<{ requests_per_s: number }>('scanning_check_rate', () => ({ requests_per_s: 5 }))
const runs = collection<Array<Run & { ends_ms: number }>>('scanning_runs', () => [], () => [])
const RUN_MS = 20_000
type HistoryRow = z.infer<typeof HistoryRun>
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
/** GET /scanning/history (kien G7a), as cmd/vedette scanninghistory.go builds it: the LAN jobs and the public scans, newest first. */
export const historyStore = collection<HistoryRow[]>('scanning_history', () => [
  { id: 'saj-h1', kind: 'device', engine: 'nmap-versions', trigger: 'person', label: '192.168.10.21', target_id: null, started_at: ago(3), ended_at: ago(2.98), outcome: 'ok', text: 'Scanned 192.168.10.21: it answered; what it runs is on its device page' },
  { id: 'saj-h2', kind: 'sweep', engine: 'nmap-discovery', trigger: 'sweep', label: 'LAN 192.168.10.0/24', target_id: null, started_at: ago(20), ended_at: ago(19.9), outcome: 'ok', text: 'Swept 254 addresses: 12 hosts answered, 2 new devices' },
  { id: 'saj-h3', kind: 'snmp', engine: 'snmp', trigger: 'automatic', label: 'SNMP read', target_id: null, started_at: ago(21), ended_at: ago(20.95), outcome: 'partial', text: '2 of 3 devices answered over SNMP' },
], () => [])
/** The addresses each mock SNMP read asked (the box keeps them in its probes; History shows only the count). */
const snmpAsked: Record<string, string[]> = { 'saj-h3': ['192.168.10.1', '192.168.10.21', '192.168.10.30'] }

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
  return kept.map(({ ends_ms, ...r }) => {
    const started = Date.parse(r.started_at)
    return { ...r, progress: mockDeviceProgress(started, (now - started) / (ends_ms - started), now) }
  })
}
/** Every run going on (#850 review M7): discovery, the LAN vulnerability checks (scan mock) and the public scan (exposure mock). */
function live(): Run[] {
  const out = discoveryRuns()
  for (const r of liveScanRuns()) out.push({ engine: 'nuclei', id: r.id, label: r.total === 1 && r.current ? `Check ${r.current.label}` : `Vulnerability checks on ${r.total} devices`, target_id: null, started_at: r.started_at, progress: r.progress })
  const ex = exposureMockRun()
  if (ex?.status === 'running') out.push({ engine: ex.phase === 'greenbone' ? 'openvas' : 'zap', id: ex.id, label: ex.target_value, target_id: ex.target_id, started_at: ex.started_at, progress: ex.progress })
  return out
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
    else if (g.state === 'starting' || g.state === 'loading') { state = 'starting'; reason = g.reason ?? 'OpenVAS is loading its feed (first time takes about 2 hours).' }
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

/** c (a CIDR or an IPv4 address, its /32) lies inside one of list's ranges or addresses: adding it changes nothing. */
const coveredBy = (c: string, list: string[]) => {
  const r = cidrRange(c.includes('/') ? c : `${c}/32`)
  return list.find((o) => { const q = cidrRange(o.includes('/') ? o : `${o}/32`); return r.base >= q.base && r.base + r.size <= q.base + q.size })
}
const SCOPE_NOT_CONFIRMED = 'Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.'

export const handlers = [
  http.get(`${API}/scanning`, () => guard('viewer') ?? HttpResponse.json(scanningView())),
  http.get(`${API}/scanning/history`, ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    // kien G7b/c: ?asset= keeps the runs that reached the device's address now: its checks and the SNMP reads that asked it
    const asset = new URL(request.url).searchParams.get('asset')
    const ip = asset === null ? null : assetsStore.get().find((a) => a.id === asset)?.ip ?? '—'
    const rows = ip === null ? historyStore.get() : historyStore.get().filter((r) => ip !== '—' && ((r.kind === 'device' && r.label === ip) || (r.kind === 'snmp' && (snmpAsked[r.id] ?? []).includes(ip))))
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
    if (discoveryRuns().length) return fail(409, 'already_running', 'A scan is already running. Wait for it to finish or press Stop now.')
    const targets = b.targets ?? []
    const assets = assetsStore.get()
    const picked = []
    for (const t of targets) {
      const a = assets.find((x) => x.id === t || x.ip === t)
      if (!a) return fail(400, 'unknown_device', `No device has the address or id ${t.slice(0, 40)}. Let discovery find it first, or add it under Devices.`, { target: t })
      if (!a.ip || a.ip === '—') return fail(400, 'not_scannable', `${a.hostname ?? a.id} has no IP address, so it cannot be checked.`, { target: t })
      if (a.id === BOX_ID) return fail(400, 'out_of_scope', 'The Vedette box itself is never part of a scan.', { target: t })
      if (st.active.exclusions.includes(a.ip)) return fail(400, 'out_of_scope', `${a.ip} is outside the confirmed scope or excluded.`, { target: t })
      picked.push(a)
    }
    const started = nowIso()
    const run: Run & { ends_ms: number } = {
      engine: 'nmap-discovery', id: newId('sar'), started_at: started, progress: null,
      label: picked.length === 0 ? `LAN sweep ${st.lan_ranges.join(', ')}` : picked.length === 1 ? `Check ${picked[0]!.ip}` : `Check ${picked.length} devices`,
      target_id: picked.length === 1 ? picked[0]!.id : null, ends_ms: Date.parse(started) + RUN_MS * Math.max(1, picked.length),
    }
    runs.set([...runs.get(), run])
    // its jobs as History lists them: one per device checked, or the sweep (the mock ends them at once)
    const rows: HistoryRow[] = picked.length
      ? picked.map((a) => ({ id: newId('saj'), kind: 'device' as const, engine: 'nmap-versions' as const, trigger: 'person' as const, label: a.ip, target_id: null, started_at: started, ended_at: started, outcome: 'ok' as const, text: `Scanned ${a.ip}: it answered; what it runs is on its device page` }))
      : [{ id: newId('saj'), kind: 'sweep', engine: 'nmap-discovery', trigger: 'sweep', label: `LAN sweep of ${st.lan_ranges.join(', ')}`, target_id: null, started_at: started, ended_at: started, outcome: 'ok', text: `Swept ${st.lan_ranges.length * 254} addresses: 0 hosts answered, 0 new devices` }]
    historyStore.set([...rows, ...historyStore.get()])
    const { ends_ms: _, ...out } = run
    return HttpResponse.json(out, { status: 202 })
  }),
]
