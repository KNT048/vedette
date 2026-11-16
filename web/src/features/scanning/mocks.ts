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
import { inventorySettingsStore } from '@/features/inventory/mocks'
import type { DiscoveryRunInput, Engine, EngineId, EnginePatch, RunningJob, Scanning, SafetyInput } from './contract'

type EngineT = z.infer<typeof Engine>
type Id = z.infer<typeof EngineId>
type Run = z.infer<typeof RunningJob>

const checkRate = collection<{ requests_per_s: number }>('scanning_check_rate', () => ({ requests_per_s: 5 }))
const greenbone = collection<{ enabled: boolean }>('scanning_openvas', () => ({ enabled: false }))
const runs = collection<Array<Run & { ends_ms: number }>>('scanning_runs', () => [], () => [])
const RUN_MS = 20_000

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

function live(): Run[] {
  const now = Date.now()
  const kept = runs.get().filter((r) => r.ends_ms > now)
  if (kept.length !== runs.get().length) runs.set(kept)
  return kept.map(({ ends_ms, ...r }) => {
    const started = Date.parse(r.started_at)
    return { ...r, progress: mockDeviceProgress(started, (now - started) / (ends_ms - started), now) }
  })
}

function enabled(d: Def): boolean {
  const st = inventorySettingsStore.get()
  if (d.module === 'sensor-active') return isOn('sensor-active') && st.active.enabled
  if (d.id === 'openvas') return isOn('exposure') && greenbone.get().enabled
  return isOn(d.module)
}

function engine(d: Def, running: Run[]): EngineT {
  const st = inventorySettingsStore.get()
  const on = enabled(d)
  const appliance = installStore.get().kind === 'appliance'
  let state: EngineT['state'] = on ? 'ready' : 'off'
  let reason: string | null = null
  if (!appliance && (d.id === 'honeypot' || d.id === 'zap' || d.id === 'openvas')) { state = 'unavailable'; reason = 'This install has no operating system helper (container-only install), so it cannot run this.' }
  else if (on && d.module === 'sensor-active' && !st.scope_confirmed_at) { state = 'needs_setup'; reason = 'Confirm the network ranges you may scan.' }
  else if (on && running.some((r) => r.engine === d.id)) state = 'running'
  const windowed = d.module === 'sensor-active' || d.id === 'nuclei'
  return {
    id: d.id, group: d.group, module: d.module, enabled: on, can_toggle: !NO_SWITCH.includes(d.id), follows: d.follows ?? null, affects: d.affects ?? [],
    state, reason, preview: d.preview ?? false, cost: d.cost,
    last_run: on ? { at: new Date(Date.now() - 9 * 3600_000).toISOString(), outcome: 'ok', text: d.id === 'nmap-discovery' ? 'Swept 508 addresses, 2 new devices' : 'Last run finished' } : null,
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

export const handlers = [
  http.get(`${API}/scanning`, () => guard('viewer') ?? HttpResponse.json(scanningView())),

  http.put(`${API}/scanning/safety`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<z.infer<typeof SafetyInput>>(request)
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
      greenbone.set({ enabled: b.enabled })
      audit('exposure.greenbone', 'openvas', b.enabled ? 'on' : 'off')
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
    if (live().length) return fail(409, 'already_running', 'A scan is already running. Wait for it to finish or press Stop now.')
    const targets = b.targets ?? []
    const assets = assetsStore.get()
    const picked = []
    for (const t of targets) {
      const a = assets.find((x) => x.id === t || x.ip === t)
      if (!a) return fail(400, 'unknown_device', `No device has the address or id ${t.slice(0, 40)}. Let discovery find it first, or add it under Devices.`, { target: t })
      if (!a.ip || a.ip === '—') return fail(400, 'not_scannable', `${a.hostname ?? a.id} has no IP address, so it cannot be checked.`, { target: t })
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
    const { ends_ms: _, ...out } = run
    return HttpResponse.json(out, { status: 202 })
  }),
]
