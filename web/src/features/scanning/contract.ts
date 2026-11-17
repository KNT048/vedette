// API contract of Settings › Scanning (#850, J2 J6): one read of every scanning engine, one writer of the shared safety block, the
// engine switches and "Scan the LAN now" / "Check this device now". Served by core (always on), so the page answers while any
// engine's module is off; core/server/modules.go maps /scanning to core and core reads each engine through a port wired in
// cmd/vedette (core imports no module). Every value here already lives in a module's store: the shared window, check rate and
// exclusions live in inventory, which the scan module reads instead of its own copy (modules/core/CONTRACT.md INV-40, D-627).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { BEHAVIOUR_KINDS } from '@/lib/deviceTypes'
import { JobProgress } from '@/lib/progress'

const iso = z.iso.datetime()
const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).describe('HH:MM')
const day = z.number().int().min(1).max(7).describe('1 = Monday … 7 = Sunday (D-57 (9))')
const BehaviourKind = z.enum(BEHAVIOUR_KINDS)

export const EngineId = z.enum(['passive', 'nmap-discovery', 'nmap-versions', 'snmp', 'osquery', 'wazuh', 'nuclei', 'zap', 'openvas', 'honeypot'])
export const EngineGroup = z.enum(['discover', 'identify', 'vuln', 'traps'])
export const EngineModule = z.enum(['sensor-passive', 'sensor-active', 'agent-intake', 'scan', 'exposure', 'honeypot'])
export const EngineState = z.enum(['off', 'needs_setup', 'starting', 'ready', 'running', 'error', 'unavailable'])
  .describe('off: switched off (or its module is); needs_setup: on, but it has nothing to work with yet (scope not confirmed, no SNMP credential, no osquery token, no Wazuh server, no verified target, no Trap IP); starting: its container is starting, or OpenVAS loads its feed; ready: on and waiting for its window, schedule or a person; running: a job runs now; error: it failed and needs a person (reason says what); unavailable: this box cannot run it (container-only install, tool missing, not enough memory)')

export const EngineCost = z.object({
  ram_mb: z.number().int().nullable().describe('Memory it may take, from a fact of the box\'s code: its container\'s memory cap (sensor 512, honeypot 256, scan 1024, ZAP 1024), or the measured peak for OpenVAS (about 4000, D-569); 0 for osquery and Wazuh, which run inside core. null when it is not known; never an estimate'),
  while: z.enum(['on', 'running']).describe('on: held as long as the engine is on (a long-running container); running: only while one of its jobs runs (a one-shot container, or OpenVAS scanning)'),
  container: z.string().nullable().describe('The container it shares with other engines (scan: nmap, SNMP and nuclei); count a shared container once. null when the figure is its own'),
})

export const LastRun = z.object({
  at: iso, outcome: z.enum(['ok', 'partial', 'failed', 'stopped']),
  text: z.string().describe('One sentence from the box, e.g. "Swept 254 addresses, 3 new devices", "Last report from an osquery agent", "Last trap hit"'),
})

export const Engine = z.object({
  id: EngineId, group: EngineGroup,
  module: EngineModule.describe('The module it belongs to; PATCH /modules/{id} of that module still works'),
  enabled: z.boolean(),
  can_toggle: z.boolean().describe('false: it has no switch of its own; follows names the engine whose switch it obeys, or reason says why'),
  follows: EngineId.nullable().describe('nmap-versions and snmp follow nmap-discovery; null otherwise'),
  affects: z.array(EngineId).describe('Engines that stop too when this one is turned off (osquery and wazuh share the agent-intake switch; nmap-discovery off stops nmap-versions and the SNMP rounds). External scans (zap, openvas) follow the External exposure module, not nuclei. The page names them before turning off'),
  state: EngineState,
  reason: z.string().nullable().describe('Plain sentence for needs_setup, starting, error and unavailable, or a warning while ready (e.g. "A sweep of these ranges needs 3 windows"); null otherwise'),
  preview: z.boolean().describe('Its module ships as Preview in v1 (SHIP.md: scan, honeypot)'),
  cost: EngineCost,
  last_run: LastRun.nullable().describe('null: never ran'),
  next_run_at: iso.nullable().describe('Next window opening (nmap-discovery, nmap-versions, snmp), next scheduled scan (nuclei), next Wazuh sync; null for engines that listen all the time (passive, osquery, honeypot) or run only when a person asks (zap, openvas)'),
})

export const RunningJob = z.object({
  engine: EngineId, id: z.string().describe('The run: a scan_run id, an exposure ScanRun id, an sa_job id, or a run of POST /scanning/engines/nmap-discovery/run'),
  label: z.string().describe('What it scans, e.g. "LAN sweep 192.168.18.0/24", "Check 192.168.18.20", "203.0.113.10"'),
  target_id: z.string().nullable().describe('The device id or exposure target id the run is about, for a link; null for a sweep or several devices'),
  started_at: iso, progress: JobProgress.nullable().describe('null until the run reports a step, and for runs that do not report one'),
})

export const Safety = z.object({
  scope: z.object({
    lan_ranges: z.array(z.string()).max(16).describe('Internal IPv4 CIDR (RFC 1918 or 100.64.0.0/10, D-461); inventory lan_ranges'),
    confirmed_at: iso.nullable(), confirmed_by: z.string().nullable(),
  }),
  window: z.object({
    days: z.array(day).describe('Empty only on a box whose discovery was saved off without a day; a save needs one'), from: hhmm, to: hhmm.describe('Earlier than from: crosses midnight'),
    time_zone: z.string().describe('IANA zone the window is read in (the organization time zone); read-only'),
  }).describe('One window for discovery, version scans, SNMP rounds and scheduled vulnerability checks. Scan now, Check this device now and external scans are not bound by it'),
  speed: z.object({
    packets_per_s: z.number().int().min(1).max(1000).describe('nmap and SNMP (inventory active.rate)'),
    requests_per_s: z.number().int().min(1).max(20).describe('nuclei on LAN devices (was scan config rate)'),
  }),
  exclusions: z.array(z.string()).describe('IPv4 or CIDR never touched by any engine on the LAN (a merge of two old lists may hold more than the 200 a save accepts)'),
  fragile: z.object({
    kinds: z.array(BehaviourKind).describe('Types scanned once, gently, when first seen; passive-only after that (D-45, D-511)'),
    regular_scan_kinds: z.array(BehaviourKind).describe('Subset of kinds that may still get regular scans'),
    devices: z.number().int().describe('Devices fragile today (by type or marked by hand), for the link to Devices with the fragile filter; read-only'),
  }),
  version: z.string().describe('Names the stored values of this block (review #860 M1): PUT /scanning/safety must send back the version it was built on (409 safety_changed otherwise), so a page opened before an inline add never drops it. Every answer that changed the block carries the new one. The same values give the same version'),
})
export const SafetyInput = z.object({
  scope: z.object({
    lan_ranges: Safety.shape.scope.shape.lan_ranges,
    confirmed: z.boolean().describe('Attestation: the ranges belong to the company and scanning them is permitted. Required true while nmap-discovery is on (400 scope_not_confirmed); changing the ranges asks for it again'),
  }),
  window: Safety.shape.window.omit({ time_zone: true }).extend({ days: z.array(day).min(1) }),
  speed: Safety.shape.speed, exclusions: z.array(z.string()).max(200).describe('IPv4 or CIDR without host bits'),
  fragile: Safety.shape.fragile.omit({ devices: true }),
  version: z.string().max(64).describe('The version of GET /scanning (safety.version) this page was built on. Not the stored one: 409 safety_changed with the current block (error.safety), nothing stored'),
})
export const SafetySaved = Safety.extend({
  adjusted: z.array(z.object({ from: z.string(), to: z.string() })).describe('Ranges and exclusions normalized on save, e.g. 192.168.18.0 → 192.168.18.0/24'),
})

export const RangeAdd = z.object({
  range: z.string().max(64).describe('One internal IPv4 CIDR (RFC 1918 or 100.64.0.0/10, D-461) to add to the scope, e.g. 192.168.20.0/24; host bits are dropped and reported in adjusted'),
  confirm: z.boolean().describe('The attestation of PUT /scanning/safety (scope.confirmed): the ranges shown, and this one, belong to the company and scanning them is permitted. Must be true (400 scope_not_confirmed); recorded as confirmed_at/confirmed_by'),
  shown_ranges: z.array(z.string().max(64)).max(16).describe('The ranges the dialog showed next to the tick (safety.scope.lan_ranges as read; order does not matter, compared as networks). The tick confirms exactly these and the new range: when the stored list is another one (an admin changed the ranges since), 409 scope_changed with the current block (error.safety) and nothing stored (review #860 H1)'),
  shown_confirmed_at: z.string().max(64).nullable().describe('The confirmation the dialog showed (safety.scope.confirmed_at as read, compared to the second; null: shown as not confirmed). When the stored one is another (an admin unconfirmed the scope, or confirmed it again, since), 409 scope_changed with the current block, nothing stored (review #860 r2 M1)'),
})
export const ExclusionAdd = z.object({
  entry: z.string().max(64).describe('One IPv4 address or IPv4 CIDR without host bits that no engine on the LAN may touch, e.g. 192.168.18.9 or 192.168.18.64/28'),
})

export const Scanning = z.object({
  safety: Safety,
  engines: z.array(Engine).describe('Every engine of this version, in display order; post-v1 ones (credentialed scans) are not listed'),
  running: z.array(RunningJob).describe('Jobs running now across engines, for the "1 scan running" indicator of the top bar'),
  box: z.object({
    memory_mb: z.number().int().nullable().describe('MemTotal of the box; null when it cannot be read (container-only install may report its limit)'),
    reserved_mb: z.number().int().describe('Sum of the cost of the engines that hold memory now (while on, plus while running for running jobs), a shared container counted once, plus core\'s 2048'),
  }),
})

export const EnginePatch = z.object({
  enabled: z.boolean(),
  with_dependencies: z.boolean().optional().describe('As PATCH /modules/{id}: also turn on the modules it needs instead of 409 missing_dependencies'),
})

export const DiscoveryRunInput = z.object({
  targets: z.array(z.string().max(96)).min(1).max(64).optional().describe('Leave out: sweep the whole LAN scope now, then identify the devices waiting for their scan ("Scan the LAN now"). Given: the devices to check now ("Check this device now", "Scan selected"), each an IPv4 address of a device or a device id. Every target must be a device inside the confirmed scope, outside the exclusions, and one its safety rules let a person check (a fragile device gets its gentle scan; "never scan" is refused)'),
})

const engineParam = z.object({ id: EngineId })

export const HistoryRun = z.object({
  id: z.string().describe('The sa_job id of a LAN run, or the exposure snapshot id of a public scan'),
  kind: z.enum(['sweep', 'device', 'snmp', 'external']).describe('sweep: discovery of the LAN ranges; device: the identification of one device (a window\'s queue, Check this device now, the first step of Scan now); snmp: SNMP reads; external: a scan of a public target (one per target and day)'),
  engine: EngineId,
  trigger: z.enum(['sweep', 'automatic', 'person', 'scan_now', 'test']).describe('sweep: a discovery sweep (the window, or Scan the LAN now: the row does not tell them apart); automatic: the window\'s queue (a new device, a weekly scan) or its SNMP round; person: a person asked (Check this device now, Read now, a public scan); scan_now: the identification step of a vulnerability check; test: an SNMP credential Test'),
  label: z.string().describe('What it scanned: "LAN 192.168.18.0/24", "192.168.18.20", "SNMP read of 3 devices", "203.0.113.10"'),
  target_id: z.string().nullable().describe('The exposure target of a public scan, for a link; null otherwise (a LAN job does not record its device)'),
  started_at: z.iso.datetime(), ended_at: z.iso.datetime().nullable(),
  outcome: z.enum(['ok', 'failed', 'stopped', 'running']),
  text: z.string().describe('The outcome in words, from the stored result: "Swept 254 addresses, 2 new devices", "Scanned 192.168.18.20: 1 host up", "Failed: <reason>", "Stopped: <reason>"'),
})

export const endpoints = defineEndpoints([
  { method: 'get', path: '/scanning/history', summary: 'Every run of the LAN engines (discovery sweeps, device identifications, SNMP reads) and every stored scan of a public target, newest first, at most 200, with its outcome in words (kien G7a). The vulnerability checks keep their own list (GET /scans/runs). Answers whether or not the Vulnerability scans module is on', stories: ['S-SCAN-4', 'S-INV-1'], role: 'viewer', response: z.object({ items: z.array(HistoryRun) }) },
  { method: 'get', path: '/scanning', summary: 'Every scanning engine with its switch, state, memory cost, last and next run, the jobs running now, and the shared safety settings (scope, window, speed, exclusions, fragile types)', stories: ['S-SCAN-4', 'S-CORE-1', 'S-INV-1'], role: 'viewer', response: Scanning },
  { method: 'put', path: '/scanning/safety', summary: 'Save the shared safety settings every LAN engine obeys (one writer; GET/PUT /inventory/settings and the window, rate and exclusions of /scans/config read and write the same values). 400 as PUT /inventory/settings: too_many_ranges, no_prefix, bad_cidr, public_range, overlap_range, bad_days, no_days, bad_time, bad_window, bad_rate (packets_per_s 1 to 1000, requests_per_s 1 to 20), bad_exclusion, too_many_exclusions, bad_kinds, scope_not_confirmed (while nmap-discovery is on); 409 safety_changed (with error.safety, the current block) when version is not the stored one: re-read, merge, save again. Publishes inventory.settings.changed: a run that the new values no longer allow stops', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: SafetyInput, response: SafetySaved },
  { method: 'post', path: '/scanning/safety/ranges', summary: 'Add one LAN range to the scope where the person is ("+ New range" in a dialog, #842), without sending the whole block: read, append and save in one transaction, so it never overwrites another edit. The dialog lists the current ranges and whether they are confirmed with the confirmation tick, and sends both back (shown_ranges, shown_confirmed_at): the tick confirms those ranges and the new one only. 400 as PUT /scanning/safety for a range: no_prefix, bad_cidr, public_range, overlap_range, too_many_ranges (16), and scope_not_confirmed when confirm is not true; 409 scope_changed (with error.safety, the current block) when the stored ranges are not shown_ranges or the stored confirmation is not shown_confirmed_at. A range the confirmed scope already covers is 200 with the block unchanged (no audit row). Audited as the PUT (inventory.settings, naming the range, and saying when the add confirmed a scope that was not confirmed) and publishes inventory.settings.changed. Returns the whole safety block with its new version, and adjusted when the range was normalized', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: RangeAdd, response: SafetySaved },
  { method: 'post', path: '/scanning/safety/exclusions', summary: 'Add one exclusion where the person is ("+ New exclusion" in a dialog, #842), without sending the whole block: read, append and save in one transaction. 400 bad_exclusion as PUT /scanning/safety, and too_many_exclusions when the list would grow past 200. An entry an exclusion already covers is 200 with the block unchanged (no audit row). Audited as the PUT (inventory.settings, naming the entry) and publishes inventory.settings.changed: a run that may no longer touch it stops. Returns the whole safety block with its new version', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: ExclusionAdd, response: Safety },
  { method: 'patch', path: '/scanning/engines/{id}', summary: 'Turn an engine on or off: its module switch (passive, osquery, wazuh, nuclei, honeypot), active discovery (nmap-discovery: on turns sensor-active on first when with_dependencies is set, off never turns the module off) or the OpenVAS flag (openvas). Audited by the switch it moves. 409 not_toggleable (nmap-versions, snmp, zap), missing_dependencies, not_appliance, module_off (openvas while External exposure is off), low_memory, low_disk; 400 no_ranges, no_days, scope_not_confirmed (nmap-discovery on, checked before anything moves), core_module. Returns the whole page, since one switch can change several engines', stories: ['S-CORE-1', 'S-SCAN-4'], role: 'admin', params: engineParam, body: EnginePatch, response: Scanning },
  { method: 'post', path: '/scanning/engines/nmap-discovery/run', summary: 'Scan the LAN now (no targets: a sweep of the whole scope, then the scans of the devices it queued) or check these devices now (targets), whatever the window, for at most one hour (devices not reached by then wait for the window). Audited before anything is sent (scanning.run: the run id and the ranges or devices; no audit row, no run). Runs in the background: the answer is the run, which GET /scanning lists in running[] with its progress until it ends. Works while the Vulnerability scans module is off. 400 unknown_device, out_of_scope (outside the ranges, excluded, or the box), scope_not_confirmed, not_scannable (the device\'s safety rules refuse it); 409 module_off (sensor-active off), engine_off (active discovery off), already_running (a run a person started), busy (discovery is running nmap now), too_soon (a sweep less than 10 minutes ago; retry_after in seconds); 503 scanner_unavailable (nmap is not available)', stories: ['S-INV-1', 'S-SCAN-4'], role: 'admin', body: DiscoveryRunInput, response: RunningJob, status: 202 },
])
