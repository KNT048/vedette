// API contract of Settings › Scanning (#850): one read of every scanning engine, one writer of the shared safety block, the
// engine switches and "Scan the LAN now" / "Check this device now". Served by core (always on), so the page answers while any
// engine's module is off; core/server/modules.go maps /scanning to core and core reads each engine through a port wired in
// cmd/vedette (core imports no module). Every value here already lives in a module's store: the shared window, check rate and
// exclusions live in inventory, which the scan module reads instead of its own copy (modules/core/CONTRACT.md INV-40).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { BEHAVIOUR_KINDS } from '@/lib/deviceTypes'
import { JobProgress } from '@/lib/progress'
import { RUN_STATUSES } from '@/lib/statusCodes'

const iso = z.iso.datetime()
const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).describe('HH:MM')
const day = z.number().int().min(1).max(7).describe('1 = Monday … 7 = Sunday')
const BehaviourKind = z.enum(BEHAVIOUR_KINDS)

export const EngineId = z.enum(['passive', 'nmap-discovery', 'nmap-versions', 'snmp', 'osquery', 'wazuh', 'nuclei', 'zap', 'openvas', 'honeypot'])
export const EngineGroup = z.enum(['discover', 'identify', 'vuln', 'traps'])
export const EngineModule = z.enum(['sensor-passive', 'sensor-active', 'agent-intake', 'scan', 'exposure', 'honeypot'])
export const EngineState = z.enum(['off', 'needs_setup', 'starting', 'ready', 'running', 'error', 'unavailable'])
  .describe('off: switched off (or its module is); needs_setup: on, but it has nothing to work with yet (scope not confirmed, no SNMP credential, no osquery token, no Wazuh server, no verified target, no Trap IP); starting: its container is starting, or OpenVAS loads its feed; ready: on and waiting for its window, schedule or a person; running: a job runs now; error: it failed and needs a person (reason says what); unavailable: this box cannot run it (container-only install, tool missing, not enough memory)')

export const EngineCost = z.object({
  ram_mb: z.number().int().nullable().describe('Memory it may take, from a fact of the box\'s code: its container\'s memory cap (sensor 512, honeypot 256, scan 1024, ZAP 1024), or the measured peak for OpenVAS (about 4000); 0 for osquery and Wazuh, which run inside core. null when it is not known; never an estimate'),
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
  preview: z.boolean().describe('Its module ships as Preview in v1 (scan, honeypot)'),
  cost: EngineCost,
  last_run: LastRun.nullable().describe('null: never ran'),
  next_run_at: iso.nullable().describe('Next window opening (nmap-discovery, nmap-versions, snmp), next scheduled scan (nuclei), next Wazuh sync; null for engines that listen all the time (passive, osquery, honeypot) or run only when a person asks (zap, openvas)'),
})

export const RunningJob = z.object({
  engine: EngineId, id: z.string().describe('The run: a scan_run id, an exposure ScanRun id, an sa_job id, or a run of POST /scanning/engines/nmap-discovery/run'),
  label: z.string().describe('What it scans, e.g. "LAN sweep 192.168.142.0/24", "Check 192.168.142.20", "203.0.113.10"'),
  target_id: z.string().nullable().describe('The device id or exposure target id the run is about, for a link; null for a sweep or several devices'),
  started_at: iso, progress: JobProgress.nullable().describe('null until the run reports a step, and for runs that do not report one'),
})

export const Safety = z.object({
  scope: z.object({
    lan_ranges: z.array(z.string()).max(16).describe('Internal IPv4 CIDR (RFC 1918 or 100.64.0.0/10); inventory lan_ranges'),
    confirmed_at: iso.nullable(), confirmed_by: z.string().nullable(),
  }),
  window: z.object({
    days: z.array(day).describe('Empty only on a box whose discovery was saved off without a day; a save needs one'), from: hhmm, to: hhmm.describe('Earlier than from: crosses midnight'),
    time_zone: z.string().describe('IANA zone the window is read in (the organization time zone); read-only'),
  }).describe('One window for discovery, version scans, SNMP rounds, scheduled vulnerability checks and the scheduled scans of public targets. Scan now and Check this device now are not bound by it'),
  speed: z.object({
    packets_per_s: z.number().int().min(1).max(1000).describe('nmap and SNMP (inventory active.rate)'),
    requests_per_s: z.number().int().min(1).max(20).describe('nuclei on LAN devices (was scan config rate)'),
  }),
  exclusions: z.array(z.string()).describe('IPv4 or CIDR never touched by any engine on the LAN (a merge of two old lists may hold more than the 200 a save accepts)'),
  fragile: z.object({
    kinds: z.array(BehaviourKind).describe('Types scanned once, gently, when first seen; passive-only after that'),
    regular_scan_kinds: z.array(BehaviourKind).describe('Subset of kinds that may still get regular scans'),
    devices: z.number().int().describe('Devices fragile today (by type or marked by hand), for the link to Devices with the fragile filter; read-only'),
  }),
  version: z.string().describe('Names the stored values of this block (#860): PUT /scanning/safety must send back the version it was built on (409 safety_changed otherwise), so a page opened before an inline add never drops it. Every answer that changed the block carries the new one. The same values give the same version'),
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
  adjusted: z.array(z.object({ from: z.string(), to: z.string() })).describe('Ranges and exclusions normalized on save, e.g. 192.168.142.0 → 192.168.142.0/24'),
})

export const RangeAdd = z.object({
  range: z.string().max(64).describe('One internal IPv4 CIDR (RFC 1918 or 100.64.0.0/10) to add to the scope, e.g. 192.168.20.0/24; host bits are dropped and reported in adjusted'),
  confirm: z.boolean().describe('The attestation of PUT /scanning/safety (scope.confirmed): the ranges shown, and this one, belong to the company and scanning them is permitted. Must be true (400 scope_not_confirmed); recorded as confirmed_at/confirmed_by'),
  shown_ranges: z.array(z.string().max(64)).max(16).describe('The ranges the dialog showed next to the tick (safety.scope.lan_ranges as read; order does not matter, compared as networks). The tick confirms exactly these and the new range: when the stored list is another one (an admin changed the ranges since), 409 scope_changed with the current block (error.safety) and nothing stored (#860)'),
  shown_confirmed_at: z.string().max(64).nullable().describe('The confirmation the dialog showed (safety.scope.confirmed_at as read, compared to the second; null: shown as not confirmed). When the stored one is another (an admin unconfirmed the scope, or confirmed it again, since), 409 scope_changed with the current block, nothing stored (#860)'),
})
export const ScopeCostInput = z.object({
  lan_ranges: z.array(z.string().max(64)).max(16).describe('The ranges as typed in the form; lines that are not an internal IPv4 CIDR are left out of the count'),
  exclusions: z.array(z.string().max(64)).max(400).describe('The exclusions as typed; lines that are not an IPv4 address or CIDR are left out'),
  window: z.object({ days: z.array(day).max(7), from: hhmm, to: hhmm }),
  packets_per_s: z.number().int().min(1).max(1000),
})
export const ScopeCost = z.object({
  addresses: z.number().int().min(0).describe('Addresses one pass walks: the ranges minus the exclusions'),
  pass_seconds: z.number().int().min(0).describe('One pass at the rate, a floor: an address on the box\'s own networks costs one packet, one behind a router 17'),
  window_seconds: z.number().int().min(0).describe('One window; 0 when the times are not valid'),
  windows: z.number().int().min(0).describe('Windows one pass needs (1: it fits one window); 0 with no window or nothing to sweep'),
  week_windows: z.number().int().min(0).max(7).describe('Windows in a week: the window\'s days'),
  fits_window: z.boolean(), fits_week: z.boolean().describe('False: a save of this scope is refused (400 scope_too_large)'),
})
export const ExclusionAdd = z.object({
  entry: z.string().max(64).describe('One IPv4 address or IPv4 CIDR without host bits that no engine on the LAN may touch, e.g. 192.168.142.9 or 192.168.142.64/28'),
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
  label: z.string().describe('What it scanned: "LAN 192.168.142.0/24", "192.168.142.20", "SNMP read of 3 devices", "203.0.113.10"'),
  target_id: z.string().nullable().describe('The exposure target of a public scan, for a link; null otherwise (a LAN job does not record its device)'),
  started_at: z.iso.datetime(), ended_at: z.iso.datetime().nullable(),
  outcome: z.enum(['ok', 'partial', 'failed', 'stopped', 'running']).describe('partial: it ended, but part of it found nothing usable (an SNMP device of several that did not answer, a sweep batch or a read that failed, a public scan step not checked or an OpenVAS run that failed)'),
  text: z.string().describe('The outcome in words, only from what the run stored: "Swept 254 addresses: 12 hosts answered, 2 new devices", "2 of 3 devices answered over SNMP", "Failed: the device did not answer over SNMP." (an SNMP read nothing answered is failed, never partial), "Scanned 192.168.142.20: 3 open ports (22 ssh, 80 http, 443 https); OS guess <nmap\'s guess>; nothing changed since the previous check" (a device check: its open ports; the OS it recorded only when it is the OS the device page shows now, "OS guess <x>" for nmap\'s fingerprint, "OS <x>" for the device\'s own answer, "OS guess now <x> (changed since the previous check)"; otherwise "OS: scan guess not used now", never a second OS value; "since the previous check: port 8080 newly open, port 23 no longer open"), "Scanned 192.168.142.20: it did not answer", "Stopped: <reason>. Swept 64 addresses … before it ended", "Failed: <reason>."'),
})

// Runs: every run of every engine (a LAN sweep, a device check, an SNMP read, the vulnerability checks, an exposure scan and its
// engine steps) as one model, core/run. The Runs tab lists them; /runs/<id> shows one; every "Open the run" link goes there.
const word = z.string().regex(/^[a-z0-9_]{1,40}$/)
export const RunStatus = z.enum(RUN_STATUSES).describe('queued: waits for its lane (another run of the same engine runs); waiting: paused with work left until what waiting_for names; running; stopping: a stop was asked and the work is ending; done; partial: ended with part of the work done; failed; stopped: by a person, by its module turned off, or by a restart (stop_reason says which)')
export const RunTrigger = z.enum(['manual', 'schedule', 'event']).describe('manual: a person asked; schedule: a schedule came due; event: something the box saw (a new device, a finished sweep)')
export const RunSubject = z.object({
  kind: word.describe('device | target | scope (open)'),
  id: z.string().describe('Its id in its module: a device id links to the device page, a target id to the exposure target'),
  label: z.string().describe('Its name when the run was made; kept when the subject is gone'),
})
export const Run = z.object({
  id: z.string(),
  module: z.string().describe('The module whose engine does the work'),
  kind: word.describe('lan_sweep | device_check | snmp_read | all_ports | vuln_check | exposure_scan | … (open)'),
  lane: word.describe('What it occupies: one run at a time per lane (nmap, nuclei, exposure, openvas, …)'),
  title: z.string().describe('What it does, e.g. "LAN sweep of 192.0.2.0/24, 10.20.0.0/16"'),
  trigger: RunTrigger,
  trigger_note: z.string().nullable().describe('Words on the trigger, e.g. "a new device appeared"'),
  requested_by: z.string().describe('Who asked (an email), or system'),
  schedule_id: z.string().nullable().describe('The schedule that came due, with trigger schedule'),
  subject: RunSubject.nullable().describe('What the run is about; null for a run over several devices without one subject'),
  parent_id: z.string().nullable().describe('The run this one is a step of (an engine step of an exposure scan)'),
  status: RunStatus,
  waiting_for: z.string().nullable().describe('Set only while waiting, e.g. "the scan window (opens 23:00)"'),
  stop_reason: z.string().nullable().describe('Why it stopped, e.g. "Stopped by ann@example.com", "Vedette restarted"'),
  error: z.string().nullable().describe('What went wrong, with failed or partial'),
  total: z.number().int().min(0).describe('Units of work (addresses, devices, templates): the sum over its steps; 0 when it does not count them'),
  done: z.number().int().min(0),
  queued_at: iso, started_at: iso.nullable().describe('The first start; null while it never ran'), ended_at: iso.nullable().describe('Set exactly when the state is final'), updated_at: iso,
  can_stop: z.boolean().describe('Queued, waiting or running, and the person asking may stop it (an operator)'),
  can_resume: z.boolean().describe('Waiting, or stopped with work left when its engine can go on from its steps, and the person asking may resume it (an operator; an administrator for a kind whose start is an administrator\'s, a LAN sweep)'),
  summary: z.string().describe('The state in one line of words, made by the box: "Queued behind “LAN sweep of 10.0.0.0/16”; it starts when that run ends", "Waiting for the scan window (opens 23 Nov 2026, 23:00); 6,272 of 65,792 addresses; about 9 more nights at 50 packets/s", "Stopped: Vedette restarted", "Done: 254 of 254 addresses". Pages show it as it is'),
  blocked_by: z.object({ id: z.string(), title: z.string() }).nullable().describe('With queued: the run that holds the lane it waits for; null otherwise'),
})
export const RunStep = z.object({
  seq: z.number().int().min(1), name: z.string().describe('A phase or a range: "192.0.2.0/24", "identify services", "ZAP passive scan"'),
  status: RunStatus, total: z.number().int().min(0), done: z.number().int().min(0),
  note: z.string().nullable(), started_at: iso.nullable(), ended_at: iso.nullable(),
})
export const RunItem = z.object({
  seq: z.number().int().min(1),
  subject_kind: word.describe('device | host | target (open)'),
  subject_id: z.string().nullable().describe('A device id for a link; null for an address no device has yet'),
  label: z.string(), outcome: word.describe('found | new | checked | unreachable | failed | skipped (open)'), note: z.string().nullable(),
})
export const RunLogLine = z.object({ ts: iso, level: z.enum(['info', 'warn', 'error']), text: z.string() })
export const RunDetail = Run.extend({
  steps: z.array(RunStep).describe('In order; a resumed run continues from the first that is not done'),
  items: z.array(RunItem).max(500).describe('The devices or hosts it touched, in the order they came, the first 500'),
  items_total: z.number().int().min(0),
  log: z.array(RunLogLine).max(200).describe('The newest 200 lines, oldest first (a run keeps 2,000 lines for 30 days)'),
  children: z.array(Run).describe('The runs that are steps of this one'),
})
export const RunList = z.object({
  items: z.array(Run).max(200).describe('Newest first'),
  total: z.number().int().min(0).describe('Runs that match the filters, every page'),
})
const runParam = z.object({ id: z.string().max(96) })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/runs', summary: 'Every run of every engine, newest first: LAN sweeps, device checks, SNMP reads, vulnerability checks, exposure scans and their engine steps. Filtered by module, kind, state and subject (a device\'s runs: subject_kind=device and subject_id); searched over the title, the subject\'s name, who asked and the id; paged by offset and limit (at most 200). A run is kept 400 days after it ended', stories: ['S-SCAN-4'], role: 'viewer',
    query: z.object({
      module: z.string().max(32).optional(), kind: z.string().max(40).optional(), status: RunStatus.optional(),
      subject_kind: z.string().max(40).optional(), subject_id: z.string().max(96).optional(),
      q: z.string().max(200).optional(),
      offset: z.string().regex(/^[0-9]{1,6}$/).optional().describe('Rows to skip, default 0'),
      limit: z.string().regex(/^[0-9]{1,3}$/).optional().describe('Rows of the page, 1 to 200 (default and above: 200)'),
    }),
    response: RunList, example: { query: { q: '', offset: '0', limit: '25' } } },
  { method: 'get', path: '/runs/{id}', summary: 'One run: who or what started it and what it is about, its state with the reason when it waits or stopped, its progress per step, the devices it touched, the tail of its log and the runs under it. 404 not_found', stories: ['S-SCAN-4'], role: 'viewer', params: runParam, response: RunDetail, example: { params: { id: 'run-m1' } } },
  { method: 'post', path: '/runs/{id}/stop', summary: 'Stop a run and the runs under it: a queued or waiting run stops at once, a running one is stopping until its work ends. Audited (scanning.run_stop). Answers the run as it is now; a run already stopping answers as it is. 404 not_found; 409 not_running (it has already ended)', stories: ['S-SCAN-4'], role: 'operator', params: runParam, response: Run },
  { method: 'post', path: '/runs/{id}/resume', summary: 'Resume a run that waits, or one that was stopped with work left when its engine can go on from its steps (can_resume): it is queued again and continues from the first step that is not done. A run whose start needs an administrator (a LAN sweep) needs one to resume (403 forbidden otherwise). Audited (scanning.run_resume). Answers the run as it is now. 404 not_found; 409 not_resumable', stories: ['S-SCAN-4'], role: 'operator', params: runParam, response: Run },
  { method: 'get', path: '/scanning/history', summary: 'Every run of the LAN engines (discovery sweeps, device identifications, SNMP reads) and every stored scan of a public target, newest first, at most 200, with its outcome in words. The vulnerability checks keep their own list (GET /scans/runs). Answers whether or not the Vulnerability scans module is on', stories: ['S-SCAN-4', 'S-INV-1'], role: 'viewer', query: z.object({ asset: z.string().max(96).optional().describe('A device id (the device page\'s Last checks): only that device\'s runs, at most 200 of each kind: its identifications (kind device: the checks that name it, and checks stored before checks named their device that reached its address now), from the year of runs the box keeps; and, only while SNMP is set up on it, the SNMP reads of its SNMP read address, among the newest 1000 reads (a read of its address with a shared credential, before SNMP moved to each device, is not its own when it has no SNMP set up). No sweep, no public scan. An unknown device gives an empty list') }), response: z.object({ items: z.array(HistoryRun) }) },
  { method: 'get', path: '/scanning', summary: 'Every scanning engine with its switch, state, memory cost, last and next run, the jobs running now, and the shared safety settings (scope, window, speed, exclusions, fragile types)', stories: ['S-SCAN-4', 'S-CORE-1', 'S-INV-1'], role: 'viewer', response: Scanning },
  { method: 'put', path: '/scanning/safety', summary: 'Save the shared safety settings every LAN engine obeys (one writer; GET/PUT /inventory/settings and the window, rate and exclusions of /scans/config read and write the same values). 400 as PUT /inventory/settings: too_many_ranges, no_prefix, bad_cidr, public_range, overlap_range, bad_days, no_days, bad_time, bad_window, bad_rate (packets_per_s 1 to 1000, requests_per_s 1 to 20), bad_exclusion, too_many_exclusions, bad_kinds, scope_not_confirmed (while nmap-discovery is on), scope_too_large (one pass would not end within a week of windows: the message gives the numbers, see POST /scanning/safety/estimate); 409 safety_changed (with error.safety, the current block) when version is not the stored one: re-read, merge, save again. Publishes inventory.settings.changed: a run that the new values no longer allow stops', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: SafetyInput, response: SafetySaved },
  { method: 'post', path: '/scanning/safety/estimate', summary: 'What one pass of active discovery over a scope would cost, before it is saved (the range form shows it as it is typed): the addresses, the time of one pass at the rate, and whether it fits one window and a week of windows. Saving a scope that does not fit a week is refused (400 scope_too_large on PUT /scanning/safety and POST /scanning/safety/ranges); one that needs several windows is swept as one run over several nights. Changes nothing', stories: ['S-SCAN-4', 'S-INV-1'], role: 'viewer', body: ScopeCostInput, response: ScopeCost },
  { method: 'post', path: '/scanning/safety/ranges', summary: 'Add one LAN range to the scope where the person is ("+ New range" in a dialog, #842), without sending the whole block: read, append and save in one transaction, so it never overwrites another edit. The dialog lists the current ranges and whether they are confirmed with the confirmation tick, and sends both back (shown_ranges, shown_confirmed_at): the tick confirms those ranges and the new one only. 400 as PUT /scanning/safety for a range: no_prefix, bad_cidr, public_range, overlap_range, too_many_ranges (16), scope_too_large, and scope_not_confirmed when confirm is not true; 409 scope_changed (with error.safety, the current block) when the stored ranges are not shown_ranges or the stored confirmation is not shown_confirmed_at. A range the confirmed scope already covers is 200 with the block unchanged (no audit row). Audited as the PUT (inventory.settings, naming the range, and saying when the add confirmed a scope that was not confirmed) and publishes inventory.settings.changed. Returns the whole safety block with its new version, and adjusted when the range was normalized', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: RangeAdd, response: SafetySaved },
  { method: 'post', path: '/scanning/safety/exclusions', summary: 'Add one exclusion where the person is ("+ New exclusion" in a dialog, #842), without sending the whole block: read, append and save in one transaction. 400 bad_exclusion as PUT /scanning/safety, and too_many_exclusions when the list would grow past 200. An entry an exclusion already covers is 200 with the block unchanged (no audit row). Audited as the PUT (inventory.settings, naming the entry) and publishes inventory.settings.changed: a run that may no longer touch it stops. Returns the whole safety block with its new version', stories: ['S-SCAN-4', 'S-INV-1'], role: 'admin', body: ExclusionAdd, response: Safety },
  { method: 'patch', path: '/scanning/engines/{id}', summary: 'Turn an engine on or off: its module switch (passive, osquery, wazuh, nuclei, honeypot), active discovery (nmap-discovery: on turns sensor-active on first when with_dependencies is set, off never turns the module off) or the OpenVAS flag (openvas). Audited by the switch it moves. 409 not_toggleable (nmap-versions, snmp, zap), missing_dependencies, not_appliance, module_off (openvas while External exposure is off), low_memory, low_disk; 400 no_ranges, no_days, scope_not_confirmed (nmap-discovery on, checked before anything moves), core_module. Returns the whole page, since one switch can change several engines', stories: ['S-CORE-1', 'S-SCAN-4'], role: 'admin', params: engineParam, body: EnginePatch, response: Scanning },
  { method: 'post', path: '/scanning/engines/nmap-discovery/run', summary: 'Scan the LAN now (no targets: a sweep of the whole scope, then the scans of the devices it queued) or check these devices now (targets), whatever the window, for at most one hour (devices not reached by then wait for the window). Audited before anything is sent (scanning.run: the run id and the ranges or devices; no audit row, no run). Runs in the background: the answer is the run, which GET /scanning lists in running[] with its progress until it ends. Works while the Vulnerability scans module is off. 400 unknown_device, out_of_scope (outside the ranges, excluded, or the box), scope_not_confirmed, not_scannable (the device\'s safety rules refuse it); 409 module_off (sensor-active off), engine_off (active discovery off), already_running (a run a person started), busy (discovery is running nmap now), too_soon (a sweep less than 10 minutes ago; retry_after in seconds); 503 scanner_unavailable (nmap is not available)', stories: ['S-INV-1', 'S-SCAN-4'], role: 'admin', body: DiscoveryRunInput, response: RunningJob, status: 202 },
])
