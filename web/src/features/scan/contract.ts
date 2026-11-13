// Hợp đồng API module scan (D-18). Kiểu UI suy ra từ schema ở đây (types.ts).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()
const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).describe('HH:MM')
const day = z.number().int().min(1).max(7).describe('1 = Monday … 7 = Sunday (D-57)')

export const ScanTarget = z.object({
  id: z.string().describe('device id (a-nas02) or ext:<target id> for a verified external target'),
  kind: z.enum(['internal', 'external']), device_kind: z.enum(['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown']).nullable().describe('Device type in the inventory; null for external targets'), label: z.string(), ip: z.string(),
  fragile: z.boolean().describe('Fragile, or not yet classified (kind unknown): only scanned when picked by hand, at a quarter of the speed (D-126)'), findings: z.number().int(),
  pick_only: z.boolean().describe('Fragile, unclassified or added by hand: scanned only when a person ticks it in Scan now (D-126 (2)). The page never ticks it for you: not by default, not with Select all, not from a link'),
  selectable: z.boolean(), reason: z.enum(['unapproved', 'excluded', 'out_of_scope', 'box', 'regular_scan_never', 'unverified', 'expired', 'not_supported']).nullable()
    .describe('null when the target can be scanned by picking it. box: the Vedette box itself is never scanned. regular_scan_never: a person set "never scan" on the device (D-126). not_supported: external targets are not scanned by this version yet'),
})
export const ScanScope = z.object({ networks: z.array(z.string()), commitment: z.object({ confirmed_at: iso, by: z.string() }).nullable().describe('The scope commitment ticked under Devices, Scope and sensors (inventory scope_confirmed_at)') })
export const ScanConfig = z.object({
  window: z.object({ days: z.array(day).min(1), from: hhmm, to: hhmm }),
  rate: z.number().int().min(1).max(20).describe('requests per second'),
  exclusions: z.array(z.string()).max(200).describe('IP or CIDR'),
  stop_on_unresponsive: z.boolean(),
  unresponsive_after: z.number().int().min(2).max(20),
  auto_rescan: z.boolean(),
  schedule: z.object({ enabled: z.boolean(), frequency: z.enum(['daily', 'weekly']), weekday: day, at: hhmm }),
})
export const ScanConfigPatch = z.object({
  window: ScanConfig.shape.window.partial(), rate: ScanConfig.shape.rate, exclusions: ScanConfig.shape.exclusions,
  stop_on_unresponsive: z.boolean(), unresponsive_after: ScanConfig.shape.unresponsive_after, auto_rescan: z.boolean(),
  schedule: ScanConfig.shape.schedule.partial(),
  dangerous_checks: z.literal(false).describe('Rejected when true: no exploitation, no DoS'),
}).partial()
export const ScanConfigResponse = z.object({
  config: ScanConfig, next_run: iso.nullable(), scope: ScanScope,
  can_scan: z.boolean().describe('false without the scope commitment, or while the scanner in the scan container is not available'), block_reason: z.string().nullable(), dangerous_checks: z.literal(false),
  schedule_blocked_reason: z.string().nullable().describe('Set while the schedule is on but nothing automated can start because the organization time zone cannot be read; next_run is null then (D-261 (3))'),
})

export const RunStatus = z.enum(['running', 'stopping', 'done', 'stopped', 'auto_stopped'])
export const RunResultKind = z.enum(['matched', 'not_matched', 'not_applicable', 'no_template', 'no_response', 'skipped'])
export const RunResultRow = z.object({
  target_id: z.string(), label: z.string(), ip: z.string(), template: z.string().nullable(), result: RunResultKind, finding_id: z.string().nullable(), note: z.string(),
})
export const IdentReason = z.enum(['host_down', 'no_open_ports', 'filtered', 'no_version', 'os_low_confidence', 'gentle_only', 'timed_out', 'busy', 'unavailable', 'declared_by_hand', 'scanning_off', 'not_approved', 'out_of_scope', 'no_ip', 'not_scanned'])
export const RunIdentRow = z.object({
  target_id: z.string(), label: z.string(), ip: z.string(),
  found: z.array(z.string()).max(20).describe('What the identification recorded, in words: "Operating system: …", "Type: …", "Software: …"'),
  reason: IdentReason.nullable().describe('null: software was recorded and compared with the KEV list. Otherwise why nothing was: host_down (no answer), no_open_ports (all closed), filtered (probes dropped), no_version (services gave no product or version), os_low_confidence (OS guess under 85%), gentle_only (fragile: gentle scan only), timed_out, busy (discovery was running nmap), unavailable (nmap not available or Active discovery off), declared_by_hand, scanning_off, not_approved, out_of_scope, no_ip, not_scanned (D-501)'),
  note: z.string().describe("The box's sentence for the reason, shown as is"),
})
export const ScanRun = z.object({
  id: z.string(), trigger: z.enum(['manual', 'schedule', 'new_kev']), trigger_note: z.string().nullable(),
  started_at: iso, started_by: z.string(), ended_at: iso.nullable(), status: RunStatus,
  total: z.number().int(), done: z.number().int(), current: z.object({ label: z.string(), ip: z.string() }).nullable(),
  results: z.array(RunResultRow), matched: z.number().int(), stop_reason: z.string().nullable(),
  identification: z.array(RunIdentRow).describe('One row per device of a Scan now run: what nmap identified first, or exactly why nothing was (D-501). Empty for scheduled scans and KEV rescans, and while the run is going'),
})
export const ProbeEntry = z.object({
  id: z.string(), ts: iso, run_id: z.string().nullable(), ip: z.string(), label: z.string(), template: z.string(), request: z.string(),
  result: z.enum(['matched', 'not_matched', 'no_response', 'banner', 'stopped']).describe('stopped: the request was on its way when the scan was stopped'),
})
export const RescanEvent = z.object({
  id: z.string(), ts: iso, cve: z.string(), product: z.string(), devices: z.array(z.string()), latency_min: z.number().nullable(), run_id: z.string().nullable(),
  result: z.enum(['matched', 'clear', 'skipped_off', 'no_match', 'pick_only', 'stopped', 'expired_no_template', 'expired_scanner', 'expired_zone']).describe('clear: no match reported, never "not affected" (D-133 (5)); pick_only: every device that matches may only be scanned by a hand pick (D-126 (2)), devices names them; stopped: the run stopped before every device was done (D-145 (7)); expired_*: the rescan waited 7 days and was dropped, for no template in the installed pack, the scanner not ready, or the organization time zone unreadable; devices is empty, no run (D-261 (2))'),
})
export const CredTarget = z.object({
  id: z.string(), asset_id: z.string(), label: z.string(), host: z.string(), port: z.number().int(), username: z.string(),
  key_last4: z.string().describe('Last 4 characters only. The private key is stored encrypted on the box (SYS-4) and never shown or returned again (D-57)'), created_at: iso,
  last_test: z.object({ ok: z.boolean(), ts: iso, message: z.string() }).nullable(),
})

export const endpoints = defineEndpoints([
  { method: 'get', path: '/scans/config', summary: 'Scan settings: time window, rate, exclusions, schedule, scope and commitment', stories: ['S-SCAN-1', 'S-SCAN-4'], role: 'viewer', response: ScanConfigResponse },
  { method: 'put', path: '/scans/config', summary: 'Save scan settings (partial update); dangerous checks are always rejected', stories: ['S-SCAN-2', 'S-SCAN-4'], role: 'admin', body: ScanConfigPatch, response: ScanConfigResponse },
  { method: 'get', path: '/scans/targets', summary: 'Scannable targets and why others are not (unapproved device, out of scope, external IP the box has not seen for 30 days)', stories: ['S-SCAN-1'], role: 'viewer', response: z.object({ items: z.array(ScanTarget) }) },
  { method: 'get', path: '/scans/runs', summary: 'Scan history and the running scan, with per-device results', stories: ['S-SCAN-1', 'S-SCAN-3', 'S-SCAN-4'], role: 'viewer', response: z.object({ items: z.array(ScanRun), engine_busy: z.boolean().describe('true while the scanner still works on a run that already shows stopped; a new scan is refused (409 already_running) until it is free (D-261 (4))') }) },
  { method: 'post', path: '/scans/runs', status: 201, summary: 'Scan the chosen targets now (only inside the confirmed scope, with the commitment ticked)', stories: ['S-SCAN-1'], role: 'operator', body: z.object({ targets: z.array(z.string()).min(1).max(200) }), response: ScanRun },
  { method: 'post', path: '/scans/runs/{id}/stop', summary: 'Stop a scan now (takes effect within 5 seconds)', stories: ['S-SCAN-4'], role: 'operator', params: z.object({ id: z.string() }), response: ScanRun },
  { method: 'get', path: '/scans/probes.csv', summary: 'Download the probe log (target, time, template) as CSV', stories: ['S-SCAN-4'], role: 'viewer', response: 'file' },
  { method: 'get', path: '/scans/probes', summary: 'Probe log, kept at least 90 days', stories: ['S-SCAN-4'], role: 'viewer', response: z.object({ items: z.array(ProbeEntry), retention_days: z.number().int() }) },
  { method: 'get', path: '/scans/events', summary: 'Log of automatic rescans when a new KEV entry has a scan template', stories: ['S-SCAN-2'], role: 'viewer', response: z.object({ items: z.array(RescanEvent), auto_rescan: z.boolean() }) },
  { method: 'get', path: '/scans/credentialed', summary: 'Servers scanned with an SSH account, and the state of the scan-credentialed module', stories: ['S-SCAN-5'], role: 'viewer', response: z.object({ items: z.array(CredTarget), enabled: z.boolean() }) },
  { method: 'post', path: '/scans/credentialed', status: 201, summary: 'Add a server for account-based scanning with an SSH private key (stored encrypted on the box, never shown again; only the last 4 characters are displayed)', stories: ['S-SCAN-5'], role: 'admin',
    body: z.object({ asset_id: z.string(), port: z.number().int().min(1).max(65535), username: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/), private_key: z.string().max(16384) }), response: CredTarget },
  { method: 'delete', path: '/scans/credentialed/{id}', summary: 'Remove the scan account of a server', stories: ['S-SCAN-5'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/scans/credentialed/{id}/test', summary: 'Test the SSH connection with the stored key', stories: ['S-SCAN-5'], role: 'operator', params: z.object({ id: z.string() }), response: CredTarget },
])
