// API contract of intrusion detection: the alerts of the ids module (an IPS or IDS event a firewall wrote in a log line it
// sent to the box; other sources add values to `source` without a schema change) and the overview of everything that
// watches the network (traps, logs, the mirror port, IPS events). UI types are inferred from here (types.ts), so the UI,
// the mock and the OpenAPI file cannot drift.
//
// Owners on the box: GET /detection/overview is core's, so it answers while any detection module is off (it reports that
// module as off); /detection/alerts belongs to the ids module (404 while that module is off).
//
// Handling: an alert has no handling state of its own. Repeats of one rule or CVE from one source address are one incident
// of kind intrusion, handled on the incident (PATCH /notify/incidents/{id}); a CVE the alert names that affects the
// attacked device is a finding, handled on the finding. The alert shows both states with the shared vocabularies.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { FINDING_STATUSES, INCIDENT_STATUSES } from '@/lib/statusCodes'

const iso = z.iso.datetime()
const ip = z.string().max(45).describe('IPv4 or IPv6 address as the event names it')
const cve = z.string().regex(/^CVE-\d{4}-\d{4,}$/)

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export const FindingStatus = z.enum(FINDING_STATUSES)
export const IncidentStatus = z.enum(INCIDENT_STATUSES)
export const DeviceRef = z.object({ id: z.string(), name: z.string() })

// ---- alerts ----

export const AlertSource = z.string().regex(/^[a-z0-9_]{1,40}$/)
  .describe('Where the box saw the event. Open vocabulary: log = an IPS or IDS event in a log line a firewall sent to the box (FortiGate IPS, Suricata or Snort on pfSense/OPNsense, other device profiles). New sources add values')

export const LinkedFinding = z.object({
  id: z.string(),
  cve,
  device: DeviceRef,
  status: FindingStatus.describe('The finding\'s one status (under_attack while it is open and this attack is recent)'),
}).describe('A finding of the attacked device for a CVE the alert names: this device is affected by what was fired at it')

export const AlertIncident = z.object({
  id: z.string().describe('The incident of kind intrusion that groups this alert; handle it with PATCH /notify/incidents/{id}'),
  status: IncidentStatus,
})

export const Alert = z.object({
  id: z.string(),
  source: AlertSource,
  sid: z.number().int().min(0).nullable().describe('The rule or signature number the event gives; null when it gives none'),
  signature: z.string().max(300).describe('The rule or signature name as the event wrote it'),
  category: z.string().max(120).describe('The rule\'s class as the event wrote it (for example "Attempted Administrator Privilege Gain"); empty when it gives none'),
  priority: z.number().int().min(1).max(4).describe('1 = most urgent, as the rule ranks it (Suricata priority; FortiGate critical/high/medium/low map to 1..4)'),
  severity: Severity.describe('From the priority, raised to critical when the attacked device is affected by a CVE the alert names'),
  src_ip: ip,
  src_device: DeviceRef.nullable().describe('The inventory device with the source address; null for an address outside the inventory'),
  dst_ip: ip,
  dst_port: z.number().int().min(0).max(65535).nullable().describe('null when the event gives no port (ICMP)'),
  proto: z.string().max(16).describe('Transport as the event wrote it, lower case: tcp, udp, icmp; empty when it gives none'),
  dst_device: DeviceRef.nullable().describe('The inventory device with the destination address: the device that was attacked; null when none has it'),
  cves: z.array(cve).describe('The CVE ids the event names, sorted; empty when it names none'),
  findings: z.array(LinkedFinding).describe('Findings of dst_device for the CVEs in cves; empty when the device is not affected or not in the inventory'),
  first_seen: iso,
  last_seen: iso,
  count: z.number().int().min(1).describe('Events grouped into this alert: one alert per signature, source, destination and hour'),
  incident: AlertIncident.nullable().describe('null when no incident was opened (the notify module is off)'),
})

export const AlertWindow = z.enum(['24h', '7d', '30d'])
export const AlertSort = z.enum(['last', 'count'])
export const AlertsResponse = z.object({
  items: z.array(Alert),
  total: z.number().int().min(0).describe('Alerts that match the filters, every page'),
})

// ---- overview ----

export const WatcherId = z.enum(['traps', 'logs', 'mirror_port', 'ips_events'])
  .describe('traps = decoy services and honey tokens (honeypot); logs = received logs matched against bad-address feeds and checked for anomalies (logs); mirror_port = DNS, TLS SNI, HTTP Host and flow metadata read from a mirror (SPAN) port, matched against bad-address feeds (sensor-passive); ips_events = IPS and IDS events in received firewall logs (ids). Only watchers this box can run are listed')
export const WatcherState = z.enum(['watching', 'quiet', 'failed', 'not_set_up', 'off', 'unavailable'])
  .describe('watching = on and its input arrives; quiet = set up, but its input stopped arriving (a log source silent, no traffic on the mirror port); failed = the box could not start it (a trap the host could not set up); not_set_up = the module is on and nothing feeds it yet (no Trap IP, no log source, no mirror port, no log source of a kind that writes IPS events); off = its module is off; unavailable = this install cannot run it (traps on a container-only install)')
export const WatcherAction = z.enum(['view', 'set_up', 'fix', 'turn_on'])
  .describe('The one action of the row: view = open its page; set_up = add what feeds it; fix = open what stopped; turn_on = turn its module on (Settings, Modules)')

export const Watcher = z.object({
  id: WatcherId,
  module: z.string().regex(/^[a-z0-9-]{1,40}$/).describe('The module that runs it: honeypot, logs, sensor-passive, ids'),
  state: WatcherState,
  detail: z.string().max(300).describe('One plain sentence for the row, for display only (for example "3 of 4 log sources are sending."); logic reads state'),
  last_input_at: iso.nullable().describe('When it last saw something: a trap hit, a log line, a packet on the mirror port, an IPS event; null when never'),
  detections_7d: z.number().int().min(0).describe('What it raised in the last 7 days: trap hits, bad-address hits, log anomalies, alerts'),
  action: WatcherAction.nullable().describe('null when nothing can be done here (unavailable)'),
})

export const DetectionKind = z.enum(['trap', 'bad_address', 'log_anomaly', 'unknown_device', 'intrusion'])
export const KindCount = z.object({
  kind: DetectionKind,
  incidents: z.number().int().min(0).describe('Incidents of this kind with activity in the window'),
  new: z.number().int().min(0).describe('Of those, the ones nobody acknowledged or resolved yet'),
})

export const MirrorHit = z.object({
  ts: iso,
  src_ip: ip,
  device: DeviceRef.nullable().describe('The inventory device with src_ip; null when none has it'),
  dest: z.string().max(253),
  dest_kind: z.enum(['ip', 'domain']),
  seen_via: z.enum(['span_dns', 'span_sni', 'span_http', 'span_flow']),
  feeds: z.array(z.string()).describe('Threat feeds that list the destination'),
})

export const Overview = z.object({
  generated_at: iso,
  window_days: z.literal(7),
  watchers: z.array(Watcher).describe('In display order: traps, logs, mirror_port, ips_events; a watcher this install cannot run is listed as unavailable, an engine the box does not have is never listed'),
  kinds: z.array(KindCount).describe('Every kind, in the order of DetectionKind, zero included'),
  mirror_port_hits: z.object({
    total: z.number().int().min(0).describe('Bad-address hits seen through the mirror port in the window'),
    latest: z.array(MirrorHit).max(5).describe('The newest five; the full list is GET /logs/bad-connections'),
  }),
  alerts: z.object({
    total: z.number().int().min(0).describe('Intrusion alerts with activity in the window; 0 while the ids module is off'),
    affected: z.number().int().min(0).describe('Of those, the alerts whose attacked device is affected by a CVE they name'),
  }),
})

const id = z.object({ id: z.string().max(64) })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/detection/overview', summary: 'Intrusion detection at a glance: what watches the network (traps, logs, mirror port, IPS events in firewall logs), each with its true state and one action; the incidents of the last 7 days by kind; bad-address hits seen through the mirror port; the count of intrusion alerts. Answers while any detection module is off', stories: ['S-IDS-1', 'S-LOG-4', 'S-HP-1', 'S-ALERT-3'], role: 'viewer', response: Overview },
  { method: 'get', path: '/detection/alerts', summary: 'Intrusion alerts: IPS and IDS events the box saw, one row per signature, source, destination and hour, with the CVE ids they name, the attacked device\'s findings for those CVEs and the incident that groups them. Searched by the box over the signature, category, addresses, device names and CVE ids; filtered by device (source or destination) and CVE; ordered by the newest last event (sort=last) or the most events (sort=count), ties by id; paged by offset and limit (at most 200). 400 bad_window, invalid_cve', stories: ['S-IDS-1'], role: 'viewer',
    query: z.object({
      window: AlertWindow,
      q: z.string().max(200).optional(),
      device: z.string().max(64).optional().describe('A device id: alerts where it is the source or the destination'),
      cve: z.string().max(32).optional().describe('Alerts that name this CVE'),
      sort: AlertSort.optional().describe('Default last'),
      offset: z.string().regex(/^[0-9]{1,6}$/).optional().describe('Rows to skip, default 0'),
      limit: z.string().regex(/^[0-9]{1,3}$/).optional().describe('Rows of the page, 1 to 200 (default and above: 200)'),
    }),
    response: AlertsResponse, example: { query: { window: '7d', q: '', sort: 'last', offset: '0', limit: '25' } } },
  { method: 'get', path: '/detection/alerts/{id}', summary: 'One intrusion alert, as in the list (the link of its incident)', stories: ['S-IDS-1'], role: 'viewer', params: id, response: Alert, example: { params: { id: 'ida-1' } } },
])
