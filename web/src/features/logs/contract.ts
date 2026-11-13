// Hợp đồng API module logs (D-18, D-43, S-LOG-1..4). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { KIND_IDS } from './kinds'

const iso = z.iso.datetime()
const ipv4 = z.string().regex(/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/)

export const SourceKind = z.enum(KIND_IDS)
export const Proto = z.enum(['udp', 'tcp', 'tls'])
export const SourceState = z.enum(['receiving', 'silent', 'never'])

export const LogSource = z.object({
  id: z.string(),
  kind: SourceKind,
  name: z.string(),
  sender_ip: ipv4,
  asset_id: z.string().nullable().describe('Inventory device with the same IP; null when none'),
  asset_name: z.string().nullable(),
  proto: Proto,
  port: z.number().int().min(1).max(65535),
  last_received: iso.nullable(),
  lines_per_hour: z.number().int().min(0),
  state: SourceState,
  created_at: iso,
  client_cert_sha256: z.string().nullable().describe('TLS sources only: the SHA-256 of the client certificate the device must present (64 lowercase hex characters); null = the sender is known by its IP address alone'),
})
export const SourceInput = z.object({
  kind: SourceKind,
  name: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/),
  sender_ip: ipv4,
  proto: Proto,
  port: z.number().int().min(1).max(65535),
  client_cert_sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional().describe('TLS sources only: pin the device\'s client certificate by its SHA-256; absent or null = no pin'),
})
export const BoxTls = z.object({
  kind: z.enum(['box_ca', 'self_signed', 'issued']).describe('Which certificate `pem` holds: box_ca = the box\'s own certificate authority, which signs the box certificate (a device that trusts it keeps trusting the box through every renewal); self_signed = the box certificate itself; issued = the certificates the owner gave the box, because another authority issued it'),
  issuer: z.string().describe('Issuer of the certificate the box presents on the syslog TLS port'),
  port: z.number().int().min(1).max(65535).describe('The port a device sends syslog over TLS to'),
  fingerprint_sha256: z.string().describe('SHA-256 of the first certificate in `pem`, 64 lowercase hex characters'),
  subject: z.string().describe('Subject of the first certificate in `pem`'),
  not_after: iso.describe('Expiry of the first certificate in `pem`'),
  pem: z.string().describe('What a device must import as trusted, as PEM (public data), for the download'),
})
export const SourcesResponse = z.object({
  box: z.object({ ip: z.string().nullable().describe('Box address on the LAN; null when no LAN range is declared, or when the box has no address in it (a container cannot see the host\'s LAN address)'), hostname: z.string(), lan: z.string().nullable(), iface: z.string(), tls: BoxTls.nullable().optional().describe('The certificate of the syslog TLS port; null or absent when this box serves no TLS (plain HTTP)') }),
  sources: z.array(LogSource),
  retention_days: z.number().int(),
})

// A sender whose syslog the box dropped because no source declares it, or declares it with another protocol (FORBID-5). The address comes
// from the socket, never from the line text; the box keeps 256 such senders in memory, counted since the syslog listener last started,
// and returns the 10 seen most recently. A sender declared now with the protocol it used is left out.
export const UnknownSender = z.object({
  ip: z.string().max(45).describe('The sender address as the socket saw it (IPv4, or IPv6 when the box listens on IPv6)'),
  proto: Proto.describe('How these messages arrived: one item per address and protocol, so a sender that used two protocols is two items'),
  count: z.number().int().min(1).describe('Datagrams and connections dropped since the syslog listener last started'),
  last_seen: iso,
})
export const UnknownSendersResponse = z.object({ items: z.array(UnknownSender).max(10) })

export const NewItem = z.object({ id: z.string(), signature: z.string(), source_id: z.string(), source_name: z.string(), count: z.number().int(), first_seen: iso, sample: z.string() })
export const SpikeItem = z.object({ id: z.string(), signature: z.string(), source_id: z.string(), source_name: z.string(), count: z.number().int(), baseline_per_day: z.number(), sample: z.string() })
// A connection from a LAN device to an address on a threat feed (S-LOG-2, S-LOG-4). Stored in collection logs_ioc_hits as
// { id, ts, asset_id, src_ip, dest, dest_kind, seen_via, feeds, confidence, blocked, listed_as }; the response module reads the stored rows with peek.
// The API row adds asset_name, resolved from the inventory when read.
export const IocHit = z.object({
  id: z.string(), ts: iso,
  asset_id: z.string().nullable().describe('Inventory device with this IP; null when it is not in the inventory'),
  asset_name: z.string().nullable(),
  src_ip: ipv4,
  dest: z.string(),
  dest_kind: z.enum(['ip', 'domain']),
  seen_via: z.string().describe('How the box saw it. SPAN metadata: span_dns | span_sni | span_http | span_flow. Syslog: "syslog:<device name>"'),
  feeds: z.array(z.string()).describe('Threat feeds that list the destination'),
  confidence: z.number().min(0).max(1).describe('0 to 1; response rules only act automatically on high confidence'),
  blocked: z.boolean().describe('The device that sent the log blocked the connection (the line records an attempt, for example a FortiGate deny or a blocked web-filter request); false when the line went through or does not say'),
  listed_as: z.string().nullable().describe('The name a feed lists for itself and all of its subdomains when dest is one of them (hagezi TIF, D-228, D-425): look this name up in Feeds. null when a feed lists dest itself'),
})
export const Digest = z.object({ generated_at: iso, lines_24h: z.number().int(), baseline_days: z.number().int(), history_days: z.number().int().min(0).describe('Whole days of logs so far, at most baseline_days: from the first line of the source heard from the longest. Below baseline_days the digest is still learning what is normal'), new: z.array(NewItem), spikes: z.array(SpikeItem), bad_connections: z.array(IocHit), ioc_matching: z.boolean().describe('false when no connection can be matched: Feeds off, or no switched-on feed lists an indicator (every IOC feed off, or none loaded yet)') })

export const LogEvent = z.object({
  id: z.string(), ts: iso, source_id: z.string(), source_name: z.string(), line: z.string().describe('The line as stored: what search and evidence use'),
  host: z.string().nullable().describe('The sending host the syslog header names (RFC 5424 or 3164); null when it does not say (W1-22, D-485)'),
  app: z.string().nullable().describe('The program the header names (sshd, CRON, …); null when it does not say'),
  message: z.string().describe('The line without its syslog header (no "<38>Nov 13 …"); the whole line when it has none'),
})
export const EventWindow = z.enum(['1h', '24h', '7d'])
export const EventsResponse = z.object({
  events: z.array(LogEvent),
  total: z.number().int().describe('Number of matching rows; events returns at most the 200 newest. With a keyword, the matches found so far (the search walks back from the newest line and stops at 200 matches or when its time is up)'),
  searched_back_to: iso.optional().describe('Present with next_cursor: the search has covered the lines from now back to this time and stopped before the start of the window (200 matches found, or the time budget ran out)'),
  next_cursor: z.string().max(64).nullable().describe('Opaque cursor (API_CONVENTIONS section 4): send it as cursor to search the older lines of the window. null = the whole window was searched'),
})

export const SiemFormat = z.enum(['syslog', 'cef', 'json'])
export const SiemEvent = z.enum(['findings', 'alerts', 'honeypot', 'bad_conn'])
export const SiemConfig = z.object({
  enabled: z.boolean(),
  format: SiemFormat,
  host: z.string(),
  port: z.number().int(),
  proto: Proto,
  url: z.string(),
  secret_last4: z.string().nullable().describe('The signing key is never returned, only its last 4 characters (SYS-4)'),
  events: z.array(SiemEvent),
  last_test: z.object({ at: iso, ok: z.boolean(), detail: z.string() }).nullable(),
})
export const SiemInput = z.object({
  enabled: z.boolean(),
  format: SiemFormat,
  host: z.string(),
  port: z.number().int(),
  proto: Proto,
  url: z.string(),
  events: z.array(SiemEvent).min(1),
  secret: z.string().min(16).optional().describe('Leave blank to keep the saved key'),
})
export const SiemTestResult = z.object({ ok: z.boolean(), at: iso, detail: z.string() })

const id = z.object({ id: z.string() })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/logs/sources', summary: 'Declared log sources, where the box listens, retention period', stories: ['S-LOG-1'], role: 'viewer', response: SourcesResponse },
  { method: 'post', path: '/logs/sources', status: 201, summary: 'Create a log source (device type, sender IP, protocol, port)', stories: ['S-LOG-1'], role: 'admin', body: SourceInput, response: LogSource },
  { method: 'put', path: '/logs/sources/{id}', summary: 'Update a log source', stories: ['S-LOG-1'], role: 'admin', params: id, body: SourceInput, response: LogSource },
  { method: 'delete', path: '/logs/sources/{id}', summary: 'Delete a log source; already received logs are kept until retention expires', stories: ['S-LOG-1'], role: 'admin', params: id, response: null },
  { method: 'get', path: '/logs/unknown-senders', summary: 'Senders whose syslog was dropped because no source declares them (the 10 seen most recently since the listener started)', stories: ['S-LOG-1'], role: 'operator', response: UnknownSendersResponse },
  { method: 'get', path: '/logs/digest', summary: 'Digest: connections to known-bad addresses (from SPAN metadata and syslog), new log types, spikes', stories: ['S-LOG-1', 'S-LOG-2', 'S-LOG-4'], role: 'viewer', response: Digest },
  { method: 'get', path: '/logs/events', summary: 'Search stored log events by time range, source and keyword', stories: ['S-LOG-1'], role: 'viewer',
    query: z.object({ window: EventWindow, source: z.string().optional(), q: z.string().max(200).optional(), cursor: z.string().max(64).optional().describe('The next_cursor of a previous answer: search the lines older than it. Only with q (else 400 bad_cursor)') }), response: EventsResponse, example: { query: { window: '24h', source: '', q: '' } } },
  { method: 'put', path: '/logs/retention', summary: 'Change log retention (7, 30, 90 or 180 days)', stories: ['S-LOG-1'], role: 'admin', body: z.object({ days: z.union([z.literal(7), z.literal(30), z.literal(90), z.literal(180)]) }), response: z.object({ retention_days: z.number().int() }) },
  { method: 'get', path: '/logs/siem', summary: 'SIEM forwarding configuration (without the signing key)', stories: ['S-LOG-3'], role: 'admin', response: SiemConfig },
  { method: 'put', path: '/logs/siem', summary: 'Save SIEM forwarding configuration (syslog, CEF or JSON webhook)', stories: ['S-LOG-3'], role: 'admin', body: SiemInput, response: SiemConfig },
  { method: 'post', path: '/logs/siem/test', summary: 'Send a test record to the saved SIEM', stories: ['S-LOG-3'], role: 'admin', response: SiemTestResult },
])
