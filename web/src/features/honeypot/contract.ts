// API contract of module honeypot (D-18, D-50, S-HP-1, S-HP-2). UI types are inferred from here (types.ts).
// Traps only listen and log, they never hit back (LEGAL §3). Ports of the services OpenCanary supports: SMB 445, RDP 3389, SSH 22, MSSQL 1433, HTTP 80.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

export const HpService = z.enum(['smb', 'rdp', 'ssh', 'mssql', 'http'])

export const Trap = z.object({
  service: HpService,
  port: z.number().int(),
  enabled: z.boolean(),
  state: z.enum(['off', 'listening', 'conflict']).describe('conflict = on, but the secondary IP clashes with a device in the inventory'),
  since: z.iso.datetime().nullable(),
  hits_7d: z.number().int(),
  last_hit_at: z.iso.datetime().nullable(),
})

export const HpOverview = z.object({
  secondary_ip: z.string().nullable(),
  hostname: z.string(),
  lan: z.string().nullable().describe('Box network range; null on a fresh install with no LAN range declared'),
  box: z.object({ ip: z.string().nullable(), name: z.string() }),
  ignored_7d: z.number().int().describe('Hits from the Vedette scanner itself that were ignored in the last 7 days'),
  conflict_asset: z.object({ id: z.string(), name: z.string() }).nullable(),
  traps: z.array(Trap),
  summary: z.object({ today: z.number().int(), week: z.number().int(), last_hit_at: z.iso.datetime().nullable(), last_src: z.string().nullable() }),
  updated_at: z.iso.datetime(),
})

export const HitKind = z.enum(['service', 'token', 'scan']).describe('service = a connection to a decoy port; token = a honey token was used; scan = a sweep or port scan touched the decoy IPs')

// Stored rows in collection hp_hits also carry source_ip (same value as src_ip) for the response module, which reads them with peek.
export const Hit = z.object({
  id: z.string(),
  ts: z.iso.datetime(),
  kind: HitKind,
  service: HpService.nullable().describe('Set for kind=service on the classic ports; null otherwise'),
  label: z.string().describe('What was touched, e.g. "SMB", "Credential token svc-backup-old", "Port scan across 5 decoy IPs"'),
  port: z.number().int().nullable(),
  src_ip: z.string(),
  src_asset_id: z.string().nullable(),
  src_name: z.string().nullable().describe('Source device name, looked up from the inventory when read; null = not in the inventory'),
  is_test: z.boolean(),
  excerpt: z.string(),
})

export const HitEvent = z.object({ ts: z.iso.datetime(), source: z.enum(['honeypot', 'firewall', 'dhcp', 'ad', 'vedette']), text: z.string(), mark: z.boolean() })

export const HitDetail = Hit.extend({
  trap_ip: z.string(),
  trap_hostname: z.string(),
  asset: z.object({ id: z.string(), kind: z.string(), ip: z.string(), approved: z.boolean() }).nullable(),
  events: z.array(HitEvent),
  window_minutes: z.number().int(),
})

export const Personality = z.enum(['windows_fs', 'nas', 'printer', 'camera', 'linux'])
export const Decoy = z.object({
  id: z.string(), personality: Personality, name: z.string(), ip: z.string(), enabled: z.boolean(), created_at: z.iso.datetime(),
  services: z.array(z.object({ name: z.string(), port: z.number().int() })),
})
export const DecoySuggestion = z.object({ personality: Personality, count: z.number().int(), examples: z.array(z.string()) }).describe('A device type that really exists in the inventory, so a decoy of that type blends in')
export const DecoysResponse = z.object({ items: z.array(Decoy), suggestions: z.array(DecoySuggestion), spare_ips: z.array(z.string()) })
export const DecoyInput = z.object({ personality: Personality, name: z.string(), ip: z.string() })

export const TokenType = z.enum(['file', 'credential', 'url', 'dns'])
export const Token = z.object({
  id: z.string(), type: TokenType, name: z.string(), value: z.string().describe('File name, user name, URL or hostname to plant'),
  password: z.string().nullable().describe('Only for credential tokens: the decoy password'),
  plant_at: z.string().describe('Where the owner plants it'),
  created_at: z.iso.datetime(), last_triggered_at: z.iso.datetime().nullable(), triggers: z.number().int(),
})
export const TokenInput = z.object({ type: TokenType, name: z.string(), plant_at: z.string(), ext: z.enum(['docx', 'xlsx']).optional() })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/honeypot', summary: 'The decoy machine, traps by service, hit summary and the excluded scanner', stories: ['S-HP-1'], role: 'viewer', response: HpOverview },
  { method: 'put', path: '/honeypot/config', summary: 'Set the secondary IP and decoy hostname (rejects an IP that matches a device, the IP of the box itself, or an IP outside the network of the box)', stories: ['S-HP-1'], role: 'admin', body: z.object({ secondary_ip: z.string(), hostname: z.string() }), response: HpOverview },
  { method: 'patch', path: '/honeypot/traps/{service}', summary: 'Turn the trap of one service on or off', stories: ['S-HP-1'], role: 'admin', params: z.object({ service: HpService }), body: z.object({ enabled: z.boolean() }), response: HpOverview },
  { method: 'get', path: '/honeypot/hits', summary: 'Trap hits, newest first; filtered by source device when asset is given', stories: ['S-HP-1'], role: 'viewer', query: z.object({ asset: z.string().optional() }), response: z.object({ items: z.array(Hit) }) },
  { method: 'get', path: '/honeypot/hits/{id}', summary: 'One trap hit with the log events in the hour around it', stories: ['S-HP-1'], role: 'viewer', params: z.object({ id: z.string() }), response: HitDetail, example: { params: { id: 'hit-seed-1' } } },
  { method: 'post', path: '/honeypot/test-hit', summary: '"Test trap": creates a hit labelled as a test from the box itself, not counted in statistics, no alert sent', stories: ['S-HP-1'], role: 'operator', body: z.object({ service: HpService }), response: Hit },
  { method: 'get', path: '/honeypot/decoys', summary: 'Decoy personalities in use, suggestions from the inventory and spare IPs', stories: ['S-HP-2'], role: 'viewer', response: DecoysResponse },
  { method: 'post', path: '/honeypot/decoys', summary: 'Add a decoy with a personality on a spare IP', stories: ['S-HP-2'], role: 'admin', body: DecoyInput, response: Decoy },
  { method: 'patch', path: '/honeypot/decoys/{id}', summary: 'Turn a decoy on or off', stories: ['S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), body: z.object({ enabled: z.boolean() }), response: Decoy },
  { method: 'delete', path: '/honeypot/decoys/{id}', summary: 'Delete a decoy', stories: ['S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/honeypot/test-scan', summary: '"Test scan": a labelled test scan alert from the box across the decoy IPs, not counted, no alert sent', stories: ['S-HP-2'], role: 'operator', response: Hit },
  { method: 'get', path: '/honeypot/tokens', summary: 'Honey tokens with last triggered time', stories: ['S-HP-2'], role: 'viewer', response: z.object({ items: z.array(Token) }) },
  { method: 'post', path: '/honeypot/tokens', summary: 'Create a honey token (decoy file, fake credentials, URL or DNS name)', stories: ['S-HP-2'], role: 'admin', body: TokenInput, response: Token },
  { method: 'delete', path: '/honeypot/tokens/{id}', summary: 'Delete a honey token; the planted copy stops alerting', stories: ['S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/honeypot/tokens/{id}/test', summary: '"Test token": a labelled test trigger, not counted, no alert sent', stories: ['S-HP-2'], role: 'operator', params: z.object({ id: z.string() }), response: Hit },
])
