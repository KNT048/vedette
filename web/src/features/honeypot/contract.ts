// API contract of module honeypot (D-18, D-50, D-466, S-HP-1, S-HP-2). UI types are inferred from here (types.ts).
// Traps only listen and log, they never hit back (LEGAL §3). Ports of the services OpenCanary supports: SMB 445, RDP 3389, SSH 22, MSSQL 1433, HTTP 80.
// D-466: a Trap IP is a profile (name, IP, vendor MAC prefix, its own services); the host lets each address answer only its own ports.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

export const HpService = z.enum(['smb', 'rdp', 'ssh', 'mssql', 'http'])

export const TrapState = z.enum(['off', 'listening', 'conflict', 'starting', 'stopping', 'failed'])
  .describe('What the box reports, not the switch. conflict = on, but the IP clashes with a device in the inventory or the host refused it. starting = switched on, the box is bringing it up (container start and health check take minutes). stopping = switched off, the host has not confirmed yet. failed = switched on, but the box could not set it up (see problem / reason)')

/** One service across the box: on when at least one enabled Trap IP has it (D-466). */
export const Trap = z.object({
  service: HpService,
  port: z.number().int(),
  enabled: z.boolean().describe('At least one enabled Trap IP has this service'),
  state: TrapState.describe('The best state of the enabled Trap IPs that have this service: listening when one of them listens'),
  trap_ips: z.array(z.string()).describe('Names of the enabled Trap IPs that have this service'),
  hits_7d: z.number().int(),
  last_hit_at: z.iso.datetime().nullable(),
})

export const HpOverview = z.object({
  problem: z.string().nullable().describe('Why switched-on Trap IPs do not listen at all (the host or the container failed), with the host reason when it gave one; null otherwise. Per-address reasons are on each Trap IP'),
  lan: z.string().nullable().describe('Box network range; null on a fresh install with no LAN range declared'),
  box: z.object({ ip: z.string().nullable(), name: z.string() }),
  ignored_7d: z.number().int().describe('Hits from the Vedette scanner itself that were ignored in the last 7 days'),
  trap_ips: z.object({ total: z.number().int(), enabled: z.number().int(), listening: z.number().int(), failing: z.number().int().describe('Enabled Trap IPs in state failed or conflict: they need the user') }),
  smb_name: z.string().nullable().describe('The one NetBIOS name of the box\'s SMB share: the name of the first enabled Trap IP (creation order) that has SMB; null when none has it'),
  http_page: z.enum(['login', 'nas']).nullable().describe('The one HTTP login page of the box: nas when the first enabled Trap IP that has HTTP is a NAS, else login; null when none has HTTP'),
  traps: z.array(Trap),
  summary: z.object({ today: z.number().int(), week: z.number().int(), last_hit_at: z.iso.datetime().nullable(), last_src: z.string().nullable() }),
  updated_at: z.iso.datetime(),
})

export const HitKind = z.enum(['service', 'token', 'scan']).describe('service = a connection to a trap port; token = a honey token was used; scan = a sweep or port scan touched the Trap IPs')

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
  trap_hostname: z.string().describe('Name of the Trap IP that was hit (D-466), or of the token / "Decoy sweep"'),
  asset: z.object({ id: z.string(), kind: z.string(), ip: z.string(), approved: z.boolean() }).nullable(),
  events: z.array(HitEvent),
  window_minutes: z.number().int(),
})

export const TrapPreset = z.enum(['file_server', 'nas', 'printer', 'camera', 'linux', 'database', 'custom'])
  .describe('What the Trap IP looks like; a preset fills services and vendor, which stay editable. custom = services picked by hand')
export const TrapVendor = z.enum(['dell', 'hp', 'vmware', 'hyperv', 'supermicro', 'synology', 'qnap', 'brother', 'canon', 'hikvision', 'dahua', 'axis'])
  .describe('Vendor whose MAC prefix (OUI) the address gets; null = a locally administered MAC derived by the host')

export const TrapIP = z.object({
  id: z.string(),
  name: z.string().describe('Host name of the Trap IP (NetBIOS form, up to 15 characters); the label of its hits'),
  ip: z.string(),
  preset: TrapPreset,
  vendor: TrapVendor.nullable(),
  services: z.array(HpService).describe('The services this address answers on; every other port is closed on it'),
  enabled: z.boolean(),
  state: TrapState.describe('From the host, not the switch: listening only when the container runs and the host holds the address with its ports'),
  reason: z.string().nullable().describe('Why state is failed or conflict, or why an enabled Trap IP is off; also a note when it listens but the host cannot keep its services apart; null otherwise'),
  mac: z.string().nullable().describe('MAC address the box gave this IP, as the host reports it; null until known'),
  created_at: z.iso.datetime(),
})
export const TrapSuggestion = z.object({ preset: TrapPreset, count: z.number().int(), examples: z.array(z.string()) }).describe('A device type that really exists in the inventory, so a Trap IP of that type blends in')
export const TrapIPsResponse = z.object({ items: z.array(TrapIP), suggestions: z.array(TrapSuggestion), spare_ips: z.array(z.string()), spare_checked: z.boolean().describe('false while the inventory has no device in the box network: nothing was compared, so spare_ips are only addresses not seen yet') })
export const TrapIPInput = z.object({ name: z.string(), ip: z.string(), preset: TrapPreset, vendor: TrapVendor.nullable(), services: z.array(HpService) })

export const TokenType = z.enum(['file', 'credential', 'url', 'dns'])
export const Token = z.object({
  id: z.string(), type: TokenType, name: z.string(), value: z.string().describe('File name, user name, URL or hostname to plant'),
  password: z.string().nullable().describe('Only for credential tokens: the decoy password'),
  plant_at: z.string().describe('Where the owner plants it'),
  created_at: z.iso.datetime(), last_triggered_at: z.iso.datetime().nullable(), triggers: z.number().int(),
})
export const TokenInput = z.object({ type: TokenType, name: z.string(), plant_at: z.string(), ext: z.enum(['docx', 'xlsx']).optional() })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/honeypot', summary: 'Trap IP counts, services across the Trap IPs, the box-wide SMB name and HTTP page, hit summary and the excluded scanner', stories: ['S-HP-1'], role: 'viewer', response: HpOverview },
  { method: 'get', path: '/honeypot/hits', summary: 'Trap hits, newest first; filtered by source device when asset is given', stories: ['S-HP-1'], role: 'viewer', query: z.object({ asset: z.string().optional() }), response: z.object({ items: z.array(Hit) }) },
  { method: 'get', path: '/honeypot/hits/{id}', summary: 'One trap hit with the log events in the hour around it', stories: ['S-HP-1'], role: 'viewer', params: z.object({ id: z.string() }), response: HitDetail, example: { params: { id: 'hit-seed-1' } } },
  { method: 'post', path: '/honeypot/test-hit', summary: '"Test trap": creates a hit labelled as a test from the box itself, on the first enabled Trap IP with that service; not counted in statistics, no alert sent', stories: ['S-HP-1'], role: 'operator', body: z.object({ service: HpService }), response: Hit },
  { method: 'get', path: '/honeypot/trap-ips', summary: 'Trap IPs with their state, suggestions from the inventory and addresses not seen yet', stories: ['S-HP-1', 'S-HP-2'], role: 'viewer', response: TrapIPsResponse },
  { method: 'post', path: '/honeypot/trap-ips', status: 201, summary: 'Add a Trap IP: name, address, preset, vendor and services. Rejects an address of a device, of the box or outside the box network, and a name in use', stories: ['S-HP-1', 'S-HP-2'], role: 'admin', body: TrapIPInput, response: TrapIP },
  { method: 'put', path: '/honeypot/trap-ips/{id}', summary: 'Change a Trap IP: name, address, preset, vendor and services, with the same checks as adding one', stories: ['S-HP-1', 'S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), body: TrapIPInput, response: TrapIP },
  { method: 'patch', path: '/honeypot/trap-ips/{id}', summary: 'Turn a Trap IP on or off', stories: ['S-HP-1', 'S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), body: z.object({ enabled: z.boolean() }), response: TrapIP },
  { method: 'delete', path: '/honeypot/trap-ips/{id}', summary: 'Delete a Trap IP; the address stops answering, its hits stay', stories: ['S-HP-1', 'S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/honeypot/test-scan', summary: '"Test scan": a labelled test scan alert from the box across the Trap IPs, not counted, no alert sent', stories: ['S-HP-2'], role: 'operator', response: Hit },
  { method: 'get', path: '/honeypot/tokens', summary: 'Honey tokens with last triggered time', stories: ['S-HP-2'], role: 'viewer', response: z.object({ items: z.array(Token) }) },
  { method: 'post', path: '/honeypot/tokens', status: 201, summary: 'Create a honey token (decoy file, fake credentials, URL or DNS name)', stories: ['S-HP-2'], role: 'admin', body: TokenInput, response: Token },
  { method: 'delete', path: '/honeypot/tokens/{id}', summary: 'Delete a honey token; the planted copy stops alerting', stories: ['S-HP-2'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/honeypot/tokens/{id}/test', summary: '"Test token": a labelled test trigger, not counted, no alert sent', stories: ['S-HP-2'], role: 'operator', params: z.object({ id: z.string() }), response: Hit },
])
