// Hợp đồng API module inventory (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

export const ObsSource = z.enum(['manual', 'agent', 'snmp', 'nmap', 'passive', 'scan'])
export const AssetKind = z.enum(['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown'])
export const ObsField = z.enum(['hostname', 'mac', 'vendor', 'model', 'os', 'kind'])
const dt = z.iso.datetime()
const confidence = z.number().min(0).max(1)

export const Observed = z.object({ value: z.string(), source: ObsSource, confidence, seen_at: dt })
export const Software = z.object({
  id: z.string(), display: z.string().describe('Commercial name the user recognizes'), vendor: z.string(), product: z.string(), version: z.string().nullable(),
  kev: z.array(z.string()).describe('KEV match keys: lowercase "vendorproject|product"'), source: ObsSource, confidence,
})
export const Service = z.object({ port: z.number().int().min(1).max(65535), proto: z.enum(['tcp', 'udp']), name: z.string(), product: z.string().optional(), version: z.string().optional(), source: ObsSource, confidence })
export const Asset = z.object({
  id: z.string(), site: z.string(), ip: z.string().describe('"—" when declared manually and the IP is unknown'), mac: z.string().nullable(), hostname: z.string().nullable(), kind: AssetKind,
  vendor: Observed.nullable(), model: Observed.nullable(), os: Observed.nullable(), software: z.array(Software), services: z.array(Service),
  first_seen: dt, last_seen: dt, approved: z.boolean(), fragile: z.boolean(), origin: z.enum(['discovered', 'manual']), notes: z.string().optional(),
})

/** Một lần quan sát một trường. Không bao giờ bị ghi đè: giá trị mới thêm vào, "đang dùng" chọn theo khai tay > tin cậy cao > mới hơn (ARCHITECTURE §4). */
export const Observation = z.object({ id: z.string(), field: ObsField, value: z.string(), source: ObsSource, confidence, seen_at: dt, current: z.boolean() })

export const RegularScan = z.enum(['follow', 'allow', 'never']).describe('Per-device override of the type setting for regular scans after the one gentle scan (D-45); never = never actively scanned again, for every kind of device (D-74)')
/** D-45, D-84: a fragile device, or one of unknown kind, gets ONE gentle scan when first seen (lowest speed, no service/OS detection), then it is passive-only until classified or allowed; regular_scan=never means never for every kind; discovery never scans the box itself (only a person's pick in Scan now does, D-470). */
const ScanInfo = z.object({
  is_box: z.boolean().describe('true for the Vedette box itself: the first device, always present, cannot be deleted (409)'),
  first_scan_at: dt.nullable().describe('When the one gentle first scan happened; null = no gentle scan (declared by hand, the box itself, or a known kind that is not fragile and not set to never)'),
  regular_scan: RegularScan,
  approved_at: dt.nullable().describe('When a person approved the device, or osquery enrolment did (D-471: "Approved in the last 24 h"); approving again does not move it; null = not approved, added by hand, or approved before this field existed'),
})
export const DeviceRow = Asset.extend(ScanInfo.shape).extend({
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  summary: z.object({ source: ObsSource, confidence }).nullable().describe('Source of the most trusted value; confidence is that of the weakest value'),
})
export const DevicesResponse = z.object({
  items: z.array(DeviceRow),
  counts: z.object({ all: z.number().int(), pending: z.number().int(), fragile: z.number().int(), manual: z.number().int() }),
  notify_new: z.boolean(),
  notify_available: z.boolean().describe('false when the notify module is off'),
})
export const SoftwareView = Software.omit({ kev: true }).extend({ kev_cves: z.array(z.string()) })
export const DeviceDetail = z.object({
  asset: Asset.omit({ software: true }).extend(ScanInfo.shape).extend({ software: z.array(SoftwareView) }),
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  observations: z.array(Observation),
  kinds: z.array(AssetKind),
})
export const CatalogItem = z.object({
  id: z.string().describe('Stable: curated entries have fixed ids, entries from CISA KEV have id "kev:<vendor>:<product>"'), display: z.string().describe('Name the user recognizes'), hint: z.string(),
  category: z.string(), vendor: z.string(), product: z.string(), kind: AssetKind, version_hint: z.string(),
  kev_cves: z.number().int().describe('Number of the product vulnerabilities ever exploited in the wild (CISA KEV)'),
})
export const CatalogResponse = z.object({ items: z.array(CatalogItem), total: z.number().int().describe('Number of matching results; items returns at most 30') })

export const AddDeviceInput = z.object({
  catalog_id: z.string().optional().describe('Product from the catalog; leave blank when entering vendor + product manually'),
  vendor: z.string().max(64).optional().describe('Entered manually when the product is not found; matched by vendor'), product: z.string().max(64).optional(),
  version: z.string().max(40).optional().describe('Letters, digits, . - + ( ) and spaces'),
  name: z.string().max(64).optional().describe('Must not contain < >'), ip: z.string().optional().describe('IPv4; 409 if the IP already exists'),
})
export const AddDeviceResult = z.object({ id: z.string(), display: z.string(), kev_cves: z.number().int() })
export const ImportInput = z.object({ filename: z.string(), size: z.number().int(), sha256: z.string(), text: z.string().describe('UTF-8 CSV content, at most 200 KB and 500 rows') })
export const ImportResult = z.object({ created: z.number().int(), skipped: z.number().int(), errors: z.array(z.object({ line: z.number().int(), message: z.string() })), notes: z.array(z.object({ line: z.number().int(), message: z.string() })).describe('Rows that were added but need a word: a public IP, or an IP outside the saved network ranges') })

export const ActiveWindow = z.object({
  enabled: z.boolean(), days: z.array(z.number().int().min(1).max(7)).describe('1 = Monday … 7 = Sunday'),
  from: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), to: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).describe('Earlier than "from" means it crosses midnight'),
  rate: z.number().int().min(1).max(1000).describe('Packets per second'), exclusions: z.array(z.string()).describe('IPv4 or CIDR'),
})
export const InventorySettings = z.object({
  lan_ranges: z.array(z.string()).max(16).describe('Internal IPv4 CIDR (RFC 1918, or the RFC 6598 shared address space 100.64.0.0/10, D-461)'), active: ActiveWindow, fragile_kinds: z.array(AssetKind).describe('Device types scanned only once, gently, when first seen; passive-only after that'),
  regular_scan_kinds: z.array(AssetKind).describe('Subset of fragile_kinds for which the owner allowed regular scans'),
  scope_confirmed_at: dt.nullable(), scope_confirmed_by: z.string().nullable(),
})
export const SettingsInput = InventorySettings.extend({ scope_confirmed: z.boolean().describe('Attestation: the ranges belong to the company and scanning them is permitted') })
export const SettingsSaved = InventorySettings.extend({
  adjusted: z.array(z.object({ from: z.string(), to: z.string() })).describe('Ranges normalized on save, e.g. 192.168.18.0 → 192.168.18.0/24'),
})

export const SensorStatus = z.enum(['online', 'offline', 'never_connected', 'starting']).describe('online: a heartbeat in the last 90 s; offline: it reported before, then nothing for 90 s; never_connected: no heartbeat ever (D-387); starting: not online while the box is still starting the sensor container (an appliance after setup or after the module is turned on: the start is being retried, for up to 10 minutes, or was confirmed less than 3 minutes ago; walk 2, W2-6). A container-only install never says starting: the customer starts it')
/** Chỉ cảm biến của chính hộp này (chưa hỗ trợ nhiều site). */
export const Sensor = z.object({
  id: z.string(), name: z.string(), interface: z.string().nullable().describe('The port the sensor listens on: the card chosen (the SPAN port when SPAN is on), else the default card, the management port (D-380); null: none. Set in Settings → Box network; on a container-only install with PATCH /inventory/sensors/{id} (D-387, D-393)'), interfaces: z.array(z.string()).describe('The cards the sensor reported in its last heartbeat'), span: z.boolean(),
  chosen: z.boolean().describe('true: interface is a stored choice (the SPAN port of Settings → Box network, or the card chosen with PATCH on a container-only install); false: interface is the default card (D-380) or null (D-393)'),
  span_status: z.object({ verdict: z.enum(['off', 'ok', 'own_only', 'no_traffic', 'no_link']), packets_per_s: z.number().int(), other_macs: z.number().int() }).describe('Live mirrored-traffic health, the same as Settings → Box network'),
  status: SensorStatus, last_seen: dt.nullable(), version: z.string().nullable(), devices_seen: z.number().int(),
  capture_error: z.enum(['no_permission', 'no_interface', 'filters_invalid', 'capture_failed']).nullable().describe('Why the sensor, online, does not capture on its card (from its heartbeat, D-399): no_permission = no CAP_NET_RAW (rootless container), no_interface = the card is not on that machine, filters_invalid = the capture filters cannot be read, capture_failed = anything else (the sensor log says what); null while it captures, has no card, or is not online'),
})
export const SensorsResponse = z.object({ sensors: z.array(Sensor) })
export const SensorPatch = z.object({
  interface: z.string().max(15).nullable().describe('A card of the sensor\'s last heartbeat (younger than 90 s); null: no card chosen, the sensor listens on the default one (D-380)'),
  span: z.boolean().describe('The card receives mirrored traffic; it must have no IPv4 address. true needs an interface'),
})

/** Chỉ osquery dùng token (Vedette là máy chủ TLS của osquery). Wazuh là kết nối kéo qua API (WazuhConnection), không có token. Không hỗ trợ Trivy (D-33). */
export const AgentKind = z.enum(['osquery'])
export const AgentToken = z.object({
  id: z.string(), name: z.string(), kind: AgentKind, last4: z.string(), created_at: dt, last_received: dt.nullable(), hosts: z.number().int(),
  expires_at: dt.nullable().describe('null = never expires; default 7 days. The token only enrolls osquery (it can read nothing) and can be revoked'),
})
const Installer = z.object({ url: z.string(), sha256: z.string().describe('SHA-256 (lowercase hex) of the script served by the box; users compare it before running'), script: z.string().describe('Full script text, for the admin to read first') })
export const OsqueryPackage = z.object({
  file: z.string().describe('File name; the browser downloads it from /api/v1/install/osquery/{file} (D-404)'),
  platform: z.enum(['linux', 'windows']), format: z.enum(['deb', 'rpm', 'msi']), arch: z.enum(['x86_64', 'arm64']),
  size: z.number().int().describe('Bytes'),
  sha256: z.string().describe("SHA-256 (lowercase hex) from the box's SHA256SUMS, which the core build writes from deploy/osquery/PINS"),
})
export const Installers = z.object({
  osquery_version: z.string(), linux: Installer, windows: Installer,
  packages: z.array(OsqueryPackage).describe('The osquery packages this box serves (D-404); empty when it has no copy (a development build without the mirror)'),
})
export const OsqueryStatusBody = z.object({ host_identifier: z.string().max(200).optional().describe('The name this machine enrols under (the install script sets osquery host_identifier = specified and sends the same name here); the install script sends it so the answer is about THIS machine') })
export const OsqueryStatus = z.object({
  enrolled: z.boolean(), hosts: z.number().int(),
  host_last_seen: z.string().nullable().optional().describe('Only when host_identifier was sent: when the box last heard from the machine of this token with that name (a hostname match ignores case), null when no machine of the token has enrolled under it; absent when no usable host_identifier was sent. It tells nothing about machines of other tokens'),
})
// osquery TLS remote API (D-169): machine to machine, called by osqueryd only, never by this GUI. Shapes follow
// https://osquery.readthedocs.io/en/stable/deployment/remote/ . osquery sends more keys than these (host_details, decorations, ...): the loose
// objects accept them and the box ignores what it does not use. Every credential failure is HTTP 200 with node_invalid: true (osquery does not handle HTTP errors).
export const OsqueryEnrollBody = z.looseObject({
  enroll_secret: z.string().max(256).optional().describe('The enrollment token (osquery reads it from enroll_secret_path)'),
  host_identifier: z.string().max(256), host_details: z.looseObject({}).optional(),
})
export const OsqueryEnrollResult = z.object({ node_key: z.string().optional().describe('Returned once, only when enrollment succeeds; osquery sends it with every later call'), node_invalid: z.boolean() })
export const OsqueryNodeBody = z.looseObject({ node_key: z.string().max(128) })
export const OsquerySchedule = z.object({ query: z.string(), interval: z.number().int(), snapshot: z.boolean().optional(), platform: z.string().optional() })
export const OsqueryConfig = z.object({ schedule: z.record(z.string(), OsquerySchedule).optional(), node_invalid: z.boolean().optional() })
export const OsqueryLogBody = z.looseObject({
  node_key: z.string().max(128), log_type: z.enum(['result', 'status']),
  data: z.array(z.looseObject({})).describe('Events: scheduled-query snapshots (result) or osquery own log lines (status, read for size and dropped)'),
})
export const OsqueryAck = z.object({ node_invalid: z.boolean() })
export const WazuhConnection = z.object({
  url: z.string().describe('Wazuh server API address, e.g. https://wazuh-manager:55000'), username: z.string(), password_last4: z.string().describe('Password is stored encrypted; only the last 4 characters'),
  interval_minutes: z.number().int(), status: z.enum(['never', 'connected', 'error']), last_sync: dt.nullable(), agents: z.number().int(), packages: z.number().int(), error: z.string().nullable(),
})
export const WazuhInput = z.object({
  url: z.string().max(200), username: z.string().max(64), password: z.string().max(200).optional().describe('Leave blank when editing to keep the saved password'),
  interval_minutes: z.number().int().describe('5, 15, 60, 360 or 1440'),
})
export const WazuhTestResult = z.object({ ok: z.literal(true), version: z.string(), agents: z.number().int().describe('Number of Wazuh agents the API user can read') })
export const AgentsResponse = z.object({ install: Installers, tokens: z.array(AgentToken), server_url: z.string().describe('https://<box IP>:8443, or https://<VEDETTE_BOX_IP>:8443 when the IP is unknown'), wazuh: WazuhConnection.nullable() })
export const CreateTokenResult = z.object({ token: AgentToken, secret: z.string().describe('Full token, returned only at creation') })
export const SampleResult = z.object({ devices: z.number().int(), software: z.number().int() })

/** SNMP credentials (D-512, S-INV-1): read-only GETs from the scan container to approved devices in the scan scope. Secrets are stored encrypted; the API never returns them, only their last 4 characters. */
export const SnmpVersion = z.enum(['v2c', 'v3']).describe('No SNMPv1 (D-512)')
export const SnmpAuth = z.enum(['sha', 'sha256']).describe('v3 authentication: HMAC-SHA-1 or HMAC-SHA-256 (no MD5)')
export const SnmpPriv = z.enum(['aes128', 'none']).describe('v3 privacy: AES-128 (authPriv) or none (authNoPriv); no DES')
export const SnmpCredential = z.object({
  id: z.string(), name: z.string(), version: SnmpVersion,
  username: z.string().nullable().describe('v3 user name; null for v2c'),
  auth: SnmpAuth.nullable().describe('null for v2c'), priv: SnmpPriv.nullable().describe('null for v2c'),
  secret_last4: z.string().describe('Last 4 characters of the community (v2c) or of the authentication password (v3); empty when it has fewer than 8 characters'),
  priv_last4: z.string().describe('Last 4 characters of the v3 privacy password; empty when there is none or it has fewer than 8 characters'),
  scope: z.array(z.string()).describe('IPv4 addresses and CIDR ranges this credential is sent to (1 to 16): only approved devices of the scan scope inside them'),
  created_at: dt, last_answer_at: dt.nullable().describe('When a device last answered with it (a round in the scan window, or a Test)'),
  answered: z.number().int().describe('Devices that answered with it in its latest round in the scan window; a Test that got an answer makes it at least 1'),
})
export const SnmpCredentialInput = z.object({
  name: z.string().max(64).describe('1 to 64 characters, not < >; unique (case does not matter)'), version: SnmpVersion,
  community: z.string().max(64).optional().describe('v2c: 1 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  username: z.string().max(64).optional().describe('v3: letters, digits and . _ @ -'), auth: SnmpAuth.optional(),
  auth_password: z.string().max(64).optional().describe('v3: 8 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  priv: SnmpPriv.optional().describe('v3; default aes128'),
  priv_password: z.string().max(64).optional().describe('v3 with aes128: 8 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  scope: z.array(z.string()).min(1).max(16).describe('Required: the IPv4 addresses or CIDR ranges of the local network this credential belongs to (400 scope_required when empty). A device someone plugs in later and gets approved never receives it (D-512)'),
})
export const SnmpResponse = z.object({
  credentials: z.array(SnmpCredential).describe('In the order they are tried (oldest first), at most 8'),
  ready: z.boolean().describe('false while the scan container cannot read SNMP (not reporting, or older than this version)'), message: z.string().nullable().describe('Why not ready'),
})
export const SnmpTestReason = z.enum([
  'ok', 'no_answer', 'auth_failed', 'unknown_user', 'error', 'not_in_inventory', 'not_approved', 'out_of_scope', 'not_for_this_credential',
  'scanning_off', 'scope_not_confirmed', 'declared_by_hand', 'box', 'regular_scan_never', 'unavailable', 'busy',
])
export const SnmpAnswer = z.object({
  sys_descr: z.string(), sys_object_id: z.string(), sys_name: z.string().describe('What the device said, cleaned; empty when it has none'),
  vendor: z.string(), product: z.string().describe('Product family from sysObjectID, e.g. FortiGate'), model: z.string(), os: z.string(), kind: z.string().describe('A device type id, or empty'),
  serial: z.string(), firmware: z.string().describe('ENTITY-MIB chassis firmware text; shown, not stored'),
})
export const SnmpTestResult = z.object({
  ok: z.boolean(), reason: SnmpTestReason, message: z.string().describe('Plain words for the person'),
  device_id: z.string().nullable().describe('The inventory device at that IP, when there is one'),
  answer: SnmpAnswer.nullable().describe('What the device said, when it answered; it is also recorded in the inventory with source snmp'),
})

const id = z.object({ id: z.string() })
const ok = z.object({ ok: z.literal(true) })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/inventory/devices', summary: 'List devices with counts per filter', stories: ['S-INV-1', 'S-INV-3'], role: 'viewer', response: DevicesResponse },
  { method: 'post', path: '/inventory/devices', status: 201, summary: 'Declare a device manually using a product from the suggestion list', stories: ['S-INV-2'], role: 'operator', body: AddDeviceInput, response: AddDeviceResult },
  { method: 'get', path: '/inventory/devices/{id}', summary: 'Device details: observations, services, software', stories: ['S-INV-1'], role: 'viewer', params: id, response: DeviceDetail, example: { params: { id: 'a-nas02' } } },
  { method: 'patch', path: '/inventory/devices/{id}', summary: 'Change the type, mark as fragile, override regular scans or edit the notes of a device', stories: ['S-INV-1'], role: 'operator', params: id,
    body: z.object({ kind: AssetKind.optional(), fragile: z.boolean().optional(), regular_scan: RegularScan.optional(), notes: z.string().max(2000).optional() }), response: ok },
  { method: 'delete', path: '/inventory/devices/{id}', summary: 'Delete a device from the inventory, along with its findings (409 for the Vedette box itself, which is always the first device)', stories: ['S-INV-3'], role: 'operator', params: id, response: null },
  { method: 'post', path: '/inventory/devices/{id}/approve', summary: 'Approve a new device', stories: ['S-INV-3'], role: 'operator', params: id, response: ok },
  { method: 'post', path: '/inventory/devices/{id}/suspicious', summary: 'Mark or unmark a device as suspicious', stories: ['S-INV-3'], role: 'operator', params: id, body: z.object({ suspicious: z.boolean() }), response: ok },
  { method: 'post', path: '/inventory/devices/{id}/software', status: 201, summary: 'Declare additional software running on a device', stories: ['S-INV-2'], role: 'operator', params: id,
    body: AddDeviceInput.omit({ name: true, ip: true }), response: z.object({ kev_cves: z.number().int() }) },
  { method: 'patch', path: '/inventory/devices/{id}/software/{sid}', summary: 'Change the version of manually declared software (400 not_manual for software a sensor or agent saw); an empty version removes it; the device is matched again (D-471)', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }),
    body: z.object({ version: z.string().max(40).describe('Letters, digits, . - + ( ) and spaces; empty removes the version') }), response: ok },
  { method: 'delete', path: '/inventory/devices/{id}/software/{sid}', summary: 'Remove manually declared software from a device', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }), response: null },
  { method: 'get', path: '/inventory/catalog', summary: 'Suggest products by vendor or commercial name', stories: ['S-INV-2'], role: 'viewer', query: z.object({ q: z.string().max(80) }), response: CatalogResponse, example: { query: { q: 'forti' } } },
  { method: 'put', path: '/inventory/notify-new', summary: 'Turn alerts for new devices on or off', stories: ['S-INV-3'], role: 'operator', body: z.object({ enabled: z.boolean() }), response: z.object({ enabled: z.boolean() }) },
  { method: 'get', path: '/inventory/export.csv', summary: 'Download the device list as CSV (UTF-8 with BOM, opens in Excel)', stories: ['S-INV-2'], role: 'viewer', response: 'file' },
  { method: 'get', path: '/inventory/import-template.csv', summary: 'Download a sample CSV for importing devices', stories: ['S-INV-2'], role: 'viewer', response: 'file' },
  { method: 'post', path: '/inventory/import', summary: 'Import devices from CSV content; invalid rows are reported by row number, valid rows are still added', stories: ['S-INV-2'], role: 'operator', body: ImportInput, response: ImportResult },
  { method: 'get', path: '/inventory/settings', summary: 'LAN ranges, active scan window, device types scanned only once (and which allow regular scans), scope attestation', stories: ['S-INV-1'], role: 'admin', response: InventorySettings },
  { method: 'put', path: '/inventory/settings', summary: 'Save the scan scope; enabling active scanning requires scope attestation', stories: ['S-INV-1'], role: 'admin', body: SettingsInput, response: SettingsSaved },
  { method: 'get', path: '/inventory/sensors', summary: 'Sensors of this box only (multiple sites not supported yet)', stories: ['S-INV-1'], role: 'admin', response: SensorsResponse },
  { method: 'patch', path: '/inventory/sensors/{id}', summary: 'Container-only install: choose the card the sensor reads (any card of its last heartbeat, with or without an address; null: back to the default card) and whether it is the SPAN card (D-387, D-393). 400 bad_interface: not a reported card, no heartbeat in 90 s, or a SPAN card with an address. 409 set_in_box_network on an appliance, where Settings → Box network sets it', stories: ['S-CORE-8', 'S-INV-1'], role: 'admin', params: id, body: SensorPatch, response: Sensor },
  { method: 'get', path: '/inventory/agents', summary: 'Issued osquery tokens and the Wazuh connection (if any)', stories: ['S-INV-4'], role: 'admin', response: AgentsResponse },
  { method: 'post', path: '/inventory/agents/tokens', status: 201, summary: 'Issue an osquery token, returning the full token once', stories: ['S-INV-4'], role: 'admin', body: z.object({ name: z.string().max(64), kind: AgentKind.optional(), expires_in_days: z.number().int().min(0).max(365).optional().describe('Default 7; 0 = never expires') }), response: CreateTokenResult },
  { method: 'delete', path: '/inventory/agents/tokens/{id}', summary: 'Revoke an osquery token', stories: ['S-INV-4'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/inventory/agents/tokens/{id}/sample-data', summary: 'PREVIEW ONLY (mock): send sample data as if the agent had reported in, to see the effect', stories: ['S-INV-4'], role: 'admin', params: id, response: SampleResult },
  { method: 'get', path: '/install/osquery.sh', summary: 'One-line osquery install script for Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux; x86_64 or arm64), served by the box; public, contains no secrets (the token is passed as a parameter); 404 no_box_address while the box knows no address other machines can reach', stories: ['S-INV-4'], role: 'public', response: 'file' },
  { method: 'get', path: '/install/osquery.ps1', summary: 'osquery install script for Windows Server, served by the box; public, contains no secrets; 404 no_box_address while the box knows no address other machines can reach', stories: ['S-INV-4'], role: 'public', response: 'file' },
  { method: 'post', path: '/intake/osquery/status', summary: 'The install script asks "has THIS machine enrolled yet" (body: its host_identifier; empty body = token-wide counts only); token goes in the Authorization: Bearer header, never in the URL', stories: ['S-INV-4'], role: 'public', body: OsqueryStatusBody, bodyOptional: true, response: OsqueryStatus },
  { method: 'post', path: '/intake/osquery/enroll', summary: 'osquery enrollment (machine to machine): exchanges a valid enrollment token for a node key; node_invalid: true when the token is unknown, revoked or expired', stories: ['S-INV-4'], role: 'public', body: OsqueryEnrollBody, response: OsqueryEnrollResult },
  { method: 'post', path: '/intake/osquery/config', summary: 'osquery config (machine to machine): the read-only snapshot schedule for an enrolled node; node_invalid: true makes osquery enroll again', stories: ['S-INV-4'], role: 'public', body: OsqueryNodeBody, response: OsqueryConfig },
  { method: 'post', path: '/intake/osquery/log', summary: 'osquery logger (machine to machine): results of the scheduled queries from an enrolled node; they update the inventory with source agent', stories: ['S-INV-4'], role: 'public', body: OsqueryLogBody, response: OsqueryAck },
  { method: 'get', path: '/intake/ca.pem', summary: 'The certificate osquery pins to trust this box (PEM, public, no secret); the install script embeds the same text', stories: ['S-INV-4'], role: 'public', response: 'file', fileType: 'application/x-pem-file' },
  { method: 'get', path: '/install/osquery/{file}', summary: 'The official osquery packages and SHA256SUMS the box ships (osquery_<v>-1.linux_amd64.deb, osquery-<v>-1.linux.x86_64.rpm, osquery_<v>-1.linux_arm64.deb, osquery-<v>-1.linux.aarch64.rpm, osquery-<v>.msi), so servers need no Internet; public, no secret, any other name is 404', stories: ['S-INV-4'], role: 'public', params: z.object({ file: z.string() }), response: 'file', example: { params: { file: 'SHA256SUMS' } } },
  { method: 'put', path: '/inventory/agents/wazuh', summary: 'Connect (or edit) a Wazuh server: verify the API login, then save; the password is stored encrypted', stories: ['S-INV-4'], role: 'admin', body: WazuhInput, response: WazuhConnection },
  { method: 'post', path: '/inventory/agents/wazuh/test', summary: 'Test the connection to the Wazuh API with the form values, without saving', stories: ['S-INV-4'], role: 'admin', body: WazuhInput, response: WazuhTestResult },
  { method: 'delete', path: '/inventory/agents/wazuh', summary: 'Disconnect Wazuh and delete the saved password', stories: ['S-INV-4'], role: 'admin', response: null },
  { method: 'post', path: '/inventory/agents/wazuh/sample-data', summary: 'PREVIEW ONLY (mock): sync sample data as if just pulled from Wazuh', stories: ['S-INV-4'], role: 'admin', response: SampleResult },
  { method: 'get', path: '/inventory/snmp', summary: 'SNMP credentials (secrets only as their last 4 characters) and whether the scan container can read SNMP now (D-512)', stories: ['S-INV-1'], role: 'admin', response: SnmpResponse },
  { method: 'post', path: '/inventory/snmp', status: 201, summary: 'Add an SNMP credential (v2c community or v3 user); its secrets are stored encrypted. 409 name_taken, 409 too_many (8 at most)', stories: ['S-INV-1'], role: 'admin', body: SnmpCredentialInput, response: SnmpCredential },
  { method: 'put', path: '/inventory/snmp/{id}', summary: 'Edit an SNMP credential; a blank secret keeps the saved one', stories: ['S-INV-1'], role: 'admin', params: id, body: SnmpCredentialInput, response: SnmpCredential },
  { method: 'delete', path: '/inventory/snmp/{id}', summary: 'Delete an SNMP credential and its secrets; what devices said stays in the inventory', stories: ['S-INV-1'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/inventory/snmp/{id}/test', summary: 'Read one device with this credential now (read-only GETs from the scan container, logged in the probe log) and say what it answered, or why not; an answer is recorded in the inventory', stories: ['S-INV-1'], role: 'admin', params: id,
    body: z.object({ ip: z.string().max(15).describe('IPv4 of a device in the inventory') }), response: SnmpTestResult },
])
