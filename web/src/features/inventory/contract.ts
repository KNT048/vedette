// Hợp đồng API module inventory (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { BEHAVIOUR_KINDS, TYPE_IDS } from '@/lib/deviceTypes'

export const ObsSource = z.enum(['manual', 'agent', 'snmp', 'nmap', 'passive', 'scan'])
/** Device type (D-511): one of content/devicetypes/types.json, grouped in categories; the 13 types of before keep their ids. */
export const AssetKind = z.enum(TYPE_IDS).describe('Device type (content/devicetypes/types.json, D-511)')
/** The 13 kinds behaviour is keyed on (fragile defaults, never-touch gateways, …); every device type acts as one of them (D-511). */
export const BehaviourKind = z.enum(BEHAVIOUR_KINDS)
export const ObsField = z.enum(['hostname', 'mac', 'vendor', 'model', 'os', 'kind'])
const dt = z.iso.datetime()
const confidence = z.number().min(0).max(1)

export const Observed = z.object({ value: z.string(), source: ObsSource, confidence, seen_at: dt })
export const Software = z.object({
  id: z.string(), display: z.string().describe('Commercial name the user recognizes'), vendor: z.string(), product: z.string(), version: z.string().nullable(),
  kev: z.array(z.string()).describe('KEV match keys: lowercase "vendorproject|product"'), source: ObsSource, confidence,
})
export const Service = z.object({
  port: z.number().int().min(1).max(65535), proto: z.enum(['tcp', 'udp']), name: z.string(), product: z.string().optional(), version: z.string().optional(),
  detail: z.string().optional().describe('What the service said about the device besides product and version: nmap extra info and device type, page title, certificate subject (D-511). Evidence only, never software'),
  source: ObsSource, confidence,
})
export const KindGuess = z.object({
  kind: AssetKind, confidence, evidence: z.string().describe('What matched and what it most likely means, one sentence'),
  model: z.string().optional().describe('A model a certificate or page title states'),
  alternatives: z.array(AssetKind).optional().describe('Other types the same signals fit, offered next to the guess'),
}).describe('What the identification rules say the device most likely is (D-511), only while kind is unknown; it changes no behaviour until a person sets the kind')
export const Asset = z.object({
  id: z.string(), site: z.string(), ip: z.string().describe('"—" when declared manually and the IP is unknown'), mac: z.string().nullable(),
  hostname: z.string().nullable().describe('The host name the network reports (scan, SNMP, agents, passive), or the name typed when the device was added manually; read-only'),
  name: z.string().nullable().describe('The name a person gave the device in Vedette (G2, PATCH name): it wins over every other name on every page; null = the default name (the naming rule, D-471)'),
  kind: AssetKind,
  kind_source: ObsSource.nullable().describe('Source of the kind; null for the default unknown (D-511)'), guess: KindGuess.nullable(),
  vendor: Observed.nullable(), model: Observed.nullable(), os: Observed.nullable(), software: z.array(Software), services: z.array(Service),
  first_seen: dt, last_seen: dt, approved: z.boolean(), fragile: z.boolean(), origin: z.enum(['discovered', 'manual']), notes: z.string().optional(),
})

/** Một lần quan sát một trường. Không bao giờ bị ghi đè: giá trị mới thêm vào, "đang dùng" chọn theo khai tay > tin cậy cao > mới hơn (ARCHITECTURE §4). */
export const Observation = z.object({ id: z.string(), field: ObsField, value: z.string(), source: ObsSource, confidence, seen_at: dt, current: z.boolean() })

/** D-601: a person turns each active source of the box on or off per device, on its Sources card. */
export const SourceState = z.enum(['on', 'off'])
export const SourcesInput = z.object({ scan: SourceState.optional(), snmp: SourceState.optional() }).describe('At least one; a source left out is left alone')
export const SourcesState = z.object({ scan_source: SourceState, snmp_source: SourceState })
export const RegularScan = z.enum(['follow', 'allow', 'never']).describe('Per-device override of the type setting for regular scans after the one gentle scan (D-45); never = never actively scanned again, for every kind of device (D-74)')
/** D-45, D-84: a fragile device, or one of unknown kind, gets ONE gentle scan when first seen (lowest speed, no service/OS detection), then it is passive-only until classified or allowed; regular_scan=never means never for every kind; discovery never scans the box itself (only a person's pick in Scan now does, D-470). */
const ScanInfo = z.object({
  is_box: z.boolean().describe('true for the Vedette box itself: the first device, always present, cannot be deleted (409)'),
  first_scan_at: dt.nullable().describe('When the one gentle first scan happened; null = no gentle scan (declared by hand, the box itself, or a known kind that is not fragile and not set to never)'),
  regular_scan: RegularScan,
  scan_source: SourceState.describe('D-601: the box\'s network scan of this device (discovery\'s nmap and the vulnerability scans). on: the box\'s own scan settings decide; off: no scan packet goes to it. Default: on for a device a sensor found, off for one added by hand. Off is answered as regular_scan_never by the scan refusals'),
  snmp_source: SourceState.describe('D-601: the box\'s SNMP reads of this device, as scan_source (default on for a device a sensor found, off for one added by hand). Off: no SNMP read goes to it (Test answers snmp_off)'),
  approved_at: dt.nullable().describe('When a person approved the device, or osquery enrolment did (D-471: "Approved in the last 24 h"); approving again does not move it; null = not approved, added by hand, or approved before this field existed'),
  ignored_at: dt.nullable().describe('D-630: when a person ignored the device (a staff phone: known, not watched); null = watched. An ignored device is out of To review, the counts and the Devices list (ignored=true lists them), sends no new-device alert, is not scanned or read over SNMP, its open findings are closed (what a person settled keeps its status) and none are made; a trap hit or an intrusion-detection incident from it still alerts'),
})
/** #849: what feeds a device, in the words of the Devices search (source:…). scan = nmap or a vulnerability scan; osquery and Wazuh are
 * told apart (both are source agent in observations): osquery by the device's agent binding (D-598), Wazuh by its sync. */
export const DeviceSource = z.enum(['manual', 'passive', 'scan', 'snmp', 'osquery', 'wazuh'])
export const DeviceRow = Asset.extend(ScanInfo.shape).extend({
  sources: z.array(DeviceSource).describe('Every source that told Vedette something about the device and is still kept (its details, software or open ports), plus manual for a device added manually, in the order of DeviceSource (#849 source: filter, #829 sources of the device page)'),
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  summary: z.object({ source: ObsSource, confidence }).nullable().describe('Source of the most trusted value; confidence is that of the weakest value'),
})
/** #849: the filters of the Devices search; all optional, ANDed; each list ORs its values. counts stay over the whole inventory. */
export const DevicesQuery = z.object({
  approved: z.enum(['true', 'false']).optional().describe('true: the Devices list (approved); false: To review'),
  ignored: z.enum(['true', 'false']).optional().describe('D-630: true lists only the ignored devices; false or absent leaves them out'),
  type: z.string().max(400).optional().describe('Comma-separated device type ids; a value also matches the types that act as it (D-511: type=server finds a hypervisor). Unknown id: 400 bad_filter'),
  source: z.string().max(200).optional().describe(`Comma-separated: ${DeviceSource.options.join(', ')}. Unknown value: 400 bad_filter`),
  fragile: z.enum(['true', 'false']).optional(),
  has_findings: z.enum(['true', 'false']).optional().describe('true: findings_count > 0'),
  q: z.string().max(80).optional().describe('Free text, case-insensitive, matched in the name (the name in Vedette, the host name, or the product of a device added manually), IP, MAC (any notation: aa:bb, aa-bb, aabb), vendor and model'),
})
export const DevicesResponse = z.object({
  items: z.array(DeviceRow),
  counts: z.object({ all: z.number().int(), pending: z.number().int(), fragile: z.number().int(), manual: z.number().int(), ignored: z.number().int().describe('Ignored devices (D-630); no other count includes them') }),
  notify_new: z.boolean(),
  notify_available: z.boolean().describe('false when the notify module is off'),
})
export const SoftwareView = Software.omit({ kev: true }).extend({ kev_cves: z.array(z.string()) })
/** D-599 (#829, J2): when the inventory cannot be sure two rows are one machine (a phone or laptop with a new private Wi-Fi address and a
 * generic name, an older MAC two rows share), a person decides: "Possibly the same device as X" with Merge and Keep separate. */
export const PossibleSame = z.object({
  id: z.string(), name: z.string().describe('The other device, named as every page names it (D-471)'),
  why: z.string().describe('What the two share, in plain words to show as is, e.g. Same name "iPhone", never online at the same time, and a private Wi-Fi address (phones and laptops change it).'),
  approved: z.boolean(), last_seen: dt,
})
export const SameRef = PossibleSame.omit({ why: true })
export const DeviceDetail = z.object({
  asset: Asset.omit({ software: true }).extend(ScanInfo.shape).extend({ software: z.array(SoftwareView) }),
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  observations: z.array(Observation),
  kinds: z.array(AssetKind),
  possible_same: z.array(PossibleSame).describe('Devices that may be this same machine (D-599), the 5 seen last, the one seen last first; empty for the box and when none. A pair is offered when the rows share a MAC, or a host name or stated model while one uses a private Wi-Fi address; never when a person kept them separate, two agents or two different burned-in MACs say two machines, they state another name, model or OS, or one was seen while the other was'),
})
export const SamePairs = z.object({
  items: z.array(z.object({
    a: SameRef.describe('The approved device when one is, else the one seen first: the one a merge most likely keeps'), b: SameRef, why: PossibleSame.shape.why,
  })).describe('Every pair of devices that may be one machine (D-599), the pair seen last first'),
})
export const MergeInput = z.object({ from: z.string().min(1).max(96).describe('The device that goes into the device of the path') })
export const KeepSeparateInput = z.object({ other: z.string().min(1).max(96).describe('The other device of the pair') })
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
  lan_ranges: z.array(z.string()).max(16).describe('Internal IPv4 CIDR (RFC 1918, or the RFC 6598 shared address space 100.64.0.0/10, D-461)'), active: ActiveWindow, fragile_kinds: z.array(BehaviourKind).describe('Device types scanned only once, gently, when first seen; passive-only after that. Every type acting as one of them counts (D-511)'),
  regular_scan_kinds: z.array(BehaviourKind).describe('Subset of fragile_kinds for which the owner allowed regular scans'),
  scope_confirmed_at: dt.nullable(), scope_confirmed_by: z.string().nullable(),
  version: z.string().describe('Version of the shared safety block (the same as GET /scanning safety.version, inventory INV-32): send it back on PUT to be refused with 409 safety_changed instead of replacing a change made since the page loaded'),
})
export const SettingsInput = InventorySettings.extend({
  scope_confirmed: z.boolean().describe('Attestation: the ranges belong to the company and scanning them is permitted'),
  version: z.string().max(64).optional().describe('The version this page read. Given and not the stored one: 409 safety_changed, nothing stored (review #860 M1). Left out: no check, so a range or exclusion added since the page loaded is replaced; this page is being replaced by Settings › Scanning (#850)'),
})
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
/** #829 C4: a device that answered this credential and has since moved to an address outside its scope. It is not read there (the scope is the safety line, D-512) until a person adds the address. */
export const SnmpMoved = z.object({
  device_id: z.string(), name: z.string().describe('How a person knows the device: host name, else model, else vendor; empty when none'),
  ip: z.string().describe('Its address now, outside the credential\'s scope'),
  message: z.string().describe('Plain words, e.g. "ipchg-c4 moved to 192.168.18.206, outside the scope of this credential. If it is still ipchg-c4, add the address to the scope to keep reading it. Nothing is sent there until then."'),
})
export const SnmpCredential = z.object({
  id: z.string(), name: z.string(), version: SnmpVersion,
  username: z.string().nullable().describe('v3 user name; null for v2c'),
  auth: SnmpAuth.nullable().describe('null for v2c'), priv: SnmpPriv.nullable().describe('null for v2c'),
  secret_last4: z.string().describe('Last 4 characters of the community (v2c) or of the authentication password (v3); empty when it has fewer than 8 characters'),
  priv_last4: z.string().describe('Last 4 characters of the v3 privacy password; empty when there is none or it has fewer than 8 characters'),
  port: z.number().int().describe('The UDP port it is sent to: 161 (the SNMP port) unless the person set another for a device that answers SNMP elsewhere'),
  scope: z.array(z.string()).describe('IPv4 addresses and CIDR ranges this credential is sent to (1 to 16): only approved devices of the scan scope inside them'),
  created_at: dt, last_answer_at: dt.nullable().describe('When a device last answered with it (a round in the scan window, or a Test)'),
  answered: z.number().int().describe('Devices that answered with it in its latest round in the scan window; a Test that got an answer makes it at least 1'),
  secret_lost: z.boolean().describe('A saved secret of it cannot be opened on this box (a backup restored without its decryption key, or the box key changed, #868): it is sent nowhere (Test and Read now answer 409 secret_lost, the scan window skips it) until Edit saves it with the secret typed again'),
  moved_out: z.array(SnmpMoved).describe('Devices that answered with it and moved out of its scope (#829 C4); empty on add and edit responses'),
})
export const SnmpCredentialInput = z.object({
  name: z.string().max(64).describe('1 to 64 characters, not < >; unique (case does not matter)'), version: SnmpVersion,
  community: z.string().max(64).optional().describe('v2c: 1 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  username: z.string().max(64).optional().describe('v3: letters, digits and . _ @ -'), auth: SnmpAuth.optional(),
  auth_password: z.string().max(64).optional().describe('v3: 8 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  priv: SnmpPriv.optional().describe('v3; default aes128'),
  priv_password: z.string().max(64).optional().describe('v3 with aes128: 8 to 64 printable ASCII characters; blank when editing keeps the saved one'),
  port: z.number().int().min(1).max(65535).optional().describe('The UDP port the devices answer SNMP on; left out = 161. A device on another port gets a credential of its own whose scope holds it'),
  scope: z.array(z.string()).max(16).describe('Required: the IPv4 addresses or CIDR ranges of the local network this credential belongs to (400 scope_required when empty, from the handler so the person reads why). A device someone plugs in later and gets approved never receives it (D-512)'),
})
export const SnmpResponse = z.object({
  credentials: z.array(SnmpCredential).describe('In the order they are tried (oldest first), at most 8'),
  ready: z.boolean().describe('false while the scan container cannot read SNMP (not reporting, or older than this version)'), message: z.string().nullable().describe('Why not ready'),
})
export const SnmpTestReason = z.enum([
  'ok', 'no_answer', 'auth_failed', 'unknown_user', 'error', 'not_in_inventory', 'not_approved', 'out_of_scope', 'not_for_this_credential',
  'scanning_off', 'scope_not_confirmed', 'declared_by_hand', 'box', 'regular_scan_never', 'unavailable', 'busy', 'snmp_off', 'excluded',
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

/** #849 SNMP by range: "Read now" for every approved device of a credential's scope, outside the window like Test (D-512 holds:
 * nothing is sent to a device that is not approved, or to an address with no device). One read at a time on the box (409 busy). */
export const SnmpRead = z.object({
  id: z.string(), credential_id: z.string(), by: z.string(), started_at: dt, finished_at: dt.nullable(),
  status: z.enum(['running', 'done', 'stopped', 'failed']),
  message: z.string().nullable().describe('Why the read stopped or failed, in plain words; null while running and when done'),
  total: z.number().int().describe('Approved devices of the scope that get one read'), done: z.number().int(), answered: z.number().int(),
  skipped: z.number().int().describe('Devices of the inventory in the credential\'s scope that are not read: not approved yet (approve them under To review first), added manually, set to never, the box, or outside the scan scope; and devices that answered it and moved out of its scope (#829 C4). Nothing is sent to them, nor to an address with no device'),
  results: z.array(SnmpTestResult.extend({ ip: z.string() })).describe('One row per device read so far, as Test answers it; a device that answered this credential and moved out of its scope is a row with reason not_for_this_credential at its new address, counted in skipped, and is not read (#829 C4)'),
})

const id = z.object({ id: z.string() })
const ok = z.object({ ok: z.literal(true) })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/inventory/devices', summary: 'List devices matching the filters (all when none), with counts per tab over the whole inventory', stories: ['S-INV-1', 'S-INV-3'], role: 'viewer', query: DevicesQuery, response: DevicesResponse },
  { method: 'post', path: '/inventory/devices', status: 201, summary: 'Declare a device manually using a product from the suggestion list', stories: ['S-INV-2'], role: 'operator', body: AddDeviceInput, response: AddDeviceResult },
  { method: 'get', path: '/inventory/devices/{id}', summary: 'Device details: observations, services, software', stories: ['S-INV-1'], role: 'viewer', params: id, response: DeviceDetail, example: { params: { id: 'a-nas02' } } },
  { method: 'patch', path: '/inventory/devices/{id}', summary: 'Rename the device in Vedette, change the type, mark as fragile, override regular scans or edit the notes of a device. 400 bad_name: a name over 64 characters or with < or >', stories: ['S-INV-1'], role: 'operator', params: id,
    body: z.object({
      name: z.string().max(200).optional().describe('The name in Vedette (G2): trimmed, at most 64 characters, no < or >; empty clears it (back to the default name). The host name the network reports is not changed'),
      kind: AssetKind.optional(), fragile: z.boolean().optional(), regular_scan: RegularScan.optional(), notes: z.string().max(2000).optional(),
    }), response: ok },
  { method: 'put', path: '/inventory/devices/{id}/sources', summary: 'Turn the network scan or the SNMP reads of one device on or off (D-601). On is the person\'s consent to that traffic: a device added by hand gets it from then on, inside every other safety rule (scope, exclusions, window, fragile, never scan); turning the network scan on queues the device for the next window. Off stops it for any device (the run on it stops); what the source found stays and manual values still win. One audit row per source changed. 400 bad_source: neither, or not on/off. 404 not_found. 409 box_device: the Vedette box itself. 409 device_ignored: turning a source on for an ignored device (D-630)', stories: ['S-INV-1', 'S-INV-4'], role: 'admin', params: id, body: SourcesInput, response: SourcesState },
  { method: 'delete', path: '/inventory/devices/{id}', summary: 'Delete a device from the inventory, along with its findings (409 for the Vedette box itself, which is always the first device)', stories: ['S-INV-3'], role: 'operator', params: id, response: null },
  { method: 'post', path: '/inventory/devices/{id}/approve', summary: 'Approve a new device', stories: ['S-INV-3'], role: 'operator', params: id, response: ok },
  { method: 'get', path: '/inventory/possible-same', summary: 'Every pair of devices that may be the same machine, for a person to merge or keep separate (D-599)', stories: ['S-INV-3'], role: 'viewer', response: SamePairs },
  { method: 'post', path: '/inventory/devices/{id}/merge', summary: 'The same machine: device `from` joins this device and is gone (D-599). This device keeps its id, approval (it becomes approved when `from` was, and loses a suspicious mark as on Approve), notes (both kept), findings and settings; the MACs, sources, software and open ports of `from` move to it, and its address when it was seen later and this device was found by a sensor (a device added by hand keeps the address typed). 400 invalid: the same device twice. 404 not_found: either device. 409 box_device: either is the Vedette box. 409 not_same_device: two agents, or two different burned-in MACs, say two machines', stories: ['S-INV-3'], role: 'admin', params: id, body: MergeInput, response: id },
  { method: 'post', path: '/inventory/devices/{id}/keep-separate', summary: 'Two machines: the pair is never offered as possibly the same device again, until either is deleted or merged (D-599). Saying it again changes nothing. 400 invalid, 404 not_found, 409 box_device as for merge', stories: ['S-INV-3'], role: 'admin', params: id, body: KeepSeparateInput, response: ok },
  { method: 'post', path: '/inventory/devices/{id}/ignore', summary: 'Ignore a device that needs no watching, such as a staff phone, or stop ignoring it (D-630). Ignored: it stays known (seen again by its MAC or agent, it is the same device) but leaves To review and the Devices list, its new-device alert closes, its network scan and SNMP reads turn off and its open findings close as not relevant ("Closed by Vedette: the device was ignored by <person>.", no notice; findings a person settled keep their status); a trap hit or an intrusion-detection incident from it still alerts. Stopped: it goes back to To review (not approved), its own scan and SNMP settings apply again (they are kept while it is ignored), the findings Ignore closed reopen, matched again. Saying it again changes nothing. 404 not_found. 409 box_device: the Vedette box itself', stories: ['S-INV-3'], role: 'operator', params: id, body: z.object({ ignored: z.boolean() }), response: ok },
  { method: 'post', path: '/inventory/devices/{id}/suspicious', summary: 'Mark or unmark a device as suspicious', stories: ['S-INV-3'], role: 'operator', params: id, body: z.object({ suspicious: z.boolean() }), response: ok },
  { method: 'post', path: '/inventory/devices/{id}/software', status: 201, summary: 'Declare additional software running on a device', stories: ['S-INV-2'], role: 'operator', params: id,
    body: AddDeviceInput.omit({ name: true, ip: true }), response: z.object({ kev_cves: z.number().int() }) },
  { method: 'patch', path: '/inventory/devices/{id}/software/{sid}', summary: 'Change the version of manually declared software (400 not_manual for software a sensor or agent saw); an empty version removes it; the device is matched again (D-471)', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }),
    body: z.object({ version: z.string().max(40).describe('Letters, digits, . - + ( ) and spaces; empty removes the version') }), response: ok },
  { method: 'delete', path: '/inventory/devices/{id}/software/{sid}', summary: 'Remove manually declared software from a device', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }), response: null },
  { method: 'get', path: '/inventory/catalog', summary: 'Suggest products by vendor or commercial name', stories: ['S-INV-2'], role: 'viewer', query: z.object({ q: z.string().max(80) }), response: CatalogResponse, example: { query: { q: 'forti' } } },
  { method: 'put', path: '/inventory/notify-new', summary: 'Turn alerts for new devices on or off', stories: ['S-INV-3'], role: 'operator', body: z.object({ enabled: z.boolean() }), response: z.object({ enabled: z.boolean() }) },
  { method: 'get', path: '/inventory/export.csv', summary: 'Download the device list as CSV (UTF-8 with BOM, opens in Excel); the filters of GET /inventory/devices export what the page shows', stories: ['S-INV-2'], role: 'viewer', query: DevicesQuery, response: 'file' },
  { method: 'get', path: '/inventory/import-template.csv', summary: 'Download a sample CSV for importing devices', stories: ['S-INV-2'], role: 'viewer', response: 'file' },
  { method: 'post', path: '/inventory/import', summary: 'Import devices from CSV content; invalid rows are reported by row number, valid rows are still added', stories: ['S-INV-2'], role: 'operator', body: ImportInput, response: ImportResult },
  { method: 'get', path: '/inventory/settings', summary: 'LAN ranges, active scan window, device types scanned only once (and which allow regular scans), scope attestation', stories: ['S-INV-1'], role: 'admin', response: InventorySettings },
  { method: 'put', path: '/inventory/settings', summary: 'Save the scan scope; enabling active scanning requires scope attestation. 409 safety_changed when the version sent is not the stored one', stories: ['S-INV-1'], role: 'admin', body: SettingsInput, response: SettingsSaved },
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
  { method: 'put', path: '/inventory/snmp/{id}', summary: 'Edit an SNMP credential; a blank secret keeps the saved one. 409 secret_lost when a blank secret would keep one this box cannot open (type it again)', stories: ['S-INV-1'], role: 'admin', params: id, body: SnmpCredentialInput, response: SnmpCredential },
  { method: 'delete', path: '/inventory/snmp/{id}', summary: 'Delete an SNMP credential and its secrets; what devices said stays in the inventory', stories: ['S-INV-1'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/inventory/snmp/{id}/test', summary: 'Read one device with this credential now (read-only GETs from the scan container, logged in the probe log) and say what it answered, or why not; an answer is recorded in the inventory. 409 secret_lost when its saved secret cannot be opened on this box (nothing is sent; Edit and type it again)', stories: ['S-INV-1'], role: 'admin', params: id,
    body: z.object({ ip: z.string().max(15).describe('IPv4 of a device in the inventory') }), response: SnmpTestResult },
  { method: 'post', path: '/inventory/snmp/{id}/read', status: 202, summary: 'Read now every approved device in this credential\'s scope (read-only GETs from the scan container, logged in the probe log); answers at once with the run. 409 busy while another read, a Test or the window\'s round runs; 409 scanning_off, scope_not_confirmed or unavailable when nothing can be sent; 409 secret_lost when its saved secret cannot be opened on this box (Edit and type it again); 409 stopped when active discovery was turned off while the read started', stories: ['S-INV-1'], role: 'admin', params: id, response: SnmpRead },
  { method: 'get', path: '/inventory/snmp/{id}/read', summary: 'The read of this credential that runs now, or the last one; null when none since the box started', stories: ['S-INV-1'], role: 'admin', params: id, response: SnmpRead.nullable() },
])
