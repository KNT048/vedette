// API contract of the inventory module. The UI types are derived from the schema here (types.ts), so UI ↔ mock ↔ OpenAPI cannot drift.
import { z } from 'zod'
import { DEVICE_STATUSES } from '@/lib/statusCodes'
import { defineEndpoints } from '@/lib/contract'
import { BEHAVIOUR_KINDS, TYPE_IDS } from '@/lib/deviceTypes'

export const ObsSource = z.enum(['manual', 'declared', 'agent', 'snmp', 'nmap', 'passive', 'scan'])
/** Device type: one of content/devicetypes/types.json, grouped in categories; the 13 types of before keep their ids. */
export const AssetKind = z.enum(TYPE_IDS).describe('Device type (content/devicetypes/types.json)')
/** The 13 kinds behaviour is keyed on (fragile defaults, never-touch gateways, …); every device type acts as one of them. */
export const BehaviourKind = z.enum(BEHAVIOUR_KINDS)
export const ObsField = z.enum(['hostname', 'mac', 'vendor', 'model', 'os', 'kind'])
const dt = z.iso.datetime()
const confidence = z.number().min(0).max(1)

/** How Vedette knows a value besides its source: stated = the device announced it about itself (the OS in its LLDP description, on
 *  a network card of that vendor, and the model of that frame); stated_web = the device's own web page or API gave its firmware to anyone
 *  without a login (an iLO's page, an ESXi's service content), stated_sip = its SIP answer did; guess = nmap's OS fingerprint, a guess: show it as one, never as a confidence level. */
export const Basis = z.enum(['stated', 'stated_web', 'stated_sip', 'guess'])
const basis = Basis.optional().describe('stated: the device announced it about itself (the OS in its LLDP description on its own vendor\'s network card, and the model of the same frame); guess: nmap\'s OS fingerprint, shown as a guess and never as a confidence level; absent: the source and confidence say it all')
export const Observed = z.object({ value: z.string(), source: ObsSource, confidence, seen_at: dt, basis,
  software_id: z.string().optional().describe('The software row the value is read from: the OS or firmware row a person declared (a device added by hand as FortiGate, FortiOS v7.2.13 has os FortiOS 7.2.13, model FortiGate); absent when an observation gives it') })
export const Software = z.object({
  id: z.string(), display: z.string().describe('Commercial name the user recognizes'), vendor: z.string(), product: z.string(), version: z.string().nullable(),
  kev: z.array(z.string()).describe('KEV match keys: lowercase "vendorproject|product"'), source: ObsSource, confidence,
  basis: Basis.optional().describe('guess on the row of nmap\'s OS fingerprint (no version, no match key); absent otherwise'),
  not_installed: z.boolean().describe('A person said this software is not installed on the device: it matches nothing; what the device runs (the assistant, MCP) leaves it out and the export marks it'),
}).describe('One software line of the device (one row per product, or per release train of a product whose trains install side by side), its value the strongest reading; the same line and value on every page, the export and the assistant')
export const Service = z.object({
  port: z.number().int().min(1).max(65535), proto: z.enum(['tcp', 'udp']), name: z.string(), product: z.string().optional(), version: z.string().optional(),
  detail: z.string().optional().describe('What the service said about the device besides product and version: nmap extra info and device type, page title, certificate subject. Evidence only, never software'),
  source: ObsSource, confidence,
  address: z.string().optional().describe('The other address of the device a scan found the port on (an IP, or a MAC when that interface has no IP now); absent for the main address and for an agent\'s list. One port open on two interfaces is two rows'),
})
export const KindGuess = z.object({
  kind: AssetKind, confidence, evidence: z.string().describe('What matched and what it most likely means, one sentence'),
  model: z.string().optional().describe('A model a certificate or page title states'),
  alternatives: z.array(AssetKind).optional().describe('Other types the same signals fit, offered next to the guess'),
}).describe('What the identification rules say the device most likely is, only while kind is unknown; it changes no behaviour until a person sets the kind')
export const Asset = z.object({
  id: z.string(), site: z.string(), ip: z.string().describe('"—" when declared manually and the IP is unknown'), mac: z.string().nullable(),
  hostname: z.string().nullable().describe('The host name the network reports (scan, SNMP, agents, passive), or the name typed when the device was added manually; read-only'),
  name: z.string().nullable().describe('The name a person gave the device in Vedette (PATCH name): it wins over every other name on every page; null = the default name (the naming rule)'),
  kind: AssetKind,
  kind_source: ObsSource.nullable().describe('Source of the kind; null for the default unknown'), guess: KindGuess.nullable(),
  vendor: Observed.nullable(), model: Observed.nullable(), os: Observed.nullable(), software: z.array(Software), services: z.array(Service),
  first_seen: dt, last_seen: dt, approved: z.boolean(), fragile: z.boolean(), origin: z.enum(['discovered', 'manual']), notes: z.string().optional(),
  private_mac: z.boolean().describe('The MAC is a private (randomised) address the device picks for itself and changes (locally administered, not a stable virtual prefix such as QEMU/KVM, Docker or VirtualBox)'),
  quiet: z.boolean().describe('Not approved, but held out of To review and of the new-device notice: a private-address device with no open service that has not stayed past a day. It is listed with the approved devices and moves to To review when it earns a look; false for every approved device'),
})

/** One observation of one field. Never overwritten: a new value is added, and the "in use" value is chosen by manual > high confidence > newer (ARCHITECTURE §4). */
export const Observation = z.object({ id: z.string(), field: ObsField, value: z.string(), source: ObsSource, confidence, seen_at: dt, current: z.boolean(),
  contradicts_type: z.boolean().optional().describe('An nmap OS guess the device type rules out (Android on a firewall): kept, never the device OS; absent otherwise'),
  basis: basis.describe('On an OS or model observation, as Observed.basis') })

/** Only osquery uses a token (Vedette is osquery's TLS server). Wazuh is a pull connection over its API (WazuhConnection), with no token. Trivy is not supported. */
export const AgentKind = z.enum(['osquery'])
export const AgentToken = z.object({
  id: z.string(), name: z.string(), kind: AgentKind, last4: z.string(), created_at: dt, created_by: z.string().nullable().describe('Who made it (null for a token made before this was kept)'), last_received: dt.nullable(), hosts: z.number().int(),
  expires_at: dt.nullable().describe('When it stops enrolling machines. null = never; default 7 days once a machine has enrolled; a token no machine enrolled with expires 24 hours after it was made. The token only enrolls osquery (it can read nothing) and can be revoked'),
  device_id: z.string().nullable().describe('The device it was made for (its agent row offers Show setup); null = any machine'),
})
/** A person turns each active source of the box on or off per device, on its Sources card. */
export const SourceState = z.enum(['on', 'off'])
export const SourcesInput = z.object({ scan: SourceState.optional(), snmp: SourceState.optional(),
  agent: SourceState.optional().describe('The agents\' data of this device (osquery, Wazuh). off: every agent\'s data for it is refused and what they read stops counting (its software readings and open ports of the agents go); on: taken again, and an osquery agent is asked to send its software now'),
}).describe('At least one; a source left out is left alone')
export const SourcesState = z.object({ scan_source: SourceState, snmp_source: SourceState, agent_source: SourceState.describe('Default on') })
/** The device page's Sources: three equal rows (network scan, SNMP, agent), each decided on the server. */
export const SourceRowKind = z.enum(['scan', 'snmp', 'agent'])
export const SourceRowState = z.enum(['module_off', 'no_address', 'off', 'waiting', 'working', 'not_approved', 'not_set_up', 'not_answering', 'none', 'reporting', 'quiet', 'never_reported', 'replaced', 'unavailable', 'box', 'ignored']).describe(
  'module_off: the module behind the source is off. no_address: the device has no address to send to (scan, snmp). off: a person turned the source off for this device. waiting: on, nothing read yet (scan: the first check is the next scan window\'s; snmp: set up, no read yet). working: the scan read the device, or SNMP answers. not_approved: SNMP reads approved devices only. not_set_up: no SNMP settings for this device. not_answering: the last SNMP read got no answer. none: no agent of this box reads the device. reporting: the agent reports on its rhythm (osquery by its own calls, Wazuh by its pull, the box by its own hourly list). quiet: an agent (osquery or Wazuh) silent for more than three of its own rhythm (rhythm_s of the agents list), the same rule everywhere. Agent row: waiting = a token was made for this device and no agent reads it yet; off = a person turned the agent off for this device. never_reported: enrolled, never sent its data. replaced: a newer enrolment of the same machine took over. unavailable: the module could not say just now. box: the Vedette box itself, which reads its own packages and ports and is not scanned or read over SNMP (no switch, no button). ignored: a person ignored the device: the box does not scan or read it until they stop ignoring it (no switch, no button)')
export const SourceDot = z.enum(['green', 'amber', 'red', 'grey']).describe('green: working or reporting; amber: quiet or never reported; red: SNMP not answering; grey: everything else (off, not set up, waiting, module off)')
export const SourceAction = z.enum(['turn_on_module', 'scan_now', 'approve', 'set_up', 'check_now', 'create_token', 'show_setup', 'check', 'box_check']).describe(
  'The one button of the row. box_check: the box\'s own agent reads its packages and ports now (POST /inventory/box/check). turn_on_module: the module is off. scan_now: check the device now instead of at the next window. approve: approve the device (SNMP reads approved devices only). set_up: set up SNMP for this device (PUT /inventory/snmp/devices/{id}). check_now: SNMP Check now (POST /inventory/snmp/devices/{id}/check). create_token: no agent reads the device and no token was made for it: create an agent token for it (POST /inventory/agents/tokens with device_id). show_setup: a token was made for this device and no agent reads it yet, or its agent enrolled and never reported: show the token (the row\'s token) and the install command again. check: the agent reported at least once: the troubleshooting steps')
export const DeviceSourceRow = z.object({
  source: SourceRowKind, state: SourceRowState, dot: SourceDot,
  last_at: dt.nullable().describe('When the source last read the device: the newest scan result (observation, open port, software banner); SNMP\'s last answer; the agent\'s last call (osquery) or its newest data (Wazuh, the box). null when never'),
  switch: SourceState.nullable().describe('The person\'s switch of this source for this device (PUT /inventory/devices/{id}/sources); null when the row has none: SNMP before it is set up, an agent row with no agent (unless it is off), the box itself and an ignored device'),
  action: SourceAction.nullable().describe('null when the row offers no button'),
  agent: z.enum(['osquery', 'wazuh', 'box', 'none']).nullable().describe('Agent row: which agent of this box reads the device (box = the Vedette box itself, which reads its own packages); null on the other rows'),
  next_at: dt.nullable().describe('When the source reads the device next by itself: the box\'s own agent row (its hourly read of its packages and ports); null on the other rows and before the box\'s first read since it started'),
  token: AgentToken.nullable().describe('Agent row: the token Show setup shows: the token its osquery agent enrolled with, else the newest token made for this device that still enrolls machines (the secret is never here: it is shown once, when the token is made); administrators only (the tokens list is theirs): null for the other roles, and on the other rows'),
})
export const DeviceSourcesView = z.object({
  rows: z.array(DeviceSourceRow).describe('Always three rows: scan, snmp, agent, in this order'),
  only: z.enum(['passive', 'manual']).nullable().describe('What feeds the device when none of the rows does: passive = only heard on the network ("Seen passively"), manual = only what a person entered ("Added by hand"); null otherwise'),
  manual_at: dt.nullable().describe('When a person last entered or changed something on the device (as DeviceDetail.manual_at)'),
})
export const RegularScan = z.enum(['follow', 'allow', 'never']).describe('Per-device override of the type setting for regular scans after the one gentle scan; never = never actively scanned again, for every kind of device')
/** A fragile device, or one of unknown kind, gets ONE gentle scan when first seen (lowest speed, no service/OS detection), then it is passive-only until classified or allowed; regular_scan=never means never for every kind; discovery never scans the box itself (only a person's pick in Scan now does). */
const ScanInfo = z.object({
  is_box: z.boolean().describe('true for the Vedette box itself: the first device, always present, cannot be deleted (409)'),
  first_scan_at: dt.nullable().describe('When the one gentle first scan happened; null = no gentle scan (declared by hand, the box itself, or a known kind that is not fragile and not set to never)'),
  regular_scan: RegularScan,
  scan_source: SourceState.describe('the box\'s network scan of this device (discovery\'s nmap and the vulnerability scans). on: the box\'s own scan settings decide; off: no scan packet goes to it. Default: on for a device a sensor found, off for one added by hand. Off is answered as regular_scan_never by the scan refusals'),
  snmp_source: SourceState.describe('The box\'s SNMP reads of this device, as scan_source (default on for a device a sensor found, off for one added by hand); saving the device\'s SNMP settings turns it on. Off: no SNMP read goes to it (Check now answers snmp_off, and the device\'s SNMP says so in blocked)'),
  approved_at: dt.nullable().describe('When a person approved the device, or osquery enrolment did ("Approved in the last 24 h"); approving again does not move it; null = not approved, added by hand, or approved before this field existed'),
  ignored_at: dt.nullable().describe('when a person ignored the device (a staff phone: known, not watched); null = watched. An ignored device is out of To review, the counts and the Devices list (ignored=true lists them), sends no new-device alert, is not scanned or read over SNMP, its open findings are closed (what a person settled keeps its status) and none are made; a trap hit or an intrusion-detection incident from it still alerts'),
})
/** #849: what feeds a device, in the words of the Devices search (source:…). scan = nmap or a vulnerability scan; osquery and Wazuh are
 * told apart (both are source agent in observations): osquery by the device's agent binding, Wazuh by its sync. */
export const DeviceSource = z.enum(['manual', 'passive', 'scan', 'snmp', 'osquery', 'wazuh'])
/** A device's badge in every list (like Defender's exposure level): findings' device status, the one function the findings lists,
 * the device page and Home read. Its most urgent open finding status with the distinct CVEs at it, else needs_input with the items
 * waiting for a person. null when it has none. */
export const DeviceRisk = z.object({
  code: z.enum(DEVICE_STATUSES),
  count: z.number().int().min(1).describe('An open status: distinct CVEs of the device at that status ("2 exploited"); needs_input: the items of the Needs your input queue for the device'),
}).describe('The device\'s badge (findings\' device status): null when it has none, for the Vedette box itself, and while the findings module is off')
/** A software name of the Devices search's software: suggestions, with the number of devices that run it. */
export const SoftwareName = z.object({ name: z.string(), count: z.number().int().min(1).describe('Devices with a software line of this name') })
export const DeviceRow = Asset.omit({ software: true, services: true }).extend(ScanInfo.shape).extend({
  software_count: z.number().int().min(0).describe('Number of the device\'s software lines (a line a person said is not installed counts). The lines themselves are on the device page (GET /inventory/devices/{id}): the list never carries them'),
  service_count: z.number().int().min(0).describe('Number of the device\'s open services (ports); the services themselves are on the device page'),
  product: Software.nullable().describe('A device added by hand: its first software line by name that is installed (the line that names a device with no host name, and the product Settings › Declared software lists); null for a discovered device or one with no such line'),
  matched_software: z.array(Software).optional().describe('Only with the software filter: the device\'s lines that hold one of its words, by name (the Matched software column)'),
  sources: z.array(DeviceSource).describe('Every source that told Vedette something about the device and is still kept (its details, software or open ports), plus manual for a device added manually, in the order of DeviceSource (#849 source: filter, #829 sources of the device page)'),
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  risk: DeviceRisk.nullable(),
  summary: z.object({ source: ObsSource, confidence }).nullable().describe('Source of the most trusted value; confidence is that of the weakest value'),
})
/** #849: the filters of the Devices search; all optional, ANDed; each list ORs its values. counts stay over the whole inventory. */
export const DevicesQuery = z.object({
  approved: z.enum(['true', 'false']).optional().describe('true: the Devices list (approved, and quiet private-address devices); false: To review (not approved, not quiet)'),
  ignored: z.enum(['true', 'false']).optional().describe('true lists only the ignored devices; false or absent leaves them out'),
  type: z.string().max(400).optional().describe('Comma-separated device type ids; a value also matches the types that act as it (type=server finds a hypervisor). Unknown id: 400 bad_filter'),
  source: z.string().max(200).optional().describe(`Comma-separated: ${DeviceSource.options.join(', ')}. Unknown value: 400 bad_filter`),
  fragile: z.enum(['true', 'false']).optional(),
  has_findings: z.enum(['true', 'false']).optional().describe('true: the device has open findings (a status of one of the five layers; needs_input alone is none). findings_count counts every state and is not used. The Vedette box is never marked, so never under true. Statuses unreadable: 503 risk_unavailable'),
  risk: z.string().max(120).optional().describe(`Comma-separated device statuses: ${DEVICE_STATUSES.join(', ')}, or none (no badge). Unknown value: 400 bad_filter`),
  q: z.string().max(80).optional().describe('Free text, case-insensitive, matched in the name (the name in Vedette, the host name, or the product of a device added manually), IP, MAC (any notation: aa:bb, aa-bb, aabb), vendor and model'),
  software: z.string().max(400).optional().describe('Comma-separated words, case-insensitive: keeps the devices with a software line whose "name vendor product" holds one of them; each row then lists those lines in matched_software'),
})
export const DevicesResponse = z.object({
  items: z.array(DeviceRow),
  counts: z.object({ all: z.number().int(), pending: z.number().int(), fragile: z.number().int(), manual: z.number().int(), ignored: z.number().int().describe('Ignored devices; no other count includes them') }),
  notify_new: z.boolean(),
  notify_available: z.boolean().describe('false when the notify module is off'),
  risk_unavailable: z.boolean().describe('The badges could not be read (the findings module failed): no row has one and a badge filter was not applied'),
  top_software: z.object({
    devices: z.array(SoftwareName).describe('Over the listed devices that are approved or quiet'),
    review: z.array(SoftwareName).describe('Over the listed devices that are To review'),
  }).describe('The 12 software names most of the listed devices run (most devices first, then by name), for the search\'s software: suggestions; declared software with no device is left out'),
})
/** INV-41: a person's correction of a row a sensor or agent reported. */
export const SoftwareCorrection = z.object({
  set_at: dt.describe('When the person set it (or last changed it)'),
  set_by: z.string().describe('Who set it (email); "" for a correction stored without one'),
  detected: z.object({
    id: z.string(), display: z.string(), version: z.string().nullable(), pkg_version: z.string().nullable(), source: ObsSource, seen_at: dt,
  }).nullable().describe('The corrected row when its source still reports it (it does not match while the correction stands), else that source\'s newest row of the product at another version (that one matches on its own: a second install or an update); null when the source reports the product no more: say "no scan or agent reports it now"'),
  disagrees: z.boolean().describe('The source reads another product, version or package release than the person (always true while active is false): show "You set X on <date>; the last scan reads Y"'),
  not_installed: z.boolean().optional().describe('INV-41 (6): the person said the reported row is not installed on the device. While active it matches nothing and disagrees is false; show "Not installed (you said, <date>)" with Clear. Not active: the source now reads another version (detected), a new install that matches: "You said not installed on <date>; the scan now reads Y"'),
  active: z.boolean().describe('true: the row it corrects is still reported and matching uses the correction. false: the source moved on (detected = what it reads now) or reports the product no more (detected null); matching uses the source\'s reading until the person sets the correction again (PATCH on detected.id, or on this row, which moves it onto what the source reads now). Show it as not in use: "You set X on <date>; the scan now reads Y (Vedette uses that)" with Set again and Clear'),
})
/** INV-50: another source's reading of a software line. */
export const AlsoSeen = z.object({
  id: z.string().describe('The line\'s id: a reading is not a row of its own'), source: ObsSource, version: z.string().describe('"" when the source gave none'), pkg_version: z.string().describe('"" when none'), seen_at: dt,
  same_release: z.boolean().describe('The line\'s release with more or less detail (10.2, 10.2p1, 10.2_p1-r1): not a disagreement'),
})
/** INV-52: what a source reads of a line a person gave another version. */
export const CorrectedFrom = z.object({ source: z.string(), version: z.string().describe('"" when none'), pkg_version: z.string().describe('"" when none') })
/** One software line of a device as the device page shows it, built on the server: the line's value (the strongest reading), the
 *  other readings under it, a person's entry or "not installed" mark. The page shows it as it is; nothing is merged in the browser. */
export const SoftwareLine = Software.omit({ kev: true }).extend({
  kev_cves: z.array(z.string()).describe('Exploited CVEs of the line\'s product; empty on a line a person said is not installed'),
  pkg_version: z.string().optional().describe('The full package release: an agent\'s packaged reading ("1:9.6p1-3ubuntu13.14") or a person\'s entry ("10.2_p1-r1"); absent when none'),
  packaged: z.boolean().describe('Read from the operating system\'s package database'),
  cpe: z.string().describe('"" when none'),
  set_by: z.string().describe('Who entered the value, when it is a person\'s entry (source manual); "" otherwise'),
  seen_at: dt.describe('When the source of the value last read it'),
  also_seen: z.array(AlsoSeen).describe('The other readings of the line, strongest source first'),
  differs: z.boolean().describe('Another reading reads another release than the line (matching keeps it too): the first also_seen with same_release false is the one to name'),
  corrected: z.boolean().describe('The value is a person\'s entry that a source reads otherwise (corrected_from says what). It lapses by itself when a source later reads a newer version (the device history says so)'),
  corrected_from: CorrectedFrom.nullable().describe('What the strongest source reads; null when the line is not corrected'),
  correction: SoftwareCorrection.optional().describe('On a line a person gave a version or marked not installed (INV-41): when, by whom, and what the sources read now. Clear = DELETE /inventory/devices/{id}/software/{sid}'),
  can_correct: z.boolean().describe('A person may give this line a version (INV-52): PATCH /inventory/devices/{id}/software/{sid} with { version }, whatever source it was read from; true on every line'),
})
/** INV-41: the OS a person set on the device; it wins over every source and drives matching while it stands. */
export const OsCorrection = z.object({
  value: z.string(), set_at: dt,
  detected: Observed.nullable().describe('The OS the sources read without the correction (the value that would win); null when none reads one'),
  disagrees: z.boolean().describe('The sources read another OS: show "You set X on <date>; the last scan reads Y"'),
})
/** INV-47: a value a person entered (it wins everywhere) and a different value a trusted source reads (an agent, SNMP, a statement the device makes about itself). */
export const DetectedField = z.enum(['hostname', 'vendor', 'model', 'os', 'kind'])
export const DetectedDiffers = z.object({
  field: DetectedField, entered: z.string().describe('What the person entered: the value in use'), detected: z.string().describe('What the trusted source reads now'),
  source: ObsSource.describe('agent, snmp, or passive (the device\'s own LLDP statement: basis stated)'), basis: Basis.optional(), seen_at: dt.describe('When the source last read that value'),
}).describe('Never raised against a scan guess or a passive hint, nor when the two only differ by case, a domain, a legal suffix such as Inc., or a version the entered OS leaves out')
export const DetectedChoice = z.object({ detected: z.string().min(1).max(253).describe('The detected value the person saw. 409 detected_changed when the sources read another value now or it no longer differs: reload') })
/** When the inventory cannot be sure two rows are one machine (a phone or laptop with a new private Wi-Fi address and a
 * generic name, an older MAC two rows share), a person decides: "Possibly the same device as X" with Merge and Keep separate. */
/** What two devices share when they are offered as possibly one machine, strongest first. */
export const SameReason = z.enum(['same_mac', 'mac_block', 'same_name_cards', 'rotating_name', 'rotating_model', 'mac_at_added_device', 'same_os'])
  .describe('same_mac: seen with one MAC, never online at once; mac_block: burned-in MACs from one block of a maker on network gear (the interfaces of one router or firewall); same_name_cards: one host name on two cards with burned-in MACs (Wi-Fi and cable); rotating_name / rotating_model: one name or stated model and a private Wi-Fi address, never online at once; mac_at_added_device: a MAC seen at the address of a device added by hand; same_os: a device added by hand without any address runs the operating system or firmware a found device runs, at the same version or build')
export const PossibleSame = z.object({
  id: z.string(), name: z.string().describe('The other device, named as every page names it'),
  why: z.string().describe('What the two share, in plain words to show as is, e.g. Same name "iPhone", never online at the same time, and a private Wi-Fi address (phones and laptops change it).'),
  reason: SameReason,
  approved: z.boolean(), last_seen: dt,
  never_seen: z.boolean().describe('The device was added by hand and nothing has seen it since: last_seen is when it was added, not a sighting'),
  ignored: z.boolean().describe('a person ignored the other device. A merge keeps the kept device watched or ignored, except that an approved device a person watches is never hidden: merged with it, an ignored device is watched again'),
})
export const SameRef = PossibleSame.omit({ why: true, ignored: true, reason: true })
/** One address of a device: an interface as it was seen (an IPv4 address, a MAC, or both). */
export const DeviceAddress = z.object({
  ip: z.string().nullable(), mac: z.string().nullable(),
  main: z.boolean().describe('The main address: the one lists show and every scan and read of the device goes to. Exactly one when the device has any address'),
  source: z.string().describe('What last tied the address to the device: the sensor that last saw it there (passive, nmap, scan, agent, snmp), manual for the address a person typed, merge for one a person\'s merge brought that nothing has seen since'),
  first_seen: dt, last_seen: dt,
  agent: z.boolean().describe('The address the device\'s agent reports from (an osquery node bound to the device, a Wazuh agent): it cannot be split off (409 agent_address), the agent\'s machine keeps it. Offer Split off on the other addresses only'),
})
export const DeviceDetail = z.object({
  asset: Asset.omit({ software: true }).extend(ScanInfo.shape).extend({
    software: z.array(SoftwareLine).describe('The device\'s software lines, by name'),
    os_correction: OsCorrection.optional().describe('The OS a person set (PATCH os, INV-41); absent when none: os is then what the sources read'),
  }),
  suspicious: z.boolean(),
  findings_count: z.number().int().describe('Number of findings attached to the device; deleting the device also deletes these findings'),
  risk: DeviceRisk.nullable(),
  risk_unavailable: z.boolean().describe('The badge could not be read (the findings module failed)'),
  observations: z.array(Observation),
  detected_differs: z.array(DetectedDiffers).describe('INV-47: fields where a trusted source reads another value than the one a person entered, which still wins. The page offers Use detected / Keep mine next to each; empty when none or when the person kept their value for the value now detected'),
  manual_at: dt.nullable().describe('INV-46: when a person last entered or changed something on the device: a value typed when it was added or set later (type, OS), a software row added or edited, a correction or "not installed"; the time it was added for a device added by hand with nothing newer; null when no person entered anything. The Manual source shows it ("last changed 2 hours ago")'),
  kinds: z.array(AssetKind),
  possible_same: z.array(PossibleSame).describe('Devices that may be this same machine, the 5 seen last, the one seen last first; empty for the box and when none. A pair is offered when the rows share a MAC, or a host name or stated model while one uses a private Wi-Fi address, or a device added by hand without an address runs the OS a found device runs at the same release; never when a person kept them separate, two agents or two different burned-in MACs say two machines, they state another name, model or OS, or one was seen while the other was. Two network cards of one machine are offered too: one host name on two burned-in MACs, or burned-in MACs from one block of a maker on network gear (reason)'),
  addresses: z.array(DeviceAddress).describe('Every address of the device, the main one first, then the others, the one seen last first: the device is found by any of them. Split off = POST /inventory/devices/{id}/split'),
})
export const SamePairs = z.object({
  items: z.array(z.object({
    a: SameRef.describe('The approved device when one is, else the one seen first: the one a merge most likely keeps'), b: SameRef, why: PossibleSame.shape.why, reason: SameReason,
  })).describe('Every pair of devices that may be one machine, the pair seen last first'),
})
/** The name, type and OS a person picked for the kept device where the merged devices differ; each must be one of their own values (MergePreview differs). */
export const MergeChoice = z.object({
  name: z.string().min(1).max(64).optional(), kind: AssetKind.optional(), os: z.string().min(1).max(200).optional(),
})
export const MergeInput = z.object({
  from: z.array(z.string().min(1).max(96)).min(1).max(8).describe('The devices that go into the device of the path, 1 to 8 (the interfaces of one firewall in one step)'),
  fields: MergeChoice.optional().describe('Values a person chose where the devices differ; left out: the merge\'s own result (MergePreview differs kept)'),
})
export const MergeValue = z.object({
  device: z.string(), value: z.string(),
  guess: z.boolean().optional().describe('kind only: the type the identification rules guess for a device whose type is unknown (Asset guess); it may be picked for the merged device'),
})
export const MergeField = z.object({
  field: z.enum(['name', 'kind', 'os', 'vendor', 'model', 'hostname']),
  values: z.array(MergeValue).describe('Each device\'s value, the kept device first; a device without a value is left out'),
  kept: z.string().describe('What the kept device has after the merge unless the person picks another: the kept device\'s own name in Vedette (else the first that has one), the strongest source\'s reading for the other fields; for kind "unknown" when no source states a type (a guess is never the type)'),
  choosable: z.boolean().describe('name, kind and os: the merge takes a choice (fields); the others follow the sources'),
  missing: z.array(z.string()).describe('kind and os: the devices without a value (a type or OS only one device states is a row too, so the person sees what the merged device ends with); empty for the other fields'),
})
export const MergeSide = z.object({
  id: z.string(), name: z.string(), approved: z.boolean(), ignored: z.boolean(), agent: z.boolean().describe('An agent reports from it'),
  addresses: z.array(DeviceAddress), software: z.number().int().describe('Software lines present'), open_ports: z.number().int(),
  findings: z.number().int(), risk: DeviceRisk.nullable(), last_seen: dt,
})
export const MergePreview = z.object({
  into: MergeSide.describe('The device that stays'), from: z.array(MergeSide).describe('The devices that go into it, in the order given'),
  moves: z.object({
    addresses: z.number().int().describe('Addresses that become the kept device\'s, each with what a scan read there'),
    software_new: z.number().int().describe('Software lines the kept device does not have'),
    software_shared: z.number().int().describe('Lines it has too: one line keeps every reading of both'),
    readings: z.number().int().describe('Software readings that move; none is dropped'),
    open_ports: z.number().int(),
    findings: z.number().int().describe('Findings that move, with their history and decisions; one CVE of one software line becomes one finding'),
    exploited: z.number().int().describe('Exploited CVEs the devices taken are marked with'),
  }),
  differs: z.array(MergeField).describe('Only the fields the devices state differently (for type and OS also one device\'s value against none); empty when they agree'),
  refusal: z.object({ code: z.enum(['box_device', 'not_same_device']), message: z.string() }).nullable().describe('Why the merge would be refused (409 with this code); null when it may go ahead'),
})
export const MergePreviewQuery = z.object({ from: z.string().min(1).max(800).describe('Comma-separated ids of the devices that would go into the device of the path, 1 to 8') })
export const SplitInput = z.object({ address: z.string().min(1).max(40).describe('One IPv4 address or MAC of the device: that interface (its IP and MAC together) becomes a device of its own') })
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
  lan_ranges: z.array(z.string()).max(16).describe('Internal IPv4 CIDR (RFC 1918, or the RFC 6598 shared address space 100.64.0.0/10)'), active: ActiveWindow, fragile_kinds: z.array(BehaviourKind).describe('Device types scanned only once, gently, when first seen; passive-only after that. Every type acting as one of them counts'),
  regular_scan_kinds: z.array(BehaviourKind).describe('Subset of fragile_kinds for which the owner allowed regular scans'),
  scope_confirmed_at: dt.nullable(), scope_confirmed_by: z.string().nullable(),
  version: z.string().describe('Version of the shared safety block (the same as GET /scanning safety.version, inventory INV-32): send it back on PUT to be refused with 409 safety_changed instead of replacing a change made since the page loaded'),
})
export const SettingsInput = InventorySettings.extend({
  scope_confirmed: z.boolean().describe('Attestation: the ranges belong to the company and scanning them is permitted'),
  version: z.string().max(64).optional().describe('The version this page read. Given and not the stored one: 409 safety_changed, nothing stored (#860). Left out: no check, so a range or exclusion added since the page loaded is replaced; this page is being replaced by Settings › Scanning (#850)'),
})
export const SettingsSaved = InventorySettings.extend({
  adjusted: z.array(z.object({ from: z.string(), to: z.string() })).describe('Ranges normalized on save, e.g. 10.142.0.0 → 10.142.0.0/24'),
})

export const SensorStatus = z.enum(['online', 'offline', 'never_connected', 'starting']).describe('online: a heartbeat in the last 90 s; offline: it reported before, then nothing for 90 s; never_connected: no heartbeat ever; starting: not online while the box is still starting the sensor container (an appliance after setup or after the module is turned on: the start is being retried, for up to 10 minutes, or was confirmed less than 3 minutes ago). A container-only install never says starting: the customer starts it')
/** Only the sensor of this box itself (multiple sites are not supported yet). */
export const Sensor = z.object({
  id: z.string(), name: z.string(), interface: z.string().nullable().describe('The port the sensor listens on: the card chosen (the SPAN port when SPAN is on), else the default card, the management port; null: none. Set in Settings → Box network; on a container-only install with PATCH /inventory/sensors/{id}'), interfaces: z.array(z.string()).describe('The cards the sensor reported in its last heartbeat'), span: z.boolean(),
  chosen: z.boolean().describe('true: interface is a stored choice (the SPAN port of Settings → Box network, or the card chosen with PATCH on a container-only install); false: interface is the default card or null'),
  span_status: z.object({ verdict: z.enum(['off', 'ok', 'own_only', 'no_traffic', 'no_link']), packets_per_s: z.number().int(), other_macs: z.number().int() }).describe('Live mirrored-traffic health, the same as Settings → Box network'),
  status: SensorStatus, last_seen: dt.nullable(), version: z.string().nullable(), devices_seen: z.number().int(),
  capture_error: z.enum(['no_permission', 'no_interface', 'filters_invalid', 'capture_failed']).nullable().describe('Why the sensor, online, does not capture on its card (from its heartbeat): no_permission = no CAP_NET_RAW (rootless container), no_interface = the card is not on that machine, filters_invalid = the capture filters cannot be read, capture_failed = anything else (the sensor log says what); null while it captures, has no card, or is not online'),
})
export const SensorsResponse = z.object({ sensors: z.array(Sensor) })
export const SensorPatch = z.object({
  interface: z.string().max(15).nullable().describe('A card of the sensor\'s last heartbeat (younger than 90 s); null: no card chosen, the sensor listens on the default one'),
  span: z.boolean().describe('The card receives mirrored traffic; it must have no IPv4 address. true needs an interface'),
})

const Installer = z.object({ url: z.string(), sha256: z.string().describe('SHA-256 (lowercase hex) of the script served by the box; users compare it before running'), script: z.string().describe('Full script text, for the admin to read first') })
export const OsqueryPackage = z.object({
  file: z.string().describe('File name; the browser downloads it from /api/v1/install/osquery/{file}'),
  platform: z.enum(['linux', 'windows']), format: z.enum(['deb', 'rpm', 'msi']), arch: z.enum(['x86_64', 'arm64']),
  size: z.number().int().describe('Bytes'),
  sha256: z.string().describe("SHA-256 (lowercase hex) from the box's SHA256SUMS, which the core build writes from deploy/osquery/PINS"),
})
export const Installers = z.object({
  osquery_version: z.string(), linux: Installer, windows: Installer,
  packages: z.array(OsqueryPackage).describe('The osquery packages this box serves; empty when it has no copy (a development build without the mirror)'),
})
export const OsqueryStatusBody = z.object({ host_identifier: z.string().max(200).optional().describe('The name this machine enrols under (the install script sets osquery host_identifier = specified and sends the same name here); the install script sends it so the answer is about THIS machine') })
export const OsqueryStatus = z.object({
  enrolled: z.boolean(), hosts: z.number().int(),
  host_last_seen: z.string().nullable().optional().describe('Only when host_identifier was sent: when the box last heard from the machine of this token with that name (a hostname match ignores case), null when no machine of the token has enrolled under it; absent when no usable host_identifier was sent. It tells nothing about machines of other tokens'),
})
// osquery TLS remote API: machine to machine, called by osqueryd only, never by this GUI. Shapes follow
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
  interval_minutes: z.number().int().describe('Minutes between pulls, 5 or more. It is the schedule agent-intake.wazuh, which the schedule editor changes too'),
})
export const WazuhTestResult = z.object({ ok: z.literal(true), version: z.string(), agents: z.number().int().describe('Number of Wazuh agents the API user can read') })
/** How an enrolled osquery agent is doing, from its own check-ins against its own schedule (it asks for its config every 5 minutes). */
export const AgentState = z.enum(['reporting', 'quiet', 'never_reported', 'replaced'])
export const AgentOs = z.enum(['windows', 'linux'])
export const AgentNode = z.object({
  id: z.string(), token_id: z.string(), host: z.string().describe('The name the machine enrolled under'), os: AgentOs,
  state: AgentState.describe('reporting = it called within three of its rhythm (rhythm_s); quiet = it did not (quiet_since is its last call); never_reported = it calls but has delivered no result since it enrolled, after the first hour; replaced = a newer agent of the same machine (same name, any token) took over, so this record is only left to remove'),
  enrolled_at: dt, last_seen: dt.describe('Its last call to the box (config or results)'), last_result_at: dt.nullable().describe('Its last delivered result log; null = none yet'),
  quiet_since: dt.nullable().describe('state quiet: when it was last heard; null otherwise'),
  rhythm_s: z.number().int().describe('The interval it is judged by, in seconds: the longer of how often it was told to call (osquery: its 5-minute config refresh; the package reporter: its hourly run) and how often it really calls. Quiet after three of it'),
})
export const AgentsResponse = z.object({ install: Installers, tokens: z.array(AgentToken), nodes: z.array(AgentNode).describe('Every enrolled osquery agent, the quiet ones first, then by name'), server_url: z.string().describe('https://<box IP>:8443, or https://<VEDETTE_BOX_IP>:8443 when the IP is unknown'), wazuh: WazuhConnection.nullable() })
export const CreateTokenResult = z.object({ token: AgentToken, secret: z.string().describe('Full token, returned only at creation') })
export const RemoveUnusedResult = z.object({ removed: z.number().int() })
export const SampleResult = z.object({ devices: z.number().int(), software: z.number().int() })
/** "I updated it" for software an agent reads (S-MIT-1): which agent of this box reads the device, and the open ask. */
export const AgentReport = z.object({
  agent: z.enum(['osquery', 'wazuh', 'none', 'box']).describe('osquery = an osquery agent enrolled with this box reports on the device: Vedette can ask it to send its software now; wazuh = only the Wazuh pull reads it: Vedette cannot ask, the next pull brings the list; none = no agent of this box reads it now; box = the Vedette box itself, which reads its own packages every hour'),
  asked_at: dt.nullable().describe('The open ask: when a person asked the osquery agent to send its software now, until its list (built with its OS answer: kernel_info, os_revision) arrives or 15 minutes pass; null when none is open'),
  ask_again_at: dt.nullable().describe('agent osquery: when a new ask is possible (10 minutes after the last one) while that is still ahead; null otherwise'),
  last_seen: dt.nullable().describe('agent osquery: when the agent last called the box (config or results); agent wazuh: when a pull last delivered the device; null otherwise'),
  state: AgentState.nullable().describe('agent osquery or wazuh: reporting, quiet (silent for more than three of its rhythm: show "quiet since quiet_since" and, for osquery, the command to check the service) or never_reported (osquery); null for the other agents'),
  quiet_since: dt.nullable().describe('state quiet: when the agent last called the box; null otherwise'),
  rhythm_s: z.number().int().nullable().describe('agent osquery or wazuh: the interval its state is judged by, in seconds (osquery: the longer of its config refresh and how often it really calls; wazuh: the pull interval); null otherwise'),
  off: z.boolean().describe('A person turned the agent off for this device: its data is refused and it cannot be asked (409 agent_off)'),
  os: AgentOs.nullable().describe('agent osquery: the machine\'s system, which picks the service commands to show; null otherwise'),
  stale: z.boolean().describe('state quiet: no agent reports this device now (an ask reaches an osquery agent only when it is back); false otherwise'),
  wazuh_interval_minutes: z.number().int().nullable().describe('agent wazuh: how often Vedette pulls from the Wazuh server, in minutes (5 or more); null otherwise'),
})

/** S-INV-1: SNMP is set up per device, like a Zabbix host's SNMP interface. Each device has its own version, community or
 * v3 user, port and "read from" address (its management address, by default its own IP); its secrets are stored encrypted, the API
 * never returns them (only their last 4 characters), and they are sent to that one address only. There are no credential profiles
 * and no scopes. Reads are read-only GETs from the scan container, in the scan window or by Check now. */
export const SnmpVersion = z.enum(['v2c', 'v3']).describe('No SNMPv1: it is not secure')
export const SnmpAuth = z.enum(['sha', 'sha256']).describe('v3 authentication: HMAC-SHA-1 or HMAC-SHA-256 (no MD5)')
export const SnmpPriv = z.enum(['aes128', 'none']).describe('v3 privacy: AES-128 (authPriv) or none (authNoPriv); no DES')
export const SnmpState = z.enum(['working', 'not_answering', 'waiting', 'not_set_up']).describe(
  'working: the last read got an answer. not_answering: the last read got none, or an error (error says why). waiting: set up, not read yet (the next scan window reads it, or Check now). not_set_up: no SNMP settings on this device')
export const SnmpReason = z.enum([
  'ok', 'no_answer', 'auth_failed', 'unknown_user', 'error',
  'not_set_up', 'not_approved', 'out_of_scope', 'scanning_off', 'scope_not_confirmed', 'declared_by_hand', 'box', 'regular_scan_never', 'snmp_off', 'excluded', 'no_ip', 'moved', 'secret_lost', 'unavailable', 'busy',
]).describe('ok, no_answer, auth_failed, unknown_user, error: what the device did. The others: why nothing was sent (the device or the box refuses it now)')
export const SnmpAnswer = z.object({
  sys_descr: z.string(), sys_object_id: z.string(), sys_name: z.string().describe('What the device said, cleaned; empty when it has none'),
  vendor: z.string(), product: z.string().describe('Product family from sysObjectID, e.g. FortiGate'), model: z.string(), os: z.string(), kind: z.string().describe('A device type id, or empty'),
  serial: z.string(), firmware: z.string().describe('ENTITY-MIB chassis firmware text (or the OS version a vendor MIB states)'),
})
export const SnmpBlocked = z.object({ reason: SnmpReason, message: z.string().describe('Plain words for the person, what to do included') })
export const DeviceSnmp = z.object({
  device_id: z.string(),
  ip: z.string().nullable().describe('The device\'s own address in the inventory; null when none'),
  state: SnmpState,
  read_from: z.string().nullable().describe('The one address SNMP reads (and the secret) go to; null when not set up. The device\'s IP unless the person set its management address, e.g. "100.66.253.1" for a FortiGate whose ip is "100.66.254.1". It never makes or merges a device: what answers there is this device'),
  read_from_default: z.boolean().describe('true when Read from was left to the device\'s address (it was the device\'s IP when saved). If the device later moves to another IP, nothing is sent until a person sets Read from again (blocked reason moved); a Read from the person typed stays as it is'),
  version: SnmpVersion.nullable(), username: z.string().nullable().describe('v3 user name; null for v2c'),
  auth: SnmpAuth.nullable().describe('null for v2c'), priv: SnmpPriv.nullable().describe('null for v2c'),
  port: z.number().int().nullable().describe('The UDP port reads go to (161 unless set); null when not set up'),
  secret_last4: z.string().describe('Last 4 characters of the community (v2c) or the authentication password (v3); empty when not set up or it has fewer than 8 characters'),
  priv_last4: z.string().describe('Last 4 characters of the v3 privacy password; empty when there is none or it has fewer than 8 characters'),
  secret_lost: z.boolean().describe('A saved secret cannot be opened on this box (a backup restored without its decryption key, #868): nothing is sent until Edit saves it typed again'),
  last_checked_at: dt.nullable().describe('When the box last sent a read (scan window or Check now)'),
  last_answer_at: dt.nullable().describe('When the device last answered'),
  last_reason: SnmpReason.nullable().describe('The outcome of the last read (ok, no_answer, auth_failed, unknown_user, error); null when never read'),
  error: z.string().nullable().describe('Plain words for the last read that got no answer; null when working, waiting or not set up'),
  answer: SnmpAnswer.nullable().describe('What answered at read_from at last_answer_at (sysName, model, serial, firmware…), so a wrong Read from is obvious; null when it never answered'),
  blocked: SnmpBlocked.nullable().describe('Why the box will not send a read to this device now, even though it is set up (not approved, SNMP off, excluded, moved, secret lost, scanning off…); null when it may. Check now answers the same reason'),
  updated_at: dt.nullable(),
})
export const DeviceSnmpInput = z.object({
  copy_from: z.string().optional().describe('A device id: copy that device\'s SNMP settings (version, user, algorithms, port and the saved community or passwords) on the box; the secret never goes to the browser. With copy_from only read_from is read from this body, and it must be the device\'s own IP (left out or equal): a copied secret goes only there; any other read_from is 400 secret_required (type the secret instead)'),
  read_from: z.string().max(15).optional().describe('The IPv4 address SNMP answers on; left out or empty = the device\'s IP. Any local address (inside or outside the LAN ranges), not the box or a trap address, not multicast or broadcast'),
  version: SnmpVersion.optional().describe('Required unless copy_from'),
  community: z.string().max(64).optional().describe('v2c: 1 to 64 printable ASCII characters; blank on an edit keeps the saved one (not when Read from changes)'),
  username: z.string().max(64).optional().describe('v3: letters, digits and . _ @ -'), auth: SnmpAuth.optional(),
  auth_password: z.string().max(64).optional().describe('v3: 8 to 64 printable ASCII characters; blank on an edit keeps the saved one (not when Read from changes)'),
  priv: SnmpPriv.optional().describe('v3; default aes128'),
  priv_password: z.string().max(64).optional().describe('v3 with aes128: 8 to 64 printable ASCII characters; blank on an edit keeps the saved one'),
  port: z.number().int().min(1).max(65535).optional().describe('The UDP port the device answers SNMP on; left out = 161'),
})
export const SnmpCheckResult = z.object({
  ok: z.boolean(), reason: SnmpReason, message: z.string().describe('Plain words for the person'),
  answer: SnmpAnswer.nullable().describe('What the device said, when it answered; it is also recorded on this device in the inventory with source snmp'),
  snmp: DeviceSnmp.describe('The device\'s SNMP state after the check'),
})
export const SnmpDeviceRow = z.object({
  device_id: z.string(), name: z.string().describe('How a person knows the device: its name in Vedette or host name, else model, else vendor; empty when none'),
  ip: z.string().nullable(), read_from: z.string(), version: SnmpVersion, username: z.string().nullable(), port: z.number().int(),
  state: SnmpState.exclude(['not_set_up']), last_answer_at: dt.nullable(),
  blocked: SnmpBlocked.nullable().describe('As DeviceSnmp.blocked'),
})
export const SnmpNotice = z.object({ id: z.number().int(), at: dt, text: z.string().describe('Plain words, e.g. what the move to per-device SNMP did to a saved credential') })
export const SnmpResponse = z.object({
  ready: z.boolean().describe('false while the scan container cannot read SNMP (not reporting, or older than this version)'), message: z.string().nullable().describe('Why not ready'),
  devices: z.array(SnmpDeviceRow).describe('Every device with SNMP set up, by name: the Copy from list and the Scanning card'),
  notices: z.array(SnmpNotice).describe('What the box did to SNMP settings by itself (the move from credentials to devices), until a person dismisses them'),
})

const id = z.object({ id: z.string() })
const ok = z.object({ ok: z.literal(true) })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/inventory/devices', summary: 'List devices matching the filters (all when none), with counts per tab over the whole inventory', stories: ['S-INV-1', 'S-INV-3'], role: 'viewer', query: DevicesQuery, response: DevicesResponse },
  { method: 'post', path: '/inventory/devices', status: 201, summary: 'Declare a device manually using a product from the suggestion list', stories: ['S-INV-2'], role: 'operator', body: AddDeviceInput, response: AddDeviceResult },
  { method: 'get', path: '/inventory/devices/{id}', summary: 'Device details: observations, services, software', stories: ['S-INV-1'], role: 'viewer', params: id, response: DeviceDetail, example: { params: { id: 'a-nas02' } } },
  { method: 'patch', path: '/inventory/devices/{id}', summary: 'Rename the device in Vedette, change the type, mark as fragile, override regular scans or edit the notes of a device. 400 bad_name: a name over 64 characters or with < or >', stories: ['S-INV-1'], role: 'operator', params: id,
    body: z.object({
      name: z.string().max(200).optional().describe('The name in Vedette: trimmed, at most 64 characters, no < or >; empty clears it (back to the default name). The host name the network reports is not changed'),
      kind: AssetKind.optional(), fragile: z.boolean().optional(), regular_scan: RegularScan.optional(), notes: z.string().max(2000).optional(),
      os: z.string().max(400).optional().describe('Correct the operating system (INV-41): trimmed, at most 200 characters, no < or >; it wins over every sensor and agent and drives matching until cleared. Empty clears it (back to what the sources read). 400 bad_os'),
    }), response: ok },
  { method: 'put', path: '/inventory/devices/{id}/sources', summary: 'Turn the network scan, the SNMP reads or the agents\' data of one device on or off. On is the person\'s consent to that traffic: a device added by hand gets it from then on, inside every other safety rule (scope, exclusions, window, fragile, never scan); turning the network scan on queues the device for the next window. Off stops it for any device (the run on it stops); what the source found stays and manual values still win. Agent off: every agent\'s data for the device is refused and what the agents read stops counting (their software readings and open ports go); on: taken again, and an osquery agent is asked to send its software now. One audit row per source changed. 400 bad_source: neither, or not on/off. 404 not_found. 409 box_device: the Vedette box itself. 409 device_ignored: turning a source on for an ignored device', stories: ['S-INV-1', 'S-INV-4'], role: 'admin', params: id, body: SourcesInput, response: SourcesState },
  { method: 'get', path: '/inventory/devices/{id}/sources', summary: 'The device\'s sources as three rows (network scan, SNMP, agent): each with its state, colour, last time it read the device, switch and one button, decided on the server. 404 not_found', stories: ['S-INV-1', 'S-INV-4'], role: 'viewer', params: id, response: DeviceSourcesView, example: { params: { id: 'a-nas02' } } },
  { method: 'post', path: '/inventory/box/check', summary: 'The box\'s own agent reads the packages installed on the box and the ports it listens on now, as its hourly read does; answers the box\'s source rows. One audit row inventory.box_check. 409 not_appliance: a container-only install (no packages of its own). 502 box_read_failed: the read failed, what was read last stays', stories: ['S-INV-1', 'S-INV-4'], role: 'operator', response: DeviceSourcesView },
  { method: 'delete', path: '/inventory/devices/{id}', summary: 'Delete a device from the inventory, along with its findings (409 for the Vedette box itself, which is always the first device)', stories: ['S-INV-3'], role: 'operator', params: id, response: null },
  { method: 'post', path: '/inventory/devices/{id}/approve', summary: 'Approve a new device', stories: ['S-INV-3'], role: 'operator', params: id, response: ok },
  { method: 'get', path: '/inventory/possible-same', summary: 'Every pair of devices that may be the same machine, for a person to merge or keep separate', stories: ['S-INV-3'], role: 'viewer', response: SamePairs },
  { method: 'get', path: '/inventory/devices/{id}/merge-preview', summary: 'What merging the devices `from` into this device would do, without changing anything: both sides (addresses, software, ports, findings, badge), what moves, the fields they state differently with the value the kept device gets, and the refusal the merge would answer. 400 invalid: no device, more than 8, one twice or this device itself. 404 not_found: any device', stories: ['S-INV-3'], role: 'admin', params: id, query: MergePreviewQuery, response: MergePreview, example: { params: { id: 'a-fw01' }, query: { from: 'a-nas02' } } },
  { method: 'post', path: '/inventory/devices/{id}/merge', summary: 'The same machine: every device of `from` joins this device and is gone, in one step. This device keeps its id, main address, approval (it becomes approved when one of them was, and loses a suspicious mark as on Approve), notes (all kept), findings and settings; the addresses of each (with what a scan read at each one: the device is found by any of them, and a scan of one address never replaces what another address showed), MACs, sources, software, open ports and findings move to it. `fields` sets the name, type or OS a person picked where the devices differ. 400 invalid: no device, more than 8, one twice or this device itself. 400 bad_choice: a picked value none of the devices has. 404 not_found: any device. 409 box_device: one is the Vedette box. 409 not_same_device: two agents say two machines', stories: ['S-INV-3'], role: 'admin', params: id, body: MergeInput, response: id },
  { method: 'post', path: '/inventory/devices/{id}/split', summary: 'Split off an address (the undo of a merge): that interface, its IP and MAC together, becomes a device of its own with what was read only there (the MAC\'s observations, the readings and open ports a scan took at that address); what an agent or SNMP read of the whole machine stays. When it was the main address, the other address seen last becomes the main one. The new device is approved when this one was (no new-device alert), and the pair is kept separate: never offered as possibly the same device again. Findings follow the software (matched again on both). One audit row. Returns the new device. 400 bad_address: not an IPv4 address or MAC. 404 not_found; 404 address_not_found: not one of this device\'s addresses. 409 box_device; 409 only_address: the device has no other address; 409 agent_address: the device\'s agent reports from this address (DeviceAddress.agent), so it stays with the agent\'s machine: split off the other addresses', stories: ['S-INV-3'], role: 'admin', params: id, body: SplitInput, response: id },
  { method: 'post', path: '/inventory/devices/{id}/keep-separate', summary: 'Two machines: the pair is never offered as possibly the same device again, until either is deleted or merged. Saying it again changes nothing. 400 invalid, 404 not_found, 409 box_device as for merge', stories: ['S-INV-3'], role: 'admin', params: id, body: KeepSeparateInput, response: ok },
  { method: 'post', path: '/inventory/devices/{id}/differs/{field}/use', summary: 'Use the detected value: the person\'s own value of that field is removed, so the sources\' reading is the one shown and used (INV-47). One audit row with the person. 400 bad_field. 404 not_found. 409 detected_changed', stories: ['S-INV-1'], role: 'operator', params: id.extend({ field: DetectedField }), body: DetectedChoice, response: ok },
  { method: 'post', path: '/inventory/devices/{id}/differs/{field}/keep', summary: 'Keep the person\'s value against the detected one (INV-47): the notice stays hidden until the sources read another value. Nothing else changes. One audit row. 400 bad_field. 404 not_found. 409 detected_changed', stories: ['S-INV-1'], role: 'operator', params: id.extend({ field: DetectedField }), body: DetectedChoice, response: ok },
  { method: 'post', path: '/inventory/devices/{id}/ignore', summary: 'Ignore a device that needs no watching, such as a staff phone, or stop ignoring it. Ignored: it stays known (seen again by its MAC or agent, it is the same device) but leaves To review and the Devices list, its new-device alert closes, its network scan and SNMP reads turn off and its open findings close as not relevant ("Closed by Vedette: the device was ignored by <person>.", no notice; findings a person settled keep their status); a trap hit or an intrusion-detection incident from it still alerts. Stopped: it goes back to To review (not approved), its own scan and SNMP settings apply again (they are kept while it is ignored), the findings Ignore closed reopen, matched again. Saying it again changes nothing. 404 not_found. 409 box_device: the Vedette box itself', stories: ['S-INV-3'], role: 'operator', params: id, body: z.object({ ignored: z.boolean() }), response: ok },
  { method: 'post', path: '/inventory/devices/{id}/suspicious', summary: 'Mark or unmark a device as suspicious', stories: ['S-INV-3'], role: 'operator', params: id, body: z.object({ suspicious: z.boolean() }), response: ok },
  { method: 'post', path: '/inventory/devices/{id}/software', status: 201, summary: 'Declare additional software running on a device', stories: ['S-INV-2'], role: 'operator', params: id,
    body: AddDeviceInput.omit({ name: true, ip: true }), response: z.object({ kev_cves: z.number().int() }) },
  { method: 'patch', path: '/inventory/devices/{id}/software/{sid}', summary: 'Change a software row (INV-41). A row a person declared changes in place. A row a sensor or agent reported is corrected: the values go in a manual correction row (source manual, correction set) that replaces exactly that row (its source, product and version, and its re-reports) for matching until it is deleted; another install of the product (another version or source) keeps matching. Fields left out keep their value (the CPE, the packaged flag, the source package; the package release while the version stays); another product starts clean. `not_installed: true` (alone) on a reported row, or on its correction, says the software is not installed (INV-41 (6)): a correction of the same kind that replaces the row with nothing while the row stays reported; its open findings close (findings INV-6c); a later edit of the version or product makes it an ordinary correction; DELETE clears it. Audit inventory.mark_not_installed. The device is matched again. 400 bad_edit (nothing to change; not_installed with another field; not_installed on a row a person added, which DELETE removes), bad_version, bad_pkg_version, unknown_product, incomplete_product, bad_product. 409 duplicate_software; 409 box_device (not_installed on the box\'s own software)', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }),
    body: z.object({
      version: z.string().max(40).optional().describe('Letters, digits, . - + ( ) and spaces; empty removes the version'),
      pkg_version: z.string().max(100).optional().describe('The package release the device\'s package manager shows ("10.2_p1-r1", "1:9.6p1-3ubuntu13.14"); empty removes it'),
      catalog_id: z.string().max(64).optional().describe('Another product, from GET /inventory/catalog'),
      vendor: z.string().max(64).optional(), product: z.string().max(64).optional().describe('Another product typed by hand (both vendor and product)'),
      not_installed: z.boolean().optional().describe('true: the software is not installed on the device (INV-41 (6)); send it alone. false or absent: no change'),
    }), response: ok },
  { method: 'delete', path: '/inventory/devices/{id}/software/{sid}', summary: 'Remove manually declared software from a device; on a correction (INV-41) this clears it and the reported row matches again (audit inventory.clear_software_correction)', stories: ['S-INV-2'], role: 'operator', params: id.extend({ sid: z.string() }), response: null },
  { method: 'get', path: '/inventory/catalog', summary: 'Suggest products by vendor or commercial name', stories: ['S-INV-2'], role: 'viewer', query: z.object({ q: z.string().max(80) }), response: CatalogResponse, example: { query: { q: 'forti' } } },
  { method: 'put', path: '/inventory/notify-new', summary: 'Turn alerts for new devices on or off', stories: ['S-INV-3'], role: 'operator', body: z.object({ enabled: z.boolean() }), response: z.object({ enabled: z.boolean() }) },
  { method: 'get', path: '/inventory/export.csv', summary: 'Download the device list as CSV (UTF-8 with BOM, opens in Excel); the filters of GET /inventory/devices export what the page shows', stories: ['S-INV-2'], role: 'viewer', query: DevicesQuery, response: 'file' },
  { method: 'get', path: '/inventory/import-template.csv', summary: 'Download a sample CSV for importing devices', stories: ['S-INV-2'], role: 'viewer', response: 'file' },
  { method: 'post', path: '/inventory/import', summary: 'Import devices from CSV content; invalid rows are reported by row number, valid rows are still added', stories: ['S-INV-2'], role: 'operator', body: ImportInput, response: ImportResult },
  { method: 'get', path: '/inventory/settings', summary: 'LAN ranges, active scan window, device types scanned only once (and which allow regular scans), scope attestation', stories: ['S-INV-1'], role: 'admin', response: InventorySettings },
  { method: 'put', path: '/inventory/settings', summary: 'Save the scan scope; enabling active scanning requires scope attestation. 409 safety_changed when the version sent is not the stored one', stories: ['S-INV-1'], role: 'admin', body: SettingsInput, response: SettingsSaved },
  { method: 'get', path: '/inventory/sensors', summary: 'Sensors of this box only (multiple sites not supported yet)', stories: ['S-INV-1'], role: 'admin', response: SensorsResponse },
  { method: 'patch', path: '/inventory/sensors/{id}', summary: 'Container-only install: choose the card the sensor reads (any card of its last heartbeat, with or without an address; null: back to the default card) and whether it is the SPAN card. 400 bad_interface: not a reported card, no heartbeat in 90 s, or a SPAN card with an address. 409 set_in_box_network on an appliance, where Settings → Box network sets it', stories: ['S-CORE-8', 'S-INV-1'], role: 'admin', params: id, body: SensorPatch, response: Sensor },
  { method: 'get', path: '/inventory/agents', summary: 'Issued osquery tokens and the Wazuh connection (if any)', stories: ['S-INV-4'], role: 'admin', response: AgentsResponse },
  { method: 'post', path: '/inventory/agents/tokens', status: 201, summary: 'Issue an osquery token, returning the full token once', stories: ['S-INV-4'], role: 'admin', body: z.object({ name: z.string().max(64), kind: AgentKind.optional(), expires_in_days: z.number().int().min(0).max(365).optional().describe('Default 7; 0 = never expires'),
    device_id: z.string().min(1).max(96).optional().describe('The device it is made for: the device\'s agent row then shows it under Show setup until a machine enrolls with it. 404 not_found: no such device; 409 box_device: the Vedette box itself') }), response: CreateTokenResult },
  { method: 'post', path: '/inventory/agents/tokens/remove-unused', summary: 'Remove every token with no machine enrolled now, made over an hour ago (tokens with machines and tokens made in the last hour stay). Audited. Also offered when 409 too_many_tokens says the limit of 500 is reached', stories: ['S-INV-4'], role: 'admin', response: RemoveUnusedResult },
  { method: 'delete', path: '/inventory/agents/tokens/{id}', summary: 'Revoke an osquery token', stories: ['S-INV-4'], role: 'admin', params: id, response: null },
  { method: 'get', path: '/inventory/agents/devices/{id}/report', summary: 'Which agent of this box reads the device and whether an ask to send its software now is open ("I updated it", S-MIT-1). 404 not_found: no such device; 404 too while agent-intake is off', stories: ['S-MIT-1', 'S-INV-4'], role: 'viewer', params: id, response: AgentReport },
  { method: 'post', path: '/inventory/agents/devices/{id}/report', summary: 'I updated it: ask the device\'s osquery agent to send its software now. For 15 minutes, or until its list arrives, the box\'s config gives the agent\'s software queries (the same read-only queries, nothing else) a 60 s interval; osquery reads its config every 5 minutes. An open ask is answered as it is; a new ask within 10 minutes of the last: 429 rate_limited (retry_after). 409 cannot_ask: no osquery agent of this box reports on the device (Wazuh only, or none). 409 agent_off: a person turned the agent off for this device. 404 not_found. Audited', stories: ['S-MIT-1', 'S-INV-4'], role: 'operator', params: id, response: AgentReport },
  { method: 'delete', path: '/inventory/agents/nodes/{id}', summary: 'Remove one agent record (an uninstalled agent, a decommissioned machine, or the older record of a machine enrolled again) without revoking the token the other machines use. The device it was bound to is released. The agent, if it still runs, enrols again with its token. 404 not_found. Audited', stories: ['S-INV-4'], role: 'admin', params: id, response: null },
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
  { method: 'get', path: '/inventory/snmp', summary: 'Whether the scan container can read SNMP now, every device with SNMP set up, and the notices of what the box changed by itself', stories: ['S-INV-1'], role: 'admin', response: SnmpResponse },
  { method: 'post', path: '/inventory/snmp/notices/dismiss', summary: 'Dismiss every SNMP notice', stories: ['S-INV-1'], role: 'admin', response: ok },
  { method: 'get', path: '/inventory/snmp/devices/{id}', summary: 'The SNMP settings and state of one device: working, not answering, waiting or not set up; read from, last answer and what answered; never a secret, only its last 4 characters. 404 not_found: no such device', stories: ['S-INV-1'], role: 'admin', params: id, response: DeviceSnmp },
  { method: 'put', path: '/inventory/snmp/devices/{id}', summary: 'Set up or edit the SNMP of one device: version, community or v3 user, port, Read from; or copy_from another device (the secret is copied on the box). Saving is the person\'s consent: it turns the device\'s SNMP source on when it was not. A blank secret keeps the saved one, unless Read from changes. One audit row. 400 bad_version, bad_secret, secret_required (also copy_from with a read_from other than the device\'s IP), bad_user, bad_auth, bad_priv, bad_port, bad_read_from, read_from_not_local, copy_from_self. 404 not_found, copy_from_not_found (no such device with SNMP set up). 409 no_ip (the device has no address yet), read_from_taken (another device reads from that address; the message names it), box_device, read_from_box (the box or a trap address), secret_lost (a kept or copied secret this box cannot open), device_ignored', stories: ['S-INV-1'], role: 'admin', params: id, body: DeviceSnmpInput, response: DeviceSnmp },
  { method: 'delete', path: '/inventory/snmp/devices/{id}', summary: 'Remove the SNMP settings of one device and its secrets; what it said stays in the inventory; its SNMP source switch is left as it is. 404 not_found when the device has none', stories: ['S-INV-1'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/inventory/snmp/devices/{id}/check', summary: 'Check now: read this device at once at its Read from address (read-only GETs from the scan container, logged in the probe log, every rule but the window) and say what it answered, or why not; an answer is recorded on this device. 404 not_found. 409 not_set_up, secret_lost, stopped (the module or scanning was turned off), changed (the settings changed while it started)', stories: ['S-INV-1'], role: 'admin', params: id, response: SnmpCheckResult },
])
