// API contract of the findings module. The UI types are derived from the schema here (types.ts), so UI ↔ mock ↔ OpenAPI cannot drift.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { TYPE_IDS } from '@/lib/deviceTypes'
import { DEVICE_STATUSES, FINDING_RESOLUTIONS, FINDING_STATUSES, OPEN_FINDING_STATUSES } from '@/lib/statusCodes'

const iso = z.iso.datetime()
const findingId = z.string().min(1).max(64)

export const FindingStatus = z.enum(['confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted'])
export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export const AssetKind = z.enum(TYPE_IDS) // the inventory's device types
export const FirewallVendor = z.enum(['fortigate', 'mikrotik', 'generic'])
export const ApplyItem = z.enum(['patch', 'workaround', 'fortigate', 'mikrotik', 'generic'])
/** How far ahead a risk can be accepted. */
export const MAX_ACCEPT_DAYS = 365

export const Finding = z.object({
  id: z.string(),
  asset_id: z.string(),
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  status: FindingStatus,
  severity: Severity,
  confidence: z.number().min(0).max(1).describe('How sure the match is, 0 to 1. A finding its evidence confirms (a scan, the version the device itself reports, or a person) is at least 0.95 in any status, never below a scan\'s confirmation'),
  basis: z.enum(['scan', 'version', 'product', 'person']).describe('scan = confirmed by a scan template; person = confirmed by a person (an admin, with a note); version = the version is inside the affected range (confirmed when evidence.source says the device itself stated it, suspected otherwise); product = only the product matches'),
  evidence: z.object({
    summary: z.string(), template: z.string().optional(), request: z.string().optional(), response: z.string().optional(), checked_at: iso,
    agent: z.boolean().optional().describe('the version compared is the one the device\'s own agent (osquery, Wazuh) reports installed: a detection, shown as "Detected by the agent", with nothing for the person to look up'),
    agent_row: z.boolean().optional().describe('a product-only match on a software row the device\'s own agent reported with its installed version: Vedette could not compare that version with NVD\'s data, so the page does not ask to add the version'),
    source: z.enum(['snmp', 'agent']).optional().describe('basis version only: the device itself stated the exact version (snmp: its answer to Vedette\'s SNMP read; agent: its own agent\'s OS or package list) and it is inside an affected range with an end, so the finding is confirmed by the version the device reports. Absent for a banner, an OS guess or a version a person typed'),
  }).nullable(),
  first_seen: iso.describe('When Vedette first matched this vulnerability to the device'),
  last_seen: iso.describe('When Vedette last matched it: each re-match (after a change to the device\'s software, and every hour) or scan that still finds it moves it. Not when the device or its software was last seen; known_version.seen_at says when the version was reported'),
  resolved_by: z.string().nullable(),
  resolved_at: iso.nullable(),
  resolution_note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('risk_accepted only: the last day of the acceptance (UTC); the finding reopens by itself after it'),
  history: z.array(z.object({ ts: iso, user: z.string(), action: z.string(), note: z.string().optional() })),
})

export const KevInfo = z.object({
  name: z.string(), vendor: z.string(), product: z.string(), display: z.string(), required_action: z.string(), links: z.array(z.string()),
  date_added: z.string(), due_date: z.string().nullable(), ransomware: z.boolean(), epss: z.number().nullable(), has_template: z.boolean().describe('A safe vulnerability check exists for the CVE: the template pack the scan itself plans with has one (not the nuclei-templates feed flag), so a vulnerability check can confirm or rule it out'),
  source: z.enum(['cisa-kev', 'vulncheck-kev']).optional().describe('Which list the entry is on: texts and the source badge name it; an entry of VulnCheck KEV is never called CISA\'s'),
  published: z.iso.date().nullable().describe('the day the CVE was published (NVD `published`), never the day CISA added it; null when NVD has not answered for it (then it counts as recent: an older CVE is not a finding on a product-only match, and a missing date never closes a finding)'),
})
export const FindingAsset = z.object({
  id: z.string(), name: z.string().describe('The name the Devices page shows: hostname, else vendor and model, else the IP, else the software; never the internal id'),
  hostname: z.string().nullable(), ip: z.string().describe('"—" when the device has no IP address'), kind: AssetKind, display: z.string(),
  approved: z.boolean().describe('false = "Device not added yet": nobody approved the device; its findings offer Add device (approve) and Ignore'),
  ignored: z.boolean().describe('a person ignored the device: its findings are hidden from the other tabs and listed under Ignored, with Restore'),
})
export const Cvss = z.object({
  score: z.number().min(0).max(10).describe('The CVSS base score (0.0 to 10.0, one decimal); its band follows from FIRST\'s table (3.x, 4.0) or NVD\'s v2 table (2.0: Low, Medium, High; no Critical)'),
  version: z.enum(['4.0', '3.1', '3.0', '2.0']).describe('The newest CVSS version NVD lists for the CVE with a usable score and vector (2.0 only when NVD has nothing newer)'),
  source: z.enum(['nvd', 'cna']).describe('nvd = NVD\'s own score ("Primary"); cna = another scorer NVD lists as "Secondary" (the CVE Numbering Authority or CISA\'s ADP), used only when NVD gives none for that version'),
  vector: z.string().min(1).max(200).describe('NVD\'s vector string of the score ("CVSS:3.1/AV:N/AC:L/…"; 2.0: "AV:N/AC:L/Au:N/…"): FIRST asks that a score be shown with its vector, so a score without a valid one is not shown'),
}).describe('#825 (findings INV-22, feeds INV-28): the CVSS base score from the same NVD records feeds already reads (nvd-kev, else nvd-recent). Shown next to the exploited status, never instead of it')
export const FindingRow = Finding.extend({
  urgency: z.number().int().min(1).max(5).describe('Why the finding matters now, most urgent first: 1 under attack here (an intrusion alert on this network named it), 2 exploited in the wild, 3 public exploit available, 4 critical on a device attackers target first, 5 update recommended (no sign of exploitation). Only 1 and 2 are "exploited"'),
  asset: FindingAsset.nullable(), kev: KevInfo.nullable().describe('Read from KEV, not from the project recommendation pack'),
  cvss: Cvss.nullable().describe('null = no CVSS score known: the pages say "No score", never 0'),
  resolution_reason: z.string().nullable().describe('not_affected_version when Vedette closed the finding by itself (a matcher proof, or one of its rules that compares no version); null for a person\'s own action and for open findings. A string, not an enum: a new reason must not break the list'),
  proved_version: z.string().nullable().describe('A finding closed by proof (resolution_reason set): the version or package release the matcher compared to rule it out, as the device row gives it; null when the closure compared none (name only, age, an open platform question, another platform) or it is not closed by Vedette. An entry a person typed closed it only when this equals the entry'),
  software_id: z.string().describe('The device\'s software row the matcher matched the finding on, stored when it opens, touches or closes the finding; "" until the next match reaches an older finding. Never guessed from the product'),
})

export const CodeStep = z.object({
  title: z.string(), code: z.string(), note: z.string().optional(),
  side_effect: z.string().optional().describe('Side effect that must be stated before the user pastes the command'),
  check: z.array(z.string()).optional().describe('#897 r2, AI config blocks only: the IP addresses the block names that are not the device\'s or a sent firewall\'s (netmasks, wildcards, 0.0.0.0 and :: aside), as written; the page shows "Check these addresses" above the block. Nothing is left out for an address'),
})
export const FirewallGuide = z.object({
  vendor: FirewallVendor, label: z.string(), detected: z.boolean().describe('The user declared a device of this vendor in the inventory'),
  intro: z.string(), steps: z.array(CodeStep),
  alternative: z.object({ title: z.string(), intro: z.string(), steps: z.array(CodeStep) }).optional(),
  verify: z.array(CodeStep), undo: z.array(CodeStep), plain: z.array(z.string()).optional(),
})
export const MitigationPack = z.object({
  cve: z.string(), confirmed_by: z.string(), confirmed_at: iso, drafted_with: z.string(),
  sources: z.array(z.object({ title: z.string(), url: z.string() })),
  patch: z.object({ summary: z.string(), fixed: z.string(), steps: z.array(z.string()), side_effect: z.string(), url: z.string() }),
  workaround: z.object({ summary: z.string(), steps: z.array(z.string()), side_effect: z.string() }),
  firewall: z.array(FirewallGuide), checklist: z.array(z.string()),
})
export const Indicator = z.object({
  kind: z.enum(['file', 'web', 'log', 'process']), title: z.string(), detail: z.string(),
  commands: z.array(z.object({ label: z.string(), code: z.string() })).optional(),
})
export const CompromiseCheck = z.object({ summary: z.string(), indicators: z.array(Indicator), if_found: z.array(z.string()) })
export const GeneralHardening = z.object({
  software: z.string().describe('The software the checks are for, as the page names it'),
  family: z.string().describe('The family the checks are written for ("Linux", "Network device", "General")'),
  checks: CompromiseCheck.nullable().describe('General "Have I been hit?" checks for the software family'),
}).describe('Mitigation INV-8: general compromise checks written by reviewed code, not a recommendation for the CVE: never shown as "Vedette confirmed", never run by Vedette. The generated firewall configs and the admin network field are gone')
export const AiAnswerKey = z.enum(['affected', 'fix', 'workaround', 'urgency'])
  .describe('affected = Am I affected? (yes, no or needs a check, with the evidence: version, who or what confirmed it, a condition from the record); fix = How do I fix it? (the exact fixed release with a direct link); workaround = What if I cannot patch yet? (the workaround with its link, or "none published"); urgency = How urgent? (the status reasons, attack vector, privileges)')
export const AiAnswer = z.object({
  key: AiAnswerKey,
  text: z.string().max(1200).describe('A few short sentences; no heading'),
  links: z.array(z.object({ title: z.string().max(200), url: z.string().regex(/^https?:\/\//) })).max(8).describe('The references the answer rests on, from the brief; http(s) only'),
})
export const AiResult = z.object({
  skill: z.enum(['explain', 'mitigation-config']), ts: iso, model: z.string(),
  profile: z.string().optional().describe('Name of the AI profile that answered'),
  tokens: z.object({ input: z.number(), output: z.number() }),
  paragraphs: z.array(z.string()), steps: z.array(z.string()),
  citations: z.array(z.object({ title: z.string(), url: z.string().optional() })),
  configs: z.array(CodeStep).optional().describe('mitigation-config: config blocks to paste as they are, the device\'s own workaround first, then a rule for each firewall vendor in Devices (nftables when none); `note` says what the change is based on, `side_effect` what it can break. Absent for explain and for answers stored before'),
  no_config_reason: z.string().optional().describe('#897 r1 H1, mitigation-config: why no configuration, or no firewall rule, helps for this finding (the attack is local or needs a user, or no open port serves the vulnerable part), in the AI\'s words; the page shows it where the configuration would be'),
  shortened: z.boolean().optional().describe('A part of the answer was longer than Vedette keeps: a text was cut at the end of a sentence (never in the middle of one) or a config block was left out whole'),
  answers: z.array(AiAnswer).max(4).optional().describe('explain and mitigation-config: the four short answers, in the order of AiAnswerKey, each rephrasing only the CVE brief and the finding, every claim that has a reference with its link; the page gives each its heading. When present, the page shows them instead of paragraphs and steps. Absent for answers stored before'),
})
export const AppliedEntry = z.object({ item: z.string(), ts: iso, user: z.string() })

export const FixedIn = z.object({
  kind: z.enum(['fixed', 'up_to', 'end_listed', 'branches', 'distro', 'feature_update', 'esu']).describe('fixed = the device version is inside a range that ends before `fixed`, and `fixed` is outside every range that applies; up_to = inside a range whose end `fixed` is itself affected (no fixed release named); end_listed = inside a range that ends before `fixed`, but NVD lists releases of `fixed` itself as affected (Junos: "before 20.4", then 20.4R1 … one by one): `fixed` is not a fix, the vendor advisory names it; branches = the version is unknown or unreadable, `branches` lists the fix of each release line; distro = a package of the distribution, whose security updates carry the fix under their own numbers: an agent read it from the device\'s package database (deb, rpm or apk), a person gave its package release (an apk, Debian or RPM release, or any release on a device that runs a Linux distribution), or the version carries a marker such as ubuntu, +deb12, .el9; feature_update = a Windows release NVD does not list for the fix, which only a later release of its line (`branches[0].branch`, from build `fixed`) has: Microsoft no longer updates it, so it needs a feature update; esu = the fixing Windows build `fixed` comes only with Extended Security Updates for `branches[0].branch`'),
  version: z.string().describe("The device's version; for branches empty when it has none, else the text Vedette cannot read"),
  fixed: z.string().describe('The fixed release (fixed), the last affected release (up_to), the upstream fixed release as a reference when NVD names one (distro: the backport may keep the package\'s number below it); empty for branches'),
  branches: z.array(z.object({ branch: z.string().describe('Release line such as 7.4; empty when it cannot be told'), fixed: z.string() })).describe('At most 5, newest first'),
  more: z.number().int().min(0).describe('Release lines with a fix left out of branches'),
  no_fix: z.number().int().min(0).describe('Release lines NVD gives no fixed release for (a range that ends at an affected version)'),
  distro: z.string().describe('"Ubuntu", "Debian" or "Alpine Linux" when the device runs one, empty otherwise. distro: whose security updates to install (empty = the distribution). Other kinds: set only when the software is not known to come from the package database (typed by a person, read by a scan, or an agent row stored before inventory kept the flag); the page adds "if you installed it from the distribution\'s packages, install its security updates instead"'),
  distro_fixed: z.string().describe('Kind distro only: the version of the distribution\'s package that fixes the CVE on the device\'s release (Ubuntu security data, Debian Security Tracker, Alpine Linux security database); `version` is then the device\'s full package version. Empty when the distribution\'s data does not say'),
  distro_release: z.string().describe('The device\'s release with distro_fixed ("24.04", "12", "3.23"); empty otherwise'),
  distro_pro: z.boolean().describe('distro_fixed is in Ubuntu Pro (ESM) only'),
  restart_into: z.string().optional().describe('Kind distro on a Linux kernel only: the installed kernel (package release, at or above distro_fixed) the device runs after a restart, so a restart alone fixes it; absent otherwise'),
  source: z.string().describe('Where the versions come from: "NVD affected versions", "CVE.org affected versions (from the CVE record\'s CNA)" when NVD has none, or with distro_fixed "Ubuntu security data" / "Debian Security Tracker" / "Alpine Linux security database"'),
})
export const KnownVersion = z.object({
  software: z.string().describe('Display name of the software the finding was matched on'),
  version: z.string(),
  source: z.enum(['agent', 'snmp', 'stated', 'scan', 'manual']).describe('Who gave the version: the device\'s agent, its answer to Vedette\'s SNMP read, its own statement on the network (LLDP), a network scan, or a person on the Devices page'),
  seen_at: iso.nullable().describe('When that source last gave the version: the agent\'s last list, the last scan or SNMP read that returned it, or when a person entered it; null when not known. Not the same as the finding\'s last_seen'),
}).describe('The version the box has for the matched software; the page says it and how a newer one reaches Vedette, never "find which version"')
export const FindingDetail = FindingRow.extend({
  known_version: KnownVersion.nullable().describe('Null when the matched software has no version or its source is not known'),
  suspected_why: z.string().nullable().describe('A suspected finding only: why it is not confirmed and what would confirm it, in words (who stated the version, whether a vulnerability check exists for the CVE and whether the scan reaches the device); null for any other status'),
  fixed_in: FixedIn.nullable().describe('The release that fixes this finding on this device, from the NVD affected versions; null = NVD gives none, the page shows CISA and the vendor advisory only'),
  pack: MitigationPack.nullable().describe('null = no recommendation confirmed by Vedette maintainers yet'),
  compromise: CompromiseCheck.nullable(),
  recheck: z.object({ steps: z.array(z.string()), code: z.string().optional() }),
  ai: z.object({ explain: AiResult.nullable(), config: AiResult.nullable() }),
  ai_available: z.object({ explain: z.boolean(), config: z.boolean() }).describe('Whether an AI profile is assigned and allowed for each job'),
  applied: z.array(AppliedEntry),
  hardening: GeneralHardening.nullable().describe('null when the confirmed pack has its own compromise signs, or mitigation is off'),
})
export const UncheckedAnswer = z.object({
  label: z.string().describe('The button: "Alpine Linux 3.23", "Another system", "Enter the package release"'),
  os: z.string().optional().describe('One click: PATCH /inventory/devices/{asset_id} {os} with this value (INV-41)'),
  ask: z.array(z.enum(['os', 'pkg_version'])).optional().describe('What the person types: os → PATCH /inventory/devices/{asset_id} {os}; pkg_version → PATCH /inventory/devices/{asset_id}/software/{software_id} {pkg_version} (the bare release or the line `apk info -e -v openssh-server` prints, "openssh-server-10.2_p1-r1"). "Another system" asks both: on a row a scan saw only the row\'s release rules it out'),
})
export const FindingList = z.object({ items: z.array(FindingRow) })

/** FIRST's EPSS probability from which a CVE is "likely to be exploited"; feeds.EPSSLikely on the box. */
export const EPSS_LIKELY = 0.1

/** Home's "Fix first" list and trend (#825): how many items and days the summary carries. */
export const SUMMARY_TOP = 5
export const SUMMARY_DAYS = 30
export const SummaryItem = z.object({
  id: z.string(), cve: z.string(), status: z.enum(['confirmed', 'suspected']).describe('Open findings only'), severity: Severity,
  urgency: z.number().int().min(1).max(5).describe('The finding\'s urgency layer, as FindingRow.urgency'),
  asset: FindingAsset.nullable().describe('null when the device was removed'),
  product: z.string().describe('The product as the findings list names it (the KEV display name, else "<vendor> <product>"; empty when the CVE is on no exploited list)'),
  software: z.string().describe('The device\'s software the exploited-list entry is keyed to, as the finding\'s page names it (e.g. "Windows Server 2025"); empty when not known. Home leads with it and keeps `product` as context'),
  ransomware: z.boolean().describe('The exploited list says ransomware campaigns use it'),
  source: z.enum(['cisa-kev', 'vulncheck-kev']).nullable().describe('Which exploited list names it; null when the CVE is on no list'),
  cvss: Cvss.nullable().describe('null = no score known: "No score", never 0'),
  first_seen: iso,
})
export const HomeSummary = z.object({
  open: z.object({
    total: z.number().int().describe('Open findings (confirmed + suspected): a device runs software a known vulnerability affects'),
    confirmed: z.number().int().describe('Of them, confirmed: by a scan, a person or the version the device itself reports'),
    devices: z.number().int().describe('Devices with at least one open finding'),
    ransomware: z.number().int().describe('Open findings whose CVE ransomware campaigns use'),
  }),
  top: z.array(SummaryItem).max(SUMMARY_TOP).describe('The open findings to fix first: the most urgent layer, then confirmed before suspected, then ransomware, then the highest CVSS (no score last), then the newest'),
  trend: z.array(z.number().int()).length(SUMMARY_DAYS).describe('Open findings at the end of each of the last 30 days of the organization time zone, oldest first; the last is now'),
  devices: z.object({ total: z.number().int().describe('Devices on the Devices page'), pending: z.number().int().describe('Devices waiting for review') }),
  alerts: z.object({ sent: z.number().int(), failed: z.number().int(), days: z.number().int() }).nullable().describe('Alert messages (incidents, vulnerabilities; not approval requests) sent and failed in the last `days` days; a failure resent later with success to the same channel is not counted as failed; null when Notifications is off'),
  incidents: z.object({ open: z.number().int().describe('Open incidents (new or acknowledged)'), urgent: z.number().int().describe('Of them, high or critical') }).nullable().describe('null when Notifications is off'),
  unchecked: z.object({ cves: z.number().int().describe('Distinct exploited CVEs in the Findings "could not be checked" list'), devices: z.number().int() }).describe('#910 phase 1'),
  generated_at: iso.describe('When the box computed this summary (it keeps it up to 60 s, and drops it at every finding change)'),
})

// ---------- The findings model: one row per (device, CVE, software line); one status per finding, computed on the server ----------
// Detection (whether and how we know), handling (what was done, by whom, how) and urgency (why it matters now) are three separate
// facts; the status code below is derived from them by one function on the server and rendered by one component in the GUI.

const cve = z.string().regex(/^CVE-\d{4}-\d{4,}$/)
/** The finding vocabulary lives in lib/statusCodes.ts so other contracts import the same lists. */
export const StatusCode = z.enum(FINDING_STATUSES).describe('under_attack = someone on your network sent this exploit and this device is affected (layer 1); exploited = attackers use it in real attacks (layer 2); public_exploit = working exploit code is public (layer 3); critical_edge = critical, no login needed, on a device class attackers target first (layer 4); update_recommended = a known flaw, no sign of exploitation yet (layer 5); patched, mitigated, accepted, not_relevant, false_positive = handled, as the handling resolution says')
export const OpenStatus = z.enum(OPEN_FINDING_STATUSES).describe('The open statuses: OPEN_FINDING_STATUSES[layer - 1]')
export const Resolution = z.enum(FINDING_RESOLUTIONS)
  .describe('patched = the fixed version is installed or the software is gone; mitigated = a workaround is in place, the flaw is still in the software; accepted = a person decided to live with it until a day; not_relevant = it does not apply to this device; false_positive = the match was wrong')
export const Via = z.enum(['person', 'version_moved', 'software_removed', 'distro_fixed', 'scan_clear', 'data_corrected', 'not_installed', 'outside_window'])
  .describe('How it was handled: person = a person marked it; version_moved = the software moved past the affected version (from_version, to_version); software_removed = the software is gone; distro_fixed = the distribution says the installed package is fixed; scan_clear = a safe check that had matched came back clear; data_corrected = no longer detected while nothing on the device changed (the match was corrected: never patch credit); not_installed = a person said the software is not installed; outside_window = the CVE left the reporting window (older than 12 months, not exploited in the wild: never patch credit; it opens again when the CVE is back inside it)')
export const Verified = z.enum(['no', 'device', 'scan', 'person'])
  .describe('no = not confirmed yet; device = the device itself reports the affected version (agent, SNMP, package list); scan = a safe check confirmed it; person = a person confirmed it')
export const Basis = z.enum(['scan', 'device_version', 'package', 'banner_version', 'statement', 'person'])
  .describe('What the match rests on: scan = a safe check; device_version = a version the device itself reports; package = a distribution package release; banner_version = a version read from a network banner; statement = a version a person typed for the device; person = a person said it is affected')
export const FixKind = z.enum(['update', 'distro_update', 'os_update', 'feature_update', 'restart', 'none_yet', 'unknown'])
  .describe('update = install `version` of the software or later; distro_update = install the distribution\'s package release `version` or later; os_update = install the operating system update `ref` (a KB number) or build `version`; feature_update = no update of this release fixes it, move to release `version`; restart = the fixed Linux kernel (package release `version`) is installed but the device still runs an older one: restart the device; none_yet = the vendor has no fix yet (`url` is the advisory); unknown = no fix data')
export const FixChannel = z.enum(['public', 'ubuntu_pro', 'esu'])
  .describe('Where the fix is published: public = the vendor\'s or the distribution\'s ordinary updates; ubuntu_pro = only Ubuntu Pro (ESM) has the fixed package (`sudo pro attach`, free for personal use on a few machines); esu = the fixing Windows build comes only with Extended Security Updates. A fix of another channel is its own "By fix" group')
export const SeverityBand = z.enum(['critical', 'high', 'medium', 'low', 'none'])
export const DeviceStatusCode = z.enum(DEVICE_STATUSES)
export const QuestionKind = z.enum(['version_needed', 'platform', 'package_release', 'not_comparable', 'no_range_data', 'older_line'])
  .describe('version_needed = the software has no version Vedette can read; platform = the CVE affects only some platforms and nothing says which this is; package_release = the distribution\'s package release decides; not_comparable = the version cannot be compared with the affected ranges; no_range_data = the CVE names the product but gives no versions that decide this one ("Possibly affected: check the version"; versions_listed says whether it lists any); older_line = the vendor names fixes for these CVEs only on newer release lines (fixes) and says nothing about the device\'s line (line): one question for all of them (cve_list)')
export const EventKind = z.enum(['created', 'confirmed', 'unconfirmed', 'handled', 'reopened', 'urgency_changed', 'fix_changed', 'redetected', 'no_longer_detected', 'acceptance_expired'])
/** Most findings one handle request may touch. */
export const MAX_HANDLE = 500
/** Cards (By device, By fix) or rows (Needs your input, Handled) of one page: the default and the largest. */
export const PAGE_DEFAULT = 20
export const PAGE_MAX = 100
/** Home's "Fix first" list and its trend. */
export const FIRST_TOP = 5
export const TREND_DAYS = 30

export const DeviceRef = z.object({
  id: z.string(),
  name: z.string().describe('The name the Devices page shows; never the internal id'),
  ip: z.string().nullable().describe('null when the device has no IP address'),
  kind: AssetKind,
  added: z.boolean().describe('false = "Not added yet": nobody added this device; its card offers Add device and Ignore'),
  ignored: z.boolean().describe('A person ignored the device: its findings are left out of every list and count except the Ignored devices tab'),
})
export const SoftwareRef = z.object({
  id: z.string().describe('The software line of the device (inventory)'),
  name: z.string().describe('Display name, as on the device page'),
  version: z.string().nullable().describe('The version the match compared'),
})
export const CveSeverity = z.object({
  band: SeverityBand,
  score: z.number().min(0).max(10),
  version: z.enum(['4.0', '3.1', '3.0', '2.0']),
  vector: z.string().min(1).max(200),
}).describe('The CVSS base score of the CVE and its band (the score the catalogue picks for it). Never changes the status. null = "Not scored yet", never 0')
export const Reason = z.object({
  layer: z.number().int().min(1).max(4),
  source: z.string().regex(/^[a-z0-9-]{1,40}$/).describe('The signal source: cisa-kev, msrc, chrome, cisco, fortinet, apple, android, rapid7, gti, nuclei, metasploit, exploit-db, github-poc; ids for an attack seen here (layer 1); cvss for layer 4 (computed)'),
  name: z.string().describe('The source as people name it: "CISA KEV", "Rapid7", "GitHub"'),
  date: z.iso.date().describe('When the source said so (or the box first saw it say so); layer 1: the newest alert; layer 4: since when the rule holds'),
  url: z.url().nullable(),
  detail: z.string().max(120).nullable().describe('A short fact of the signal: "244 stars" for a public exploit, the attacker address for layer 1; null when none'),
  due: z.iso.date().nullable().describe('Layer 2: the day the list asks for the fix (CISA KEV due date); null otherwise'),
}).describe('One urgency layer that applies, with its evidence')
export const Urgency = z.object({
  layer: z.number().int().min(1).max(5).describe('The most urgent layer that applies; the open status is OPEN_FINDING_STATUSES[layer - 1]'),
  since: iso.describe('When the finding entered this layer'),
  reasons: z.array(Reason).describe('Every layer 1 to 4 that applies, most urgent first, each source its own entry; empty for layer 5. The GUI says "not yet in CISA KEV" for a layer 2 without a cisa-kev entry'),
  internet: z.iso.date().nullable().describe('"Reachable from the Internet (seen <date>)": the day an exposure scan last saw the affected service from outside; raises the order inside a layer, never the layer'),
})
export const Verification = z.object({
  verified: Verified,
  basis: Basis,
  by: z.string().nullable().describe('verified person: who confirmed it, or whose entered version confirmed it (entered)'),
  entered: z.boolean().optional().describe('verified person: true when Vedette confirmed it because the version that person entered is affected, not a Confirm the person pressed ("Confirmed: the version <user> entered")'),
  at: iso.nullable().describe('When it was confirmed; null while not confirmed'),
}).describe('The second line under the status: "Confirmed by a safe check", "Confirmed: the device reports this version", "Confirmed by <user>", "Confirmed: the version <user> entered", "Not confirmed yet: based on a scan banner"')
export const Handled = z.object({
  resolution: Resolution,
  via: Via,
  by: z.string().describe('"system" when Vedette handled it; else the person (via version_moved too: a person changed the version they had entered)'),
  at: iso,
  note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('accepted: the last day; the finding reopens by itself after it. null otherwise'),
  from_version: z.string().nullable().describe('via version_moved: the version that was affected'),
  to_version: z.string().nullable().describe('via version_moved: the version now installed'),
}).describe('Who and how, from stored fields: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov)", "Mitigated by <user> (17 Nov): <note>"')
export const Reopened = z.object({
  why: z.enum(['still_detected', 'detected_again', 'acceptance_expired']).describe('still_detected = a person marked it patched and a newer reading still shows the affected version; detected_again = it came back after Vedette closed it; acceptance_expired = the accepted risk reached its last day'),
  at: iso.describe('still_detected, detected_again: the time of the reading; acceptance_expired: when it reopened'),
  by: z.string().nullable().describe('detected_again: the person whose version entry made it detected again (they set the version back); null when a source\'s reading did, and for the other reasons'),
}).describe('An open finding that was handled before: the line that says why it is open again')
export const Fix = z.object({
  key: z.string().min(1).max(400).describe('The "By fix" group (the same key on every device the same fix applies to); opaque'),
  kind: FixKind,
  product: z.string().describe('The product the fix is for, as people name it ("OpenSSH")'),
  version: z.string().nullable().describe('update, distro_update, feature_update: the version or release to install; os_update: the build when known; restart: the installed kernel\'s package release the device runs after the restart'),
  ref: z.string().nullable().describe('os_update: the KB number; none_yet: the advisory id when known'),
  channel: FixChannel,
  url: z.url().nullable().describe('The vendor advisory or release notes'),
})
export const CveRow = z.object({
  id: z.string().describe('The finding'),
  cve,
  status: StatusCode,
  severity: CveSeverity.nullable(),
  verified: Verified,
  safe_check: z.boolean().describe('A safe check exists for the CVE and can reach the device: a vulnerability check of the device can confirm it, rule it out, or see whether a fix holds'),
  urgency: Urgency.describe('The same urgency and reasons as the finding\'s View: the reasons line under the status'),
  verification: Verification.describe('The same verification as the finding\'s View: the confirmation line under the status'),
}).describe('One CVE of a list, a link to its finding, with the status lines its finding\'s page shows')
export const SeverityCounts = z.object({
  critical: z.number().int().min(0), high: z.number().int().min(0), medium: z.number().int().min(0), low: z.number().int().min(0),
  none: z.number().int().min(0), unscored: z.number().int().min(0).describe('No CVSS score yet'),
}).describe('Findings by severity band: "2 Critical · 18 High · 5 Medium"')
export const StatusCounts = z.object({
  under_attack: z.number().int().min(0), exploited: z.number().int().min(0), public_exploit: z.number().int().min(0),
  critical_edge: z.number().int().min(0), update_recommended: z.number().int().min(0),
}).describe('Open findings by status')
export const DeviceStatus = z.object({
  code: DeviceStatusCode,
  count: z.number().int().min(1).describe('An open status: distinct CVEs of the device at that status ("2 exploited"); possible: the possible CVEs of the device (CVEs Vedette cannot decide), those reported only for an older build included'),
  older_build: z.number().int().min(1).optional().describe('possible: how many of count are reported only for an older build ("3 possible · 2 older build"); absent when none'),
}).nullable().describe('The device badge: the most urgent open status of its findings with a count, else possible when only possible CVEs wait, else null. A link to the device\'s findings with that status. The Devices list, the device page and Home show the same value')
export const FixBlock = z.object({
  fix: Fix,
  software: SoftwareRef.nullable().describe('The software line the fix is for; null only for a safe-check finding on a device with no row for that product'),
  status: OpenStatus.describe('The most urgent status inside the block'),
  cause: cve.describe('The CVE that gives the block its status'),
  severity: SeverityCounts,
  findings: z.array(CveRow).min(1).describe('Every open finding of the block, the most severe first (no score last), then the most urgent, then the CVE id'),
}).describe('One fix on one device: "Update OpenSSH 10.2p1 → 10.6: fixes 25 CVEs"; "No fix known yet" when fix.kind is none_yet')
export const DeviceCard = z.object({
  device: DeviceRef,
  status: DeviceStatus,
  counts: StatusCounts,
  findings: z.number().int().min(1).describe('Open findings of the device'),
  cves: z.number().int().min(1).describe('Distinct CVEs among them (a CVE on two software lines is two findings, one CVE)'),
  blocks: z.array(FixBlock).min(1).describe('The most urgent first, then the most findings'),
})
export const DeviceCards = z.object({
  items: z.array(DeviceCard),
  total: z.number().int().min(0).describe('Devices that match, every page'),
  findings: z.number().int().min(0).describe('Open findings of those devices, every page: equals the sum over By fix and Overview.open.findings for the same filter'),
})
export const FixDevice = z.object({
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  status: OpenStatus,
  severity: SeverityCounts,
  findings: z.number().int().min(1),
  others: z.array(Fix).describe('The fixes of the other steps for the same software line on this device, the most findings first: a line is in several steps only when no single release is known to fix all of its CVEs (or some name no release). Empty when this step is the line\'s only one'),
})
export const FixCard = z.object({
  fix: Fix,
  status: OpenStatus.describe('The most urgent status inside the card'),
  cause: cve,
  devices: z.number().int().min(1),
  findings: z.number().int().min(1),
  severity: SeverityCounts,
  items: z.array(FixDevice).min(1).describe('Every device the fix applies to, the most urgent first. A device\'s CVEs: its card in GET /findings/devices?device=<id> (the block with the same fix key)'),
}).describe('One fix across devices: "Update OpenSSH to 10.6: 3 devices, 61 findings"')
export const FixCards = z.object({
  items: z.array(FixCard),
  total: z.number().int().min(0).describe('Fixes that match, every page'),
  findings: z.number().int().min(0).describe('Open findings of those fixes, every page'),
})
export const InputUnchecked = z.object({
  kind: z.literal('device_unchecked'),
  id: z.string().describe('The item'),
  device: DeviceRef,
}).describe('A device a person added that Vedette cannot check (an entry of a device card): it knows no software, firmware or OS the device runs, so no finding can appear for it. Answered by saying what runs there: its firmware version (POST /inventory/devices/{id}/software), SNMP read access (Sources), or an agent')
export const InputUnconfirmed = z.object({
  kind: z.literal('unconfirmed'),
  id: z.string().describe('The finding'),
  cve,
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  status: z.enum(['under_attack', 'exploited', 'public_exploit', 'critical_edge']).describe('Only layers 1 to 4 ask for confirmation; update_recommended never does'),
  severity: CveSeverity.nullable(),
  basis: Basis,
  safe_check: z.boolean().describe('A safe check exists for the CVE and can reach the device: "Run the safe check" (POST /scans/runs) comes first'),
}).describe('An urgent finding not confirmed yet: Run the safe check, Confirm vulnerability (POST /findings/{id}/verify) or Not affected (POST /findings/handle)')
export const InputQuestion = z.object({
  kind: z.literal('question'),
  id: z.string().describe('The question'),
  question: QuestionKind,
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  cve: cve.nullable().describe('The CVE the question is about; null when it decides several (version_needed, not_comparable)'),
  cves: z.number().int().min(1).describe('CVEs that wait on the answer'),
  asked_at: iso,
  url: z.url().nullable().describe('The advisory to read'),
  command: z.string().nullable().describe('What prints the answer on the device ("apk info -e -v openssh-server"); null when none'),
  choices: z.array(UncheckedAnswer).describe('platform, package_release: the answers, each an inventory correction; empty for the other kinds (version_needed, not_comparable: type the version on the software line; no_range_data, older_line: POST /findings/questions/{id}/answer)'),
  cve_list: z.array(cve).describe('older_line, version_needed: the CVEs that wait on the answer; empty when the question is about one CVE (cve)'),
  fixes: z.array(z.string()).describe('older_line: the newest release the vendor names as fixed on each newer line, oldest line first ("7.3.2-86009 Update 5"); empty for the other kinds'),
  line: z.string().nullable().describe('older_line: the release line the device runs ("7.2.1"); null for the other kinds'),
  versions_listed: z.boolean().describe('no_range_data: true when the CVE lists affected versions of the software but none that decides this one (only exact releases, or no end); false when it lists none. false for the other kinds'),
  attribute: z.enum(['edition', 'architecture', 'platform', 'unlisted_line']).nullable().describe('not_comparable: the build attribute NVD pins that decides the CVE and Vedette could not derive from what it knows (edition: ESR or the normal release; architecture: the 64-bit or 32-bit build; platform: the system the build is for), or unlisted_line: the build is a Mozilla ESR of an end-of-life line the CVE\'s ESR rows do not list, so whether that line is affected is unknown. The question asks for it, not for the version, and is answered per CVE (POST /findings/questions/{id}/answer). null when the version is what cannot be compared, and for the other kinds'),
}).describe('What Vedette cannot decide without a person')
export const InputSoftwareGroup = z.object({
  kind: z.literal('software_group'),
  id: z.string().describe('"sw:<software line id>"'),
  software: SoftwareRef.nullable(),
  cves: z.number().int().min(1).describe('CVEs that wait on this software line, each counted once'),
  questions: z.array(InputQuestion).min(1).describe('The line\'s questions, one per (CVE, kind): the one whose action fixes the most first (version_needed, not_comparable, platform, package_release, older_line, no_range_data), then by CVEs waiting. The version or edition a person enters lives on the line, so one entry fixes every CVE of it at the next match; each CVE\'s Affected / Not affected is its own question'),
}).describe('One software line of a device inside its card: "Thunderbird 115.9.0: 196 CVEs waiting" with its one action; the per-CVE detail is behind a click')
export const InputItem = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('device_not_added'),
    id: z.string().describe('The item: "device:<device id>"'),
    device: DeviceRef,
    status: DeviceStatus,
    findings: z.number().int().min(1),
  }).describe('A device nobody added has open findings: Add device (POST /inventory/devices/{id}/approve) or Ignore (POST /inventory/devices/{id}/ignore)'),
  z.object({
    kind: z.literal('devices_not_added'),
    id: z.literal('devices_not_added').describe('The item'),
    count: z.number().int().min(1).describe('Devices in the Devices list\'s To review that have no open finding'),
  }).describe('One card for every device nobody added yet that has no open finding, after the unconfirmed findings and the questions; it counts as one item. Review opens the Devices list\'s To review (/devices?tab=review), where each is added or ignored. Not in a queue read for one device or by a search'),
  z.object({
    kind: z.literal('device_needs'),
    id: z.string().describe('The card: "needs:<device id>"'),
    device: DeviceRef,
    entries: z.array(z.discriminatedUnion('kind', [InputUnchecked, InputUnconfirmed, InputSoftwareGroup])).min(1).describe('What Vedette needs to know about the device: what runs there (device_unchecked), urgent findings not confirmed yet (unconfirmed), then its software lines by CVEs waiting (software_group)'),
  }).describe('One card per added device: everything Vedette needs from a person about it, the questions grouped by software line. Ignore for the whole device: POST /findings/questions/ignore'),
])
export const InputList = z.object({
  items: z.array(InputItem).describe('Devices not added yet first, then one card per added device (what runs there, urgent findings not confirmed, its questions grouped by software line) by what waits, then the one card of the devices not added yet with no open finding; an item leaves the moment it is answered or stops being true'),
  total: z.number().int().min(0).describe('The queue length: the tab count'),
})
export const CheckSource = z.object({
  url: z.string(), title: z.string().optional(), status: z.enum(['ok', 'failed', 'skipped']), note: z.string().optional().describe('Why it was not read'),
  cited: z.boolean().optional().describe('The verdict\'s quote is from this page'),
}).describe('One reference page a check read or tried to')
export const AiReading = z.object({
  status: z.enum(['affected', 'fixed', 'not_affected', 'unsure']).describe('What the AI read the vendor states for the release line: affected, fixed (in fixed_in), not affected, or unsure'),
  line: z.string().describe('The release line the reading is keyed by (the product\'s scheme line, else the version)'),
  stated_line: z.string().nullable().describe('The release line as the AI wrote it; it extends the reading to other versions of that line only when the quote names it'),
  introduced: z.string().nullable().describe('The first affected release; null unless the quote names it'),
  fixed_in: z.string().nullable().describe('The release that fixes it; null unless the quote names it (only then is it the finding\'s fix)'),
  last_affected: z.string().nullable().describe('The last affected release; null unless the quote names it'),
  host: z.string().nullable().describe('The host of the page the quote is from; null when it is from the CVE record'),
  vendor_page: z.boolean().describe('The page is the vendor\'s own advisory: only then may "not affected" settle the CVE (never an exploited one)'),
  quote_found: z.boolean().describe('The box found the quote word for word in the page text it fetched itself; a reading whose quote was not found decides nothing'),
}).describe('The AI\'s reading of the vendor\'s statement for one release line, as the box checked it; applied to every device and version on that line')
export const PossibleCause = z.enum(['vendor_silent', 'page_unreadable', 'needs_reading', 'ai_unsure', 'ai_budget', 'identity_unproven', 'version_needed', 'pending_nvd', 'needs_person', 'distro_silent'])
  .describe('Why the CVE is still possible and what would decide it: vendor_silent (no vendor page states more than the record), page_unreadable (the pages could not be read), needs_reading (the vendor\'s advisory must be read: no AI set up, or the reading is still to come), ai_unsure (the AI could not tell, or its quote was not in the page), ai_budget (the AI\'s reading waits for the budget), identity_unproven (the software is not tied to a product the records name), version_needed (the version, build, edition, system or package release is needed), pending_nvd (NVD has not listed the affected versions yet), needs_person (a person decides: an exploited CVE read not affected, or a rejected reading), distro_silent (a distribution\'s package is judged by the distribution\'s word alone, and its security data has no word on the package for the CVE; the undecided reason says why)')
export const PossibleCheck = z.object({
  key: z.string().describe('The evidence identity the check is stored under (reject: POST /findings/possible/checks/{key}/reject)'),
  decided_by: z.enum(['structured', 'advisory', 'ai']).describe('advisory: the box read the vendor\'s advisory and its ranges decided (applied without a person); ai: the AI read the pages, a proposal a person confirms or rejects'),
  verdict: z.enum(['affected', 'not_affected', 'unsure']),
  confidence: z.enum(['confident', 'likely']).nullable().describe('ai only: confident when the AI\'s quote is in the page word for word and names a release range of this version\'s line; likely otherwise. null for the box\'s own verdicts and for unsure'),
  reason: z.string(), quote: z.string().describe('The sentence the verdict rests on, as the page writes it; "" when none'),
  sources: z.array(CheckSource), model: z.string().nullable().describe('ai only: the model'), checked_by: z.string(), checked_at: iso,
  rejected: z.boolean().describe('A person rejected this AI proposal or reading: the CVE is possible again'),
  reading: AiReading.nullable().describe('The AI\'s reading of the vendor\'s statement for the line this check shows (key: the reading); null for a check of one version'),
}).describe('A check of a possible CVE\'s advisories')
export const AnsweredQuestion = z.object({
  id: z.string().describe('The question'),
  question: QuestionKind,
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  cve: cve.nullable(),
  cves: z.number().int().min(1),
  answer: z.literal('not_affected'),
  by: z.string().describe('Who answered'),
  at: iso,
  check: PossibleCheck.nullable().describe('The check of its evidence stored by the time of the answer (a later one, made for another device sharing the evidence, is not what the person answered): decided_by ai when the answer is a confirmed AI proposal (its pages and model); null when none'),
}).describe('A question a person answered "not affected": no finding records it, so it is listed here and can be asked again')
export const AnsweredList = z.object({
  items: z.array(AnsweredQuestion).describe('The newest answer first'),
  total: z.number().int().min(0),
})
export const HandledRow = z.object({
  id: z.string(),
  cve,
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  status: Resolution,
  severity: CveSeverity.nullable(),
  handled: Handled,
})
export const HandledList = z.object({
  items: z.array(HandledRow).describe('The newest handling first'),
  total: z.number().int().min(0),
  corrections: z.number().int().min(0).describe('Findings Vedette closed itself because it corrected its own match (via data_corrected, by Vedette) that the same filters select: left out unless corrections=true, counted here either way'),
})
export const FindingEvent = z.object({
  ts: iso,
  actor: z.string().describe('"system" or the person'),
  kind: EventKind,
  layer: z.number().int().min(1).max(5).nullable().describe('urgency_changed: the new layer'),
  resolution: Resolution.nullable().describe('handled: the resolution'),
  via: Via.nullable().describe('handled: how'),
  note: z.string().nullable(),
})
export const AiIdentity = z.object({
  method: z.literal('ai'),
  title: z.string().describe('The readable name of the catalogue product the AI chose ("Identified by AI as <title>")'),
  vendor: z.string(),
  product: z.string().describe('The catalogue product as the CVE data writes it (vendor and product of a CPE, or a CVE record\'s product key)'),
  reason: z.string().max(200).describe('The AI\'s reason; "" when the choice is no longer stored'),
  model: z.string().describe('The model that chose; "" when the choice is no longer stored'),
}).describe('The software of the finding is named by no standard data; the customer\'s AI chose its product among candidates the box generated from its own catalogue, and the version is inside that product\'s affected range. A person can say "Not this product" (POST /findings/{id}/identity/reject)')
export const View = z.object({
  id: z.string(),
  cve,
  device: DeviceRef,
  software: SoftwareRef.nullable(),
  status: StatusCode,
  urgency: Urgency.describe('Kept while handled: the layer the finding had'),
  severity: CveSeverity.nullable(),
  verification: Verification,
  handled: Handled.nullable().describe('null while open'),
  reopened: Reopened.nullable().describe('null unless the finding is open again after a handling'),
  fix: Fix,
  same_cve: z.array(z.object({ id: z.string(), software: SoftwareRef.nullable(), status: StatusCode })).describe('The other findings of this CVE on this device (another software line, as Java 8 beside Java 21): handling the CVE from this page acts on them too and says how many'),
  first_seen: iso,
  last_seen: iso.describe('The last match that still detected it'),
  events: z.array(FindingEvent).describe('Oldest first, append-only'),
  ai_check: PossibleCheck.nullable().describe('A finding a person confirmed from an AI proposal, or one the AI\'s reading of the vendor\'s statement opened (range origin ai_read, reading set: labelled "Read by AI from <host>", rejected in one click): the AI\'s check it rests on (the pages it read, its quote, the model; its confirmation level still comes from how the version is known). null for any other finding'),
  identity: AiIdentity.nullable().describe('A finding opened through the AI\'s identification of its software: labelled "Identified by AI as <title>", with "Not this product". null for any other finding'),
}).describe('A finding as every place shows it: lists, the finding page, the device page, Home, reports, notices and the AI read the same fields')
export const FirstItem = z.object({ device: DeviceRef, block: FixBlock })
export const FirstRunSummary = z.object({
  id: z.string().describe('The first summary of the load (a notice id)'),
  load: z.enum(['install', 'catalogue', 'source']).describe("install: Vedette's own first look at the network (the first 36 hours); catalogue: the first load of its catalogue of vulnerabilities; source: the first load of a source of exploitation news"),
  title: z.string().describe('The first summary\'s title as the message said it ("Patch first: 7 urgent findings on 3 devices")'),
  made_at: iso.describe('When the summary was made (the first rating of its load)'),
  state: z.enum(['sent', 'waiting', 'not_sent']).describe('sent: a channel delivered it; waiting: queued (it waits a few minutes for the rest of its load, for quiet hours, or for the next deliver run); not_sent: no channel took it or every channel failed'),
  sent_at: iso.nullable().describe('sent: the first delivery'),
  channels: z.array(z.string()).describe('sent: the channels that delivered it (telegram, slack, zalo, zalo-personal, email, webhook)'),
  due_at: iso.nullable().describe('waiting: when it goes out'),
  quiet: z.boolean().describe('waiting: only quiet hours hold it'),
  not_sent: z.string().nullable().describe('not_sent: why, as the alert history says it'),
  reason: z.string().nullable().describe('not_sent: the reason code of the alert history (no_channel, channels_off, below_min_severity, failed, ...)'),
  link: z.string().describe('The findings list of every summary of the load: /findings?tab=device&status=<the statuses they named>'),
  later: z.number().int().min(0).describe('Summaries of the same load made after the first ("N more urgent findings ... to patch first")'),
  later_title: z.string().nullable().describe('The newest of them; null when later is 0'),
}).describe('The first-run summary of the newest load made in the last 7 days')
export const Undecided = z.object({
  reason: z.enum(['no_version', 'platform_unknown', 'package_unknown', 'attribute_unknown', 'version_scheme_mismatch', 'nvd_pending', 'no_ranges', 'product_not_named',
    'named_as_platform_only', 'exact_releases_only', 'ranges_do_not_decide', 'ranges_start_at_branch_only', 'eol_line_unlisted', 'third_party_tested_build', 'no_reference_page', 'fetch_failed', 'unparsed_vendor_text', 'ai_unsure',
    'version_from_network', 'distro_not_listed', 'distro_other_packages', 'distro_other_releases', 'distro_other_build', 'distro_no_data', 'distro_triage'])
    .describe('Why Vedette could not decide the CVE, machine-readable: an audit groups the undecided cases by it. version_from_network: only a version read from the network, which a CVE on no exploited list is not compared with. The distribution\'s silence on its own package (cause distro_silent): distro_not_listed (no row of the CVE), distro_triage (the distribution states it is still triaging the CVE for this package and release), distro_other_packages (rows for other packages only), distro_other_releases (rows for other releases only), distro_other_build (its row is about another build), distro_no_data (no security data of that distribution)'),
  ranges: z.array(z.string()).optional().describe('The range rows that were read and did not decide it ("<cpe> [start, end)"), at most 20'),
  text: z.string().optional().describe('Up to 500 characters of advisory text the box could not read as ranges'),
  url: z.string().optional().describe('The page text is from'),
}).describe('Why a CVE stays possible and what blocked the decision')
export const PossibleHeld = z.object({
  until: iso.describe('The automatic reading reads it again after this time; a person\'s check reads it at once'),
  reason: z.enum(['hook_refused', 'answer_unusable', 'ai_failed'])
    .describe('Why its last AI call gave no reading: hook_refused (a hook stopped the text sent), answer_unusable (the answer was outside the format or cut off), ai_failed (the AI provider failed, or the hooks could not finish in time)'),
}).describe('The automatic AI reading leaves this CVE until a time, and why')
export const PossibleOlderBuild = z.object({
  tested: z.array(z.string()).min(1).describe('The builds the third party reported, as its rows write them ("5.4.0"); each older than the release the device runs'),
  year: z.number().int().describe('The year of the report: the year of the CVE id'),
}).describe('Reported only for an older build: a third party lists the builds it tested, every one older than the installed release; the CVE is on no exploited list and its record gives no fix, workaround or reference from the vendor. It stays possible and is listed and counted apart')
export const PossibleRow = z.object({
  id: z.string().describe('The question (confirm: POST /findings/possible/{id}/confirm; answer: POST /findings/questions/{id}/answer)'),
  cve, kind: QuestionKind, device: DeviceRef, software: SoftwareRef.nullable(), severity: CveSeverity.nullable(),
  exploited: z.boolean().describe('The CVE is on an exploited list'),
  state: z.enum(['possible', 'proposal', 'settled']).describe('possible: undecided; proposal: an AI proposal waits for a person; settled: the box settled it not affected from the vendor\'s advisory (not counted)'),
  undecided: Undecided, line: z.string().nullable().describe('older_line: the device\'s release line'), fixes: z.array(z.string()).describe('older_line: the newest fixed release of each newer line'),
  check: PossibleCheck.nullable(), checkable: z.boolean().describe('A check of its advisories can still run for it'),
  bulk: z.boolean().describe('proposal: may be confirmed with its class in one step; false for an exploited CVE proposed not affected (one by one)'),
  cause: PossibleCause.nullable().describe('Why it is still possible; null for a settled row'),
  held: PossibleHeld.nullable().describe('The automatic AI reading leaves it for now (its last call was refused or failed); null when not held, settled, or while the automatic reading cannot run (switched off, today\'s reads used up, no AI profile)'),
  older_build: PossibleOlderBuild.nullable().describe('Reported only for an older build: listed apart, counted in counts.older_build, not in counts.possible; null otherwise'),
  distro_pending: z.boolean().describe('Waiting for the distribution\'s word on its own package: listed apart in its own group, counted in counts.distro_pending, not in counts.possible, Needs your input or the device badge (the server\'s one definition of the group)'),
}).describe('One possible CVE of one software line of one device')
export const PossibleCounts = z.object({
  possible: z.number().int().min(0).describe('Possible CVEs, proposals included (each (device, line, CVE) once), but those reported only for an older build and those waiting for the distribution'),
  older_build: z.number().int().min(0).describe('Possible CVEs reported only for an older build (PossibleRow.older_build), counted apart from possible'),
  distro_pending: z.number().int().min(0).describe('Possible CVEs waiting for the distribution\'s word on its own package (PossibleRow.cause distro_silent), counted apart from possible and its causes and left out of the device badge'),
  distro_pending_exploited: z.number().int().min(0).describe('How many of distro_pending are on an exploited list'),
  proposals: z.number().int().min(0).describe('AI proposals waiting for a person'),
  unchecked: z.number().int().min(0).describe('Possible CVEs a check can still look at, those reported only for an older build included: what the "Check possible with AI" button counts'),
  settled: z.number().int().min(0).describe('Settled not affected by the box from a vendor\'s advisory'),
  causes: z.object(Object.fromEntries(PossibleCause.options.map((c) => [c, z.number().int().min(0)])) as Record<z.infer<typeof PossibleCause>, z.ZodNumber>)
    .describe('The possible CVEs of possible by cause; every cause of the list is present'),
})
export const PossibleCheckRun = z.object({
  running: z.boolean(), total: z.number().int().min(0), done: z.number().int().min(0),
  advisory: z.number().int().min(0).describe('Decided by the box from a vendor\'s advisory, no AI'),
  proposals: z.number().int().min(0).describe('AI proposals made'),
  readings: z.number().int().min(0).describe('AI readings of a vendor\'s statement stored, one per release line'), undecided: z.number().int().min(0), failed: z.number().int().min(0).describe('Not checked: a page or AI call failed; the next check asks again'),
  stopped: z.string().nullable().describe('Why the check stopped before the end (the AI unavailable, the budget reached)'),
  by: z.string(), started_at: iso, finished_at: iso.nullable(),
})
export const PossibleCheckState = z.object({
  ready: z.boolean().describe('A check can run now (the AI assistant on, a profile for explaining findings)'),
  reason: z.string().nullable().describe('Why not, when ready is false'),
  run: PossibleCheckRun.nullable().describe('The last check since the box started; null when none'),
})
export const PossibleList = z.object({
  items: z.array(PossibleRow).describe('Grouped by device, then software line, exploited CVEs first'),
  total: z.number().int().min(0).describe('Rows that match, every page'),
  counts: PossibleCounts.describe('Of the device, or of every device; not narrowed by the search or the state'),
})
export const UndecidedGroup = z.object({
  reason: Undecided.shape.reason, count: z.number().int().min(0),
  examples: z.array(z.string()).describe('Distinct blocking rows or advisory snippets (with their address), at most 20'),
})
const coverageCount = z.number().int().min(0)
export const Coverage = z.object({
  at: iso.nullable().describe('When the match pass ended; null when no pass was counted yet (every count 0)'),
  devices: coverageCount.describe('Devices the pass matched (a device the pass found unchanged keeps the counts of its last full match)'),
  lines: coverageCount.describe('Their software lines, and the network OS a device states without one'),
  pairs: coverageCount.describe('(software line, CVE) pairs the catalogue relates on them'),
  outside_window: coverageCount.describe('CVEs naming a product the devices run that the pass set aside as outside the reporting window (published before the last 12 months, no evidence of exploitation in the wild, no public exploit in that time): not judged, so neither decided nor undecided and not in pairs. 0 while CVEs of every age are reported'),
  decided: z.array(z.object({
    by: z.string().max(64).describe('The source whose data decided: a range origin (nvd, cna, adp, distro, vendor_line, advisory, ai_confirmed, person, scan) or platform_list (the hand list of platform limits), or distro_no_fix (the distribution lists the package affected with no fix yet for a CVE on no exploited list: affected, no finding until the fix or an exploited list comes)'),
    affected: coverageCount, not_affected: coverageCount,
  })).describe('Decided pairs by source, the most first'),
  possible: z.array(z.object({
    cause: z.string().max(64).describe('The cause of a possible CVE (PossibleCause: vendor_silent, page_unreadable, needs_reading, ai_unsure, ai_budget, identity_unproven, version_needed, pending_nvd, needs_person, distro_silent), why a distribution\'s package its distribution\'s data has no word on stays undecided with no question (distro_other_packages, distro_other_releases: the distribution lists the CVE for other packages or releases only; distro_other_build: its row is about another build; distro_not_listed: no row of the CVE; distro_triage: the distribution states it is still triaging the CVE for this package; distro_no_data: no data of that distribution; version_needed: the agent gave no package release), or an unnamed class: pairs the matcher reached and neither decided nor asked about, so nobody is told why (other_distro_silent: a distribution\'s package its data has no word on; other_record_unread: the rows name the product and give nothing the matcher compares; other_dropped: matched on the name alone or an old entry, not listed). A pass counted before causes were kept names an undecided reason (Undecided.reason), ai_proposal or other here'),
    count: coverageCount,
    details: z.array(z.object({
      detail: z.string().max(64).describe('The matcher\'s own reason: an undecided reason (Undecided.reason, such as version_scheme_mismatch or exact_releases_only), else the question\'s kind'),
      count: coverageCount,
    })).describe('The same pairs by the matcher\'s own reason, the most first; empty for an unnamed class and for a pass counted before details were kept'),
  })).describe('Undecided pairs by cause, the most first'),
  identity: z.array(z.object({
    method: z.enum(['stated', 'catalogue', 'record', 'ai', 'ai_family', 'none']).describe('stated: the source states the product (a CPE, a distribution package); catalogue: the product catalogue names it; record: its own name reaches a CVE record or NVD row; ai: the customer\'s AI chose its product among the catalogue\'s; ai_family: the AI said it is only a part of a catalogue product\'s family (an agent, a client), which opens no finding; none: nothing in the catalogue is matched to it'),
    lines: coverageCount,
  })).describe('Software lines by how the box knows what product they are'),
}).describe('Decision coverage of the last match pass: what decided each related (line, CVE) pair, why the rest is undecided, and how each line is identified. Counts only, no device data')
export const Overview = z.object({
  open: z.object({
    findings: z.number().int().min(0).describe('Open findings on devices that are not ignored'),
    by_status: StatusCounts,
  }),
  devices: z.object({
    total: z.number().int().min(0).describe('Devices on the Devices page'),
    not_added: z.number().int().min(0).describe('Devices nobody added yet'),
    by_status: z.object({
      under_attack: z.number().int().min(0), exploited: z.number().int().min(0), public_exploit: z.number().int().min(0),
      critical_edge: z.number().int().min(0), update_recommended: z.number().int().min(0), possible: z.number().int().min(0),
    }).describe('Devices by their badge (DeviceStatus.code)'),
    affected: StatusCounts.describe('Devices with an open finding by their most urgent status, the Vedette box included (it carries no badge, but its findings count like any device\'s): "3 open findings on 1 device"'),
  }),
  possible: PossibleCounts.describe('Possible CVEs (Vedette cannot decide them), counted apart from the open findings: "158 open findings · 16 possible"'),
  input: z.number().int().min(0).describe('Devices that wait for an answer in Needs your input: one per device card or device not added that has findings; the one card of devices not added with no finding is a review and is not counted'),
  first: z.array(FirstItem).max(FIRST_TOP).describe('Fix first: the most urgent fix blocks across devices, then the most findings'),
  trend: z.array(z.number().int().min(0)).length(TREND_DAYS).describe('Open findings at the end of each of the last 30 days of the organization time zone, oldest first; the last is now'),
  trend_start: z.iso.date().describe('The first day of the trend that holds data, in the organization time zone: the first of the 30 days, or the day this box began keeping findings when that is later. The days before it are not drawn or compared'),
  alerts: HomeSummary.shape.alerts,
  incidents: HomeSummary.shape.incidents,
  first_run_summary: FirstRunSummary.nullable().describe('null when there is none in the last 7 days, or Notifications is off'),
  generated_at: iso,
}).describe('Home at a glance, from the same status function as the lists')

// Query parameters of the paged lists (API_CONVENTIONS section 4: offset and limit, a numbered pager).
const offset = z.string().regex(/^[0-9]{1,6}$/).optional().describe('Items to skip (default 0)')
const limit = z.string().regex(/^[0-9]{1,3}$/).optional().describe(`Items of the page, 1 to ${PAGE_MAX} (default ${PAGE_DEFAULT}; above: ${PAGE_MAX})`)
const q = z.string().max(200).optional().describe('Search: device name or address, software, CVE id')
const statusFilter = z.string().max(200).optional().describe('Comma-separated open statuses (OpenStatus); an unknown value: 400 bad_filter')
const deviceFilter = z.string().max(96).optional().describe('One device')
const handleNote = z.string().max(500).describe('Required (at least 3 characters) for false_positive, not_relevant and accepted')

const idParams = z.object({ id: findingId })

export const endpoints = defineEndpoints([
  // The findings model: lists grouped on the server, the finding's View, handling, Home.
  { method: 'get', path: '/findings/devices', summary: 'By device: one card per device with open findings (devices not added yet included, ignored ones only with ignored=true), the most urgent first; inside, one block per fix with its CVEs', stories: ['S-MIT-1', 'S-TIER-1'], role: 'viewer',
    query: z.object({ q, status: statusFilter, device: deviceFilter.describe('One device: its Findings tab'),
      devices: z.string().max(PAGE_MAX * 97).regex(/^[^,]{1,96}(,[^,]{1,96})*$/).optional().describe(`Comma-separated device ids, at most ${PAGE_MAX}: only these devices (more: 400 bad_filter)`),
      cve: cve.optional().describe('Only the open findings of exactly this CVE, in the blocks the list shows without it'),
      ignored: z.enum(['true', 'false']).optional().describe('true: only ignored devices (the Ignored devices tab); default false: none of them'), offset, limit }),
    response: DeviceCards, example: { query: {} } },
  { method: 'get', path: '/findings/fixes', summary: 'By fix: one card per fix across devices (ignored devices left out), the most urgent first, each with the devices it applies to', stories: ['S-MIT-1', 'S-TIER-1'], role: 'viewer',
    query: z.object({ q, status: statusFilter, offset, limit }), response: FixCards, example: { query: {} } },
  { method: 'get', path: '/findings/input', summary: 'Needs your input: devices not added yet that have findings, urgent findings not confirmed yet, and questions only a person can answer; one queue', stories: ['S-MIT-1', 'S-INV-3'], role: 'viewer',
    query: z.object({ q, device: deviceFilter, offset, limit }), response: InputList, example: { query: {} } },
  { method: 'get', path: '/findings/possible', summary: 'Possible findings: CVEs of software the devices run that Vedette cannot decide (ignored devices left out), each with why it is undecided and any check of its advisories; never part of the open totals. A finding of the same device, CVE and line wins', stories: ['S-MIT-1'], role: 'viewer',
    query: z.object({ q, device: deviceFilter, state: z.enum(['possible', 'proposal', 'settled']).optional().describe('One state; absent: every row but the settled ones'), offset, limit }),
    response: PossibleList, example: { query: {} } },
  { method: 'get', path: '/findings/possible/audit', summary: 'Every possible CVE grouped by why it is undecided, with the rows or advisory text that blocked the decision: what to teach the box to decide by itself', stories: ['S-MIT-1'], role: 'viewer',
    response: z.object({ groups: z.array(UndecidedGroup) }) },
  { method: 'get', path: '/findings/coverage', summary: 'Decision coverage of the last match pass: pairs decided by source, undecided by cause, lines by identity method', stories: ['S-MIT-1'], role: 'admin',
    response: Coverage, example: { query: {} } },
  { method: 'get', path: '/findings/possible/check', summary: 'Whether a check of possible findings can run, and how the last one stands', stories: ['S-MIT-1'], role: 'viewer', response: PossibleCheckState },
  { method: 'post', path: '/findings/possible/check', summary: 'Check possible findings (of one device, or all): in the background, each possible CVE with no check yet (at most 40 evidence identities), once per evidence: the box reads the CVE\'s reference pages itself and decides when the vendor\'s ranges do; only the rest goes to the AI, whose verdicts are proposals a person confirms. 409 ai_unavailable, check_running, nothing_to_check. Audit findings.possible_checked', stories: ['S-MIT-1'], role: 'operator',
    body: z.object({ device: z.string().max(96).optional() }), response: PossibleCheckRun },
  { method: 'post', path: '/findings/possible/{id}/confirm', summary: 'Confirm the AI proposal of one possible CVE (the question): affected records the finding, its confirmation from who stated the version, never from the AI (admin, as answering affected); not affected answers the question not affected (operator). 404 not_found when there is no waiting proposal. Audit findings.proposal_confirmed', stories: ['S-MIT-1'], role: 'operator',
    params: z.object({ id: z.string().min(1).max(96) }), response: z.object({ finding: z.string().nullable().describe('affected: the finding') }) },
  { method: 'post', path: '/findings/possible/confirm', summary: 'Confirm every AI proposal of one class (verdict and confidence) at once, of one device or all, at most 500; an exploited CVE proposed not affected is never among them. affected needs an admin', stories: ['S-MIT-1'], role: 'operator',
    body: z.object({ verdict: z.enum(['affected', 'not_affected']), confidence: z.enum(['confident', 'likely']), device: z.string().max(96).optional() }),
    response: z.object({ confirmed: z.number().int().min(0) }) },
  { method: 'post', path: '/findings/possible/checks/{key}/reject', summary: 'Reject an AI proposal, or the AI\'s reading of a vendor\'s statement (the key of a check or of a reading): it stays stored (the same evidence or page is never applied again) and the CVE is possible again on every device that shares it; a finding the reading opened closes at once (every device on the line is matched again). Audit findings.proposal_rejected or findings.ai_reading_rejected', stories: ['S-MIT-1'], role: 'operator',
    params: z.object({ key: z.string().regex(/^[0-9a-f]{64}$/) }), response: z.object({ ok: z.literal(true) }) },
  { method: 'get', path: '/findings/answered', summary: 'The questions a person answered "not affected" (ignored devices left out), the newest first: each can be asked again', stories: ['S-MIT-1'], role: 'viewer',
    query: z.object({ device: deviceFilter, offset, limit }), response: AnsweredList, example: { query: {} } },
  { method: 'get', path: '/findings/handled', summary: 'Handled: findings by handling, the newest first, each with who and how', stories: ['S-MIT-1'], role: 'viewer',
    query: z.object({ q, resolution: z.string().max(200).optional().describe('Comma-separated resolutions; an unknown value: 400 bad_filter'), device: deviceFilter,
      from: iso.optional().describe('Handled at or after'), to: iso.optional().describe('Handled at or before'),
      corrections: z.enum(['true', 'false']).optional().describe('true: also list the findings Vedette closed because it corrected its own match (never a flaw that was handled); default false: leave them out, as the report does'),
      offset, limit }),
    response: HandledList, example: { query: {} } },
  { method: 'get', path: '/findings/overview', summary: 'Home: open findings and devices by status, the queue length, the fixes to do first and the 30-day trend', stories: ['S-MIT-1', 'S-UI-1'], role: 'viewer',
    response: Overview },
  { method: 'get', path: '/findings/{id}/view', summary: 'One finding as every place shows it: status, urgency with reasons, severity, verification, handling, fix and history', stories: ['S-MIT-1', 'S-MIT-3'], role: 'viewer',
    params: idParams, response: View, example: { params: { id: 'fv-fw01-ssh-1' } } },
  { method: 'post', path: '/findings/handle', summary: `Mark findings of one device as handled, with one note: by ids (at most ${MAX_HANDLE}) or every open finding of one fix on one device; findings that already have this handling are skipped; one history and audit row per finding, all or nothing. 409 still_reported: patched on a finding the device's latest reading still shows inside the affected versions (the message names the reading); nothing is written, and the same request with confirm keeps the mark`, stories: ['S-MIT-1'], role: 'operator',
    body: z.object({
      ids: z.array(findingId).min(1).max(MAX_HANDLE).optional().describe('These findings; all of one device (else 400 many_devices). Not with device and fix'),
      device: z.string().max(96).optional().describe('With fix: that device'),
      fix: z.string().max(400).optional().describe('With device: the Fix.key whose open findings on the device are handled'),
      software: z.string().max(96).optional().describe('With device and fix: the software line of the block (FixBlock.software.id, FixDevice.software.id); absent: the block on no software line. Two lines of one product never share a handle'),
      resolution: Resolution, note: handleNote,
      until: z.iso.date().optional().describe('accepted only: the last day, from tomorrow to 365 days ahead (else 400 bad_until)'),
      confirm: z.boolean().optional().describe('true: keep "patched" although the latest reading still shows an affected version (after 409 still_reported); the finding opens again if the next reading still shows it'),
    }),
    response: z.object({ handled: z.number().int().min(0), skipped: z.number().int().min(0).describe('Already handled this way') }) },
  { method: 'post', path: '/findings/{id}/reopen', summary: 'Open a handled finding again (a person\'s handling was a mistake); history and audit', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ note: z.string().max(500) }), response: View },
  { method: 'post', path: '/findings/{id}/verify', summary: 'Confirm vulnerability on your own word: verified by a person; the note says what makes you sure; history and audit', stories: ['S-MIT-1'], role: 'admin',
    params: idParams, body: z.object({ note: z.string().max(500).describe('At least 3 characters') }), response: View },
  { method: 'post', path: '/findings/{id}/identity/reject', summary: 'Not this product: the software of a finding the AI\'s identification opened is not the product the AI chose. Stored for the software\'s name (every device with it), it wins over the AI: that product is never offered for the name again, and every finding resting on the choice closes at once (matched again). A second click changes nothing. 404 not_found when the finding does not rest on the AI\'s identification. Audit findings.ai_identity_rejected', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, response: z.object({ ok: z.literal(true) }) },
  { method: 'post', path: '/findings/{id}/unverify', summary: 'Undo Confirm vulnerability: a finding a person confirmed is not confirmed again (one a scan or the device confirmed is refused, 409 not_confirmed_by_person); history and audit', stories: ['S-MIT-1'], role: 'admin',
    params: idParams, response: View },
  { method: 'post', path: '/findings/questions/{id}/answer', summary: 'Answer a question about one CVE on one device: affected records a finding confirmed by the person and needs an admin, as Confirm vulnerability does (an operator gets 403 forbidden); not affected closes the question (operator); history and audit', stories: ['S-MIT-1'], role: 'operator',
    params: z.object({ id: z.string().min(1).max(96) }), body: z.object({ answer: z.enum(['affected', 'not_affected']), note: z.string().max(500) }),
    response: z.object({ finding: z.string().nullable().describe('affected: the finding') }) },
  { method: 'post', path: '/findings/questions/ignore', summary: 'Ignore (bypass) every open question of one device, or of one software line of it: each is answered "not affected" in one transaction with one audit row; each is listed under Answered and can be asked again one by one. "Vedette cannot check this device" is left (operator)', stories: ['S-MIT-1'], role: 'operator',
    body: z.object({ device: z.string().min(1).max(96), software: z.string().max(96).optional().describe('One software line of the device; every open question of the device when left out'), note: z.string().max(500) }),
    response: z.object({ answered: z.number().int().min(1).describe('Questions answered') }) },
  { method: 'post', path: '/findings/questions/accept-risk', summary: 'Accept the risk of one device, or of one software line of it, until a day, on your word: every open question there is answered "affected", the finding of each CVE it asks about is recorded and accepted until the day, and so is every open finding of the same scope, confirmed or suspected; one transaction, one summary audit row plus one history row per finding. The findings open again after the day; a CVE that matches later is a new question. "Vedette cannot check this device" is left. It records "affected" on your word, so it needs an admin as answering affected does (an operator gets 403 forbidden)', stories: ['S-MIT-1'], role: 'operator',
    body: z.object({ device: z.string().min(1).max(96), software: z.string().max(96).optional().describe('One software line of the device; the whole device when left out'),
      question: z.string().max(96).optional().describe('One open question (one CVE row of a software line): only its CVEs are accepted'), note: z.string().max(500).describe('Why you accept it: at least 3 characters'),
      until: z.iso.date().describe('The last day of the acceptance, from tomorrow to 365 days ahead (else 400 bad_until)') }),
    response: z.object({ questions: z.number().int().min(0).describe('Questions answered affected'), findings: z.number().int().min(1).describe('Findings accepted until the day') }) },
  { method: 'post', path: '/findings/questions/{id}/unanswer', summary: 'Take back a "not affected" answer: the question is asked again in Needs your input (an "affected" answer made a finding and is changed on its page: 409 not_answered); audit', stories: ['S-MIT-1'], role: 'operator',
    params: z.object({ id: z.string().min(1).max(96) }), response: z.object({ id: z.string().describe('The question, open again') }) },
  { method: 'get', path: '/findings', summary: 'The findings of one device in every state, newest first, each with its history: what a version entry, "I updated it" or "Not installed" changed on the device', stories: ['S-MIT-1', 'S-SCAN-3'], role: 'viewer',
    query: z.object({ asset: z.string().min(1).max(96) }), response: FindingList, example: { query: { asset: 'a-bn340' } } },
  { method: 'get', path: '/findings/{id}', summary: 'One finding: evidence, recommendation, compromise indicators, AI results', stories: ['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2'], role: 'viewer',
    params: idParams, response: FindingDetail, example: { params: { id: 'f-1' } } },
  { method: 'post', path: '/findings/{id}/applied', summary: 'Log "Applied" for one recommendation item; does not change the status by itself', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ item: ApplyItem }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/ai', summary: 'Explain or draft a recommendation with the customer AI key (BYOK); fails if AI is off', stories: ['S-AI-2', 'S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ skill: z.enum(['explain', 'mitigation-config']) }), response: FindingDetail },
])
