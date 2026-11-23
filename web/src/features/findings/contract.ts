// Hợp đồng API module findings. Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
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
export const StatusAction = z.enum(['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk', 'reopen'])
export const BulkAction = z.enum(['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk'])
/** How far ahead a risk can be accepted. */
export const MAX_ACCEPT_DAYS = 365
const until = z.iso.date().optional().describe('accept_risk only: the last day the risk is accepted, from tomorrow to 365 days ahead; the finding reopens by itself after it')
/** Most findings one bulk status change may touch (INV-10 of findings). */
export const MAX_BULK = 500

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
export const RowFix = z.object({
  group: z.string().describe('"<device id>/<software id>": the open findings with the same group are fixed by the same update'),
  kind: z.enum(['fixed', 'esu', 'feature_update', 'distro']).describe('fixed = upgrade to `fixed` (a Windows release: the monthly cumulative update with build `fixed` or later); esu = that build needs Extended Security Updates; feature_update = no update of this release fixes them, move to release `fixed`; distro = install the distribution\'s security updates for the package'),
  windows: z.boolean().describe('A Windows release row: the update is the monthly cumulative update Windows Update offers'),
  software: z.string().describe('Display name of the software row'),
  version: z.string().describe('The installed version'),
  fixed: z.string().describe('The release or build that fixes them all; feature_update: the release to move to; empty for distro'),
  distro: z.string().describe('distro: "Ubuntu" or "Debian", empty for the distribution\'s'),
  pro: z.boolean().describe('distro: the fix of at least one of them is in Ubuntu Pro (ESM) only'),
}).describe('one update fixes this finding together with the device\'s other open findings of the same software (top-tier: one item per missing update)')
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
  software_id: z.string().describe('The device\'s software row the matcher matched the finding on (the id FindingRow.fix.group and ToFixAction use), stored when it opens, touches or closes the finding; "" until the next match reaches an older finding. Never guessed from the product'),
  fix: RowFix.nullable().optional().describe('GET /findings only, open findings: the update that fixes it with others; null when there is none to name'),
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
  answers: z.array(AiAnswer).max(4).optional().describe('mitigation-config: the four short answers, in the order of AiAnswerKey, each rephrasing only the CVE brief and the finding, every claim that has a reference with its link; the page gives each its heading. When present, the page shows them instead of paragraphs and steps. Absent for answers stored before'),
})
export const AppliedEntry = z.object({ item: z.string(), ts: iso, user: z.string() })

export const FixedIn = z.object({
  kind: z.enum(['fixed', 'up_to', 'end_listed', 'branches', 'distro', 'feature_update', 'esu']).describe('fixed = the device version is inside a range that ends before `fixed`, and `fixed` is outside every range that applies; up_to = inside a range whose end `fixed` is itself affected (no fixed release named); end_listed = inside a range that ends before `fixed`, but NVD lists releases of `fixed` itself as affected (Junos: "before 20.4", then 20.4R1 … one by one): `fixed` is not a fix, the vendor advisory names it; branches = the version is unknown or unreadable, `branches` lists the fix of each release line; distro = a package of the distribution, whose security updates carry the fix under their own numbers: an agent read it from the device\'s package database (deb, rpm or apk), a person gave its package release (an apk, Debian or RPM release, or any release on a device that runs a Linux distribution), or the version carries a marker such as ubuntu, +deb12, .el9; feature_update = a Windows release NVD does not list for the fix, which only a later release of its line (`branches[0].branch`, from build `fixed`) has: Microsoft no longer updates it, so it needs a feature update; esu = the fixing Windows build `fixed` comes only with Extended Security Updates for `branches[0].branch`'),
  version: z.string().describe("The device's version; for branches empty when it has none, else the text Vedette cannot read"),
  fixed: z.string().describe('The fixed release (fixed), the last affected release (up_to), the upstream fixed release as a reference when NVD names one (distro: the backport may keep the package\'s number below it); empty for branches'),
  branches: z.array(z.object({ branch: z.string().describe('Release line such as 7.4; empty when it cannot be told'), fixed: z.string() })).describe('At most 5, newest first'),
  more: z.number().int().min(0).describe('Release lines with a fix left out of branches'),
  no_fix: z.number().int().min(0).describe('Release lines NVD gives no fixed release for (a range that ends at an affected version)'),
  distro: z.string().describe('"Ubuntu" or "Debian" when the device runs one, empty otherwise. distro: whose security updates to install (empty = the distribution). Other kinds: set only when the software is not known to come from the package database (typed by a person, read by a scan, or an agent row stored before inventory kept the flag); the page adds "if you installed it from the distribution\'s packages, install its security updates instead"'),
  distro_fixed: z.string().describe('Kind distro only: the version of the distribution\'s package that fixes the CVE on the device\'s release (Ubuntu security data, Debian Security Tracker); `version` is then the device\'s full package version. Empty when the distribution\'s data does not say'),
  distro_release: z.string().describe('The device\'s release with distro_fixed ("24.04", "12"); empty otherwise'),
  distro_pro: z.boolean().describe('distro_fixed is in Ubuntu Pro (ESM) only'),
  source: z.string().describe('Where the versions come from: "NVD affected versions", "CVE.org affected versions (from the CVE record\'s CNA)" when NVD has none, or with distro_fixed "Ubuntu security data" / "Debian Security Tracker"'),
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
export const VersionNeeded = z.object({
  asset: FindingAsset.nullable(), asset_id: z.string(), software_id: z.string(), software: z.string().describe('Display name of the software'),
  version: z.string().nullable().describe('null = no version; otherwise the version as entered, which Vedette cannot read'),
  cves: z.number().int().min(1).describe('Exploited CVEs of this product that the version would decide'),
}).describe('a software on the exploited list without a usable version is ONE item, not one finding per CVE')
export const UncheckedReason = z.enum([
  'no_nvd_data',     // NVD has no CPE configuration for the CVE yet
  'no_nvd_versions', // NVD names the product but gives no affected versions
  'not_named',       // NVD's data for the CVE names other products, not this row (#920 rule 2)
  'not_comparable',  // the device's version exists but cannot be compared with NVD's ranges (version scheme)
  'platform_unknown', // The CVE affects only some platforms or builds and nothing says which this one is (UncheckedItem.question)
  'package_unknown',  // The platform is the distribution of the fixed list; its package release decides (UncheckedItem.question)
])
export const UncheckedCve = z.object({
  cve: z.string(), name: z.string(), date_added: z.iso.date(), ransomware: z.boolean(), advisory: z.string().url().nullable(),
  nvd_pending: z.boolean().optional().describe('reason no_nvd_data while Vedette has not read NVD\'s answer for this CVE yet (new box, NVD feed off or failing): say "waiting for NVD\'s data", not "NVD has not published"'),
})
export const UncheckedAnswer = z.object({
  label: z.string().describe('The button: "Alpine Linux 3.23", "Another system", "Enter the package release"'),
  os: z.string().optional().describe('One click: PATCH /inventory/devices/{asset_id} {os} with this value (INV-41)'),
  ask: z.array(z.enum(['os', 'pkg_version'])).optional().describe('What the person types: os → PATCH /inventory/devices/{asset_id} {os}; pkg_version → PATCH /inventory/devices/{asset_id}/software/{software_id} {pkg_version} (the bare release or the line `apk info -e -v openssh-server` prints, "openssh-server-10.2_p1-r1"). "Another system" asks both: on a row a scan saw only the row\'s release rules it out'),
})
export const UncheckedQuestion = z.object({
  text: z.string().describe('"Is the OpenSSH on BN340 Alpine Linux\'s openssh-server package, or another build …? CVE-… affects only …"'),
  error: z.string().optional().describe('The last answer could not be read: "Vedette could not read the release you entered (…)"; show it at the field'),
  command: z.string().nullable().describe('What prints the answer on the device ("apk info -e -v openssh-server" for the package release, "cat /etc/alpine-release" for the branch), null when none'),
  answers: z.array(UncheckedAnswer).min(1),
}).describe('the one question left for a platform-limited CVE; every answer is an inventory correction, and the next match decides')
export const UncheckedItem = z.object({
  asset: FindingAsset.nullable(), asset_id: z.string(),
  software_id: z.string().nullable(), software: z.string().describe('Display name, as on the device page'),
  version: z.string().nullable(),
  reason: UncheckedReason,
  cves: z.array(UncheckedCve).min(1),
  action: z.enum(['add_version', 'answer_platform', 'none']).describe('add_version: only not_comparable on a software row a person declared (#920): typing the version as the vendor writes it lets Vedette check these CVEs; answer_platform: reasons platform_unknown and package_unknown, answer `question`; none: only the advisory decides'),
  question: UncheckedQuestion.optional().describe('with action answer_platform; one item per CVE then'),
}).describe('#910 phase 1: exploited CVEs of software the box has that it could not check; one item per device x software x reason. No finding is created from it')
export const FindingList = z.object({ items: z.array(FindingRow), version_needed: z.array(VersionNeeded), unchecked: z.array(UncheckedItem) })

// ---------- Updates to plan: CVE tiers 2 and 3 (S-TIER-1, S-TIER-2). Not findings: no status, no
// alert, no mitigation pack; one item per update on one device, each CVE one click away.
/** FIRST's EPSS probability from which a CVE is "likely to be exploited" (tier 2); feeds.EPSSLikely on the box. */
export const EPSS_LIKELY = 0.1
export const PlanTier = z.enum(['likely', 'recent'])
export const PlanFilter = z.enum(['likely', 'recent', 'all'])
export const PlanCve = z.object({
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  tier: PlanTier.describe('likely = EPSS 10 % or more; recent = published in the last 12 months; a CVE on an exploited list is a finding, never here'),
  basis: z.enum(['scan', 'agent', 'distro', 'version']).describe('Evidence: scan = a scan engine (nuclei, OpenVAS, ZAP) found it on the device; agent = the device\'s agent reports a build or package inside the affected range; distro = Ubuntu\'s or Debian\'s own data says the installed package is affected; version = an exact version compared with the CVE\'s ranges. Never a product-only match'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).nullable().describe('NVD\'s CVSS severity; null when NVD has not scored it yet'),
  score: z.number().min(0).max(10).nullable().describe('NVD\'s CVSS base score'),
  published: z.iso.date().describe('NVD `published`; older than 12 months only with basis scan'),
  epss: z.number().min(0).max(1).nullable(),
  percentile: z.number().min(0).max(1).nullable(),
})
/** A device's risk marker (the same value as GET /inventory/devices gives, findings.RiskMap); null when clean, for the Vedette box
 * itself, or when the marker could not be read. */
export const DeviceRiskView = z.object({ code: z.enum(DEVICE_STATUSES), count: z.number().int().min(1) }).nullable().describe('The device badge (the device status every list gives)')
  .describe('The device\'s risk marker: exploited = open exploited findings To fix lists; update = none, but a recommended update fixes a CVE likely to be exploited or of High or Critical severity; null when clean, for the Vedette box itself, or when it could not be read')
/** A recommended update a person marked as done (POST /findings/plan/done). */
export const PlanDone = z.object({
  by: z.string().describe('Who marked it done'),
  at: iso.describe('When'),
  note: z.string().describe('The note they gave; "" when none'),
  version: z.string().describe('The version of the software when it was marked: the mark holds while the device reports this version and no new CVE joins the item'),
})
export const PlanItem = z.object({
  group: z.string().describe('"<device id>/<software id>", as RowFix.group'),
  asset: z.object({ id: z.string(), name: z.string().describe('The name the Devices page shows, never the internal id') }),
  risk: DeviceRiskView,
  software: z.string().describe('Display name of the software row'),
  version: z.string().describe('The installed version'),
  fixed: z.string().describe('fixed: the version that fixes every CVE of the item; windows, esu: the build of the cumulative update; distro: the distribution\'s package version that fixes every CVE of the item on the device\'s release'),
  kind: z.enum(['fixed', 'distro', 'windows', 'esu']).describe('fixed = upgrade the software to `fixed`; distro = a distribution\'s package, judged by the distribution\'s own fix data (`distro_data`), never moved to an upstream release; windows = the monthly cumulative update with build `fixed` or later; esu = the same on a Windows release past its end of support: the update comes only with Extended Security Updates'),
  distro_data: z.enum(['fixed', 'no_fix', 'none', '']).describe('kind distro: fixed = upgrade the source package `software` from `version` to the distribution\'s fixed release `fixed` or later (Ubuntu, Debian, Alpine data); no_fix = the distribution\'s data says these CVEs have no fix from it yet (`distro` names it): nothing to install yet; none = the distribution\'s data has no word on the package (Red Hat, SUSE and others Vedette reads no data for, a package the data never names, another build): NVD lists these CVEs for its upstream version, so the page says to check `distro`\'s security updates, never that an update fixes them. "" for every other kind'),
  pro: z.boolean().describe('distro only: `fixed` is in Ubuntu Pro (ESM) only; false otherwise'),
  distro: z.string().describe('distro with `fixed` empty (distro_data no_fix or none): the distribution ("Alpine Linux", "Ubuntu", "Debian"); empty for "the distribution\'s" and for every other kind'),
  nvd_lag: z.boolean().describe('windows, esu: `fixed` is the newest monthly update Microsoft\'s release information lists for the release, newer than the update that carries every fixed build NVD names for these CVEs. The item fixes at least `cves`; the newest update\'s CVEs are not yet analysed by NVD, so the page says "at least". false otherwise'),
  kb: z.string().describe('windows, esu: the KB number of `fixed` when Microsoft\'s release information lists that build ("KB5131080"), named next to the build; "" otherwise'),
  cves: z.array(PlanCve).describe('Likely first, by EPSS; then the recent ones by CVSS score, then EPSS; then newest. Empty only for a Windows release below the newest monthly update Microsoft lists for it while no CVE NVD has analysed gives the device an item (kind windows or esu): the item names the update, lists under All and Recent, and ranks after every item with a CVE; nvd_lag is true while the update is under six weeks old ("its CVEs are not yet analysed by NVD"), false after ("NVD lists no CVE of it for this release yet")'),
  likely: z.number().int().min(0),
  recent: z.number().int().min(0),
  agent_gone: z.boolean().describe('A CVE of the item rests on an agent\'s row and no agent of this box reports the device now (agent-intake off, no agent bound, the agent silent past its stale limit; the same answer as the finding page\'s "No agent reports" line): `version` is the last one an agent reported'),
  agent_reported: z.iso.date().nullable().describe('With agent_gone: the day the agent last reported the row (YYYY-MM-DD); null otherwise or when not known'),
  done: PlanDone.nullable().describe('A person marked this item done and the mark still holds (the same version, no new CVE): listed only with ?done=true; null otherwise'),
})
export const PlanFeed = z.enum(['module_off', 'off', 'loading', 'ready']).describe('module_off = the feeds module is off (SYS-5: its data is not read); off = an admin has not turned the feed on; loading = on, first fill not finished; ready = loaded')
export const Plan = z.object({
  items: z.array(PlanItem),
  counts: z.object({
    likely: z.number().int().min(0).describe('Items the tier=likely answer lists'),
    recent: z.number().int().min(0).describe('Items the tier=recent answer lists'),
    all: z.number().int().min(0).describe('Items the tier=all answer lists'),
    done: z.number().int().min(0).describe('Items a person marked done (whatever tier), listed with ?done=true'),
  }).describe('The number of items each tier filter lists, for the same device filter, whatever tier was asked: one answer gives every tab its count'),
  compared: z.boolean().describe('false = no comparison of tier 2 and 3 CVEs with the devices has run since the box started (the plan job runs within minutes); the page says so instead of "no update to plan"'),
  compared_devices: z.number().int().min(0).describe('Devices with at least one version Vedette can compare'),
  unchecked_devices: z.number().int().min(0).describe('Devices with no version Vedette can read: not checked'),
  old_evidence: z.number().int().min(0).describe('CVEs published more than 12 months ago listed because a scan engine found them'),
  data: z.object({
    epss: PlanFeed.describe('Feed epss-all (tier 2)'),
    recent: PlanFeed.describe('Feed nvd-recent (tier 3, and the published dates of tier 2)'),
    epss_date: z.iso.date().nullable().describe('The day of the EPSS scores'),
    recent_since: z.iso.date().nullable().describe('CVEs published on or after this day are in the data (12 months back)'),
  }),
})

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
export const Via = z.enum(['person', 'version_moved', 'software_removed', 'distro_fixed', 'scan_clear', 'data_corrected', 'not_installed'])
  .describe('How it was handled: person = a person marked it; version_moved = the software moved past the affected version (from_version, to_version); software_removed = the software is gone; distro_fixed = the distribution says the installed package is fixed; scan_clear = a safe check that had matched came back clear; data_corrected = no longer detected while nothing on the device changed (the match was corrected: never patch credit); not_installed = a person said the software is not installed')
export const Verified = z.enum(['no', 'device', 'scan', 'person'])
  .describe('no = not confirmed yet; device = the device itself reports the affected version (agent, SNMP, package list); scan = a safe check confirmed it; person = a person confirmed it')
export const Basis = z.enum(['scan', 'device_version', 'package', 'banner_version', 'statement', 'person'])
  .describe('What the match rests on: scan = a safe check; device_version = a version the device itself reports; package = a distribution package release; banner_version = a version read from a network banner; statement = a version a person typed for the device; person = a person said it is affected')
export const FixKind = z.enum(['update', 'distro_update', 'os_update', 'feature_update', 'none_yet', 'unknown'])
  .describe('update = install `version` of the software or later; distro_update = install the distribution\'s package release `version` or later; os_update = install the operating system update `ref` (a KB number) or build `version`; feature_update = no update of this release fixes it, move to release `version`; none_yet = the vendor has no fix yet (`url` is the advisory); unknown = no fix data')
export const SeverityBand = z.enum(['critical', 'high', 'medium', 'low', 'none'])
export const DeviceStatusCode = z.enum(DEVICE_STATUSES)
export const QuestionKind = z.enum(['version_needed', 'platform', 'package_release', 'not_comparable', 'no_range_data'])
  .describe('version_needed = the software has no version Vedette can read; platform = the CVE affects only some platforms and nothing says which this is; package_release = the distribution\'s package release decides; not_comparable = the version cannot be compared with the affected ranges; no_range_data = the CVE names the product but gives no affected versions ("Possibly affected: check the version")')
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
  by: z.string().nullable().describe('verified person: who confirmed it'),
  at: iso.nullable().describe('When it was confirmed; null while not confirmed'),
}).describe('The second line under the status: "Confirmed by a safe check", "Confirmed: the device reports this version", "Confirmed by <user>", "Not confirmed yet: based on a scan banner"')
export const Handled = z.object({
  resolution: Resolution,
  via: Via,
  by: z.string().describe('"system" when Vedette handled it; else the person'),
  at: iso,
  note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('accepted: the last day; the finding reopens by itself after it. null otherwise'),
  from_version: z.string().nullable().describe('via version_moved: the version that was affected'),
  to_version: z.string().nullable().describe('via version_moved: the version now installed'),
}).describe('Who and how, from stored fields: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov)", "Mitigated by <user> (17 Nov): <note>"')
export const Reopened = z.object({
  why: z.enum(['still_detected', 'detected_again', 'acceptance_expired']).describe('still_detected = a person marked it patched and a newer reading still shows the affected version; detected_again = it came back after Vedette closed it; acceptance_expired = the accepted risk reached its last day'),
  at: iso.describe('still_detected, detected_again: the time of the reading; acceptance_expired: when it reopened'),
}).describe('An open finding that was handled before: the line that says why it is open again')
export const Fix = z.object({
  key: z.string().min(1).max(400).describe('The "By fix" group (the same key on every device the same fix applies to); opaque'),
  kind: FixKind,
  product: z.string().describe('The product the fix is for, as people name it ("OpenSSH")'),
  version: z.string().nullable().describe('update, distro_update, feature_update: the version or release to install; os_update: the build when known'),
  ref: z.string().nullable().describe('os_update: the KB number; none_yet: the advisory id when known'),
  url: z.url().nullable().describe('The vendor advisory or release notes'),
})
export const CveRow = z.object({
  id: z.string().describe('The finding'),
  cve,
  status: StatusCode,
  severity: CveSeverity.nullable(),
  verified: Verified,
}).describe('One CVE of a list, a link to its finding')
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
  count: z.number().int().min(1).describe('An open status: distinct CVEs of the device at that status ("2 exploited"); needs_input: the items of the Needs your input queue for the device'),
}).nullable().describe('The device badge: the most urgent open status of its findings with a count, else needs_input when only questions wait, else null. A link to the device\'s findings with that status. The Devices list, the device page and Home show the same value')
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
export const InputItem = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('device_not_added'),
    id: z.string().describe('The item: "device:<device id>"'),
    device: DeviceRef,
    status: DeviceStatus,
    findings: z.number().int().min(1),
  }).describe('A device nobody added has open findings: Add device (POST /inventory/devices/{id}/approve) or Ignore (POST /inventory/devices/{id}/ignore)'),
  z.object({
    kind: z.literal('unconfirmed'),
    id: z.string().describe('The finding'),
    cve,
    device: DeviceRef,
    software: SoftwareRef.nullable(),
    status: z.enum(['under_attack', 'exploited', 'public_exploit', 'critical_edge']).describe('Only layers 1 to 4 ask for confirmation; update_recommended never does'),
    severity: CveSeverity.nullable(),
    basis: Basis,
    safe_check: z.boolean().describe('A safe check exists for the CVE and can reach the device: "Run the safe check" (POST /scans/runs) comes first'),
  }).describe('An urgent finding not confirmed yet: Run the safe check, Confirm vulnerability (POST /findings/{id}/verify) or Not affected (POST /findings/handle)'),
  z.object({
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
    choices: z.array(UncheckedAnswer).describe('platform, package_release: the answers, each an inventory correction; empty for the other kinds (version_needed, not_comparable: type the version on the software line; no_range_data: POST /findings/questions/{id}/answer)'),
  }).describe('What Vedette cannot decide without a person'),
])
export const InputList = z.object({
  items: z.array(InputItem).describe('Devices not added yet first, then unconfirmed findings by status, then questions by CVEs waiting; an item leaves the moment it is answered or stops being true'),
  total: z.number().int().min(0).describe('The queue length: the tab count'),
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
}).describe('A finding as every place shows it: lists, the finding page, the device page, Home, reports, notices and the AI read the same fields')
export const FirstItem = z.object({ device: DeviceRef, block: FixBlock })
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
      critical_edge: z.number().int().min(0), update_recommended: z.number().int().min(0), needs_input: z.number().int().min(0),
    }).describe('Devices by their badge (DeviceStatus.code)'),
  }),
  input: z.number().int().min(0).describe('The Needs your input queue length'),
  first: z.array(FirstItem).max(FIRST_TOP).describe('Fix first: the most urgent fix blocks across devices, then the most findings'),
  trend: z.array(z.number().int().min(0)).length(TREND_DAYS).describe('Open findings at the end of each of the last 30 days of the organization time zone, oldest first; the last is now'),
  alerts: HomeSummary.shape.alerts,
  incidents: HomeSummary.shape.incidents,
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

/** One update or action on one device, from findings.DeviceUpdates (the same groupings as FindingRow.fix and the plan). */
export const ToFixAction = z.object({
  group: z.string().describe('The key of the action on its device: FindingRow.fix.group of an exploited update ("<device>/<software>", the ?fix= filter of the list), PlanItem.group of a planned one, "<device>/<software>" for findings no update is named for. Per device: "By fix" groups by product and release instead'),
  source: z.string().describe('Who reported the software row (agent, manual, scan, a sensor; "" when none): "I updated it" follows it'),
  product: z.string().describe('The software row\'s identity across devices, "vendor|product" in lower case ("" when no row matches): "By fix" groups the same update on several devices by it, whatever each device calls the row'),
  software_id: z.string().describe('The device\'s software row it is about; "" when none matches'),
  software: z.string(), version: z.string().describe('The installed version; "" when none'),
  fixed: z.string().describe('The release or build to install; "" for a distribution\'s updates and when no update is named'),
  kind: z.enum(['fixed', 'esu', 'feature_update', 'distro', 'windows', 'none']).describe('none: no update is named that fixes these findings (follow the vendor\'s advice)'),
  windows: z.boolean().describe('The monthly cumulative update of a Windows release'), distro: z.string(), pro: z.boolean(),
  distro_data: z.enum(['fixed', 'no_fix', 'none', '']).describe('Planned distro: PlanItem.distro_data (no_fix: nothing to install yet; none: NVD\'s upstream ranges, check the distribution\'s updates); "" otherwise'),
  action: z.string().describe('The sentence the page shows: "Upgrade RARLAB WinRAR from 7.01 to 7.13 or later"'),
  cves: z.array(z.string()).describe('Worst first'),
  finding_ids: z.array(z.string()).describe('The open findings of the CVEs, same order (exploited only; empty for planned)'),
  worst: z.string().describe('The finding\'s severity (critical, high, medium, low) for exploited ones; NVD\'s for planned ones; "" when none'),
  ransomware: z.number().int(), likely: z.number().int().describe('Planned: CVEs EPSS says are likely to be exploited soon'),
  confirmed: z.number().int(), detected: z.number().int(), reported: z.number().int(), suspected: z.number().int().describe('How each exploited finding is known: confirmed (a scan, a person, or a version the device itself reports inside a range with an end; the finding\'s status says confirmed), detected from a version the device reported that does not confirm it, reported but not compared, suspected from the network'),
  checkable: z.number().int().describe('Exploited: how many of the CVEs a safe vulnerability check exists for; "Run the check" is offered only when it is above 0. 0 for planned ones'),
  kb: z.string().describe('A Windows update: the KB number of `fixed` when Microsoft\'s release information lists that build; "" otherwise'),
  nvd_lag: z.boolean().describe('Planned Windows updates: PlanItem.nvd_lag (it fixes at least `cves`; the newest update\'s CVEs are not yet analysed by NVD); false otherwise'),
})
export const ToFixDevice = z.object({
  asset: FindingAsset,
  risk: DeviceRiskView,
  open: z.number().int().describe('Open findings of the device'),
  exploited: z.array(ToFixAction).describe('Open exploited findings one named update fixes, one action per update, worst first'),
  no_update: z.array(ToFixAction).describe('Open findings no update is named for, one per software row; one with confirmed + detected = 0 is the person\'s to check (Needs your input), not to fix'),
  planned: z.array(ToFixAction).describe('Recommended updates: CVEs on no exploited list, as GET /findings/plan lists them'),
  plan_compared: z.boolean().describe('The last plan pass compared this device'),
})
export const ToFix = z.object({
  devices: z.array(ToFixDevice).describe('Every device with something to fix or plan, the most urgent first: something exploited to fix (a named update, or proved), then the worst severity, ransomware, proved findings and CVEs; then the plan\'s worst severity, likely and CVEs'),
  truncated: z.boolean().describe('More devices had something than the 500 listed'),
  plan_ran: z.boolean().describe('The plan job compared the devices since the box started; false: recommended updates are not known yet'),
  plan_off: z.boolean().describe('The feeds module is off: no recommended update is listed'),
  risks: z.record(z.string(), DeviceRiskView.unwrap()).describe('The risk marker of every marked device by id, not capped like devices (empty for ?asset=): the Findings table and filter read it'),
})

export const endpoints = defineEndpoints([
  // The findings model: lists grouped on the server, the finding's View, handling, Home.
  { method: 'get', path: '/findings/devices', summary: 'By device: one card per device with open findings (devices not added yet included, ignored ones only with ignored=true), the most urgent first; inside, one block per fix with its CVEs', stories: ['S-MIT-1', 'S-TIER-1'], role: 'viewer',
    query: z.object({ q, status: statusFilter, device: deviceFilter.describe('One device: its Findings tab'), ignored: z.enum(['true', 'false']).optional().describe('true: only ignored devices (the Ignored devices tab); default false: none of them'), offset, limit }),
    response: DeviceCards, example: { query: {} } },
  { method: 'get', path: '/findings/fixes', summary: 'By fix: one card per fix across devices (ignored devices left out), the most urgent first, each with the devices it applies to', stories: ['S-MIT-1', 'S-TIER-1'], role: 'viewer',
    query: z.object({ q, status: statusFilter, offset, limit }), response: FixCards, example: { query: {} } },
  { method: 'get', path: '/findings/input', summary: 'Needs your input: devices not added yet that have findings, urgent findings not confirmed yet, and questions only a person can answer; one queue', stories: ['S-MIT-1', 'S-INV-3'], role: 'viewer',
    query: z.object({ device: deviceFilter, offset, limit }), response: InputList, example: { query: {} } },
  { method: 'get', path: '/findings/handled', summary: 'Handled: findings by handling, the newest first, each with who and how', stories: ['S-MIT-1'], role: 'viewer',
    query: z.object({ q, resolution: z.string().max(200).optional().describe('Comma-separated resolutions; an unknown value: 400 bad_filter'), device: deviceFilter,
      from: iso.optional().describe('Handled at or after'), to: iso.optional().describe('Handled at or before'), offset, limit }),
    response: HandledList, example: { query: {} } },
  { method: 'get', path: '/findings/overview', summary: 'Home: open findings and devices by status, the queue length, the fixes to do first and the 30-day trend', stories: ['S-MIT-1', 'S-UI-1'], role: 'viewer',
    response: Overview },
  { method: 'get', path: '/findings/{id}/view', summary: 'One finding as every place shows it: status, urgency with reasons, severity, verification, handling, fix and history', stories: ['S-MIT-1', 'S-MIT-3'], role: 'viewer',
    params: idParams, response: View, example: { params: { id: 'fv-fw01-ssh-1' } } },
  { method: 'post', path: '/findings/handle', summary: `Mark findings of one device as handled, with one note: by ids (at most ${MAX_HANDLE}) or every open finding of one fix on one device; findings that already have this handling are skipped; one history and audit row per finding, all or nothing`, stories: ['S-MIT-1'], role: 'operator',
    body: z.object({
      ids: z.array(findingId).min(1).max(MAX_HANDLE).optional().describe('These findings; all of one device (else 400 many_devices). Not with device and fix'),
      device: z.string().max(96).optional().describe('With fix: that device'),
      fix: z.string().max(400).optional().describe('With device: the Fix.key whose open findings on the device are handled'),
      resolution: Resolution, note: handleNote,
      until: z.iso.date().optional().describe('accepted only: the last day, from tomorrow to 365 days ahead (else 400 bad_until)'),
    }),
    response: z.object({ handled: z.number().int().min(0), skipped: z.number().int().min(0).describe('Already handled this way') }) },
  { method: 'post', path: '/findings/{id}/reopen', summary: 'Open a handled finding again (a person\'s handling was a mistake); history and audit', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ note: z.string().max(500) }), response: View },
  { method: 'post', path: '/findings/{id}/verify', summary: 'Confirm vulnerability on your own word: verified by a person; the note says what makes you sure; history and audit', stories: ['S-MIT-1'], role: 'admin',
    params: idParams, body: z.object({ note: z.string().max(500).describe('At least 3 characters') }), response: View },
  { method: 'post', path: '/findings/questions/{id}/answer', summary: 'Answer a question about one CVE on one device: affected records a finding confirmed by the person and needs an admin, as Confirm vulnerability does (an operator gets 403 forbidden); not affected closes the question (operator); history and audit', stories: ['S-MIT-1'], role: 'operator',
    params: z.object({ id: z.string().min(1).max(96) }), body: z.object({ answer: z.enum(['affected', 'not_affected']), note: z.string().max(500) }),
    response: z.object({ finding: z.string().nullable().describe('affected: the finding') }) },
  { method: 'get', path: '/findings', summary: 'List findings (CVE x device), optionally for one device', stories: ['S-MIT-1', 'S-SCAN-3'], role: 'viewer',
    query: z.object({ asset: z.string().optional() }), response: FindingList },
  { method: 'get', path: '/findings/to-fix', summary: 'To fix: every device that needs an update or an action, the most urgent first, each with its actions in plain sentences (findings.DeviceUpdates), at most 500 devices', stories: ['S-MIT-1', 'S-TIER-1'], role: 'viewer',
    query: z.object({ asset: z.string().optional().describe('One device only (its Software tab)') }), response: ToFix },
  { method: 'get', path: '/findings/{id}', summary: 'One finding: evidence, recommendation, compromise indicators, AI results', stories: ['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2'], role: 'viewer',
    params: idParams, response: FindingDetail, example: { params: { id: 'f-1' } } },
  { method: 'post', path: '/findings/{id}/status', summary: 'Change status (patched, mitigated, false positive, not relevant, accept risk until a day, reopen) with a note', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ action: StatusAction, note: z.string().max(500), until }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/confirm', summary: 'Confirm a suspected finding on your own word (admin): basis person, status confirmed; a note is required and goes into the history as "Confirmed by <user>: <note>"', stories: ['S-MIT-1'], role: 'admin',
    params: idParams, body: z.object({ note: z.string().max(500) }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/unconfirm', summary: 'Undo a confirmation a person made (admin): the finding is suspected again; a finding a scan confirmed is refused', stories: ['S-MIT-1'], role: 'admin',
    params: idParams, response: FindingDetail },
  { method: 'post', path: '/findings/{id}/applied', summary: 'Log "Applied" for one recommendation item; does not change the status by itself', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ item: ApplyItem }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/ai', summary: 'Explain or draft a recommendation with the customer AI key (BYOK); fails if AI is off', stories: ['S-AI-2', 'S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ skill: z.enum(['explain', 'mitigation-config']) }), response: FindingDetail },
  { method: 'get', path: '/findings/plan', summary: 'Updates to plan: one item per update on one device that fixes CVEs likely to be exploited (EPSS 10 % or more) or published in the last 12 months, version-confirmed only; never findings, never alerts', stories: ['S-TIER-1', 'S-TIER-2'], role: 'viewer',
    query: z.object({ tier: PlanFilter.optional().describe('Default all'), asset: z.string().max(64).optional().describe('One device'),
      done: z.enum(['true', 'false']).optional().describe('true: only the items a person marked done (Done); default false: the items to plan, without them') }), response: Plan },
])
