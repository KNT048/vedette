// Hợp đồng API module findings (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { TYPE_IDS } from '@/lib/deviceTypes'

const iso = z.iso.datetime()
const findingId = z.string().min(1).max(64)

export const FindingStatus = z.enum(['confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted'])
export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export const AssetKind = z.enum(TYPE_IDS) // the inventory's device types (D-511)
export const FirewallVendor = z.enum(['fortigate', 'mikrotik', 'generic'])
export const ApplyItem = z.enum(['patch', 'workaround', 'fortigate', 'mikrotik', 'generic'])
export const StatusAction = z.enum(['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk', 'reopen'])
export const BulkAction = z.enum(['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk'])
/** How far ahead a risk can be accepted (D-498). */
export const MAX_ACCEPT_DAYS = 365
const until = z.iso.date().optional().describe('accept_risk only (D-498): the last day the risk is accepted, from tomorrow to 365 days ahead; the finding reopens by itself after it')
/** Most findings one bulk status change may touch (INV-10 of findings, D-484). */
export const MAX_BULK = 500

export const Finding = z.object({
  id: z.string(),
  asset_id: z.string(),
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  status: FindingStatus,
  severity: Severity,
  confidence: z.number().min(0).max(1),
  basis: z.enum(['scan', 'version', 'product']).describe('scan = confirmed by a scan template; version = suspected by version; product = only the product matches'),
  evidence: z.object({
    summary: z.string(), template: z.string().optional(), request: z.string().optional(), response: z.string().optional(), checked_at: iso,
    agent: z.boolean().optional().describe('D-548: the version compared is the one the device\'s own agent (osquery, Wazuh) reports installed: a detection, shown as "Detected by the agent", with nothing for the person to look up'),
    agent_row: z.boolean().optional().describe('N52-2: a product-only match on a software row the device\'s own agent reported with its installed version: Vedette could not compare that version with NVD\'s data, so the page does not ask to add the version'),
  }).nullable(),
  first_seen: iso,
  last_seen: iso,
  resolved_by: z.string().nullable(),
  resolved_at: iso.nullable(),
  resolution_note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('risk_accepted only (D-498): the last day of the acceptance (UTC); the finding reopens by itself after it'),
  history: z.array(z.object({ ts: iso, user: z.string(), action: z.string(), note: z.string().optional() })),
})

export const KevInfo = z.object({
  name: z.string(), vendor: z.string(), product: z.string(), display: z.string(), required_action: z.string(), links: z.array(z.string()),
  date_added: z.string(), due_date: z.string().nullable(), ransomware: z.boolean(), epss: z.number().nullable(), has_template: z.boolean(),
  source: z.enum(['cisa-kev', 'vulncheck-kev']).optional().describe('Which list the entry is on (D-557): texts and the source badge name it; an entry of VulnCheck KEV is never called CISA\'s'),
  published: z.iso.date().nullable().describe('D-615: the day the CVE was published (NVD `published`), never the day CISA added it; null when NVD has not answered for it (then it counts as recent: an older CVE is not a finding on a product-only match (D-616), and a missing date never closes a finding)'),
})
export const FindingAsset = z.object({
  id: z.string(), name: z.string().describe('The name the Devices page shows: hostname, else vendor and model, else the IP, else the software; never the internal id (D-484)'),
  hostname: z.string().nullable(), ip: z.string().describe('"—" when the device has no IP address'), kind: AssetKind, display: z.string(),
})
export const RowFix = z.object({
  group: z.string().describe('"<device id>/<software id>": the open findings with the same group are fixed by the same update'),
  kind: z.enum(['fixed', 'esu', 'feature_update', 'distro']).describe('fixed = upgrade to `fixed` (a Windows release: the monthly cumulative update with build `fixed` or later); esu = that build needs Extended Security Updates; feature_update = no update of this release fixes them, move to release `fixed`; distro = install the distribution\'s security updates for the package'),
  windows: z.boolean().describe('A Windows release row (D-546): the update is the monthly cumulative update Windows Update offers'),
  software: z.string().describe('Display name of the software row'),
  version: z.string().describe('The installed version'),
  fixed: z.string().describe('The release or build that fixes them all; feature_update: the release to move to; empty for distro'),
  distro: z.string().describe('distro: "Ubuntu" or "Debian", empty for the distribution\'s'),
  pro: z.boolean().describe('distro: the fix of at least one of them is in Ubuntu Pro (ESM) only'),
}).describe('D-545: one update fixes this finding together with the device\'s other open findings of the same software (top-tier: one item per missing update)')
export const Cvss = z.object({
  score: z.number().min(0).max(10).describe('The CVSS base score (0.0 to 10.0, one decimal); its band follows from FIRST\'s table (3.x, 4.0) or NVD\'s v2 table (2.0: Low, Medium, High; no Critical)'),
  version: z.enum(['4.0', '3.1', '3.0', '2.0']).describe('The newest CVSS version NVD lists for the CVE with a usable score and vector (2.0 only when NVD has nothing newer)'),
  source: z.enum(['nvd', 'cna']).describe('nvd = NVD\'s own score ("Primary"); cna = another scorer NVD lists as "Secondary" (the CVE Numbering Authority or CISA\'s ADP), used only when NVD gives none for that version'),
  vector: z.string().min(1).max(200).describe('NVD\'s vector string of the score ("CVSS:3.1/AV:N/AC:L/…"; 2.0: "AV:N/AC:L/Au:N/…"): FIRST asks that a score be shown with its vector, so a score without a valid one is not shown'),
}).describe('#825 (findings INV-22, feeds INV-28): the CVSS base score from the same NVD records feeds already reads (nvd-kev, else nvd-recent). Shown next to the exploited status, never instead of it')
export const FindingRow = Finding.extend({
  asset: FindingAsset.nullable(), kev: KevInfo.nullable().describe('Read from KEV, not from the project recommendation pack'),
  cvss: Cvss.nullable().describe('null = no CVSS score known: the pages say "No score", never 0'),
  fix: RowFix.nullable().optional().describe('GET /findings only, open findings: the update that fixes it with others (D-545); null when there is none to name'),
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
export const AiResult = z.object({
  skill: z.enum(['explain', 'mitigation-config']), ts: iso, model: z.string(),
  profile: z.string().optional().describe('Name of the AI profile that answered (D-29)'),
  tokens: z.object({ input: z.number(), output: z.number() }),
  paragraphs: z.array(z.string()), steps: z.array(z.string()),
  citations: z.array(z.object({ title: z.string(), url: z.string().optional() })),
  configs: z.array(CodeStep).optional().describe('mitigation-config (M2-2): config blocks to paste as they are, the device\'s own workaround first, then a rule for each firewall vendor in Devices (nftables when none); `note` says what the change is based on, `side_effect` what it can break. Absent for explain and for answers stored before'),
  no_config_reason: z.string().optional().describe('#897 r1 H1, mitigation-config: why no configuration, or no firewall rule, helps for this finding (the attack is local or needs a user, or no open port serves the vulnerable part), in the AI\'s words; the page shows it where the configuration would be'),
  shortened: z.boolean().optional().describe('M2-2: a part of the answer was longer than Vedette keeps: a text was cut at the end of a sentence (never in the middle of one) or a config block was left out whole'),
})
export const AppliedEntry = z.object({ item: z.string(), ts: iso, user: z.string() })

export const FixedIn = z.object({
  kind: z.enum(['fixed', 'up_to', 'end_listed', 'branches', 'distro', 'feature_update', 'esu']).describe('fixed = the device version is inside a range that ends before `fixed`, and `fixed` is outside every range that applies; up_to = inside a range whose end `fixed` is itself affected (no fixed release named); end_listed (M2-4) = inside a range that ends before `fixed`, but NVD lists releases of `fixed` itself as affected (Junos: "before 20.4", then 20.4R1 … one by one): `fixed` is not a fix, the vendor advisory names it; branches = the version is unknown or unreadable, `branches` lists the fix of each release line; distro = a package of the distribution, whose security updates carry the fix under their own numbers: an agent read it from the device\'s package database (deb/rpm), or the version carries a marker such as ubuntu, +deb12, .el9; feature_update (D-546) = a Windows release NVD does not list for the fix, which only a later release of its line (`branches[0].branch`, from build `fixed`) has: Microsoft no longer updates it, so it needs a feature update; esu (D-546) = the fixing Windows build `fixed` comes only with Extended Security Updates for `branches[0].branch`'),
  version: z.string().describe("The device's version; for branches empty when it has none, else the text Vedette cannot read"),
  fixed: z.string().describe('The fixed release (fixed), the last affected release (up_to), the upstream fixed release as a reference when NVD names one (distro: the backport may keep the package\'s number below it); empty for branches'),
  branches: z.array(z.object({ branch: z.string().describe('Release line such as 7.4; empty when it cannot be told'), fixed: z.string() })).describe('At most 5, newest first'),
  more: z.number().int().min(0).describe('Release lines with a fix left out of branches'),
  no_fix: z.number().int().min(0).describe('Release lines NVD gives no fixed release for (a range that ends at an affected version)'),
  distro: z.string().describe('"Ubuntu" or "Debian" when the device runs one, empty otherwise. distro: whose security updates to install (empty = the distribution). Other kinds: set only when the software is not known to come from the package database (typed by a person, read by a scan, or an agent row stored before inventory kept the flag); the page adds "if you installed it from the distribution\'s packages, install its security updates instead"'),
  distro_fixed: z.string().describe('D-516, kind distro only: the version of the distribution\'s package that fixes the CVE on the device\'s release (Ubuntu security data, Debian Security Tracker); `version` is then the device\'s full package version. Empty when the distribution\'s data does not say'),
  distro_release: z.string().describe('The device\'s release with distro_fixed ("24.04", "12"); empty otherwise'),
  distro_pro: z.boolean().describe('distro_fixed is in Ubuntu Pro (ESM) only'),
  source: z.string().describe('Where the versions come from: "NVD affected versions", "CVE.org affected versions (from the CVE record\'s CNA)" when NVD has none (D-556), or with distro_fixed "Ubuntu security data" / "Debian Security Tracker" (D-516)'),
})
export const KnownVersion = z.object({
  software: z.string().describe('Display name of the software the finding was matched on'),
  version: z.string(),
  source: z.enum(['agent', 'snmp', 'stated', 'scan', 'manual']).describe('Who gave the version: the device\'s agent, its answer to Vedette\'s SNMP read, its own statement on the network (LLDP), a network scan, or a person on the Devices page'),
}).describe('M2-3: the version the box has for the matched software; the page says it and how a newer one reaches Vedette, never "find which version"')
export const FindingDetail = FindingRow.extend({
  known_version: KnownVersion.nullable().describe('M2-3: null when the matched software has no version or its source is not known'),
  fixed_in: FixedIn.nullable().describe('The release that fixes this finding on this device, from the NVD affected versions (D-488); null = NVD gives none, the page shows CISA and the vendor advisory only'),
  pack: MitigationPack.nullable().describe('null = no recommendation confirmed by Vedette maintainers yet (D-21)'),
  compromise: CompromiseCheck.nullable(),
  recheck: z.object({ steps: z.array(z.string()), code: z.string().optional() }),
  ai: z.object({ explain: AiResult.nullable(), config: AiResult.nullable() }),
  ai_available: z.object({ explain: z.boolean(), config: z.boolean() }).describe('Whether an AI profile is assigned and allowed for each job (D-29)'),
  applied: z.array(AppliedEntry),
})
export const VersionNeeded = z.object({
  asset: FindingAsset.nullable(), asset_id: z.string(), software_id: z.string(), software: z.string().describe('Display name of the software'),
  version: z.string().nullable().describe('null = no version; otherwise the version as entered, which Vedette cannot read'),
  cves: z.number().int().min(1).describe('Exploited CVEs of this product that the version would decide'),
}).describe('D-500: a software on the exploited list without a usable version is ONE item, not one finding per CVE')
export const FindingList = z.object({ items: z.array(FindingRow), version_needed: z.array(VersionNeeded) })

// ---------- Updates to plan: CVE tiers 2 and 3 (S-TIER-1, S-TIER-2; D-613, D-615, D-616). Not findings: no status, no
// alert, no mitigation pack; one item per update on one device, each CVE one click away.
/** FIRST's EPSS probability from which a CVE is "likely to be exploited" (tier 2, D-613); feeds.EPSSLikely on the box. */
export const EPSS_LIKELY = 0.1
export const PlanTier = z.enum(['likely', 'recent'])
export const PlanFilter = z.enum(['likely', 'recent', 'all'])
export const PlanCve = z.object({
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  tier: PlanTier.describe('likely = EPSS 10 % or more; recent = published in the last 12 months (D-613); a CVE on an exploited list is a finding, never here'),
  basis: z.enum(['scan', 'agent', 'distro', 'version']).describe('D-615 evidence: scan = a scan engine (nuclei, OpenVAS, ZAP) found it on the device; agent = the device\'s agent reports a build or package inside the affected range; distro = Ubuntu\'s or Debian\'s own data says the installed package is affected; version = an exact version compared with the CVE\'s ranges. Never a product-only match'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).nullable().describe('NVD\'s CVSS severity; null when NVD has not scored it yet'),
  score: z.number().min(0).max(10).nullable().describe('NVD\'s CVSS base score'),
  published: z.iso.date().describe('NVD `published`; older than 12 months only with basis scan (D-615)'),
  epss: z.number().min(0).max(1).nullable(),
  percentile: z.number().min(0).max(1).nullable(),
})
export const PlanItem = z.object({
  group: z.string().describe('"<device id>/<software id>", as RowFix.group (D-545)'),
  asset: z.object({ id: z.string(), name: z.string().describe('The name the Devices page shows, never the internal id (D-484)') }),
  software: z.string().describe('Display name of the software row'),
  version: z.string().describe('The installed version'),
  fixed: z.string().describe('fixed: the version that fixes every CVE of the item; windows, esu: the build of the cumulative update; distro: the distribution\'s package version that fixes every CVE of the item on the device\'s release (D-622)'),
  kind: z.enum(['fixed', 'distro', 'windows', 'esu']).describe('fixed = upgrade the software to `fixed`; distro = upgrade the Ubuntu or Debian source package `software` from `version` to `fixed` or later (the distribution\'s security update, D-622); windows = the monthly cumulative update with build `fixed` or later; esu = the same on a Windows release past its end of support: the update comes only with Extended Security Updates (D-617)'),
  pro: z.boolean().describe('distro only: `fixed` is in Ubuntu Pro (ESM) only; false otherwise'),
  cves: z.array(PlanCve).min(1).describe('Likely first, by EPSS; then the recent ones by CVSS score, then EPSS; then newest (D-623)'),
  likely: z.number().int().min(0),
  recent: z.number().int().min(0),
})
export const PlanFeed = z.enum(['module_off', 'off', 'loading', 'ready']).describe('module_off = the feeds module is off (SYS-5: its data is not read); off = an admin has not turned the feed on; loading = on, first fill not finished; ready = loaded')
export const Plan = z.object({
  items: z.array(PlanItem),
  counts: z.object({
    likely: z.number().int().min(0).describe('Items the tier=likely answer lists'),
    recent: z.number().int().min(0).describe('Items the tier=recent answer lists'),
    all: z.number().int().min(0).describe('Items the tier=all answer lists'),
  }).describe('M2-9: the number of items each tier filter lists, for the same device filter, whatever tier was asked: one answer gives every tab its count'),
  compared: z.boolean().describe('false = no comparison of tier 2 and 3 CVEs with the devices has run since the box started (D-617: the plan job runs within minutes); the page says so instead of "no update to plan"'),
  compared_devices: z.number().int().min(0).describe('Devices with at least one version Vedette can compare'),
  unchecked_devices: z.number().int().min(0).describe('Devices with no version Vedette can read: not checked'),
  old_evidence: z.number().int().min(0).describe('D-615: CVEs published more than 12 months ago listed because a scan engine found them'),
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
  asset: FindingAsset.nullable().describe('null when the device was removed'),
  product: z.string().describe('The product as the findings list names it (the KEV display name, else "<vendor> <product>"; empty when the CVE left the list)'),
  software: z.string().describe('n73: the device\'s software the exploited-list entry is keyed to, as the finding\'s page names it (e.g. "Windows Server 2025"); empty when not known. Home leads with it and keeps `product` as context'),
  ransomware: z.boolean().describe('The exploited list says ransomware campaigns use it'),
  source: z.enum(['cisa-kev', 'vulncheck-kev']).nullable().describe('Which exploited list names it (D-557); null when the CVE left the list'),
  cvss: Cvss.nullable().describe('null = no score known: "No score", never 0'),
  first_seen: iso,
})
export const HomeSummary = z.object({
  open: z.object({
    total: z.number().int().describe('Open findings (confirmed + suspected): a device runs software on an exploited list'),
    confirmed: z.number().int().describe('Of them, confirmed by a scan'),
    devices: z.number().int().describe('Devices with at least one open finding'),
    ransomware: z.number().int().describe('Open findings whose CVE ransomware campaigns use'),
  }),
  top: z.array(SummaryItem).max(SUMMARY_TOP).describe('The open findings to fix first: confirmed before suspected, then ransomware, then the highest CVSS (no score last), then the newest'),
  trend: z.array(z.number().int()).length(SUMMARY_DAYS).describe('Open findings at the end of each of the last 30 days (UTC), oldest first; the last is now'),
  devices: z.object({ total: z.number().int().describe('Devices on the Devices page'), pending: z.number().int().describe('Devices waiting for review') }),
  alerts: z.object({ sent: z.number().int(), failed: z.number().int(), days: z.number().int() }).nullable().describe('Alert messages (incidents, vulnerabilities; not approval requests) sent and failed in the last `days` days; a failure resent later with success to the same channel is not counted as failed; null when Notifications is off'),
  incidents: z.object({ open: z.number().int().describe('Open incidents (new or acknowledged)'), urgent: z.number().int().describe('Of them, high or critical') }).nullable().describe('null when Notifications is off'),
  generated_at: iso.describe('When the box computed this summary (it keeps it up to 60 s, and drops it at every finding change)'),
})

const idParams = z.object({ id: findingId })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/findings', summary: 'List findings (CVE x device), optionally for one device', stories: ['S-MIT-1', 'S-SCAN-3'], role: 'viewer',
    query: z.object({ asset: z.string().optional() }), response: FindingList },
  { method: 'get', path: '/findings/{id}', summary: 'One finding: evidence, recommendation, compromise indicators, AI results', stories: ['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2'], role: 'viewer',
    params: idParams, response: FindingDetail, example: { params: { id: 'f-1' } } },
  { method: 'post', path: '/findings/{id}/status', summary: 'Change status (patched, mitigated, false positive, not relevant, accept risk until a day, reopen) with a note', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ action: StatusAction, note: z.string().max(500), until }), response: FindingDetail },
  { method: 'post', path: '/findings/status', summary: 'Change the status of the open findings among the ids (at most 500) with one note; one history and audit row per finding, all or nothing; closed findings are skipped', stories: ['S-MIT-1'], role: 'operator',
    body: z.object({ ids: z.array(findingId).min(1).max(MAX_BULK), action: BulkAction, note: z.string().max(500), until }),
    response: z.object({ updated: z.number().int().describe('Open findings changed'), skipped: z.number().int().describe('Findings already closed, left as they were') }) },
  { method: 'post', path: '/findings/{id}/applied', summary: 'Log "Applied" for one recommendation item; does not change the status by itself', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ item: ApplyItem }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/ai', summary: 'Explain or draft a recommendation with the customer AI key (BYOK); fails if AI is off', stories: ['S-AI-2', 'S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ skill: z.enum(['explain', 'mitigation-config']) }), response: FindingDetail },
  { method: 'get', path: '/findings/summary', summary: 'Home at a glance (#825): open findings, the few to fix first with their CVSS, 30 days of trend, device and alert counts; one cached read', stories: ['S-FEED-1', 'S-MIT-1', 'S-UI-1'], role: 'viewer',
    response: HomeSummary },
  { method: 'get', path: '/findings/plan', summary: 'Updates to plan: one item per update on one device that fixes CVEs likely to be exploited (EPSS 10 % or more) or published in the last 12 months, version-confirmed only; never findings, never alerts', stories: ['S-TIER-1', 'S-TIER-2'], role: 'viewer',
    query: z.object({ tier: PlanFilter.optional().describe('Default all'), asset: z.string().max(64).optional().describe('One device') }), response: Plan },
])
