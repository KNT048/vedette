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
  evidence: z.object({ summary: z.string(), template: z.string().optional(), request: z.string().optional(), response: z.string().optional(), checked_at: iso }).nullable(),
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
})
export const FindingAsset = z.object({
  id: z.string(), name: z.string().describe('The name the Devices page shows: hostname, else vendor and model, else the IP, else the software; never the internal id (D-484)'),
  hostname: z.string().nullable(), ip: z.string().describe('"—" when the device has no IP address'), kind: AssetKind, display: z.string(),
})
export const FindingRow = Finding.extend({ asset: FindingAsset.nullable(), kev: KevInfo.nullable().describe('Read from KEV, not from the project recommendation pack') })

export const CodeStep = z.object({
  title: z.string(), code: z.string(), note: z.string().optional(),
  side_effect: z.string().optional().describe('Side effect that must be stated before the user pastes the command'),
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
})
export const AppliedEntry = z.object({ item: z.string(), ts: iso, user: z.string() })

export const FixedIn = z.object({
  kind: z.enum(['fixed', 'up_to', 'branches', 'distro']).describe('fixed = the device version is inside a range that ends before `fixed`, and `fixed` is outside every range that applies; up_to = inside a range whose end `fixed` is itself affected (no fixed release named); branches = the version is unknown or unreadable, `branches` lists the fix of each release line; distro = the version is a distribution package\'s (marker such as ubuntu, +deb12, .el9), no number is named'),
  version: z.string().describe("The device's version; for branches empty when it has none, else the text Vedette cannot read"),
  fixed: z.string().describe('The fixed release (fixed), the last affected release (up_to); empty for branches'),
  branches: z.array(z.object({ branch: z.string().describe('Release line such as 7.4; empty when it cannot be told'), fixed: z.string() })).describe('At most 5, newest first'),
  more: z.number().int().min(0).describe('Release lines with a fix left out of branches'),
  no_fix: z.number().int().min(0).describe('Release lines NVD gives no fixed release for (a range that ends at an affected version)'),
  distro: z.string().describe('"Ubuntu" or "Debian" when the device runs one and the version has no distribution marker: the page adds "if you installed it from the distribution\'s packages, install its security updates instead"; empty otherwise'),
  source: z.string().describe('Where the versions come from: "NVD affected versions"'),
})
export const FindingDetail = FindingRow.extend({
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
])
