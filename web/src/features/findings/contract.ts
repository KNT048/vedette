// Hợp đồng API module findings (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()
const findingId = z.string().min(1).max(64)

export const FindingStatus = z.enum(['confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant'])
export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export const AssetKind = z.enum(['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown'])
export const FirewallVendor = z.enum(['fortigate', 'mikrotik', 'generic'])
export const ApplyItem = z.enum(['patch', 'workaround', 'fortigate', 'mikrotik', 'generic'])
export const StatusAction = z.enum(['patched', 'mitigated', 'false_positive', 'not_relevant', 'reopen'])

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
  history: z.array(z.object({ ts: iso, user: z.string(), action: z.string(), note: z.string().optional() })),
})

export const KevInfo = z.object({
  name: z.string(), vendor: z.string(), product: z.string(), display: z.string(), required_action: z.string(), links: z.array(z.string()),
  date_added: z.string(), due_date: z.string().nullable(), ransomware: z.boolean(), epss: z.number().nullable(), has_template: z.boolean(),
})
export const FindingAsset = z.object({ id: z.string(), hostname: z.string().nullable(), ip: z.string(), kind: AssetKind, display: z.string() })
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

export const FindingDetail = FindingRow.extend({
  pack: MitigationPack.nullable().describe('null = no recommendation confirmed by Vedette maintainers yet (D-21)'),
  compromise: CompromiseCheck.nullable(),
  recheck: z.object({ steps: z.array(z.string()), code: z.string().optional() }),
  ai: z.object({ explain: AiResult.nullable(), config: AiResult.nullable() }),
  ai_available: z.object({ explain: z.boolean(), config: z.boolean() }).describe('Whether an AI profile is assigned and allowed for each job (D-29)'),
  applied: z.array(AppliedEntry),
})
export const FindingList = z.object({ items: z.array(FindingRow) })

const idParams = z.object({ id: findingId })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/findings', summary: 'List findings (CVE x device), optionally for one device', stories: ['S-MIT-1', 'S-SCAN-3'], role: 'viewer',
    query: z.object({ asset: z.string().optional() }), response: FindingList },
  { method: 'get', path: '/findings/{id}', summary: 'One finding: evidence, recommendation, compromise indicators, AI results', stories: ['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2'], role: 'viewer',
    params: idParams, response: FindingDetail, example: { params: { id: 'f-1' } } },
  { method: 'post', path: '/findings/{id}/status', summary: 'Change status (patched, mitigated, false positive, not relevant, reopen) with a note', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ action: StatusAction, note: z.string().max(500) }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/applied', summary: 'Log "Applied" for one recommendation item; does not change the status by itself', stories: ['S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ item: ApplyItem }), response: FindingDetail },
  { method: 'post', path: '/findings/{id}/ai', summary: 'Explain or draft a recommendation with the customer AI key (BYOK); fails if AI is off', stories: ['S-AI-2', 'S-MIT-1'], role: 'operator',
    params: idParams, body: z.object({ skill: z.enum(['explain', 'mitigation-config']) }), response: FindingDetail },
])
