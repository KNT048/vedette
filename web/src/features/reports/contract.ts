// Hợp đồng API module reports (D-18). Kiểu UI suy ra từ schema ở đây (types.ts).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()
const email = z.string().max(120)
export const FindingRow = z.object({
  id: z.string(), cve: z.string(), device: z.string(), asset_id: z.string(), product: z.string(),
  status: z.enum(['confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted']),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), since: iso,
  by: z.string().optional().describe('Who closed it (rows of what was done)'),
})
export const TopRisk = z.object({
  product: z.string().describe('The product as Findings names it'), device: z.string().describe('The device, or the first names and how many more'),
  devices: z.number().int(), open: z.number().int(), confirmed: z.number().int().describe('Open findings a scan confirmed'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).describe('The worst severity'), cve: z.string(), finding_id: z.string().describe('Its worst finding'),
  action: z.string().optional().describe('What to do this week, one sentence naming the device(s) and the fixed version when NVD says (D-490); absent in reports sent before it'),
})
export const ActionItem = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('fix'), cve: z.string(), device: z.string(), finding_id: z.string(), product: z.string().optional(), count: z.number().int().optional(), text: z.string().optional().describe('Since D-490 the sentence of the top risk action') }).describe('Since D-485 one top risk: product and count (its open findings) are set; cve and finding_id are its worst finding'),
  z.object({ kind: z.literal('verify'), cve: z.string(), device: z.string(), finding_id: z.string(), product: z.string().optional(), count: z.number().int().optional(), text: z.string().optional() }),
  z.object({ kind: z.literal('review_devices'), count: z.number().int() }),
  z.object({ kind: z.literal('plan_os'), count: z.number().int() }),
])
export const Happened = z.object({
  traps: z.number().int(), failed_logins: z.number().int(), accepted_logins: z.number().int(), bad_connections: z.number().int(), other: z.number().int(),
  summary: z.string().describe('The one sentence the page and the email say'),
  top: z.array(z.object({
    kind: z.enum(['login_accepted', 'trap', 'failed_logins', 'bad_connection', 'anomaly']), title: z.string(), severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    at: iso.describe('Last seen'),
  })).max(3),
}).describe('Incidents of the week from notify (D-490): counts per kind and the few that matter')
export const AiSummary = z.object({ paragraphs: z.array(z.string()), model: z.string(), profile: z.string().optional().describe('AI profile that answered'), tokens: z.object({ input: z.number(), output: z.number() }), generated_at: iso })
export const WeeklyReport = z.object({
  period: z.object({ from: iso, to: iso }), generated_at: iso,
  counts: z.object({
    new_findings: z.number(), resolved: z.number().describe('Closed this week; accepted risks are counted in accepted (D-498)'), open_confirmed: z.number(), open_suspected: z.number(),
    accepted: z.number().optional().describe('Risks accepted this week (D-498); absent when none or in reports sent before it'),
    accepted_until: z.iso.date().optional().describe('The earliest day one of those acceptances ends'),
    devices: z.number().describe('Devices as the Devices page counts them, this box included'), devices_unapproved: z.number(), devices_new: z.number(),
    kev_new: z.number().describe('Vulnerabilities newly exploited in the last 7 days, as Home counts them (D-485)'),
    kev_matched: z.number().describe('Products you use among them, as Home counts them (D-485; earlier reports: their CVEs on a device)'),
  }),
  top_risks: z.array(TopRisk).max(3).optional().describe('The three biggest open risks, by product (D-485); absent in reports sent before it'),
  new_findings: z.array(FindingRow), resolved: z.array(FindingRow), open: z.array(FindingRow), actions: z.array(ActionItem),
  happened: Happened.nullable().optional().describe('Absent or null when notify is off, or in reports sent before D-490'),
  sources: z.array(z.object({ id: z.enum(['inventory', 'findings', 'kev', 'incidents']), at: iso })).describe('Sources of the figures in the report; incidents only when notify is on (D-490)'),
  ai_summary: AiSummary.nullable(),
})
export const WeeklyPreview = z.object({ report: WeeklyReport, ai_available: z.boolean() })
export const Weekday = z.number().int().min(1).max(7).describe('1 = Monday … 7 = Sunday (D-57)')
export const Schedule = z.object({ enabled: z.boolean(), day: Weekday, hour: z.number().int().min(0).max(23), recipients: z.array(email).max(20), next_run: iso.nullable() })
export const ScheduleInput = Schedule.omit({ next_run: true })
const HistoryBase = { id: z.string(), ts: iso, trigger: z.enum(['manual', 'scheduled']), recipients: z.array(email), status: z.enum(['sent', 'failed']), error: z.string().optional() }
export const HistoryItem = z.object(HistoryBase)
export const HistoryEntry = z.object({ ...HistoryBase, report: WeeklyReport })

export const DataVolume = z.enum(['lt1k', '1k_10k', '10k_100k', 'gte100k'])
export const OrgSize = z.enum(['household', 'micro', 'small', 'startup', 'other'])
export const PdplOrg = z.object({
  name: z.string(), tax_code: z.string(), address: z.string(), sector: z.string(), employees: z.number().int(), data_volume: DataVolume,
  size: OrgSize.describe('Organization size under the small and medium enterprise law; decides whether Article 41 of Decree 356/2025/NĐ-CP applies'),
  processing_service: z.boolean().describe('Provides personal data processing services to others'),
  contact_name: z.string(), contact_email: z.string(), contact_phone: z.string(),
  sensitive: z.boolean(), cross_border: z.boolean(), processors: z.boolean(),
  level: z.enum(['', '1', '2', '3', '4', '5']).describe('Information system security level; empty = not determined. Not part of the personal data protection law'),
})
export const Measure = z.object({ id: z.enum(['firewall', 'patching', 'eol', 'unapproved', 'remote', 'logging', 'honeypot', 'scan', 'backup']), status: z.enum(['ok', 'attention', 'unknown']), n: z.number(), names: z.array(z.string()) })
export const Obligation = z.object({
  id: z.enum(['dpia', 'dpo', 'breach', 'consent', 'sensitive', 'cross_border', 'processors']),
  applies: z.boolean(),
  regime: z.enum(['required', 'optional', 'exempt']).describe('For dpia and dpo under Article 38 of Law 91/2025/QH15 and Article 41 of Decree 356/2025/NĐ-CP; other items are always required'),
  done: z.boolean().nullable(),
})
export const PdplReport = z.object({
  id: z.string(), generated_at: iso, org: PdplOrg,
  inventory: z.object({
    total: z.number(), approved: z.number(), unapproved: z.number(), fragile: z.number(),
    by_kind: z.array(z.object({ kind: z.string(), n: z.number() })),
    key_systems: z.array(z.object({ id: z.string(), name: z.string(), ip: z.string(), kind: z.string(), os: z.string() })),
    sources: z.array(z.object({ source: z.string(), n: z.number() })),
  }),
  measures: z.array(Measure), risks: z.array(FindingRow), obligations: z.array(Obligation),
  coverage: z.array(z.object({ module: z.string(), on: z.boolean() })), ai_summary: AiSummary.nullable(),
})
export const PdplState = z.object({ org: PdplOrg.nullable(), defaults: z.object({ name: z.string() }), report: PdplReport.nullable(), ai_available: z.boolean() })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/reports/weekly/preview', summary: 'One-page weekly report, figures computed when opened', stories: ['S-REP-1'], role: 'viewer', response: WeeklyPreview },
  { method: 'post', path: '/reports/weekly/ai-summary', summary: 'Draft a commentary for the weekly report with the customer AI', stories: ['S-REP-1', 'S-AI-6'], role: 'operator', response: AiSummary },
  { method: 'get', path: '/reports/schedule', summary: 'Weekly report schedule and recipients', stories: ['S-REP-1'], role: 'viewer', response: Schedule },
  { method: 'put', path: '/reports/schedule', summary: 'Save schedule and recipients (emails validated, max 20)', stories: ['S-REP-1'], role: 'admin', body: ScheduleInput, response: Schedule },
  { method: 'get', path: '/reports/weekly/history', summary: 'History of sent weekly reports', stories: ['S-REP-1'], role: 'viewer', response: z.object({ items: z.array(HistoryItem) }) },
  { method: 'get', path: '/reports/weekly/history/{id}', summary: 'One sent report with the original figures of that week, for reprinting', stories: ['S-REP-1'], role: 'viewer', params: z.object({ id: z.string() }), response: HistoryEntry, example: { params: { id: 'h-1' } } },
  { method: 'post', path: '/reports/weekly/send', summary: 'Send the weekly report now to the scheduled recipients', stories: ['S-REP-1'], role: 'operator', response: HistoryItem },
  { method: 'get', path: '/reports/pdpl', summary: 'Organization details and the generated assessment report', stories: ['S-REP-2'], role: 'viewer', response: PdplState },
  { method: 'put', path: '/reports/pdpl/org', summary: 'Save organization details for the assessment report (each field validated)', stories: ['S-REP-2'], role: 'operator', body: PdplOrg, response: PdplOrg },
  { method: 'post', path: '/reports/pdpl/generate', summary: 'Generate the assessment report from inventory, findings and module status', stories: ['S-REP-2'], role: 'operator', response: PdplReport },
  { method: 'post', path: '/reports/pdpl/ai-summary', summary: 'Draft a commentary for the assessment report with the customer AI', stories: ['S-REP-2', 'S-AI-6'], role: 'operator', response: AiSummary },
])
