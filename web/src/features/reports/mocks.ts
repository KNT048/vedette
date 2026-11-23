// Mock API of the reports module (S-REP-1, S-REP-2). Tables: rep_definition, rep_sent (the sent documents; the server keeps
// them in rep_history) and rep_pdpl.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, EMAIL_RE, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { aiAvailable, aiCandidates, isOn, orgStore, recordAiRun } from '@/mocks/stores'
import { buildDocument, DEFAULT_OPTIONS } from './document'
import { buildPdpl } from './pdpl'
import type { AiSummary, DataVolume, OrgSize, PdplOrg, PdplReport, ReportDefinition, ReportDefinitionInput, ReportOptions, SentReport } from './types'

const VOLUMES: DataVolume[] = ['lt1k', '1k_10k', '10k_100k', 'gte100k']
const SIZES: OrgSize[] = ['household', 'micro', 'small', 'startup', 'other']

const pdpl = collection<{ org: PdplOrg | null; report: PdplReport | null }>('rep_pdpl', () => ({ org: null, report: null }))

function aiPdpl(r: PdplReport): string[] {
  const att = r.measures.filter((m) => m.status === 'attention').length
  const unk = r.measures.filter((m) => m.status === 'unknown').length
  return [
    `The box recorded ${r.inventory.total} devices, ${r.inventory.unapproved} not approved. Of ${r.measures.length} technical measures checked, ${att} need improvement and ${unk} have no data.`,
    `${r.risks.length} findings of exploited vulnerabilities are still open. These technical weaknesses should be closed before filing any dossier.`,
    'Obligations about dossiers, procedures and contracts are outside what Vedette can see; the responsible person must confirm each one.',
  ]
}

function checkOrg(b: Partial<PdplOrg>): Response | PdplOrg {
  const s = (v: unknown) => String(v ?? '').trim()
  const name = s(b.name)
  if (name.length < 2 || name.length > 120) return fail(400, 'invalid_name', 'The organisation name must be 2 to 120 characters.')
  if (!/^\d{10}(-\d{3})?$/.test(s(b.tax_code))) return fail(400, 'invalid_tax_code', 'The tax code is 10 digits, or 10 digits, a hyphen and 3 digits for a branch. Example 0312345678.')
  if (s(b.address).length < 5 || s(b.address).length > 200) return fail(400, 'invalid_address', 'Enter the head office address (5 to 200 characters).')
  if (s(b.sector).length < 2 || s(b.sector).length > 80) return fail(400, 'invalid_sector', 'Pick the field of activity.')
  const emp = Number(b.employees)
  if (b.employees === undefined || s(b.employees) === '' || !Number.isInteger(emp) || emp < 0 || emp > 1_000_000) return fail(400, 'invalid_employees', 'Headcount is a whole number from 0 to 1,000,000.')
  if (!SIZES.includes(b.size as OrgSize)) return fail(400, 'invalid_size', 'Pick the organisation size. It decides whether you must file an impact assessment dossier and appoint a data protection person.')
  if (!VOLUMES.includes(b.data_volume as DataVolume)) return fail(400, 'invalid_volume', 'Pick how many people\'s personal data you hold.')
  if (s(b.contact_name).length < 2 || s(b.contact_name).length > 80) return fail(400, 'invalid_contact', 'Enter the name of the person in charge of data protection.')
  if (!EMAIL_RE.test(s(b.contact_email))) return fail(400, 'invalid_email', 'The contact email is not valid. Use the form name@company.com.')
  if (!/^(0|\+84)\d{9,10}$/.test(s(b.contact_phone).replace(/[\s.]/g, ''))) return fail(400, 'invalid_phone', 'The phone number starts with 0 or +84 and has 10 to 11 digits.')
  if (!['', '1', '2', '3', '4', '5'].includes(String(b.level ?? ''))) return fail(400, 'invalid_level', 'The information system level is 1 to 5, or leave it empty if not determined yet.')
  return { name, tax_code: s(b.tax_code), address: s(b.address), sector: s(b.sector), employees: emp, data_volume: b.data_volume as DataVolume, size: b.size as OrgSize, processing_service: b.processing_service === true, contact_name: s(b.contact_name), contact_email: s(b.contact_email), contact_phone: s(b.contact_phone).replace(/[\s.]/g, ''), sensitive: b.sensitive === true, cross_border: b.cross_border === true, processors: b.processors === true, level: String(b.level ?? '') as PdplOrg['level'] }
}

// ---- The periodic security report ----
const DEF_ID = 'rd-1'
const SAMPLE_TO = ['director@acme.example', 'it@acme.example']
const newDefinition = (recipients: string[]): ReportDefinition => ({
  id: DEF_ID, name: 'Security report', options: DEFAULT_OPTIONS, recipients, schedule_key: `reports.def:${DEF_ID}`,
  updated_at: nowIso(), updated_by: 'system',
})
const definition = collection<ReportDefinition>('rep_definition', () => newDefinition(SAMPLE_TO), () => newDefinition([]))
const SENT_CAP = 52
const sent = collection<SentReport[]>('rep_sent', () =>
  [1, 2].map((k): SentReport => {
    const at = Date.now() - k * 7 * 864e5
    const document = buildDocument(newDefinition(SAMPLE_TO), at)
    const failed = k === 2
    return { id: `rh-${k}`, definition_id: DEF_ID, title: document.title, sent_at: document.generated_at, period: { from: document.period.from, to: document.period.to },
      trigger: 'schedule', recipients: SAMPLE_TO, status: failed ? 'failed' : 'sent',
      error: failed ? 'The email channel has no valid SMTP settings. Check Settings, Alert channels, then send again.' : null, sent_by: null, document }
  }), () => [])

const PERIODS: ReportOptions['period'][] = ['last_7_days', 'last_30_days', 'calendar_month']
const SECTIONS = Object.keys(DEFAULT_OPTIONS.sections) as (keyof ReportOptions['sections'])[]
const isBool = (v: unknown): v is boolean => typeof v === 'boolean'

/** Validates a definition at the edge: a 400 with the field named, or the clean values. */
function checkDefinition(b: Partial<ReportDefinitionInput>): Response | ReportDefinitionInput {
  const name = String(b.name ?? '').trim()
  if (name.length < 1 || name.length > 80) return fail(400, 'invalid_name', 'The report name must be 1 to 80 characters.', { field: 'name' })
  const o = (b.options ?? {}) as Partial<ReportOptions>
  if (!PERIODS.includes(o.period as ReportOptions['period'])) return fail(400, 'invalid_period', 'Pick the period: the last 7 days, the last 30 days or the last calendar month.', { field: 'options.period' })
  if (o.grouping !== 'device' && o.grouping !== 'cve') return fail(400, 'invalid_grouping', 'Group the open findings by device or by CVE.', { field: 'options.grouping' })
  if (!isBool(o.include_not_added) || !isBool(o.include_not_relevant) || !isBool(o.charts)) return fail(400, 'invalid', 'The options are not valid.', { field: 'options' })
  const sec = (o.sections ?? {}) as Partial<ReportOptions['sections']>
  if (!SECTIONS.every((k) => isBool(sec[k]))) return fail(400, 'invalid', 'Each section is on or off.', { field: 'options.sections' })
  if (!SECTIONS.some((k) => sec[k])) return fail(400, 'no_sections', 'Turn on at least one section; a report with no section would be empty.', { field: 'options.sections' })
  const rec = b.recipients
  if (!Array.isArray(rec) || rec.length > 20) return fail(400, 'invalid_recipients', 'The recipient list holds 20 emails at most.', { field: 'recipients' })
  const bad = rec.findIndex((e) => typeof e !== 'string' || e.trim().length > 120 || !EMAIL_RE.test(e.trim()))
  if (bad >= 0) return fail(400, 'invalid_email', `The email "${String(rec[bad]).slice(0, 60)}" is not valid. Use the form name@company.com.`, { field: `recipients[${bad}]` })
  return {
    name,
    options: { period: o.period!, grouping: o.grouping, include_not_added: o.include_not_added, include_not_relevant: o.include_not_relevant, charts: o.charts,
      sections: Object.fromEntries(SECTIONS.map((k) => [k, sec[k]])) as ReportOptions['sections'] },
    recipients: [...new Set(rec.map((e: string) => e.trim().toLowerCase()))],
  }
}

const reportHandlers = [
  http.get(`${API}/reports/definition`, () => guard('viewer') ?? HttpResponse.json(definition.get())),
  http.put(`${API}/reports/definition`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const input = checkDefinition(await body<ReportDefinitionInput>(request)); if (input instanceof Response) return input
    const next = definition.update((d) => ({ ...d, ...input, updated_at: nowIso(), updated_by: currentUser()?.email ?? 'system' }))
    audit('report.definition', next.id, `${next.options.period}, ${next.recipients.length} recipients`)
    return HttpResponse.json(next)
  }),
  http.get(`${API}/reports/document`, () => guard('viewer') ?? HttpResponse.json(buildDocument(definition.get()))),
  http.post(`${API}/reports/send`, () => {
    const denied = guard('operator'); if (denied) return denied
    const d = definition.get()
    if (d.recipients.length === 0) return fail(400, 'no_recipients', 'There is no recipient. Add an email in Settings, then send again.')
    const document = buildDocument(d)
    const e: SentReport = { id: newId('rh'), definition_id: d.id, title: document.title, sent_at: document.generated_at, period: { from: document.period.from, to: document.period.to },
      trigger: 'manual', recipients: d.recipients, status: 'sent', error: null, sent_by: currentUser()?.email ?? null, document }
    sent.update((l) => [e, ...l].slice(0, SENT_CAP))
    audit('report.send', d.id, `${d.recipients.length} recipients`)
    const { document: _d, ...item } = e
    return HttpResponse.json(item)
  }),
  http.get(`${API}/reports/history`, () => guard('viewer') ?? HttpResponse.json({ items: sent.get().map(({ document: _d, ...h }) => h) })),
  http.get(`${API}/reports/history/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const h = sent.get().find((x) => x.id === params.id)
    return h ? HttpResponse.json(h) : fail(404, 'not_found', 'This report is not in the history.')
  }),
]

const aiNotReady = () => fail(409, 'ai_unavailable', isOn('ai')
  ? 'No AI profile is assigned to this task. An administrator adds or assigns one in Settings, AI assistant.'
  : 'The AI assistant module is off. Turn it on in Settings, Modules.')

export const handlers = [
  ...reportHandlers,
  http.get(`${API}/reports/pdpl`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ ...pdpl.get(), defaults: { name: orgStore.get().name }, ai_available: aiAvailable('pdpl-assessment') })
  }),
  http.put(`${API}/reports/pdpl/org`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const org = checkOrg(await body<PdplOrg>(request)); if (org instanceof Response) return org
    pdpl.update((p) => ({ ...p, org }))
    audit('report.pdpl.org', org.name)
    return HttpResponse.json(org)
  }),
  http.post(`${API}/reports/pdpl/generate`, () => {
    const denied = guard('operator'); if (denied) return denied
    const org = pdpl.get().org
    if (!org) return fail(409, 'org_required', 'Fill in and save the organisation details first, then create the report.')
    const report = buildPdpl(org)
    pdpl.set({ org, report })
    audit('report.pdpl.generate', report.id)
    return HttpResponse.json(report)
  }),
  http.post(`${API}/reports/pdpl/ai-summary`, () => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiAvailable('pdpl-assessment')) return aiNotReady()
    const p = pdpl.get()
    if (!p.report) return fail(409, 'report_required', 'Create the report first; the AI needs something to comment on.')
    const tin = 11000, tout = 4200
    const prof = aiCandidates('pdpl-assessment')[0]!
    recordAiRun('pdpl-assessment', tin, tout, p.report.id, prof)
    const s: AiSummary = { paragraphs: aiPdpl(p.report), model: prof.model, profile: prof.name, tokens: { input: tin, output: tout }, generated_at: nowIso() }
    pdpl.set({ ...p, report: { ...p.report, ai_summary: s } })
    audit('report.pdpl.ai', p.report.id)
    return HttpResponse.json(s)
  }),
]
