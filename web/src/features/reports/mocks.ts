// Mock API module reports (S-REP-1, S-REP-2). Bảng riêng: rep_schedule, rep_history, rep_weekly_ai, rep_pdpl.
import { http, HttpResponse } from 'msw'
import { API, audit, body, EMAIL_RE, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { aiAvailable, aiCandidates, isOn, orgStore, recordAiRun } from '@/mocks/stores'
import { buildPdpl } from './pdpl'
import { buildWeekly } from './weekly'
import type { AiSummary, DataVolume, HistoryEntry, OrgSize, PdplOrg, PdplReport, Schedule, WeeklyReport } from './types'

const VOLUMES: DataVolume[] = ['lt1k', '1k_10k', '10k_100k', 'gte100k']
const SIZES: OrgSize[] = ['household', 'micro', 'small', 'startup', 'other']

type StoredSchedule = Omit<Schedule, 'next_run'>
// Cài sạch: chưa có người nhận nào, chưa gửi gì, nên tắt gửi tự động cho tới khi người dùng thêm email.
const schedule = collection<StoredSchedule>('rep_schedule', () => ({ enabled: true, day: 1, hour: 8, recipients: ['director@acme.example', 'it@acme.example'] }), () => ({ enabled: false, day: 1, hour: 8, recipients: [] }))
const history = collection<HistoryEntry[]>('rep_history', () =>
  [1, 2, 3].map((k): HistoryEntry => {
    const at = Date.now() - k * 7 * 864e5
    const failed = k === 3
    return { id: `h-${k}`, ts: new Date(at).toISOString(), trigger: 'scheduled', recipients: ['director@acme.example', 'it@acme.example'], status: failed ? 'failed' : 'sent', error: failed ? 'The email channel has no valid SMTP settings. Check Settings, Alert channels, then send again.' : undefined, report: buildWeekly(at) }
  }), () => [])
const weeklyAi = collection<AiSummary | null>('rep_weekly_ai', () => null)
const pdpl = collection<{ org: PdplOrg | null; report: PdplReport | null }>('rep_pdpl', () => ({ org: null, report: null }))

/** Lần gửi kế tiếp theo ngày/giờ đã đặt (giờ địa phương của trình duyệt chạy mock). */
function nextRun(s: StoredSchedule): string | null {
  if (!s.enabled) return null
  const d = new Date()
  d.setHours(s.hour, 0, 0, 0)
  const want = s.day % 7 // 1 = Monday … 7 = Sunday; JS getDay: 0 = Sunday
  let add = (want - d.getDay() + 7) % 7
  if (add === 0 && d.getTime() <= Date.now()) add = 7
  d.setDate(d.getDate() + add)
  return d.toISOString()
}
const withNext = (s: StoredSchedule): Schedule => ({ ...s, next_run: nextRun(s) })

function weeklyNow(): WeeklyReport { return { ...buildWeekly(), ai_summary: weeklyAi.get() } }

function aiWeekly(r: WeeklyReport): string[] {
  const c = r.counts
  const first = `Last week had ${c.new_findings} new findings and ${c.resolved} resolved; ${c.open_confirmed + c.open_suspected} remain open, ${c.open_confirmed} of them confirmed.`
  const top = r.open.find((x) => x.status === 'confirmed')
  const second = top
    ? `Do first: ${top.cve} on ${top.device} was confirmed by a scan; patch it or apply a temporary fix this week.`
    : 'No finding is confirmed; check the suspected ones to rule them out or confirm them.'
  return [first, second, `${c.devices_unapproved} devices are still waiting for approval.`]
}
function aiPdpl(r: PdplReport): string[] {
  const att = r.measures.filter((m) => m.status === 'attention').length
  const unk = r.measures.filter((m) => m.status === 'unknown').length
  return [
    `The box recorded ${r.inventory.total} devices, ${r.inventory.unapproved} not approved. Of ${r.measures.length} technical measures checked, ${att} need improvement and ${unk} have no data.`,
    `${r.risks.length} findings of exploited vulnerabilities are still open. These technical weaknesses should be closed before filing any dossier.`,
    'Obligations about dossiers, procedures and contracts are outside what Vedette can see; the responsible person must confirm each one.',
  ]
}

function checkSchedule(b: Partial<StoredSchedule>) {
  if (!Number.isInteger(b.day) || (b.day as number) < 1 || (b.day as number) > 7) return fail(400, 'invalid_day', 'Pick a day of the week.')
  if (!Number.isInteger(b.hour) || (b.hour as number) < 0 || (b.hour as number) > 23) return fail(400, 'invalid_hour', 'The send hour must be 0 to 23.')
  const rec = b.recipients
  if (!Array.isArray(rec) || rec.length > 20) return fail(400, 'invalid_recipients', 'The recipient list holds 20 emails at most.')
  const bad = rec.find((e) => typeof e !== 'string' || e.length > 120 || !EMAIL_RE.test(e))
  if (bad !== undefined) return fail(400, 'invalid_email', `The email "${String(bad).slice(0, 60)}" is not valid. Use the form name@company.com.`)
  if (b.enabled === true && rec.length === 0) return fail(400, 'no_recipients', 'Automatic sending needs at least one recipient. Add an email, then save.')
  return null
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

const aiNotReady = () => fail(409, 'ai_unavailable', isOn('ai')
  ? 'No AI profile is assigned to this task. An administrator adds or assigns one in Settings, AI assistant.'
  : 'The AI assistant module is off. Turn it on in Settings, Modules.')

export const handlers = [
  http.get(`${API}/reports/weekly/preview`, () => guard('viewer') ?? HttpResponse.json({ report: weeklyNow(), ai_available: aiAvailable('weekly-report') })),

  http.post(`${API}/reports/weekly/ai-summary`, () => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiAvailable('weekly-report')) return aiNotReady()
    const r = buildWeekly()
    const tin = 3900, tout = 1500
    const prof = aiCandidates('weekly-report')[0]!
    recordAiRun('weekly-report', tin, tout, 'weekly report', prof)
    const s: AiSummary = { paragraphs: aiWeekly(r), model: prof.model, profile: prof.name, tokens: { input: tin, output: tout }, generated_at: nowIso() }
    weeklyAi.set(s)
    audit('report.weekly.ai', 'weekly')
    return HttpResponse.json(s)
  }),

  http.get(`${API}/reports/schedule`, () => guard('viewer') ?? HttpResponse.json(withNext(schedule.get()))),
  http.put(`${API}/reports/schedule`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<StoredSchedule>(request)
    const bad = checkSchedule(b); if (bad) return bad
    const next: StoredSchedule = { enabled: b.enabled === true, day: b.day!, hour: b.hour!, recipients: [...new Set(b.recipients!.map((e) => e.trim().toLowerCase()))] }
    schedule.set(next)
    audit('report.schedule', 'weekly', `${next.enabled ? 'on' : 'off'}, ${next.day} ${next.hour}:00, ${next.recipients.length} recipients`)
    return HttpResponse.json(withNext(next))
  }),

  http.get(`${API}/reports/weekly/history`, () => guard('viewer') ?? HttpResponse.json({ items: history.get().map(({ report: _r, ...h }) => h) })),
  http.get(`${API}/reports/weekly/history/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const h = history.get().find((x) => x.id === params.id)
    return h ? HttpResponse.json(h) : fail(404, 'not_found', 'This report is not in the history.')
  }),
  http.post(`${API}/reports/weekly/send`, () => {
    const denied = guard('operator'); if (denied) return denied
    const to = schedule.get().recipients
    if (to.length === 0) return fail(400, 'no_recipients', 'There is no recipient. Add an email under Schedule and recipients, then send again.')
    const e: HistoryEntry = { id: newId('h'), ts: nowIso(), trigger: 'manual', recipients: to, status: 'sent', report: weeklyNow() }
    history.update((l) => [e, ...l].slice(0, 50))
    audit('report.weekly.send', 'weekly', `${to.length} recipients`)
    const { report: _r, ...entry } = e
    return HttpResponse.json(entry)
  }),

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
