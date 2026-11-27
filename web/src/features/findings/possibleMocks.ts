// Mock of the possible findings API (contract.ts: GET /findings/possible, the check of their advisories, AI proposals). A possible
// CVE is an unanswered question about one CVE (each CVE of a version_needed question) of a device nobody ignored, less those a finding
// of the same (device, CVE, line) has, as the server reads them. The checks live in fnd_possible_check, keyed by evidence identity.
// A check run advances by a few identities on every read of its state, so the preview shows it moving; the box decides some from the
// vendor's advisory and leaves AI proposals for the rest. Every string shown is English.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { aiCandidates, isOn } from '@/mocks/stores'
import { checkKeyOf, POSSIBLE_EXPLOITED, seedPossibleChecks, type CheckRecord, type QuestionRecord } from '@/mocks/seed/findings'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { assetOf, deviceRef, event, isIgnored, questions, records, severityOf, unhandled } from './modelMocks'
import type { PossibleCheckRun, PossibleCheckState, PossibleCounts, PossibleList, PossibleRow, UndecidedReason } from './types'

export const checks = collection<Record<string, CheckRecord>>('fnd_possible_check', seedPossibleChecks, () => ({}))
/** The last check run (the box keeps it in memory since it started). */
const runs = collection<(PossibleCheckRun & { keys: string[] }) | null>('fnd_possible_run', () => null)

const REASON_OF: Record<QuestionRecord['kind'], UndecidedReason> = {
  version_needed: 'no_version', platform: 'platform_unknown', package_release: 'package_unknown', not_comparable: 'version_scheme_mismatch',
  no_range_data: 'no_ranges', older_line: 'eol_line_unlisted',
}
const undecidedOf = (q: QuestionRecord) => q.undecided ?? { reason: q.kind === 'not_comparable' && q.attribute ? 'attribute_unknown' as const : REASON_OF[q.kind] }

type Item = { q: QuestionRecord; cve: string; key: string; check: CheckRecord | null; state: PossibleRow['state'] }

/** The possible CVEs of every device nobody ignored (of one device when set), exploited first within each line. */
function items(device?: string | null): Item[] {
  const had = new Set(records.get().map((r) => `${r.asset_id}|${r.cve}|${r.software?.id ?? ''}`))
  const cs = checks.get()
  const out: Item[] = []
  for (const q of questions.get()) {
    if (q.answered || (device && q.asset_id !== device) || !assetOf(q.asset_id) || isIgnored(q.asset_id)) continue
    for (const cve of q.cve ? [q.cve] : q.cve_list ?? []) {
      if (had.has(`${q.asset_id}|${cve}|${q.software?.id ?? ''}`)) continue
      const key = checkKeyOf(q, cve)
      const check = key ? cs[key] ?? null : null
      const state = !check ? 'possible' : check.decided_by !== 'ai' && check.verdict === 'not_affected' ? 'settled'
        : check.decided_by === 'ai' && !check.rejected && check.verdict !== 'unsure' ? 'proposal' : 'possible'
      out.push({ q, cve, key, check, state })
    }
  }
  return out.sort((a, b) => a.q.asset_id.localeCompare(b.q.asset_id) || (a.q.software?.id ?? '').localeCompare(b.q.software?.id ?? '')
    || Number(POSSIBLE_EXPLOITED.has(b.cve)) - Number(POSSIBLE_EXPLOITED.has(a.cve)) || a.cve.localeCompare(b.cve))
}

const checkable = (it: Item) => !!it.key && !it.check

export function possibleCounts(device?: string): PossibleCounts {
  const c = { possible: 0, proposals: 0, unchecked: 0, settled: 0 }
  for (const it of items(device)) {
    if (it.state === 'settled') { c.settled++; continue }
    c.possible++
    if (it.state === 'proposal') c.proposals++
    if (checkable(it)) c.unchecked++
  }
  return c
}

function row(it: Item): PossibleRow {
  const exploited = POSSIBLE_EXPLOITED.has(it.cve)
  return {
    id: it.q.id, cve: it.cve, kind: it.q.kind, device: deviceRef(assetOf(it.q.asset_id)!), software: it.q.software, severity: severityOf(it.cve) ?? severityGuess(it.cve),
    exploited, state: it.state, undecided: undecidedOf(it.q), line: it.q.line ?? null, fixes: it.q.fixes ?? [], check: it.check, checkable: checkable(it),
    bulk: it.state === 'proposal' && !(exploited && it.check?.verdict === 'not_affected'),
  }
}

/** A sample severity for the CVEs the sample list does not score: the same CVE always gets the same one. */
function severityGuess(cve: string): PossibleRow['severity'] {
  const n = Number(cve.slice(-2)) % 5
  const bands = [{ band: 'critical', score: 9.8 }, { band: 'high', score: 8.1 }, { band: 'high', score: 7.5 }, { band: 'medium', score: 5.3 }, null] as const
  const b = bands[n]
  return b ? { band: b.band, score: b.score, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } : null
}

const query = (req: Request) => new URL(req.url).searchParams
function read(fn: () => object) {
  const denied = guard('viewer'); if (denied) return denied
  return HttpResponse.json(fn())
}
const who = () => currentUser()!.email
const aiReady = () => isOn('ai') && aiCandidates('explain-finding').length > 0
const NO_PROPOSAL = 'No such proposal: it was answered, rejected or the evidence changed.'

/** The run reads on: a few identities more each time its state is read, each decided by the box from the vendor's advisory or
 *  left to the AI as a proposal (or unsure), the same way every time for the same identity. */
function advance() {
  const stored = runs.get()
  if (!stored?.running) return
  const run = { ...stored }
  const next = run.keys.slice(run.done, run.done + 6)
  const cs = { ...checks.get() }
  for (const key of next) {
    const n = parseInt(key.slice(0, 4), 16) % 10
    const base = { key, checked_by: run.by, checked_at: nowIso(), rejected: false, model: null, confidence: null, quote: '', reason: '' }
    const src = [{ url: 'https://vendor.example.com/security/advisory', title: 'Vendor security advisory', status: 'ok' as const, cited: true }]
    if (n < 3) {
      cs[key] = { ...base, decided_by: 'advisory', verdict: 'not_affected', reason: 'The vendor lists the affected releases from a newer branch on; this version is older.', quote: 'Affected: versions from 8.0 before 8.2.1', sources: src }
      run.advisory++
    } else if (n < 8) {
      const affected = n % 2 === 0
      cs[key] = { ...base, decided_by: 'ai', verdict: affected ? 'affected' : 'not_affected', confidence: n < 6 ? 'confident' : 'likely', model: 'claude-sonnet-5-5', sources: src,
        reason: affected ? 'The advisory names a range that covers this version.' : 'The advisory limits it to a feature this version does not have.',
        quote: affected ? 'All releases before the fixed version are affected.' : 'Only builds with the optional module are affected.' }
      run.proposals++
    } else {
      cs[key] = { ...base, decided_by: 'ai', verdict: 'unsure', model: 'claude-sonnet-5-5', sources: src, reason: 'The pages do not name the versions of this product.' }
      run.undecided++
    }
  }
  checks.set(cs)
  run.done += next.length
  if (run.done >= run.total) { run.running = false; run.finished_at = nowIso() }
  runs.set(run)
}

const runView = (): PossibleCheckRun | null => {
  const stored = runs.get()
  if (!stored) return null
  const { keys: _keys, ...run } = stored
  return run
}

export const possibleHandlers = [
  http.get(`${API}/findings/possible`, ({ request }) => read(() => {
    const p = query(request)
    const device = p.get('device')
    const state = p.get('state')
    if (state !== null && !['possible', 'proposal', 'settled'].includes(state)) return { items: [], total: 0, counts: possibleCounts(device ?? undefined) }
    const q = (p.get('q') ?? '').trim().toLowerCase()
    const has = (v?: string | null) => !!v && v.toLowerCase().includes(q)
    const all = items(device).filter((it) => (state ? it.state === state : it.state !== 'settled')).map(row)
      .filter((r) => !q || has(r.cve) || has(r.device.name) || has(r.device.ip) || has(r.software?.name))
    const offset = Number(p.get('offset') ?? 0)
    const limit = Math.min(Math.max(Number(p.get('limit') ?? PAGE_DEFAULT), 1), PAGE_MAX)
    return { items: all.slice(offset, offset + limit), total: all.length, counts: possibleCounts(device ?? undefined) } satisfies PossibleList
  })),
  http.get(`${API}/findings/possible/audit`, () => read(() => {
    const by = new Map<string, { reason: UndecidedReason; count: number; examples: string[] }>()
    for (const it of items()) {
      if (it.state === 'settled') continue
      const u = undecidedOf(it.q)
      const g = by.get(u.reason) ?? { reason: u.reason, count: 0, examples: [] }
      g.count++
      const ex = u.text ? `${u.url ?? ''}: ${u.text}` : (u.ranges ?? []).join('; ')
      if (ex && g.examples.length < 20 && !g.examples.includes(ex)) g.examples.push(ex)
      by.set(u.reason, g)
    }
    return { groups: [...by.values()].sort((a, b) => b.count - a.count) }
  })),
  http.get(`${API}/findings/possible/check`, () => read(() => {
    advance()
    return { ready: aiReady(), reason: aiReady() ? null : 'Checking possible findings needs the AI assistant on and a profile for explaining findings (Settings, AI assistant).', run: runView() } satisfies PossibleCheckState
  })),
  http.post(`${API}/findings/possible/check`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiReady()) return fail(409, 'ai_unavailable', 'Checking possible findings needs the AI assistant on and a profile for explaining findings (Settings, AI assistant).')
    if (runs.get()?.running) return fail(409, 'check_running', 'A check is already running. Its progress shows here.')
    const b = await body<{ device: string }>(request)
    const keys = [...new Set(items(b.device || null).filter(checkable).map((it) => it.key))].slice(0, 40)
    if (!keys.length) return fail(409, 'nothing_to_check', 'Every possible finding was checked for its current evidence.')
    runs.set({ running: true, total: keys.length, done: 0, advisory: 0, proposals: 0, undecided: 0, failed: 0, stopped: null, by: who(), started_at: nowIso(), finished_at: null, keys })
    audit('findings.possible_checked', b.device || 'all', `checking ${keys.length} possible findings`)
    return HttpResponse.json(runView())
  }),
  http.post(`${API}/findings/possible/confirm`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ verdict: string; confidence: string; device: string }>(request)
    if ((b.verdict !== 'affected' && b.verdict !== 'not_affected') || (b.confidence !== 'confident' && b.confidence !== 'likely')) return fail(400, 'invalid', 'Name the class: verdict affected or not_affected, confidence confident or likely.')
    if (b.verdict === 'affected') { const admin = guard('admin'); if (admin) return admin }
    const hit = items(b.device || null).filter((it) => it.state === 'proposal' && row(it).bulk && it.check!.verdict === b.verdict && it.check!.confidence === b.confidence).slice(0, 500)
    for (const it of hit) confirmOne(it)
    return HttpResponse.json({ confirmed: hit.length })
  }),
  http.post(`${API}/findings/possible/:id/confirm`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const it = items().find((x) => x.q.id === String(params.id) && x.state === 'proposal')
    if (!it) return fail(404, 'not_found', NO_PROPOSAL)
    if (it.check!.verdict === 'affected') { const admin = guard('admin'); if (admin) return admin }
    return HttpResponse.json({ finding: confirmOne(it) })
  }),
  http.post(`${API}/findings/possible/checks/:key/reject`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const key = String(params.key)
    const c = checks.get()[key]
    if (!/^[0-9a-f]{64}$/.test(key) || !c || c.decided_by !== 'ai' || c.verdict === 'unsure' || c.rejected) return fail(404, 'not_found', NO_PROPOSAL)
    checks.update((m) => ({ ...m, [key]: { ...c, rejected: true } }))
    audit('findings.proposal_rejected', key, `rejected the AI proposal ${c.verdict.replace('_', ' ')}`)
    return HttpResponse.json({ ok: true })
  }),
]

/** A person's yes to a proposal: affected records the finding (its confirmation from how the version is known, never the AI), not
 *  affected answers the question. */
function confirmOne(it: Item): string | null {
  const user = who(), at = nowIso()
  let finding: string | null = null
  if (it.check!.verdict === 'affected') {
    finding = newId('fv')
    const id = finding
    const note = `${user} confirmed an AI check of the CVE's advisories that ${it.q.software?.name ?? ''} ${it.q.software?.version ?? ''} is affected: "${it.check!.quote}".`
    records.update((l) => [...l, {
      id, asset_id: it.q.asset_id, cve: it.cve, software: it.q.software, verified: 'device', basis: 'device_version', verified_by: null, verified_at: at,
      fix: { key: `${it.q.software?.name.toLowerCase() ?? 'unknown'}|unknown|`, kind: 'unknown', product: it.q.software?.name ?? it.cve, version: null, ref: null, channel: 'public', url: it.check!.sources[0]?.url ?? null },
      ...unhandled, layer: POSSIBLE_EXPLOITED.has(it.cve) ? 2 as const : 5 as const, urgency_at: at, reasons: [], internet: null, first_seen: at, last_seen: at, reopened: null,
      events: [event('system', 'created', { note })],
    }])
    questions.update((l) => l.filter((q) => q.id !== it.q.id))
  } else {
    questions.update((l) => l.map((q) => (q.id === it.q.id ? { ...q, answered: { by: user, at } } : q)))
  }
  audit('findings.proposal_confirmed', it.q.id, `${it.cve}: confirmed the AI proposal ${it.check!.verdict.replace('_', ' ')}`)
  return finding
}
