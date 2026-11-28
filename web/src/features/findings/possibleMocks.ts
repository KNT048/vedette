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
import { autoReadOn, autoReadReached } from '@/features/ai/mocks'
import type { PossibleCause, PossibleCheck, PossibleCheckRun, PossibleCheckState, PossibleCounts, PossibleList, PossibleRow, UndecidedReason } from './types'

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
      // the AI's reading of the vendor's page: not affected settles the CVE unless it is exploited (a person confirms that one)
      const read = !!check?.reading && check.verdict === 'not_affected' && !check.rejected
      const state = !check ? 'possible' : read ? (POSSIBLE_EXPLOITED.has(cve) ? 'proposal' : 'settled')
        : check.decided_by !== 'ai' && check.verdict === 'not_affected' ? 'settled'
        : check.decided_by === 'ai' && !check.rejected && check.verdict !== 'unsure' ? 'proposal' : 'possible'
      out.push({ q, cve, key, check, state })
    }
  }
  return out.sort((a, b) => a.q.asset_id.localeCompare(b.q.asset_id) || (a.q.software?.id ?? '').localeCompare(b.q.software?.id ?? '')
    || Number(POSSIBLE_EXPLOITED.has(b.cve)) - Number(POSSIBLE_EXPLOITED.has(a.cve)) || a.cve.localeCompare(b.cve))
}

const checkable = (it: Item) => !!it.key && !it.check

const VERSION_REASONS: UndecidedReason[] = ['no_version', 'version_from_network', 'platform_unknown', 'package_unknown', 'attribute_unknown']
const DISTRO_REASONS: UndecidedReason[] = ['distro_not_listed', 'distro_other_packages', 'distro_other_releases', 'distro_other_build', 'distro_no_data']
/** Why the CVE is still possible (the server's PossibleCause, in short); null for a settled row. */
function causeOf(it: Item): PossibleCause | null {
  const reason = undecidedOf(it.q).reason
  const c = it.check
  if (it.state === 'settled') return null
  if (it.state === 'proposal') return 'needs_person'
  if (reason === 'nvd_pending') return 'pending_nvd'
  if (DISTRO_REASONS.includes(reason)) return 'distro_silent'
  if (['version_needed', 'platform', 'package_release'].includes(it.q.kind) || VERSION_REASONS.includes(reason)) return 'version_needed'
  if (c) {
    if (c.rejected) return 'needs_person'
    if (c.reading) return c.reading.status === 'unsure' || !c.reading.quote_found ? 'ai_unsure' : 'vendor_silent'
    if (c.decided_by === 'structured') return 'page_unreadable'
    if (c.decided_by === 'ai') return 'ai_unsure'
  }
  if (!it.key) return 'identity_unproven'
  if (!aiReady()) return 'needs_reading'
  return autoReadReached() ? 'ai_budget' : 'needs_reading'
}
/** Waiting for the distribution (the server's PossibleItem.DistroPending): an open row whose reason is a distribution's silence. */
const distroPendingOf = (it: Item) => it.state === 'possible' && DISTRO_REASONS.includes(undecidedOf(it.q).reason)
/** Reported only for an older build (the server's markOlderBuilds, in short): a third party's tested builds, the CVE on no exploited
 *  list, undecided by the record or a reading of it, and the record gives nothing from the vendor. */
const OLDER_CAUSES: PossibleCause[] = ['vendor_silent', 'ai_unsure', 'needs_reading', 'ai_budget']
function olderBuildOf(it: Item): PossibleRow['older_build'] {
  const u = undecidedOf(it.q)
  const cause = causeOf(it)
  if (u.reason !== 'third_party_tested_build' || it.state !== 'possible' || POSSIBLE_EXPLOITED.has(it.cve) || it.q.vendor_word || !cause || !OLDER_CAUSES.includes(cause)) return null
  const tested = [...new Set((u.ranges ?? []).map((r) => r.split(':').slice(5, 7).filter((x) => x !== '*' && x !== '-').join(' ')))]
  return tested.length ? { tested, year: Number(it.cve.split('-')[1]) } : null
}
const CAUSES: PossibleCause[] = ['vendor_silent', 'page_unreadable', 'needs_reading', 'ai_unsure', 'ai_budget', 'identity_unproven', 'version_needed', 'pending_nvd', 'needs_person', 'distro_silent']

/** The check of a question about one CVE stored by the time of its answer (the Answered list names a confirmed AI proposal by it);
 *  null when none. */
export function checkOfQuestion(q: QuestionRecord): CheckRecord | null {
  const key = q.cve ? checkKeyOf(q, q.cve) : ''
  const c = key ? checks.get()[key] ?? null : null
  return c && (!q.answered || Date.parse(c.checked_at) <= Date.parse(q.answered.at)) ? c : null
}

export function possibleCounts(device?: string): PossibleCounts {
  const c = { possible: 0, older_build: 0, distro_pending: 0, distro_pending_exploited: 0, proposals: 0, unchecked: 0, settled: 0, causes: Object.fromEntries(CAUSES.map((k) => [k, 0])) as PossibleCounts['causes'] }
  for (const it of items(device)) {
    if (it.state === 'settled') { c.settled++; continue }
    if (it.state === 'proposal') c.proposals++
    if (checkable(it)) c.unchecked++
    if (distroPendingOf(it)) {
      c.distro_pending++
      if (POSSIBLE_EXPLOITED.has(it.cve)) c.distro_pending_exploited++
      continue
    }
    if (olderBuildOf(it)) { c.older_build++; continue }
    c.possible++
    const cause = causeOf(it)
    if (cause) c.causes[cause]++
  }
  return c
}

/** A few CVEs the automatic reading leaves for now (the server keeps this in memory): why, and how many hours until it reads them again. */
const HELD: Record<string, { reason: NonNullable<PossibleRow['held']>['reason']; hours: number }> = {
  'CVE-2026-240104': { reason: 'answer_unusable', hours: 20 },
  'CVE-2026-240105': { reason: 'ai_failed', hours: 1 },
  'CVE-2026-240106': { reason: 'hook_refused', hours: 23 },
}
function heldOf(it: Item): PossibleRow['held'] {
  const h = HELD[it.cve]
  if (!h || !it.key || it.check || it.state === 'settled') return null
  if (!aiReady() || !autoReadOn() || autoReadReached()) return null // the reading cannot run now: the cause says what waits
  const until = new Date(Date.parse(nowIso()) + h.hours * 3_600_000)
  until.setUTCMinutes(0, 0, 0)
  return { until: until.toISOString(), reason: h.reason }
}

function row(it: Item): PossibleRow {
  const exploited = POSSIBLE_EXPLOITED.has(it.cve)
  return {
    id: it.q.id, cve: it.cve, kind: it.q.kind, device: deviceRef(assetOf(it.q.asset_id)!), software: it.q.software, severity: severityOf(it.cve) ?? severityGuess(it.cve),
    exploited, state: it.state, undecided: undecidedOf(it.q), line: it.q.line ?? null, fixes: it.q.fixes ?? [], check: it.check, checkable: checkable(it),
    bulk: it.state === 'proposal' && !(exploited && it.check?.verdict === 'not_affected'),
    cause: causeOf(it),
    held: heldOf(it),
    older_build: olderBuildOf(it),
    distro_pending: distroPendingOf(it),
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
    const base = { key, checked_by: run.by, checked_at: nowIso(), rejected: false, model: null, confidence: null, quote: '', reason: '', reading: null }
    const src = [{ url: 'https://vendor.example.com/security/advisory', title: 'Vendor security advisory', status: 'ok' as const, cited: true }]
    if (n < 3) {
      cs[key] = { ...base, decided_by: 'advisory', verdict: 'not_affected', reason: 'The vendor lists the affected releases from a newer branch on; this version is older.', quote: 'Affected: versions from 8.0 before 8.2.1', sources: src }
      run.advisory++
    } else if (n < 8) {
      // the AI's reading of the vendor's statement for the release line, its quote found on the page
      const affected = n % 2 === 0
      const reading = { status: affected ? 'fixed' as const : 'not_affected' as const, line: 'line', stated_line: null, introduced: null, fixed_in: affected ? '8.2.1' : null,
        last_affected: null, host: 'vendor.example.com', vendor_page: true, quote_found: true }
      cs[key] = { ...base, decided_by: 'ai', verdict: affected ? 'affected' : 'not_affected', confidence: 'confident', model: 'qwen3:8b', sources: src, reading,
        reason: affected ? 'The vendor states the fix of this release line; this version is older.' : 'The vendor states this release line is not affected.',
        quote: affected ? 'All releases of this line before 8.2.1 are affected.' : 'This release line is not affected by the issue.' }
      if (affected) openByReading(key, cs[key]!)
      run.readings++
    } else {
      cs[key] = { ...base, decided_by: 'ai', verdict: 'unsure', model: 'qwen3:8b', sources: src, reason: 'The pages do not name the versions of this product.' }
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
    runs.set({ running: true, total: keys.length, done: 0, advisory: 0, proposals: 0, readings: 0, undecided: 0, failed: 0, stopped: null, by: who(), started_at: nowIso(), finished_at: null, keys })
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
    if (!/^[0-9a-f]{64}$/.test(key) || !c || c.decided_by !== 'ai' || (c.verdict === 'unsure' && !c.reading) || c.rejected) return fail(404, 'not_found', NO_PROPOSAL)
    checks.update((m) => ({ ...m, [key]: { ...c, rejected: true } }))
    if (c.reading) {
      // the finding the reading opened closes on every device of the line; its CVE is possible again
      const at = nowIso()
      records.update((l) => l.map((r) => (r.ai_check?.key === key && r.state === 'open' ? { ...r, state: 'handled' as const, resolution: 'not_relevant' as const, via: 'data_corrected' as const,
        resolved_by: 'system', resolved_at: at, ai_check: { ...r.ai_check, rejected: true }, events: [...r.events, event('system', 'handled', { note: 'A person rejected the AI\'s reading of the vendor\'s statement.' })] } : r)))
      restore.get()[key]?.forEach((q) => questions.update((l) => (l.some((x) => x.id === q.id) ? l : [...l, q])))
      audit('findings.ai_reading_rejected', key, `rejected the AI's reading of ${c.reading.host ?? 'the CVE record'} (${c.reading.status.replace('_', ' ')})`)
      return HttpResponse.json({ ok: true })
    }
    audit('findings.proposal_rejected', key, `rejected the AI proposal ${c.verdict.replace('_', ' ')}`)
    return HttpResponse.json({ ok: true })
  }),
]

/** The questions a finding opened by the AI's reading took the place of, by the reading's key: back when a person rejects it. */
const restore = collection<Record<string, QuestionRecord[]>>('fnd_ai_read_questions', () => ({}))

/** The AI's verified "affected" opens the finding by itself, labelled with the page's host; the question it answered leaves the list. */
export function openByReading(key: string, check: PossibleCheck) {
  const at = nowIso()
  const hit = items().filter((it) => it.key === key)
  for (const it of hit) {
    const note = `Read by AI from ${check.reading?.host ?? 'the CVE record'}: the vendor's statement lists ${it.q.software?.name ?? ''} ${it.q.software?.version ?? ''} as affected by ${it.cve}: "${check.quote}".`
    records.update((l) => [...l, {
      id: newId('fv'), asset_id: it.q.asset_id, cve: it.cve, software: it.q.software, verified: 'device', basis: 'device_version', verified_by: null, verified_at: at,
      fix: { key: `${it.q.software?.name.toLowerCase() ?? 'unknown'}|update|${check.reading?.fixed_in ?? ''}`, kind: check.reading?.fixed_in ? 'update' : 'unknown', product: it.q.software?.name ?? it.cve,
        version: check.reading?.fixed_in ?? null, ref: null, channel: 'public', url: check.sources[0]?.url ?? null },
      ...unhandled, layer: POSSIBLE_EXPLOITED.has(it.cve) ? 2 as const : 5 as const, urgency_at: at, reasons: [], internet: null, first_seen: at, last_seen: at, reopened: null,
      events: [event('system', 'created', { note })], ai_check: check,
    }])
  }
  restore.update((m) => ({ ...m, [key]: hit.map((it) => it.q) }))
  questions.update((l) => l.filter((q) => !hit.some((it) => it.q.id === q.id)))
}

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
      events: [event('system', 'created', { note })], ai_check: it.check!,
    }])
    questions.update((l) => l.filter((q) => q.id !== it.q.id))
  } else {
    questions.update((l) => l.map((q) => (q.id === it.q.id ? { ...q, answered: { by: user, at } } : q)))
  }
  audit('findings.proposal_confirmed', it.q.id, `${it.cve}: confirmed the AI proposal ${it.check!.verdict.replace('_', ' ')}`)
  return finding
}
