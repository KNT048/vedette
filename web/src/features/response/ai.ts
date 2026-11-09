// AI-sent requests (D-51): the AI names a catalog action and typed values; the SERVER decides whether the request exists at all.
// Gates, in order: breaker and maintenance, quality pause, allowed trigger, action flagged for AI, typed values and never-touch, real evidence,
// confidence, one open request per target and action, 7 days after a rejection, budget (over budget goes to a digest), second check for high risk.
import { collection, newId, nowIso, peek } from '@/mocks/db'
import { assetsStore, findingsStore } from '@/mocks/stores'
import { AI_MIN_CONFIDENCE, AI_REPEAT_DAYS } from './contract'
import { events, openKeys, planAction, plannedKey } from './engine'
import { oneLine } from './logic'
import { actionsStore, appendLog, breakerOpen, BREAKER_MSG, catById, connById, HOUR, isObj, maintenanceNow, newRequest, refuse, settings, settingsStore, step, str } from './state'
import type { ActionRequest, AiNote, AiState, Evidence, Metrics, ProposeResult, Stat, Trigger } from './types'

export interface Hint { id: string; ts: string; kind: 'rule' | 'memory'; text: string; from_request: string }
export const notesStore = collection<AiNote[]>('resp_ai_notes', () => [{
  id: 'note-seed-1', ts: new Date(Date.now() - 50 * 60e3).toISOString(), kind: 'suggestion', title: 'Consider blocking 91.92.240.12', confidence: 0.6, action_id: 'blocklist_add', target: '91.92.240.12',
  why: 'PC-HR-01 connected to an address that one feed lists (URLhaus). Confidence 0.6 is below 0.8, so this is a note, not an approval request.', evidence: [{ kind: 'ioc_hit', id: 'det-s-ioc-2', summary: 'PC-HR-01 connected to 91.92.240.12 (URLhaus, confidence 60)' }],
}], () => [])
export const hintsStore = collection<Hint[]>('resp_hints', () => [{ id: 'hint-seed-1', ts: new Date(Date.now() - 2 * 864e5).toISOString(), kind: 'memory', text: 'Our own vulnerability scanner uses 203.0.113.77. Never propose blocking it.', from_request: 'act-seed-4' }], () => [])

const FORBIDDEN = ['cli', 'rest', 'change', 'command', 'template', 'run', 'rollback', 'method', 'path', 'url', 'body', 'headers', 'script']
const aiRequests = () => actionsStore.get().filter((a) => a.source === 'ai' && a.ai)
const DECIDED = ['approved', 'executed', 'rejected', 'failed', 'rolled_back']
const keyOf = (i: ActionRequest['items'][number]) => `${i.action_id}|${i.change.cli}|${i.change.rest ? `${i.change.rest.method} ${i.change.rest.url} ${i.change.rest.body ?? ''}` : ''}`

export function quality() {
  const last = aiRequests().filter((a) => DECIDED.includes(a.status) && a.decided_at).sort((x, y) => y.decided_at!.localeCompare(x.decided_at!)).slice(0, 10)
  const rejected = last.filter((a) => a.status === 'rejected').length
  return { decided: last.length, rejected, paused: settings().ai.paused_at !== null }
}
/** Quality breaker: more than half of the last 10 decided AI requests were rejected (needs at least 5 decisions): pause AI proposals and tell the admin. */
export function checkQuality() {
  const q = quality()
  if (q.paused || q.decided < 5 || q.rejected * 2 <= q.decided) return
  const reason = `${q.rejected} of the last ${q.decided} AI requests were rejected`
  settingsStore.update((s) => ({ ...s, ai: { ...s.ai, paused_at: nowIso(), paused_reason: reason } }))
  step('response.ai_paused', 'response', 'breaker', `AI proposals paused by the quality breaker: ${reason}. The admin was notified in the app and on the alert channels.`, 'system')
}
export function resume() {
  settingsStore.update((s) => ({ ...s, ai: { ...s.ai, paused_at: null, paused_reason: null } }))
  step('response.ai_resume', 'response', 'settings', 'AI proposals resumed by an admin')
}
export function usage() {
  const now = Date.now()
  const mine = aiRequests()
  return { hour: mine.filter((a) => now - Date.parse(a.requested_at) < HOUR).length, day: mine.filter((a) => now - Date.parse(a.requested_at) < 24 * HOUR).length }
}
export const aiState = (): AiState => ({ gates: settings().ai, min_confidence: AI_MIN_CONFIDENCE, repeat_days: AI_REPEAT_DAYS, usage: usage(), quality: quality(), notes: [...notesStore.get()].sort((a, b) => b.ts.localeCompare(a.ts)), hints: [...hintsStore.get()].sort((a, b) => b.ts.localeCompare(a.ts)) })

/** Evidence must be real objects the server can find. null = not found. */
function lookup(e: { kind: string; id: string }): { summary: string; relates: string[] } | null {
  if (e.kind === 'finding') {
    const f = findingsStore.get().find((x) => x.id === e.id); if (!f) return null
    const a = assetsStore.get().find((x) => x.id === f.asset_id)
    return { summary: `Finding ${f.cve} on ${a?.hostname ?? a?.ip ?? f.asset_id} (${f.severity})`, relates: [a?.ip ?? '', a?.hostname ?? ''] }
  }
  if (e.kind === 'ioc_hit') {
    const hits = peek<unknown>('logs_ioc_hits')
    const h = Array.isArray(hits) ? hits.filter(isObj).find((x) => str(x.id) === e.id) : undefined
    if (h) return { summary: `Known-bad connection ${str(h.src_ip)} to ${str(h.dest)}`, relates: [str(h.dest), str(h.src_ip)] }
    const ev = events().find((x) => x.id === e.id && x.trigger === 'ioc_connection')
    return ev ? { summary: ev.summary, relates: [ev.fields.dest ?? '', ev.fields.src_ip ?? ''] } : null
  }
  if (e.kind === 'config_read') {
    const [cid, tool] = e.id.split('/'); const c = connById(cid)
    const t = c?.tools.find((x) => x.name === tool && x.access === 'read' && x.enabled)
    return c && c.enabled && t ? { summary: `Read ${t.name} on ${c.name}`, relates: [] } : null
  }
  return null
}

export function propose(b: Record<string, unknown>): Response | ProposeResult {
  const bad = (code: string, msg: string, status = 400) => refuse(status, code, `AI request: ${msg}`, 'response.ai')
  const sent = FORBIDDEN.filter((k) => k in b)
  if (sent.length) return bad('no_commands', `the AI never writes commands. Refused field: ${sent.join(', ')}. It may only name a catalog action and typed values.`)
  const trigger = b.trigger as Trigger
  const cat = catById(typeof b.action_id === 'string' ? b.action_id : '')
  const params = isObj(b.params) ? b.params : {}
  const conf = typeof b.confidence === 'number' ? b.confidence : NaN
  const why = typeof b.why === 'string' ? oneLine(b.why, 400) : ''
  const evIn = Array.isArray(b.evidence) ? b.evidence.filter(isObj).map((e) => ({ kind: str(e.kind), id: str(e.id) })) : []
  if (!cat || typeof trigger !== 'string' || !Number.isFinite(conf) || conf < 0 || conf > 1 || !why) return bad('invalid', 'send trigger, action_id, params, confidence (0 to 1), evidence and why.')
  const s = settings()
  const w = maintenanceNow()
  if (w) return bad('maintenance', `held, maintenance window "${w.name}" is active.`, 409)
  if (breakerOpen()) return bad('circuit_open', BREAKER_MSG, 409)
  if (s.ai.paused_at) return bad('ai_paused', `AI proposals are paused (${s.ai.paused_reason ?? 'quality breaker'}). An admin can resume them.`, 409)
  if (!s.ai.triggers.includes(trigger)) return bad('trigger_not_allowed', 'the admin has not allowed the AI to send requests for this trigger.', 403)
  if (!cat.enabled || !cat.ai_may_propose) return bad('action_not_ai_allowed', `the action "${cat.name}" is not enabled for AI proposals in the action catalog.`, 403)
  const literal: Record<string, string> = {}
  for (const [k, v] of Object.entries(params)) literal[k] = typeof v === 'string' ? v : ''
  const undoable = !!(cat.rollback.cli || cat.rollback.path || cat.rollback.body)
  const planned = planAction({ action_id: cat.id, params: literal, ttl_min: undoable ? 1440 : null }, { id: 'ai', trigger, ts: nowIso(), summary: why, fields: {}, device_kind: null, asset_id: null }, why)
  if (!planned.ok) return bad(planned.code, planned.error, 409)
  const ev: Evidence[] = []
  if (!evIn.length) return bad('evidence_missing', 'a request must reference at least one real object: a finding id, a known-bad connection id or a connection read.')
  const found = evIn.map((e) => ({ e, f: lookup(e) }))
  for (const { e, f } of found) {
    if (!f) return bad('evidence_invalid', `the evidence ${e.kind} "${oneLine(e.id, 40)}" does not exist. The AI cannot invent evidence.`, 422)
    ev.push({ kind: e.kind as Evidence['kind'], id: e.id, summary: f.summary })
  }
  const targets = Object.values(planned.p.values).filter(Boolean) as string[]
  if (!found.some(({ f }) => f!.relates.some((r) => r && targets.includes(r))) && !evIn.every((e) => e.kind === 'config_read')) return bad('evidence_mismatch', 'none of the evidence is about the target of this action.', 422)
  const target = targets.join(', ')
  if (conf < AI_MIN_CONFIDENCE) {
    const note: AiNote = { id: newId('note'), ts: nowIso(), kind: 'suggestion', title: `Consider: ${planned.p.item.title}`, why, confidence: conf, action_id: cat.id, target, evidence: ev }
    notesStore.update((l) => [note, ...l].slice(0, 50))
    step('response.ai_note', 'response.ai', 'ai_note', `Suggestion only, no approval request: ${planned.p.item.title} (confidence ${conf} is below ${AI_MIN_CONFIDENCE})`, 'ai:response')
    return { outcome: 'suggestion', request: null, note: `Confidence ${conf} is below ${AI_MIN_CONFIDENCE}: saved as a suggestion note, no approval request was sent.` }
  }
  const key = plannedKey(planned.p)
  if (openKeys().has(key)) return bad('already_open', `there is already an open request or active change for ${target} with this action.`, 409)
  const cutoff = Date.now() - AI_REPEAT_DAYS * 24 * HOUR
  const prior = aiRequests().filter((a) => a.status === 'rejected' && a.decided_at && Date.parse(a.decided_at) >= cutoff && a.items.some((i) => keyOf(i) === key))
  if (prior.length) {
    const known = new Set(prior.flatMap((a) => a.ai!.evidence.map((e) => e.id)))
    if (!ev.some((e) => !known.has(e.id))) return bad('repeat_blocked', `this was rejected within the last ${AI_REPEAT_DAYS} days and there is no new evidence, so it is not asked again.`, 409)
  }
  const u = usage()
  if (u.hour >= s.ai.budget_hour || u.day >= s.ai.budget_day) {
    const note: AiNote = { id: newId('note'), ts: nowIso(), kind: 'digest', title: planned.p.item.title, why, confidence: conf, action_id: cat.id, target, evidence: ev }
    notesStore.update((l) => [note, ...l].slice(0, 50))
    step('response.ai_note', 'response.ai', 'ai_note', `Over budget (${s.ai.budget_hour} per hour, ${s.ai.budget_day} per day): moved to the digest instead of asking now: ${planned.p.item.title}`, 'ai:response')
    return { outcome: 'digest', request: null, note: `Budget reached (${s.ai.budget_hour} per hour, ${s.ai.budget_day} per day): added to the digest.` }
  }
  const high = planned.p.item.risk === 'high'
  let second: { ok: boolean; notes: string } | null = null
  if (high) {
    // Deterministic second checker: high-risk actions need at least 2 pieces of evidence and a confidence of 0.9 or more.
    const ok = ev.length >= 2 && conf >= 0.9
    second = { ok, notes: ok ? 'Second check passed: 2 or more pieces of evidence and confidence of 0.9 or more.' : `Second check failed: a high-risk action needs at least 2 pieces of evidence (got ${ev.length}) and confidence of 0.9 or more (got ${conf}).` }
    if (!ok) return bad('second_check_failed', second.notes, 422)
  }
  const dev = assetsStore.get().find((a) => targets.includes(a.ip))
  const a: ActionRequest = newRequest({
    source: 'ai', proposal_id: `ai:${newId('p')}`, rule_id: null, rule_name: null, trigger, trigger_summary: why, finding_id: ev.find((e) => e.kind === 'finding')?.id ?? null, cve: null,
    asset_id: dev?.id ?? null, asset_name: dev?.hostname ?? target, title: planned.p.item.title, items: [{ ...planned.p.item, id: newId('it') }],
    ai: { confidence: conf, evidence: ev, why, second_check: second, in_app_only: high },
  }, true)
  appendLog('proposal', 'ai:response', `${a.title}: confidence ${conf}, evidence ${ev.map((e) => `${e.kind} ${e.id}`).join(', ')}${second ? `; ${second.notes}` : ''}`)
  return { outcome: 'request', request: a, note: high ? 'Request sent. High risk: two different people must approve, in the app with the two-step code.' : 'Request sent for approval.' }
}

/** A rejection reason of an AI request can be saved as a rule or a memory hint; then the quality breaker is checked. */
export function afterReject(a: ActionRequest, reason: string, remember: 'none' | 'rule' | 'memory') {
  if (a.source !== 'ai') return
  if (remember !== 'none' && reason.trim()) {
    hintsStore.update((l) => [{ id: newId('hint'), ts: nowIso(), kind: remember, text: oneLine(reason, 300), from_request: a.id }, ...l].slice(0, 50))
    step('response.ai_hint', a.id, 'ai_note', `Rejection reason saved as ${remember === 'rule' ? 'a rule hint' : 'a memory hint'}: ${oneLine(reason, 200)}`)
  }
  checkQuality()
}

// ---- Metrics ----
const median = (n: number[]) => { if (!n.length) return null; const s = [...n].sort((x, y) => x - y); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2 }
function stat(list: ActionRequest[]): Stat {
  const approved = list.filter((a) => ['approved', 'executed', 'failed', 'rolled_back'].includes(a.status) && !a.pre_approved)
  const rejected = list.filter((a) => a.status === 'rejected').length
  const decided = approved.length + rejected
  const mins = approved.filter((a) => a.approvals.at(-1)).map((a) => (Date.parse(a.approvals.at(-1)!.at) - Date.parse(a.requested_at)) / 60e3).filter((m) => m >= 0)
  const med = median(mins)
  return { sent: list.length, approved: approved.length, rejected, expired: list.filter((a) => a.status === 'expired').length, pending: list.filter((a) => a.status === 'pending').length,
    acceptance_rate: decided ? approved.length / decided : null, median_approve_min: med === null ? null : Math.round(med * 10) / 10 }
}
export function metrics(): Metrics {
  const all = actionsStore.get()
  const rejected = all.filter((a) => a.status === 'rejected').sort((x, y) => (y.decided_at ?? '').localeCompare(x.decided_at ?? '')).slice(0, 20)
  return {
    ai: stat(all.filter((a) => a.source === 'ai')), rules: stat(all.filter((a) => a.source === 'rule')),
    suggestions: notesStore.get().filter((n) => n.kind === 'suggestion').length, digested: notesStore.get().filter((n) => n.kind === 'digest').length,
    rejected: rejected.map((a) => ({ id: a.id, title: a.title, source: a.source, reason: a.note ?? 'No reason given', at: a.decided_at ?? a.requested_at })),
  }
}
