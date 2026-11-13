// Mock API for the response module (S-RESP-1..4, S-AI-8; D-40, D-41, D-44, D-46, D-47, D-48, D-51).
// Tables: resp_settings, resp_plans, resp_actions, resp_catalog, resp_rules, resp_allowlist, resp_blocklist (token),
// resp_tokens (email approval links), resp_done (rule x event already handled), resp_ai_notes, resp_hints, resp_log.
// Every security gate is enforced on the server side of the mock (state.ts, engine.ts, ai.ts), never only in the UI.
import { http, HttpResponse } from 'msw'
import { API, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { connectorsStore } from '@/mocks/connectors'
import { aiAvailable, aiCandidates, assetsStore, findingsStore, recordAiRun, usersStore } from '@/mocks/stores'
import { boxAddress } from '@/mocks/network'
import type { Finding } from '@/lib/types'
import { scheduledPause } from '@/features/ai/mocks'
import { aiState, afterReject, metrics, propose, resume } from './ai'
import { RISK_PHRASE } from './contract'
import { TRIGGERS } from './data'
import { TEMPLATES } from './templates'
import { checkRule, events, eventView, ruleErrCode, rulesStore, runRules, simulate, templates } from './engine'
import { isCidr, isDomain, isIpv4, TOKEN_RE, type Tpl } from './logic'
import {
  actionsStore, actionsView, allowStore, approve, approversOf, isLinked, catalogStore, catById, catView, checkCatalog, chanLabel, chanList, chanReady, connById, connView, doneStore, findAction, isObj, isResp, logStore, notFound,
  newRequest, OFF_MSG, oneLine, previewBuild, rawChans, readyChan, refuse, reject, rollbackRequest, settings, settingsStore, settingsView, step, sweep, tokensStore, unavailable, userCanApprove, who, writeToolsOf,
  type Allow, type CatErr, randomToken, reversible, TEXT_RE,
} from './state'
import type { ActionRequest, ApprovalView, BlockEntry, Plan, Proposal, RequestItem, Rule, RuleInput, StoredProposal } from './types'
import { chatNotLinked, identityHandlers } from './identity'

// ---- Plans (S-RESP-1): what the AI drafts for an unresolved critical finding, deterministic here ----
import { sampleContainment, type StoredStep } from './templates/sample-firewall'
type StoredPlan = Omit<Plan, 'steps' | 'sent_to'> & { steps: StoredStep[] }
const openCritical = (f: Finding) => f.severity === 'critical' && (f.status === 'confirmed' || f.status === 'suspected')
const plansStore = collection<StoredPlan[]>('resp_plans', () => findingsStore.get().filter(openCritical).flatMap((f) => { const p = draft(f); return p ? [p] : [] }), () => [])

function draft(f: Finding): StoredPlan | null {
  const asset = assetsStore.get().find((a) => a.id === f.asset_id)
  if (!asset) return null
  const name = asset.hostname ?? asset.ip
  const profile = aiCandidates('response-plan')[0]
  // What the AI would read and propose through the connections: sample data (the firewall read and its virtual IP live in templates/sample-firewall.ts).
  const { reads, path, contain } = sampleContainment(f, asset, name)
  const steps: StoredStep[] = []
  steps.push(contain)
  steps.push({ kind: 'check', title: 'Check for compromise', detail: 'Look for the exploitation signs listed on this finding (files, web requests, processes) before you patch, so evidence is kept.', proposal: null })
  steps.push({ kind: 'patch', title: `Patch ${f.cve}`, detail: 'Install the vendor fix, then rescan to confirm. Turn the virtual IP back on only after the fixed version is running.', proposal: null })
  return { id: `plan-${f.id}`, finding_id: f.id, cve: f.cve, asset_id: asset.id, asset_name: name, generated_at: nowIso(), model: profile?.model ?? 'claude-sonnet-5-5', profile: profile?.name ?? 'Claude Sonnet', path, reads, steps }
}
/** The catalog action that carries out an AI plan proposal: the same connection and write tool. The sample connection names MCP-style tools although it is an HTTP one, and a built-in HTTP action has no tool (D-94), so the sample plan names the action by hand. */
const SAMPLE_TOOL_ACTION: Record<string, string> = { disable_virtual_ip: 'fgt_vip_disable' }
const aiCat = (p: StoredProposal) => catalogStore.get().find((c) => c.kind === 'device' && c.connection_id === p.connector_id && (c.tool === p.tool || c.id === SAMPLE_TOOL_ACTION[p.tool]))
/** Why the proposal cannot be carried out now: the action's own reason, or its sample write tool being off. */
const proposalProblem = (p: StoredProposal, cat: NonNullable<ReturnType<typeof aiCat>>): string | null => {
  const conn = connById(p.connector_id)
  return unavailable(cat) ?? (conn && !writeToolsOf(conn).includes(p.tool) ? `The write tool ${p.tool} on ${conn.name} is turned off or missing.` : null)
}
function proposalView(p: StoredProposal): Proposal {
  const s = settings()
  const open = actionsStore.get().find((a) => a.proposal_id === p.id && (a.status === 'pending' || a.status === 'approved' || a.status === 'executed'))
  const cat = aiCat(p)
  const state: Proposal['state'] = !s.execution ? 'execution_off' : !cat || !cat.enabled ? 'tool_not_allowed' : proposalProblem(p, cat) ? 'tool_unavailable' : 'ready'
  return { ...p, state, request_id: open?.id ?? null }
}
const planView = (p: StoredPlan): Plan => ({ ...p, steps: p.steps.map((s) => ({ ...s, proposal: s.proposal ? proposalView(s.proposal) : null })), sent_to: chanList().map(chanLabel) })

// ---- Block list (pull, D-44): entries are executed block-list items still in force ----
const blockMeta = collection<{ token: string; last_fetch: { at: string; from: string } | null }>('resp_blocklist', () => ({ token: randomToken(), last_fetch: null }))
function blockEntries(): BlockEntry[] {
  const now = Date.now()
  return actionsStore.get().flatMap((a) => a.items.filter((i) => i.action_id === 'blocklist_add' && i.status === 'executed' && (!i.remove_at || Date.parse(i.remove_at) > now)).flatMap((i) => {
    const ip = i.change.cli.split(' ').pop() ?? ''
    return isIpv4(ip) ? [{ value: ip, source: a.rule_name ? `Rule: ${a.rule_name}` : a.source === 'ai' ? 'AI request' : 'AI plan', reason: i.change.after.split('Reason: ')[1] ?? a.title, added_at: i.executed_at ?? a.requested_at, expires_at: i.remove_at }] : []
  })).sort((x, y) => y.added_at.localeCompare(x.added_at))
}
const blockUrl = (token: string) => `https://${boxAddress() ?? '<box ip>'}:8443/api/v1/response/blocklist/${token}.txt`
const blockView = () => ({ url: blockUrl(blockMeta.get().token), token_last4: blockMeta.get().token.slice(-4), entries: blockEntries(), last_fetch: blockMeta.get().last_fetch })

/** The approver of a link is still valid: on the channel's list with that address, the channel ready and one of the approval channels, an active operator or admin, and the person linked that address themselves (D-191). */
function linkApproverValid(t: { user_id: string; channel: string; address: string }) {
  const ch = rawChans().find((c) => c.type === t.channel)
  return !!ch && chanReady(ch) && settings().approval_channels.includes(t.channel) && approversOf(ch).some((x) => x.user_id === t.user_id && x.address === t.address) && !!userCanApprove(t.user_id) && isLinked(t.user_id, t.channel, t.address)
}

/** State of an emailed approval link. Used by the read-only GET and re-checked by the POST. */
function tokenState(token: string) {
  const t = TOKEN_RE.test(token) ? tokensStore.get().find((x) => x.token === token) : undefined
  const a = t ? actionsStore.get().find((x) => x.id === t.action_id) : undefined
  if (!t || !a) return { state: 'unknown' as ApprovalView['state'] }
  if (t.used_at) return { state: 'used' as const, t, a }
  if (Date.parse(t.expires_at) <= Date.now() || a.status === 'expired') return { state: 'expired' as const, t, a }
  if (a.status !== 'pending') return { state: 'decided' as const, t, a }
  return { state: 'ready' as const, t, a }
}

const iso = (v: unknown) => typeof v === 'string' && !Number.isNaN(Date.parse(v))
const TRIGGER_IDS = TRIGGERS.map((t) => t.id as string)

export const handlers = [
  ...identityHandlers,
  http.get(`${API}/response/plans`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    sweep()
    const open = findingsStore.get().filter(openCritical)
    // Draft a plan for each unresolved critical finding that has none yet (needs a usable AI profile for the job).
    if (aiAvailable('response-plan') && !scheduledPause()) { // from 80 % of the month's AI budget the scheduled plan job is paused (backend: 429 budget_reached, no row)
      for (const f of open) {
        if (plansStore.get().some((p) => p.finding_id === f.id)) continue
        const p = draft(f); if (!p) continue
        plansStore.update((l) => [...l, p])
        recordAiRun('response-plan', 1850, 540, f.id)
        step('response.plan', f.id, 'proposal', `AI drafted a response plan for ${f.cve} on ${p.asset_name}`, 'ai:response-plan')
      }
    }
    const only = new URL(request.url).searchParams.get('finding')
    const ids = new Set(open.map((f) => f.id))
    const items = plansStore.get().filter((p) => ids.has(p.finding_id) && (!only || p.finding_id === only)).map(planView)
    return HttpResponse.json({ items, ai_available: aiAvailable('response-plan'), execution: settings().execution })
  }),

  http.get(`${API}/response/actions`, () => {
    const denied = guard('viewer'); if (denied) return denied
    sweep()
    return HttpResponse.json({ items: actionsView() })
  }),

  http.post(`${API}/response/proposals/:id/request`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const pid = String(params.id)
    const plan = plansStore.get().find((p) => p.steps.some((st) => st.proposal?.id === pid))
    const prop = plan?.steps.find((st) => st.proposal?.id === pid)?.proposal
    if (!plan || !prop) return fail(404, 'not_found', 'No such proposal.')
    const f = findingsStore.get().find((x) => x.id === plan.finding_id)
    if (!f || !openCritical(f)) return refuse(409, 'finding_closed', 'The finding is no longer an open critical finding.', pid)
    if (!settings().execution) return refuse(409, 'execution_off', OFF_MSG, pid)
    const cat = aiCat(prop)
    if (!cat || !cat.enabled) return refuse(403, 'tool_not_allowed', `The action "${cat?.name ?? prop.tool}" is not enabled in the action catalog (Settings, AI response).`, pid)
    const problem = proposalProblem(prop, cat)
    if (problem) return refuse(409, 'tool_unavailable', problem, pid)
    if (actionsStore.get().some((a) => a.proposal_id === pid && (a.status === 'pending' || a.status === 'executed'))) return refuse(409, 'already_requested', 'This action already has an open request or has already been carried out.', pid)
    const item: RequestItem = { id: newId('it'), action_id: cat.id, title: prop.title, risk: cat.risk, reversible: reversible(cat), connector_id: prop.connector_id, connection: prop.connection, tool: prop.tool, targets: 1, change: prop.change,
      ttl_min: null, status: 'pending', executed_at: null, remove_at: null, rolled_back_at: null, result: null, verified: null, state_unknown: false }
    const a = newRequestFromPlan(plan, prop, item)
    return HttpResponse.json(a, { status: 201 })
  }),

  http.post(`${API}/response/actions/:id/approve`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const a = findAction(String(params.id)); if (!a) return notFound()
    const b = await body<{ items: string[]; code: string }>(request)
    if (b.items !== undefined && (!Array.isArray(b.items) || !b.items.every((x) => typeof x === 'string'))) return fail(400, 'invalid', 'Send items as a list of action ids, or leave it out to approve all.')
    const r = approve(a, who(currentUser()!, 'app'), b.items, typeof b.code === 'string' ? b.code : undefined)
    return isResp(r) ? r : HttpResponse.json(r)
  }),

  http.post(`${API}/response/actions/:id/reject`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const a = findAction(String(params.id)); if (!a) return notFound()
    const b = await body<{ reason: string; remember: string }>(request)
    const u = currentUser()!
    const reason = typeof b.reason === 'string' ? oneLine(b.reason, 300).trim() : ''
    const remember = b.remember === 'rule' || b.remember === 'memory' ? b.remember : 'none'
    const r = reject(a, who(u, 'app'), reason ? `Rejected by ${u.name}: ${reason}` : `Rejected by ${u.name}`)
    if (isResp(r)) return r
    afterReject(r, reason, remember)
    return HttpResponse.json(r)
  }),

  http.post(`${API}/response/actions/:id/rollback`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const a = findAction(String(params.id)); if (!a) return notFound()
    const r = rollbackRequest(a)
    return isResp(r) ? r : HttpResponse.json(r)
  }),

  // Preview build only: the real decision arrives from the Slack/Telegram/Zalo connector on the box, not from a browser.
  http.post(`${API}/response/actions/:id/chat-decision`, async ({ params, request }) => {
    if (!previewBuild()) return fail(404, 'not_found', 'Not available.')
    const denied = guard('admin'); if (denied) return denied
    sweep()
    const a = findAction(String(params.id)); if (!a) return notFound()
    const b = await body<{ channel: string; external_id: string; decision: string }>(request)
    if ((b.channel !== 'slack' && b.channel !== 'telegram' && b.channel !== 'zalo-personal') || !/^[A-Za-z0-9_-]{1,64}$/.test(b.external_id ?? '') || (b.decision !== 'approve' && b.decision !== 'reject')) return fail(400, 'invalid', 'Send channel (slack, telegram or zalo-personal), external_id and decision (approve or reject).')
    // The address must be on THIS channel's approver list, and that user must be an active operator or admin.
    const ch = rawChans().find((c) => c.type === b.channel)
    const ap = ch ? approversOf(ch).find((x) => x.address === b.external_id) : undefined
    const u = ap ? userCanApprove(ap.user_id) : undefined
    if (!ch || !ap || !u) return refuse(403, 'approver_not_listed', `Not counted: this ${b.channel} address is not on the approver list of that channel, or its user is not an operator or admin.`, a.id)
    if (!settings().approval_channels.includes(b.channel) || !chanReady(ch)) return refuse(403, 'channel_not_allowed', `Approvals from ${b.channel} are not turned on for response.`, a.id)
    if (!isLinked(u.id, ch.type, ap.address)) return chatNotLinked(ch.type, ap.address, a.id) // D-191, D-414: the answer says how to link
    if (a.items.some((i) => i.connector_id !== null) && !settings().execution) return refuse(409, 'execution_off', OFF_MSG, a.id)
    const w = who(u, b.channel, b.external_id)
    const r = b.decision === 'approve' ? approve(a, w) : reject(a, w, `Rejected in ${b.channel} by ${u.name}`)
    if (isResp(r)) return r
    if (b.decision === 'reject') afterReject(r, '', 'none')
    return HttpResponse.json(r)
  }),

  // Emailed link, public. GET only shows the change (link scanners cannot approve); the decision is a POST.
  http.get(`${API}/response/approve/:token`, ({ params }) => {
    sweep()
    const found = tokenState(String(params.token)) as ReturnType<typeof tokenState> & { t?: { user_id: string; expires_at: string; channel: string; address: string }; a?: ActionRequest }
    // Spec 8: a link whose person may no longer approve (disabled, taken off the list, new address, channel not allowed) reads as no link at all.
    const gone = found.t ? !linkApproverValid(found.t) : false
    const { state, t, a } = gone ? ({ state: 'unknown' } as typeof found) : found
    const u = t ? usersStore.get().find((x) => x.id === t.user_id) : undefined
    const ready = state === 'ready'
    const view: ApprovalView = { state, title: ready ? a!.title : null, items: ready ? a!.items.map((i) => ({ title: i.title, risk: i.risk, change: i.change })) : [], approver: ready ? (u?.name ?? null) : null, expires_at: ready ? t!.expires_at : null, status: a?.status ?? null,
      requires_approvals: a?.requires_approvals ?? null, approved_so_far: a ? a.approvals.length : null, ai_generated: ready && !!a!.ai }
    return HttpResponse.json(view)
  }),

  http.post(`${API}/response/approve/:token`, async ({ params, request }) => {
    sweep()
    const b = await body<{ decision: string }>(request)
    if (b.decision !== 'approve' && b.decision !== 'reject') return fail(400, 'invalid', 'Send decision as approve or reject.')
    const { state, t, a } = tokenState(String(params.token)) as ReturnType<typeof tokenState> & { t?: { token: string; channel: string; user_id: string; address: string }; a?: ActionRequest }
    if (state === 'unknown' || !t || !a) return fail(404, 'unknown', 'This link is not valid.')
    if (state !== 'ready') return refuse(409, state, state === 'used' ? 'This link was already used.' : state === 'expired' ? 'This link has expired. Ask for a new approval request.' : `This request is already ${a.status.replace('_', ' ')}.`, a.id)
    // Re-check who the link belongs to: still on this channel's approver list, still an active operator or admin.
    const u = userCanApprove(t.user_id)
    if (!linkApproverValid(t) || !u) return refuse(403, 'approver_not_listed', 'This link no longer belongs to a valid approver.', a.id)
    const w = who(u, t.channel === 'zalo' ? 'zalo' : 'email', t.address)
    const r = b.decision === 'approve' ? approve(a, w) : reject(a, w, `Rejected through an emailed link by ${u.name}`)
    if (isResp(r)) return r
    tokensStore.update((l) => l.map((x) => (x.token === t.token ? { ...x, used_at: nowIso() } : x)))
    if (b.decision === 'reject') afterReject(r, '', 'none')
    return HttpResponse.json(r)
  }),

  http.get(`${API}/response/settings`, () => {
    const denied = guard('admin'); if (denied) return denied
    return HttpResponse.json(settingsView())
  }),

  http.put(`${API}/response/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<Record<string, unknown>>(request)
    const bad = (m: string) => refuse(400, 'invalid', m, 'response.settings')
    const int = (v: unknown, lo: number, hi: number) => Number.isInteger(v) && (v as number) >= lo && (v as number) <= hi
    if (!int(b.max_per_hour, 1, 20)) return bad('Actions per hour must be a whole number from 1 to 20.')
    if (!int(b.expiry_min, 15, 30)) return bad('Approval expiry must be 15 to 30 minutes.')
    if (!Array.isArray(b.approval_channels) || !b.approval_channels.every((t) => typeof t === 'string' && readyChan(t))) return bad('Approval channels must have approvals turned on and at least one approver (Settings, Alert channels).')
    if (!int(b.breaker_max_per_hour, 1, 200)) return bad('The circuit breaker limit must be 1 to 200 actions per hour.')
    if (!int(b.multi_target_max, 1, 1000)) return bad('The multi-target limit must be 1 to 1000.')
    const win = Array.isArray(b.maintenance) ? b.maintenance : null
    if (!win || win.length > 20 || !win.every((w) => isObj(w) && typeof w.id === 'string' && /^[\w.-]{1,96}$/.test(w.id) && typeof w.name === 'string' && TEXT_RE.test(w.name) && iso(w.start) && iso(w.end) && Date.parse(w.end as string) > Date.parse(w.start as string))) return bad('Maintenance windows need a name, a start and a later end (up to 20).')
    const ai = isObj(b.ai) ? b.ai : null
    if (!ai || !Array.isArray(ai.triggers) || !ai.triggers.every((t) => typeof t === 'string' && TRIGGER_IDS.includes(t)) || !int(ai.budget_hour, 1, 20) || !int(ai.budget_day, 1, 100) || (ai.budget_day as number) < (ai.budget_hour as number)) return bad('AI gates: choose triggers, an hourly budget of 1 to 20 and a daily budget of 1 to 100 (not lower than the hourly one).')
    settingsStore.update((s) => ({ ...s, ...settings(), max_per_hour: b.max_per_hour as number, expiry_min: b.expiry_min as number, approval_channels: b.approval_channels as string[], breaker_max_per_hour: b.breaker_max_per_hour as number, multi_target_max: b.multi_target_max as number,
      maintenance: (win as { id: string; name: string; start: string; end: string }[]).map((w) => ({ id: w.id, name: w.name, start: w.start, end: w.end })), ai: { ...settings().ai, triggers: ai.triggers as never, budget_hour: ai.budget_hour as number, budget_day: ai.budget_day as number } }))
    step('response.settings', 'response', 'settings', `${b.max_per_hour}/hour; expiry ${b.expiry_min} min; breaker ${b.breaker_max_per_hour}/hour; more than ${b.multi_target_max} targets needs 2 approvers; ${win.length} maintenance window(s); AI triggers: ${(ai.triggers as string[]).join(', ') || 'none'}, budget ${ai.budget_hour}/hour ${ai.budget_day}/day; channels: ${(b.approval_channels as string[]).join(', ') || 'app only'}`)
    return HttpResponse.json(settingsView())
  }),

  http.post(`${API}/response/execution`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ enabled: boolean; phrase: string }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'invalid', 'Send enabled as true or false.')
    const u = currentUser()!
    if (b.enabled) {
      if (!u.twofa) return refuse(409, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then try again.', 'response.execution')
      if (b.phrase !== RISK_PHRASE) return refuse(400, 'phrase_mismatch', `Type ${RISK_PHRASE} exactly, in capital letters.`, 'response.execution')
      if (!settings().execution) {
        settingsStore.update((s) => ({ ...s, execution: true, accepted_by: u.email, accepted_at: nowIso() }))
        step('response.execution.enable', 'response', 'settings', `${u.email} accepted the risk and turned on execution`)
      }
    } else if (settings().execution) {
      settingsStore.update((s) => ({ ...s, execution: false }))
      step('response.execution.disable', 'response', 'settings', `${u.email} turned off execution`)
    }
    return HttpResponse.json(settingsView())
  }),

  http.post(`${API}/response/emergency-stop`, () => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const u = currentUser()!
    const pending = actionsStore.get().filter((a) => a.status === 'pending')
    settingsStore.update((s) => ({ ...s, execution: false, breaker_tripped_at: s.breaker_tripped_at ?? nowIso(), stopped_at: s.stopped_at ?? nowIso() })) // INV-8: the stop also opens the breaker
    actionsStore.update((l) => l.map((a) => (a.status === 'pending' ? { ...a, status: 'rejected', decided_at: nowIso(), note: `Cancelled by emergency stop (${u.email})`, items: a.items.map((i) => ({ ...i, status: 'skipped' as const })) } : a)))
    step('response.emergency_stop', 'response', 'emergency_stop', `${u.email} stopped execution; ${pending.length} pending request${pending.length === 1 ? '' : 's'} cancelled`)
    return HttpResponse.json({ cancelled: pending.length })
  }),

  http.post(`${API}/response/breaker/reset`, () => {
    const denied = guard('admin'); if (denied) return denied
    settingsStore.update((s) => ({ ...s, breaker_tripped_at: null, breaker_notified: [], stopped_at: null }))
    step('response.breaker_reset', 'response', 'settings', `${currentUser()!.email} resumed response after the circuit breaker`)
    return HttpResponse.json(settingsView())
  }),

  // ---- Triggers, rules, events, templates (S-RESP-3) ----
  http.get(`${API}/response/triggers`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: TRIGGERS.map((t) => ({ ...t, ai_allowed: settings().ai.triggers.includes(t.id) })) })
  }),
  http.get(`${API}/response/rules`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: rulesStore.get() })
  }),
  http.post(`${API}/response/rules/run`, () => {
    if (!previewBuild()) return fail(404, 'not_found', 'Not available.')
    const denied = guard('operator'); if (denied) return denied
    sweep()
    return HttpResponse.json(runRules())
  }),
  http.post(`${API}/response/rules/simulate`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ rule: Partial<RuleInput>; event_id: string }>(request)
    const c = checkRule({ ...(isObj(b.rule) ? b.rule : {}) })
    if (typeof c === 'string') return refuse(400, ruleErrCode(c), c, 'response.simulate')
    return HttpResponse.json(simulate(c, typeof b.event_id === 'string' ? b.event_id : undefined))
  }),
  http.post(`${API}/response/rules`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const raw = await body<RuleInput>(request)
    const c = checkRule({ ...raw, live: false }) // a new rule always starts in dry run
    if (typeof c === 'string') return refuse(400, ruleErrCode(c), c, 'response.rule')
    if (rulesStore.get().length >= 30) return refuse(409, 'limit', 'Up to 30 rules.', 'response.rule')
    const r: Rule = { ...c, id: newId('rule'), template_id: null, last_fired: null }
    rulesStore.update((l) => [...l, r])
    step('response.rule.add', r.id, 'settings', `Rule added in dry run: ${r.name} (${r.trigger}, ${r.actions.length} action(s), ${r.enabled ? 'on' : 'off'}${r.pre_approved ? ', PRE-APPROVED' : ''})`)
    return HttpResponse.json(r, { status: 201 })
  }),
  http.put(`${API}/response/rules/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const old = rulesStore.get().find((r) => r.id === String(params.id)); if (!old) return fail(404, 'not_found', 'No such rule.')
    const c = checkRule(await body<RuleInput>(request))
    if (typeof c === 'string') return refuse(400, ruleErrCode(c), c, old.id)
    const r: Rule = { ...old, ...c }
    rulesStore.update((l) => l.map((x) => (x.id === r.id ? r : x)))
    step('response.rule.change', r.id, 'settings', `Rule changed: ${r.name} (${r.trigger}, ${r.live ? 'LIVE' : 'dry run'}, ${r.enabled ? 'on' : 'off'}${r.pre_approved ? ', PRE-APPROVED' : ''})`)
    return HttpResponse.json(r)
  }),
  http.delete(`${API}/response/rules/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const old = rulesStore.get().find((r) => r.id === String(params.id)); if (!old) return fail(404, 'not_found', 'No such rule.')
    rulesStore.update((l) => l.filter((r) => r.id !== old.id))
    step('response.rule.delete', old.id, 'settings', `Rule deleted: ${old.name}`)
    return new HttpResponse(null, { status: 204 })
  }),
  http.post(`${API}/response/rules/:id/manual`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const rule = rulesStore.get().find((r) => r.id === String(params.id)); if (!rule) return fail(404, 'not_found', 'No such rule.')
    if (rule.trigger !== 'manual') return refuse(409, 'not_manual', 'Only a rule with the manual trigger can be run on a chosen device.', rule.id)
    if (!rule.enabled) return refuse(409, 'rule_off', 'Switch the rule on first.', rule.id)
    const b = await body<{ asset_id: string }>(request)
    const a = assetsStore.get().find((x) => x.id === b.asset_id); if (!a) return fail(404, 'not_found', 'No such device.')
    const name = a.hostname ?? a.ip
    const ev = { id: `det-man-${rule.id}-${a.id}-${Date.now()}`, trigger: 'manual' as const, ts: nowIso(), summary: `Run by ${currentUser()!.email} on ${name}`, device_kind: a.kind, asset_id: a.id,
      fields: { device: name, ip: a.ip, mac: a.mac ?? '', switch_port: `Gi1/0/${(Number(a.ip.split('.')[3] ?? 0) % 24) + 1}` } }
    return HttpResponse.json(runRules({ rule, ev }))
  }),
  http.get(`${API}/response/events`, () => {
    const denied = guard('viewer'); if (denied) return denied
    const done = doneStore.get()
    return HttpResponse.json({ items: events().slice(0, 60).map((d) => eventView(d, done)) })
  }),
  http.get(`${API}/response/templates`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: templates() })
  }),
  http.post(`${API}/response/templates/:id/clone`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = TEMPLATES.find((x) => x.id === String(params.id)); if (!t) return fail(404, 'not_found', 'No such template.')
    if (rulesStore.get().length >= 30) return refuse(409, 'limit', 'Up to 30 rules.', 'response.rule')
    const r: Rule = { ...t.rule, id: newId('rule'), enabled: false, live: false, pre_approved: false, template_id: t.id, last_fired: null }
    rulesStore.update((l) => [...l, r])
    step('response.rule.add', r.id, 'settings', `Rule cloned from template "${t.name}": switched off, dry run`)
    return HttpResponse.json(r, { status: 201 })
  }),
  http.get(`${API}/response/allowlist`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: allowStore.get() })
  }),
  http.put(`${API}/response/allowlist`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ items: Allow[] }>(request)
    const ok = Array.isArray(b.items) && b.items.length <= 100 && b.items.every((e) => isObj(e) && typeof e.value === 'string' && (isIpv4(e.value) || isCidr(e.value) || isDomain(e.value)) && typeof e.label === 'string' && e.label.length <= 80)
    if (!ok) return refuse(400, 'invalid', 'Each entry needs an IP address, CIDR range or domain, and a label of up to 80 characters (up to 100 entries).', 'response.allowlist')
    const items = b.items!.map((e) => ({ value: e.value.toLowerCase(), label: oneLine(e.label) }))
    allowStore.set(items)
    step('response.allowlist', 'response', 'settings', `Never-touch list saved: ${items.map((e) => e.value).join(', ') || 'empty'}`)
    return HttpResponse.json({ items })
  }),

  // ---- Block list (pull) ----
  http.get(`${API}/response/blocklist`, () => {
    const denied = guard('admin'); if (denied) return denied
    sweep()
    return HttpResponse.json(blockView())
  }),
  http.post(`${API}/response/blocklist/token`, () => {
    const denied = guard('admin'); if (denied) return denied
    blockMeta.update((m) => ({ ...m, token: randomToken(), last_fetch: null }))
    step('response.blocklist.token', 'response', 'blocklist_token', 'The block list token was regenerated; the old address no longer works')
    return HttpResponse.json(blockView())
  }),
  http.get(`${API}/response/blocklist/:token.txt`, ({ params }) => {
    sweep()
    if (String(params.token) !== blockMeta.get().token) return new HttpResponse('Not found\n', { status: 404, headers: { 'Content-Type': 'text/plain' } })
    blockMeta.update((m) => ({ ...m, last_fetch: { at: nowIso(), from: 'a device on the LAN' } }))
    const e = blockEntries()
    const text = [`# Vedette block list, ${nowIso()}. One IP address per line. Lines starting with # are comments.`, ...e.flatMap((x) => [`# ${oneLine(x.source)} | ${oneLine(x.reason)} | expires ${x.expires_at ?? 'never'}`, x.value])].join('\n') + '\n'
    return new HttpResponse(text, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
  }),

  // ---- Action catalog (S-RESP-4) ----
  http.get(`${API}/response/catalog`, () => {
    const denied = guard('viewer'); if (denied) return denied
    // D-88 (26): the header lines of a template can carry an authorisation value, so only an admin sees the values; others see the names
    const admin = currentUser()?.role === 'admin'
    const hide = (t: Tpl): Tpl => (admin ? t : { ...t, headers: t.headers.split('\n').filter(Boolean).map((l) => `${l.split(':')[0]}: (hidden)`).join('\n') })
    const items = catalogStore.get().map(catView).map((a) => ({ ...a, run: hide(a.run), rollback: hide(a.rollback), verify: hide(a.verify), precheck: hide(a.precheck) }))
    return HttpResponse.json({ items, connections: connectorsStore.get().map(connView) })
  }),
  http.post(`${API}/response/catalog`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const c = checkCatalog(await body<Record<string, unknown>>(request))
    if ('error' in c) return refuse(c.code === 'read_only' ? 409 : 400, c.code, c.error, 'response.catalog')
    if (catalogStore.get().length >= 50) return refuse(409, 'limit', 'Up to 50 actions.', 'response.catalog')
    const n = { ...c, id: newId('ca'), builtin: false, pack: 'generic' as const, kind: 'device' as const }
    catalogStore.update((l) => [...l, n])
    step('response.catalog.add', n.id, 'settings', `Custom action added: ${n.name} (${n.risk} risk, ${n.enabled ? 'enabled' : 'disabled'}${n.ai_may_propose ? ', AI may propose' : ''})`)
    return HttpResponse.json(catView(n), { status: 201 })
  }),
  http.put(`${API}/response/catalog/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const old = catById(String(params.id)); if (!old) return fail(404, 'not_found', 'No such action.')
    const b = await body<Record<string, unknown>>(request)
    let n = old
    if (old.builtin) {
      for (const k of ['enabled', 'ai_may_propose'] as const) if (b[k] !== undefined && typeof b[k] !== 'boolean') return refuse(400, 'invalid', `Send ${k} as true or false.`, old.id)
      let conn = old.connection_id
      if (b.connection_id !== undefined && old.kind === 'device') {
        const c = typeof b.connection_id === 'string' ? connById(b.connection_id) : undefined
        if (!c) return refuse(400, 'invalid', 'Choose one of your connections.', old.id)
        const probe = { ...old, connection_id: c.id }
        const why = unavailable(probe)
        if (why && (why.includes('Read-only') || why.includes('Choose a') || why.includes('Choose an'))) return refuse(c && connView(c).read_only ? 409 : 400, connView(c).read_only ? 'read_only' : 'wrong_kind', why, old.id)
        conn = c.id
      }
      n = { ...old, enabled: (b.enabled as boolean | undefined) ?? old.enabled, ai_may_propose: (b.ai_may_propose as boolean | undefined) ?? old.ai_may_propose, connection_id: old.kind === 'device' ? conn : null }
    } else {
      const c = checkCatalog({ ...old, ...b })
      if ('error' in (c as CatErr)) { const e = c as CatErr; return refuse(e.code === 'read_only' ? 409 : 400, e.code, e.error, old.id) }
      n = { ...old, ...(c as object) } as typeof old
    }
    catalogStore.update((l) => l.map((x) => (x.id === n.id ? n : x)))
    step('response.catalog.change', n.id, 'settings', `Action ${n.enabled ? 'enabled' : 'disabled'}: ${n.name} (${n.risk} risk${n.ai_may_propose ? ', AI may propose' : ''})`)
    return HttpResponse.json(catView(n))
  }),
  http.delete(`${API}/response/catalog/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const old = catById(String(params.id)); if (!old) return fail(404, 'not_found', 'No such action.')
    if (old.builtin) return refuse(409, 'builtin', 'Built-in actions cannot be deleted. Disable it instead.', old.id)
    const user = rulesStore.get().find((r) => r.actions.some((a) => a.action_id === old.id))
    if (user) return refuse(409, 'in_use', `The rule "${user.name}" uses this action. Change or delete the rule first.`, old.id)
    catalogStore.update((l) => l.filter((x) => x.id !== old.id))
    step('response.catalog.delete', old.id, 'settings', `Custom action deleted: ${old.name}`)
    return new HttpResponse(null, { status: 204 })
  }),

  // ---- AI requests (gates in ai.ts) ----
  http.get(`${API}/response/ai`, () => {
    const denied = guard('viewer'); if (denied) return denied
    sweep()
    return HttpResponse.json(aiState())
  }),
  http.post(`${API}/response/ai/proposals`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    const r = propose(await body<Record<string, unknown>>(request))
    return isResp(r as Response | ActionRequest) ? (r as Response) : HttpResponse.json(r, { status: (r as { outcome: string }).outcome === 'request' ? 201 : 200 })
  }),
  http.post(`${API}/response/ai/resume`, () => {
    const denied = guard('admin'); if (denied) return denied
    resume()
    return HttpResponse.json(aiState())
  }),
  http.get(`${API}/response/metrics`, () => {
    const denied = guard('viewer'); if (denied) return denied
    sweep()
    return HttpResponse.json(metrics())
  }),

  // ---- Log (D-48) ----
  http.get(`${API}/response/log`, () => {
    const denied = guard('operator'); if (denied) return denied
    sweep()
    return HttpResponse.json({ items: logStore.get() })
  }),
]

function newRequestFromPlan(plan: StoredPlan, prop: StoredProposal, item: RequestItem): ActionRequest {
  return newRequest({ source: 'ai', proposal_id: prop.id, rule_id: null, rule_name: null, trigger: 'finding', trigger_summary: `${plan.cve} on ${plan.asset_name}`, finding_id: plan.finding_id, cve: plan.cve, asset_id: prop.asset_id, asset_name: prop.asset_name,
    title: prop.title, items: [item], ai: null }, true)
}
