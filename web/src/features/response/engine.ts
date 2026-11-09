// Rule engine of the response mock (D-51): events with typed fields -> WHEN/IF/THEN -> planned actions -> one bundled request.
// Trigger data is attacker-controlled: every parameter is resolved from the event, then checked by type before it can reach a template.
import { collection, dataMode, daysAgo, nowIso, newId, peek } from '@/mocks/db'
import { assetsStore, findingsStore } from '@/mocks/stores'
import type { Finding } from '@/lib/types'
import { KINDS, TRIGGERS } from './data'
import { SEED_RULES, TEMPLATES } from './templates'
import { exposingVip } from './templates/sample-firewall'
import { checkValues, condText, evalCondition, isCidr, isIpv4, oneLine, PARAM_CHECK, refsIn, resolveParam, touches, type ParamType } from './logic'
import {
  actionsStore, allowStore, approve, breakerOpen, BREAKER_MSG, buildChange, catById, checkBreaker, connById, doneStore, HOUR, isObj, maintenanceNow, newRequest, paramsOf, refuse, requiredApprovals,
  reversible, str, step, targetCount, TEXT_RE, unavailable, isOpen,
} from './state'
import type { Condition, EventView, RequestItem, Rule, RuleAction, RuleInput, RunSummary, Simulation, Template, Trigger } from './types'

// ---- Rules ----
const C = (field: string, op: Condition['op'], value: string, n: number | null = null, window_min: number | null = null): Condition => ({ field, op, value, n, window_min })
const seedRules = (on: boolean): Rule[] => [
  { id: 'r-ioc', name: 'Block destinations of known-bad connections', enabled: on, live: true, trigger: 'ioc_connection', match: 'all', conditions: [C('dest_kind', 'eq', 'ip'), C('confidence', 'gte', '0.8')], actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 1440 }], pre_approved: true, max_per_hour: 10, schedule_min: null, template_id: null, last_fired: on ? daysAgo(0, 2) : null },
  { id: 'r-ioc-ask', name: 'Ask before blocking medium-confidence matches', enabled: on, live: true, trigger: 'ioc_connection', match: 'all', conditions: [C('dest_kind', 'eq', 'ip'), C('confidence', 'gte', '0.5')], actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 720 }, { action_id: 'msg_send', params: { text: 'Known-bad connection from {{trigger.device}} to {{trigger.dest}}' }, ttl_min: null }], pre_approved: false, max_per_hour: 10, schedule_min: null, template_id: null, last_fired: on ? daysAgo(0, 0.02) : null },
  ...SEED_RULES.map((r): Rule => ({ ...r, trigger: r.trigger as Rule['trigger'], conditions: r.conditions as Rule['conditions'], last_fired: null })),
]
export const rulesStore = collection<Rule[]>('resp_rules', () => seedRules(true), () => seedRules(false))

// ---- Events (what the triggers watch) ----
export interface Det { id: string; trigger: Trigger; ts: string; summary: string; fields: Record<string, string>; device_kind: string | null; asset_id: string | null; finding_id?: string; cve?: string }
const portOf = (ip: string) => `Gi1/0/${(Number(ip.split('.')[3] ?? 0) % 24) + 1}` // mock of the switch MAC table lookup
function deviceOf(ip: string, fallback?: string) {
  const a = assetsStore.get().find((x) => x.ip === ip)
  return { asset_id: a?.id ?? null, name: a ? (a.hostname ?? a.ip) : (fallback ?? ip), kind: a?.kind ?? null }
}
const openFinding = (f: Finding) => f.status === 'confirmed' || f.status === 'suspected'
const SEVERITIES = ['critical', 'high', 'medium', 'low']

export function events(): Det[] {
  const out: Det[] = []
  const add = (d: Det) => { if (!out.some((x) => x.id === d.id)) out.push(d) }
  const sample = dataMode() === 'sample'
  const ioc = (id: string, src: string, dest: string, kind: 'ip' | 'domain', conf: number, feeds: string, ts: string) => {
    const dev = deviceOf(src)
    add({ id, trigger: 'ioc_connection', ts, device_kind: dev.kind, asset_id: dev.asset_id, summary: `${dev.name} connected to ${dest} (${feeds}, confidence ${conf})`,
      fields: { src_ip: src, device: dev.name, dest, dest_kind: kind, dest_ip: kind === 'ip' ? dest : '', dest_domain: kind === 'domain' ? dest : '', feeds, confidence: String(conf), switch_port: portOf(src) } })
  }
  if (sample) {
    ioc('det-s-ioc-1', '192.168.10.105', '185.220.101.47', 'ip', 0.92, 'Tor exit list', daysAgo(0, 2))
    ioc('det-s-ioc-2', '192.168.10.107', '91.92.240.12', 'ip', 0.6, 'URLhaus', daysAgo(0, 1))
    ioc('det-s-ioc-3', '192.168.10.107', 'cdn-update.badhost.example', 'domain', 0.55, 'URLhaus', daysAgo(0, 1))
    ioc('det-s-ioc-4', '192.168.10.10', '1.1.1.1', 'ip', 0.85, 'IPsum', daysAgo(0, 0.5)) // a noisy feed lists a public DNS server: the never-touch list must stop it
  }
  // Logs module: known-bad connection list (peek, may be absent).
  const hits = peek<unknown>('logs_ioc_hits')
  if (Array.isArray(hits)) {
    for (const h of hits.filter(isObj).slice(0, 200)) {
      const src = str(h.src_ip), dest = str(h.dest), kind = h.dest_kind === 'domain' ? 'domain' : 'ip'
      if (!isIpv4(src) || !str(h.id) || !dest) continue
      const c = typeof h.confidence === 'number' && h.confidence >= 0 && h.confidence <= 1 ? h.confidence : 0 // 0 to 1 everywhere (D-57 (13))
      ioc(`det-l-${str(h.id)}`, src, dest, kind, c, Array.isArray(h.feeds) ? h.feeds.map(String).join(', ') : '', str(h.ts) || nowIso())
    }
  }
  // Honeypot module: every real hit is a touch. Module never opened and sample data: one sample touch.
  const hp = peek<unknown>('hp_hits')
  const touch = (id: string, ip: string, decoy: string, kind: string, ts: string, fallback?: string) => {
    const dev = deviceOf(ip, fallback)
    add({ id, trigger: 'honeypot', ts, device_kind: dev.kind, asset_id: dev.asset_id, summary: `${dev.name} touched a trap (${decoy}, ${kind})`, fields: { source_ip: ip, source_device: dev.name, decoy, kind, switch_port: portOf(ip) } })
  }
  if (Array.isArray(hp)) {
    for (const h of hp.filter(isObj)) {
      const ip = str(h.src_ip) || str(h.source_ip)
      if (h.is_test === true || !isIpv4(ip) || !str(h.id)) continue
      touch(`det-hp-${str(h.id)}`, ip, str(h.trap_hostname) || str(h.trap_ip) || 'decoy', ['service', 'token', 'scan'].includes(str(h.kind)) ? str(h.kind) : 'service', str(h.ts) || nowIso())
    }
  } else if (sample) touch('det-s-hp-1', '192.168.10.107', 'FILESRV-OLD', 'service', daysAgo(1, 1), 'PC-HR-01')
  // Findings (open), with the virtual IP that exposes the device when a readable firewall connection says so (sample data).
  for (const f of findingsStore.get().filter(openFinding).slice(0, 60)) {
    const asset = assetsStore.get().find((a) => a.id === f.asset_id)
    if (!asset) continue
    const vip = exposingVip(asset.ip)
    const name = asset.hostname ?? asset.ip
    // ponytail: the KEV flag comes from the Feeds module on a real box; the mock treats critical findings as exploited in the wild.
    add({ id: `det-f-${f.id}`, trigger: 'finding', ts: f.last_seen, device_kind: asset.kind, asset_id: asset.id, finding_id: f.id, cve: f.cve,
      summary: `${name}: ${f.cve} (${f.severity})${vip ? `, reachable from the Internet through ${vip.name}` : ''}`,
      fields: { device: name, ip: asset.ip, cve: f.cve, severity: SEVERITIES.includes(f.severity) ? f.severity : 'low', kev: String(f.severity === 'critical'), exposed_via_nat: String(!!vip), vip: vip?.name ?? '' } })
  }
  for (const a of assetsStore.get().filter((x) => !x.approved).slice(0, 20)) {
    add({ id: `det-ud-${a.id}`, trigger: 'unknown_device', ts: a.first_seen, device_kind: a.kind, asset_id: a.id, summary: `Unknown device ${a.mac ?? a.ip} (${a.vendor?.value ?? 'unknown vendor'}) at ${a.ip}`,
      fields: { ip: a.ip, mac: a.mac ?? '', vendor: a.vendor?.value ?? 'Unknown vendor', kind: KINDS.includes(a.kind) ? a.kind : 'unknown' } })
  }
  if (sample) {
    add({ id: 'det-s-log-1', trigger: 'log_threshold', ts: daysAgo(0, 0.4), device_kind: null, asset_id: null, summary: '12 failed VPN logins from 203.0.113.99 in 5 minutes', fields: { source_device: 'vpn-client-203', source_ip: '203.0.113.99', signature: 'vpn_login_failed', count: '12', window: '5' } })
    add({ id: 'det-s-log-2', trigger: 'log_threshold', ts: daysAgo(0, 3), device_kind: null, asset_id: null, summary: '8 failed SSH logins from 203.0.113.45 in 10 minutes', fields: { source_device: 'ssh-scan', source_ip: '203.0.113.45', signature: 'ssh_login_failed', count: '8', window: '10' } })
    add({ id: 'det-s-port-1', trigger: 'new_port', ts: daysAgo(0, 5), device_kind: 'web', asset_id: null, summary: 'New open port 8080 on public IP 203.0.113.10 (http-alt)', fields: { ip: '203.0.113.10', port: '8080', service: 'http-alt', device: 'WEB-01' } })
  }
  return out.sort((a, b) => b.ts.localeCompare(a.ts))
}
export const eventView = (d: Det, done: string[] = doneStore.get()): EventView => {
  const names = new Map(rulesStore.get().map((r) => [r.id, r.name]))
  return { id: d.id, trigger: d.trigger, ts: d.ts, summary: d.summary, fields: d.fields, device_kind: d.device_kind, handled_by: done.filter((k) => k.endsWith(`:${d.id}`)).map((k) => names.get(k.slice(0, k.length - d.id.length - 1)) ?? 'a deleted rule') }
}
const fieldsOf = (t: Trigger) => TRIGGERS.find((x) => x.id === t)!.fields
const sampleEvent = (t: Trigger): Det => ({ id: `example-${t}`, trigger: t, ts: nowIso(), summary: 'Example values from the trigger catalog', device_kind: null, asset_id: null, fields: Object.fromEntries(fieldsOf(t).map((f) => [f.key, f.example])) })

// ---- Checking a rule from the client ----
const TEXT_VAL = /^[\w .,:/@#-]{0,200}$/
const compatible = (p: ParamType, ft: string) => ft === p || p === 'text'

export function checkRule(b: Partial<RuleInput>): string | RuleInput {
  if (typeof b.name !== 'string' || !TEXT_RE.test(b.name)) return 'Name: 1 to 80 letters, numbers, spaces and . , : \' ( ) / -'
  if (typeof b.enabled !== 'boolean') return 'Send enabled as true or false.'
  if (typeof b.live !== 'boolean') return 'Send live as true or false.'
  if (typeof b.pre_approved !== 'boolean') return 'Send pre_approved as true or false.'
  const trig = TRIGGERS.find((t) => t.id === b.trigger)
  if (!trig) return 'Choose a trigger (WHEN).'
  if (b.match !== 'all' && b.match !== 'any') return 'Choose whether all or any of the conditions must match.'
  if (!Number.isInteger(b.max_per_hour) || b.max_per_hour! < 1 || b.max_per_hour! > 100) return 'Maximum actions per hour must be 1 to 100.'
  if (trig.id === 'schedule') { if (!Number.isInteger(b.schedule_min) || b.schedule_min! < 15 || b.schedule_min! > 10080) return 'Schedule: run every 15 minutes to 7 days.' } else if (b.schedule_min != null) return 'Only the schedule trigger has a run interval.'
  if (!Array.isArray(b.conditions) || b.conditions.length > 10) return 'Up to 10 conditions.'
  const conds: Condition[] = []
  for (const c of b.conditions) {
    if (!isObj(c) || typeof c.op !== 'string') return 'Each condition needs a field, a test and a value.'
    const field = typeof c.field === 'string' ? c.field : '', value = typeof c.value === 'string' ? c.value : ''
    const f = trig.fields.find((x) => x.key === field)
    const n = Number.isInteger(c.n) ? (c.n as number) : null, win = Number.isInteger(c.window_min) ? (c.window_min as number) : null
    if (c.op === 'device_type') { if (!value.split(',').every((k) => KINDS.includes(k.trim()))) return 'Device type: use device types such as camera, nvr, iot.' } else if (!f) return `The field "${oneLine(field, 30)}" does not exist for this trigger.`
    if (!TEXT_VAL.test(value)) return 'Condition values: letters, numbers and . , : / @ # - only.'
    if (c.op === 'in_cidr' && !isCidr(value)) return 'In range: give a CIDR range such as 192.168.10.0/24.'
    if ((c.op === 'gte' || c.op === 'lte') && !(value !== '' && Number.isFinite(Number(value)))) return 'At least / at most: give a number.'
    if (c.op === 'count_window' && (n === null || n < 1 || n > 1000 || win === null || win < 1 || win > 1440)) return 'Count in window: give how many (1 to 1000) and the minutes (1 to 1440).'
    if (c.op === 'first_time' && (n === null || n < 1 || n > 720)) return 'First time: give the hours (1 to 720).'
    if (!['eq', 'in', 'in_cidr', 'gte', 'lte', 'device_type', 'count_window', 'first_time'].includes(c.op)) return 'Unknown condition test.'
    conds.push({ field, op: c.op as Condition['op'], value, n: c.op === 'count_window' || c.op === 'first_time' ? n : null, window_min: c.op === 'count_window' ? win : null })
  }
  if (!Array.isArray(b.actions) || b.actions.length < 1 || b.actions.length > 6) return 'Add 1 to 6 actions (THEN).'
  const actions: RuleAction[] = []
  for (const a of b.actions) {
    const cat = isObj(a) ? catById(typeof a.action_id === 'string' ? a.action_id : '') : undefined
    if (!isObj(a) || !cat) return 'Choose an action from the catalog.'
    const given = isObj(a.params) ? a.params : {}
    const params: Record<string, string> = {}
    for (const p of paramsOf(cat)) {
      const spec = typeof given[p] === 'string' ? (given[p] as string).trim() : ''
      if (!spec || spec.length > 200) return `Action "${cat.name}": fill in {${p}}.`
      const refs = refsIn(spec)
      for (const r of refs) { const f = trig.fields.find((x) => x.key === r); if (!f) return `Action "${cat.name}": the trigger has no field "${oneLine(r, 30)}".`; if (!compatible(p, f.type)) return `Action "${cat.name}": {${p}} needs ${p === 'text' ? 'text' : `a field of type ${p}`}, but ${r} is ${f.type}.` }
      if (refs.length) { if (p !== 'text' && !/^\{\{\s*trigger\.[a-z_]+\s*\}\}$/.test(spec)) return `Action "${cat.name}": {${p}} must be exactly one trigger field or a fixed value, not a mix.` } else if (!PARAM_CHECK[p](spec)) return `Action "${cat.name}": "${oneLine(spec, 40)}" is not a valid ${p} value.`
      params[p] = spec
    }
    const ttl = a.ttl_min == null ? null : a.ttl_min
    if (ttl !== null && (!Number.isInteger(ttl) || (ttl as number) < 5 || (ttl as number) > 43200)) return 'Undo after: 5 minutes to 30 days.'
    actions.push({ action_id: cat.id, params, ttl_min: ttl as number | null })
  }
  if (b.pre_approved) { const bad = preApprovedProblem(actions); if (bad) return bad }
  return { name: b.name, enabled: b.enabled, live: b.live, trigger: trig.id, match: b.match, conditions: conds, actions, pre_approved: b.pre_approved, max_per_hour: b.max_per_hour!, schedule_min: trig.id === 'schedule' ? b.schedule_min! : null }
}
/** Pre-approved: only low-risk, reversible actions with an undo time of 24 hours or less (D-51). Checked on save and again at run time. */
export function preApprovedProblem(actions: RuleAction[]): string | null {
  for (const a of actions) {
    const cat = catById(a.action_id)
    if (!cat) return 'Pre-approved: an action is missing from the catalog.'
    if (cat.risk !== 'low') return `Pre-approved is only for low-risk actions. "${cat.name}" is ${cat.risk} risk.`
    if (!reversible(cat)) return `Pre-approved is only for actions that can be undone. "${cat.name}" cannot.`
    if (a.ttl_min === null || a.ttl_min > 1440) return `Pre-approved needs an undo time of 24 hours or less for "${cat.name}".`
  }
  return null
}

// ---- Planning: resolve, validate, render ----
export interface Planned { action: RuleAction; cat: NonNullable<ReturnType<typeof catById>>; values: Partial<Record<ParamType, string>>; item: Omit<RequestItem, 'id'>; key: string }
type Plan1 = { ok: true; p: Planned } | { ok: false; code: string; error: string; title: string }

/** One action: resolve placeholders from the event, check each value by type, apply the never-touch list, render the exact change. */
export function planAction(a: RuleAction, ev: Det, why: string): Plan1 {
  const cat = catById(a.action_id)
  const title = cat?.name ?? a.action_id
  if (!cat || !cat.enabled) return { ok: false, code: 'tool_not_allowed', error: `the action "${title}" is not enabled in the action catalog.`, title }
  const values: Partial<Record<ParamType, string>> = {}
  for (const p of paramsOf(cat)) values[p] = resolveParam(a.params[p] ?? '', ev.fields).trim()
  const bad = checkValues(paramsOf(cat), values)
  if (bad) return { ok: false, code: 'invalid_target', error: bad, title }
  // Never touch the gateway, DNS servers, domain controllers, this box or management IPs. For a finding the device itself must stay reachable.
  const acted = [...Object.entries(values).filter(([k]) => ['ip', 'cidr', 'domain'].includes(k)).map(([, v]) => v!), ...(ev.trigger === 'finding' && ev.fields.ip ? [ev.fields.ip] : [])]
  const spared = allowStore.get().find((e) => acted.some((v) => touches(e.value, v)))
  if (spared) return { ok: false, code: 'never_touch', error: `${acted.join(' / ')} matches the never-touch list (${spared.label}, ${spared.value}). Nothing was changed.`, title }
  const conn = connById(cat.connection_id)
  const why2 = unavailable(cat)
  if (why2 && cat.kind === 'device') return { ok: false, code: 'tool_unavailable', error: why2, title }
  const change = buildChange(cat, values, conn, why, a.ttl_min)
  const first = Object.values(values)[0]
  const item: Omit<RequestItem, 'id'> = {
    action_id: cat.id, title: cat.id === 'blocklist_add' ? `Add ${values.ip} to the block list` : cat.id === 'msg_send' ? 'Send a message to your alert channels' : `${cat.name}: ${first}`, risk: cat.risk, reversible: reversible(cat),
    connector_id: cat.kind === 'device' ? cat.connection_id : null, connection: cat.kind === 'device' ? conn?.name ?? null : null, tool: cat.tool ?? cat.id,
    targets: targetCount(values), change, ttl_min: a.ttl_min, status: 'pending', executed_at: null, remove_at: null, rolled_back_at: null, result: null, verified: null, state_unknown: false,
  }
  return { ok: true, p: { action: a, cat, values, item, key: `${cat.id}|${Object.values(values).join('|')}` } }
}

export function conditionsOk(rule: RuleInput, ev: Det, all: Det[]): { ok: boolean; results: { text: string; ok: boolean }[] } {
  const others = all.filter((d) => d.trigger === rule.trigger)
  const results = rule.conditions.map((c) => ({ text: condText(c), ok: evalCondition(c, ev, others) }))
  return { ok: !results.length || (rule.match === 'all' ? results.every((r) => r.ok) : results.some((r) => r.ok)), results }
}

export const openKeys = () => new Set(actionsStore.get().filter(isOpen).flatMap((a) => a.items.filter((i) => i.status === 'pending').map(itemKey)).concat(
  actionsStore.get().flatMap((a) => a.items.filter((i) => i.status === 'executed' && (!i.remove_at || Date.parse(i.remove_at) > Date.now())).map(itemKey))))
const itemKey = (i: RequestItem) => `${i.action_id}|${i.change.cli}|${i.change.rest ? `${i.change.rest.method} ${i.change.rest.url} ${i.change.rest.body ?? ''}` : ''}`
const plannedKey = (p: Planned) => `${p.item.action_id}|${p.item.change.cli}|${p.item.change.rest ? `${p.item.change.rest.method} ${p.item.change.rest.url} ${p.item.change.rest.body ?? ''}` : ''}`
export const dedupeKeysOf = openKeys
export { plannedKey }

// ---- Firing a rule on an event ----
function fire(rule: Rule, ev: Det, sum: RunSummary) {
  const actor = `rule:${rule.name}`
  step('response.rule_fired', rule.id, 'rule_fired', `${rule.name}: ${ev.summary}`, actor)
  rulesStore.update((l) => l.map((r) => (r.id === rule.id ? { ...r, last_fired: nowIso() } : r)))
  const no = (code: string, msg: string) => { sum.refused++; refuse(409, code, `${rule.name}: ${msg}`, rule.id) }
  const w = maintenanceNow()
  if (w) return no('maintenance', `held, maintenance window "${w.name}" is active. Nothing was requested.`)
  if (breakerOpen()) return no('circuit_open', BREAKER_MSG)
  const planned: Planned[] = []
  for (const a of rule.actions) {
    const r = planAction(a, ev, ev.summary)
    if (!r.ok) return no(r.code, r.error) // fail closed: one bad action refuses the whole run
    planned.push(r.p)
  }
  // Same target + same action already open or in force: nothing new to ask. Duplicates inside one run merge into one.
  const open = openKeys(), seen = new Set<string>()
  const fresh = planned.filter((p) => { const k = plannedKey(p); if (open.has(k) || seen.has(k)) return false; seen.add(k); return true })
  if (!fresh.length) { sum.deduped++; step('response.deduped', rule.id, 'deduped', `${rule.name}: same target and action is already open or in force, merged: ${ev.summary}`, actor); return }
  const lastHour = actionsStore.get().filter((a) => a.rule_id === rule.id && Date.now() - Date.parse(a.requested_at) < HOUR).length
  if (lastHour >= rule.max_per_hour) return no('rule_rate_limited', `limit of ${rule.max_per_hour} runs per hour reached.`)
  if (!rule.live) {
    sum.dry_run++
    step('response.dry_run', rule.id, 'dry_run', `${rule.name}: dry run, nothing was requested or run. Would do: ${fresh.map((p) => `${p.item.title} (${p.item.change.rest ? `${p.item.change.rest.method} ${p.item.change.rest.url}` : p.item.change.cli.split('\n')[0]})`).join('; ')}`, actor)
    return
  }
  if (checkBreaker(fresh.length)) return no('circuit_open', BREAKER_MSG)
  const pre = rule.pre_approved && preApprovedProblem(rule.actions) === null
  const a = newRequest({
    source: 'rule', proposal_id: `rule:${rule.id}:${ev.id}`, rule_id: rule.id, rule_name: rule.name, trigger: rule.trigger, trigger_summary: ev.summary, finding_id: ev.finding_id ?? null, cve: ev.cve ?? null,
    asset_id: ev.asset_id, asset_name: ev.fields.device ?? ev.fields.source_device ?? ev.fields.ip ?? ev.fields.source_ip ?? 'Network',
    title: fresh.length === 1 ? fresh[0]!.item.title : `${rule.name}: ${fresh.length} actions`, items: fresh.map((p) => ({ ...p.item, id: newId('it') })), ai: null,
  }, !pre)
  sum.requests++
  if (pre) {
    // Pre-approved: no person. Re-checked here: low risk, reversible, undo time of 24 hours or less. Every other gate still applies.
    const r = approve(a, { id: `rule:${rule.id}`, name: `Rule: ${rule.name}`, email: 'rule@vedette', via: 'auto' })
    if (r instanceof Response) { actionsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, status: 'rejected', decided_at: nowIso(), note: 'Pre-approval refused by a safety gate (see the log).', items: x.items.map((i) => ({ ...i, status: 'skipped' as const })) } : x))); sum.refused++ }
    else { actionsStore.update((l) => l.map((x) => (x.id === a.id ? { ...x, pre_approved: true } : x))); sum.executed++ }
  }
}

export function runRules(only?: { rule: Rule; ev: Det }): RunSummary {
  const sum: RunSummary = { matched: 0, dry_run: 0, requests: 0, executed: 0, refused: 0, deduped: 0 }
  const all = events()
  const done = new Set(doneStore.get())
  if (only) { sum.matched++; fire(only.rule, only.ev, sum); return sum }
  // Schedule rules: one synthetic event per due run.
  for (const r of rulesStore.get().filter((x) => x.enabled && x.trigger === 'schedule' && x.schedule_min)) {
    const due = !r.last_fired || Date.now() - Date.parse(r.last_fired) >= r.schedule_min! * 60e3
    if (due) all.push({ id: `det-sch-${r.id}-${Math.floor(Date.now() / (r.schedule_min! * 60e3))}`, trigger: 'schedule', ts: nowIso(), summary: `Scheduled run of ${r.name}`, fields: { run_at: nowIso().slice(0, 16).replace('T', ' '), scope: 'whole network' }, device_kind: null, asset_id: null })
  }
  for (const d of all) {
    for (const rule of rulesStore.get().filter((r) => r.enabled && r.trigger === d.trigger)) {
      const key = `${rule.id}:${d.id}`
      if (done.has(key) || !conditionsOk(rule, d, all).ok) continue
      done.add(key); doneStore.set([...done])
      sum.matched++
      fire(rule, d, sum)
    }
  }
  return sum
}

/** Simulation: render exactly what a live run would do with the latest event, and execute nothing. */
export function simulate(rule: RuleInput, eventId?: string): Simulation {
  const all = events()
  const found = eventId ? all.find((d) => d.id === eventId) : all.find((d) => d.trigger === rule.trigger)
  const notes: string[] = []
  const ev = found ?? sampleEvent(rule.trigger)
  if (!found) notes.push('No event of this trigger yet, so the example values from the trigger catalog were used.')
  const { ok, results } = conditionsOk(rule, ev, all)
  if (!ok) notes.push('The conditions do not match this event, so a live run would do nothing for it. The steps below show what would happen if it matched.')
  const steps: Simulation['steps'] = []
  const planned: Planned[] = []
  for (const a of rule.actions) {
    const r = planAction(a, ev, ev.summary)
    if (r.ok) { planned.push(r.p); steps.push({ action: r.p.item.title, risk: r.p.item.risk, ok: true, error: null, change: r.p.item.change }) }
    else steps.push({ action: r.title, risk: catById(a.action_id)?.risk ?? 'low', ok: false, error: r.error, change: null })
  }
  if (!rule.live) notes.push('This rule is in dry run: a real match is only logged.')
  if (rule.pre_approved) notes.push(preApprovedProblem(rule.actions) ?? 'Pre-approved: a live run would carry this out without asking a person.')
  else notes.push('Every action needs approval before it runs.')
  const open = openKeys()
  if (planned.some((p) => open.has(plannedKey(p)))) notes.push('One of these actions is already open or in force for this target, so a live run would merge it instead of asking again.')
  if (maintenanceNow()) notes.push(`A maintenance window is active: ${maintenanceNow()!.name}. Nothing would be requested now.`)
  if (breakerOpen()) notes.push('The circuit breaker is open: nothing would be requested now.')
  const need = requiredApprovals(planned.map((p) => p.item))
  if (need.why) notes.push(need.why)
  step('response.simulate', rule.name, 'simulated', `Simulated "${rule.name}" with ${ev.id}: ${steps.map((s) => (s.ok ? s.action : `refused (${s.error})`)).join('; ')}. Nothing was executed.`)
  return { event: eventView(ev), matched: ok, conditions: results, steps, notes, approvals: need.n, executed: 0 }
}

export function templates(): Template[] {
  return TEMPLATES.map((t) => {
    const risks = t.rule.actions.map((a) => catById(a.action_id)?.risk ?? 'low')
    const risk = risks.includes('high') ? 'high' : risks.includes('medium') ? 'medium' : 'low'
    return { id: t.id, name: t.name, description: t.description, trigger: t.rule.trigger, risk, approvals: requiredApprovals(t.rule.actions.map((a) => ({ risk: catById(a.action_id)?.risk ?? 'low', targets: 1 }))).n, rule: t.rule }
  })
}
