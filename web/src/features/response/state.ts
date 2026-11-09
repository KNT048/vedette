// Server side of the response mock: stores, the hash-chained log, the action catalog, and the lifecycle of a request
// (create, approve, reject, execute, verify, roll back, expire). Every gate is enforced HERE, never only in the UI (D-41, D-51).
// A request carries stored templates + validated values; the client can never send its own command.
import { audit, currentUser, fail } from '@/mocks/http'
import { collection, daysAgo, newId, nowIso, peek } from '@/mocks/db'
import { connectorsStore, type Connector } from '@/mocks/connectors'
import { boxInfo, usersStore } from '@/mocks/stores'
import { isHttpKind } from '@/lib/connections'
import { RISK_PHRASE } from './contract'
import type { StoredCat } from './data'
import { CLI_BAN, seedCatalog } from './templates'
import {
  approvalToken, EMPTY_TPL, fill, GENESIS, isMcp, KIND_FIELDS, kindProblem, logHashSync, needsPrecheck, oneLine, randomToken, readBackProblem, cliProblem, READ_ONLY, RUNTIME_VALUES, tplEmpty, tplParams, TOKEN_RE, validatePrecheck, validateTpl, verifyChain,
  type ConnKind, type ParamType, type Tpl,
} from './logic'
import type { ActionRequest, CatalogAction, Change, Connection, LogEntry, RequestItem, Risk, Settings, SettingsView, Trigger } from './types'

export { RISK_PHRASE, verifyChain, TOKEN_RE, randomToken, oneLine }
export type LogKind = LogEntry['kind']
export const HOUR = 3600e3
export const ID_RE = /^[\w.-]{1,96}$/
export const previewBuild = () => import.meta.env.VITE_API_MOCK !== 'off'
export const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null
export const str = (v: unknown) => (typeof v === 'string' ? v : '')

// ---- Settings ----
const DEFAULTS = (): Settings => ({
  execution: false, accepted_by: null, accepted_at: null, max_per_hour: 3, expiry_min: 15, approval_channels: [],
  breaker_max_per_hour: 20, breaker_tripped_at: null, breaker_notified: [], multi_target_max: 5, maintenance: [],
  ai: { triggers: ['ioc_connection', 'finding'], budget_hour: 2, budget_day: 5, paused_at: null, paused_reason: null },
})
export const settingsStore = collection<Settings>('resp_settings', DEFAULTS)
export const settings = () => ({ ...DEFAULTS(), ...settingsStore.get() })

// ---- Never-touch list ----
export interface Allow { value: string; label: string }
export const allowStore = collection<Allow[]>('resp_allowlist', () => [
  { value: '192.168.10.1', label: 'Office firewall (gateway)' }, { value: '192.168.10.10', label: 'Internal DNS and domain controller (SRV-AD)' },
  { value: '192.168.10.250', label: 'This Vedette box' }, { value: '192.168.99.0/24', label: 'Management network' },
  { value: '1.1.1.1', label: 'Public DNS (Cloudflare)' }, { value: 'mail.acme.example', label: 'Declared service: company mail' },
], () => [{ value: boxInfo().ip ?? '127.0.0.1', label: 'This Vedette box' }])

// ---- Tamper-evident log (D-48): collection `resp_log`, oldest first; the core agent reads it for "download all logs" ----
export const logStore = collection<LogEntry[]>('resp_log', () => {
  const rows: [string, LogKind, string, string][] = [
    [daysAgo(0, 2), 'rule_fired', 'rule:Block destinations of known-bad connections', 'Block destinations of known-bad connections: PC-SALES-02 connected to 185.220.101.47 (Tor exit list, confidence 0.92)'],
    [daysAgo(0, 2), 'request', 'rule:Block destinations of known-bad connections', 'Add 185.220.101.47 to the block list; pre-approved by the rule (low risk, reversible, undone in 24 hours)'],
    [daysAgo(0, 2), 'executed', 'system', 'blocklist add 185.220.101.47; undone automatically in 1440 minutes; read back: entry present'],
    [daysAgo(2), 'request', 'ai:response', 'Add 203.0.113.77 to the block list (AI, confidence 0.83)'],
    [daysAgo(2), 'rejected', 'it@acme.example (app)', 'Add 203.0.113.77 to the block list, rejected: Our own vulnerability scanner'],
    [daysAgo(0, 6), 'approved', 'admin@acme.example (app)', 'Add 198.51.100.23 to the block list, approved'],
    [daysAgo(0, 6), 'executed', 'system', 'blocklist add 198.51.100.23; undone automatically in 1440 minutes; read back: entry present'],
  ]
  let prev = GENESIS
  return rows.map(([ts, kind, actor, detail], i) => { const core = { id: `rl-seed-${i + 1}`, ts, kind, actor, detail, prev_hash: prev }; prev = logHashSync(core); return { ...core, hash: prev } })
}, () => [])

export function appendLog(kind: LogKind, actor: string, detail: string) {
  const l = logStore.get()
  const core = { id: newId('rl'), ts: nowIso(), kind, actor, detail: oneLine(detail, 1500), prev_hash: l.at(-1)?.hash ?? GENESIS }
  logStore.set([...l, { ...core, hash: logHashSync(core) }])
}
/** One response step = one audit line (SYS-3) and one hash-chained response log line. */
export function step(action: string, target: string, kind: LogKind, detail: string, actor?: string) {
  audit(action, target, oneLine(detail, 1500))
  appendLog(kind, actor ?? currentUser()?.email ?? 'system', detail)
}
/** A refusal is also an audit step and a response log line. */
export function refuse(status: number, code: string, message: string, target = 'response') {
  step('response.refused', target, 'refused', `${code}: ${message}`)
  return fail(status, code, message)
}
export const OFF_MSG = 'Execution is off. Turn it on in Settings, AI response (high risk).'

// ---- Notify data (read across modules with peek; may be absent). Approvers live in each channel (D-46). ----
interface NChan { type: string; configured: boolean; enabled: boolean; approvals?: boolean; approvers?: { user_id: string; address: string }[]; fields?: Record<string, string> }
const CH_NAME: Record<string, string> = { slack: 'Slack', telegram: 'Telegram', zalo: 'Zalo OA', 'zalo-personal': 'Zalo (personal)', email: 'Email', webhook: 'Webhook' }
export const APPROVAL_TYPES = ['slack', 'telegram', 'email', 'zalo', 'zalo-personal']
export const LINK_TYPES = ['email', 'zalo']
export const rawChans = (): NChan[] => { const l = peek<unknown>('notify_channels'); return Array.isArray(l) ? l.filter(isObj) as unknown as NChan[] : [] }
export const chanLabel = (c: NChan) => (c.type === 'slack' && c.fields?.label ? `Slack ${c.fields.label}` : CH_NAME[c.type] ?? c.type)
export const chanList = () => rawChans().filter((c) => c.configured && c.enabled)
export const approversOf = (c: NChan) => (Array.isArray(c.approvers) ? c.approvers.filter((a) => isObj(a) && typeof a.user_id === 'string' && typeof a.address === 'string') : [])
export const chanReady = (c: NChan) => c.configured && c.enabled && c.approvals === true && APPROVAL_TYPES.includes(c.type) && approversOf(c).length > 0
export const readyChan = (type: string) => rawChans().find((c) => c.type === type && chanReady(c))
export const userCanApprove = (id: string) => { const u = usersStore.get().find((x) => x.id === id); return !!u && !u.disabled && (u.role === 'operator' || u.role === 'admin') ? u : undefined }

// ---- Email approval links (D-46): one token per approver, single use, 30 minutes, bound to request and approver ----
export interface Token { token: string; action_id: string; user_id: string; address: string; channel: string; expires_at: string; used_at: string | null }
export const tokensStore = collection<Token[]>('resp_tokens', () => [])
export const TOKEN_MIN = 30
export const linkUrl = (t: string) => `https://${boxInfo().ip ?? '<box ip>'}:8443/approve/${t}`

// ---- Action catalog (D-47, D-51) ----
export const catalogStore = collection<StoredCat[]>('resp_catalog', seedCatalog)
export const catById = (id: string | null | undefined) => (id ? catalogStore.get().find((c) => c.id === id) : undefined)
export const connById = (id: string | null | undefined) => (id ? connectorsStore.get().find((c) => c.id === id) : undefined)
export const writeToolsOf = (c: Connector) => c.tools.filter((t) => t.enabled && t.access === 'write').map((t) => t.name)
export const connView = (c: Connector): Connection => ({ id: c.id, name: c.name, enabled: c.enabled, kind: c.kind, write_tools: writeToolsOf(c), read_only: writeToolsOf(c).length === 0 })
// A browser that kept the sample data of an earlier build has catalog rows without a check before: read them as none.
const preOf = (c: Pick<StoredCat, 'precheck'>): Tpl => c.precheck ?? EMPTY_TPL
const refuseOf = (c: Pick<StoredCat, 'precheck_refuse'>): string[] => c.precheck_refuse ?? []
const expectOf = (c: Pick<StoredCat, 'precheck_expect'>): string => c.precheck_expect ?? ''
export const paramsOf = (c: Pick<StoredCat, 'run' | 'rollback' | 'verify' | 'precheck'>) => tplParams(c.run, c.rollback, c.verify, preOf(c))
export const reversible = (c: Pick<StoredCat, 'rollback'>) => !tplEmpty(c.rollback)

/** The action sends an API call, a command, or an MCP tool call; the connection kind must be able to carry it. */
function fits(c: StoredCat, conn: Connector): string | null {
  const api = !!(c.run.method && c.run.path), cli = !!c.run.cli.trim()
  if (isMcp(conn.kind)) return c.tool ? null : 'This action is an API call or a command. Choose an API or SSH connection, not an MCP server.'
  if (conn.kind === 'ssh') return cli ? null : 'This action is an API call. Choose an API connection, not an SSH one.'
  return api ? null : 'This action is an SSH command. Choose an SSH connection.'
}
/** Values read from the device while an action runs: Vedette cannot read them yet (a later version, action-templates 12.1). Only {expiry_s}, the time to live, is worked out without the device. */
const NEEDS_DEVICE_READ = RUNTIME_VALUES.filter((r) => r !== 'expiry_s')
export const runtimeNeeded = (c: Pick<StoredCat, 'run' | 'rollback' | 'verify' | 'precheck'>) => NEEDS_DEVICE_READ.find((r) => [c.run, c.rollback, c.verify, preOf(c)].some((t) => [t.cli, t.path, t.body, t.headers, t.expect ?? ''].some((x) => x.includes(`{${r}}`))))
/** null = the action can run now; otherwise why not (plain words). */
export function unavailable(c: StoredCat): string | null {
  if (c.kind === 'box') return null
  const conn = connById(c.connection_id)
  if (!conn) return 'No connection is chosen for this action.'
  if (!conn.enabled) return `The connection ${conn.name} is turned off in Settings → Connections.`
  if (!writeToolsOf(conn).length) return `${conn.name}: ${READ_ONLY}.`
  if (c.tool && !writeToolsOf(conn).includes(c.tool)) return `The write tool ${c.tool} on ${conn.name} is turned off or missing.`
  const wrong = fits(c, conn)
  if (wrong) return wrong
  const rv = runtimeNeeded(c)
  if (rv) return `Not available yet: this action needs a value that is read from the device while it runs ({${rv}}), and Vedette cannot read that yet.`
  if (needsPrecheck(c.run, c.rollback, c.verify, preOf(c), refuseOf(c), !c.builtin)) return 'Not available: an action that can name a port needs a check before it, with at least one text that makes it refuse (so a trunk or uplink port is never touched).'
  if (isMcp(conn.kind) && (!tplEmpty(preOf(c)) || !tplEmpty(c.verify))) return `Not available yet: the check before and the read-back of this action need a read tool, and Vedette cannot name one for ${conn.name} yet.`
  return stepFits(preOf(c), conn, 'check before')
}
/** null = the step has a form the connection kind can run: a command for SSH, an API call for the HTTP kinds. An action with both forms fits both. */
function stepFits(t: Tpl, conn: Connector, what: string): string | null {
  if (tplEmpty(t) || isMcp(conn.kind)) return null
  if (conn.kind === 'ssh' && !t.cli.trim()) return `Not available: the ${what} of this action is an API call, and ${conn.name} is an SSH connection.`
  if (conn.kind !== 'ssh' && !(t.method && t.path)) return `Not available: the ${what} of this action is a command, and ${conn.name} is an API connection.`
  return null
}
export const catView = (c: StoredCat): CatalogAction => {
  const conn = connById(c.connection_id)
  return { ...c, precheck: preOf(c), precheck_refuse: refuseOf(c), precheck_expect: expectOf(c), connection: conn?.name ?? null, connection_kind: conn?.kind ?? null, params: paramsOf(c), reversible: reversible(c), device: c.kind === 'device', available: unavailable(c) === null, unavailable_reason: unavailable(c) }
}

const TEXT_RE = /^[A-Za-z0-9 _.,:'()/-]{1,80}$/
export { TEXT_RE }
export interface CatErr { error: string; code: string }
export type CatClean = { name: string; description: string; connection_id: string; tool: string | null; rollback_tool: string | null; run: Tpl; rollback: Tpl; verify: Tpl; precheck: Tpl; precheck_refuse: string[]; precheck_expect: string; risk: Risk; enabled: boolean; ai_may_propose: boolean }
/** Validate custom catalog fields (everything the client may set). The fields must fit the kind of the chosen connection. */
export function checkCatalog(b: Record<string, unknown>): CatErr | CatClean {
  const bad = (error: string, code = 'invalid'): CatErr => ({ error, code })
  const tpl = (v: unknown): Tpl => { const o = (v ?? {}) as Partial<Tpl>; const s = (x: unknown) => (typeof x === 'string' ? x : ''); return { cli: s(o.cli), method: (['', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE'] as const).find((m) => m === o.method) ?? '', path: s(o.path), body: s(o.body), headers: s(o.headers), expect: s(o.expect) } }
  if (typeof b.name !== 'string' || !TEXT_RE.test(b.name)) return bad('Name: 1 to 80 letters, numbers, spaces and . , : \' ( ) / -')
  if (typeof b.description !== 'string' || b.description.length > 300) return bad('Description: up to 300 characters.')
  if (b.risk !== 'low' && b.risk !== 'medium' && b.risk !== 'high') return bad('Risk must be low, medium or high.')
  if (typeof b.enabled !== 'boolean') return bad('Send enabled as true or false.')
  if (typeof b.ai_may_propose !== 'boolean') return bad('Send ai_may_propose as true or false.')
  const conn = typeof b.connection_id === 'string' ? connById(b.connection_id) : undefined
  if (!conn) return bad('Choose one of your connections (Settings → Connections).')
  if (!writeToolsOf(conn).length) return bad(`${conn.name}: ${READ_ONLY}.`, 'read_only')
  const kind = conn.kind as ConnKind
  const run = tpl(b.run), rollback = tpl(b.rollback), verify = tpl(b.verify), precheck = tpl(b.precheck)
  const refuse = Array.isArray(b.precheck_refuse) && b.precheck_refuse.every((x) => typeof x === 'string') ? (b.precheck_refuse as string[]) : b.precheck_refuse == null ? [] : null
  if (refuse === null) return bad('Check before: the texts that make it refuse must be a list of up to 8 texts.')
  const expect = typeof b.precheck_expect === 'string' ? b.precheck_expect : b.precheck_expect == null ? '' : null
  if (expect === null) return bad('Check before: the text the output must contain must be text.')
  if (tplEmpty(verify) && verify.expect) return bad('Read-back: give the read-back command or API call before the text to look for.')
  for (const [what, t] of [['Action', run], ['Rollback', rollback], ['Check before', precheck]] as const) if (t.expect) return bad(`${what}: the text to look for belongs to the read-back only.`)
  let tool: string | null = null, rollback_tool: string | null = null
  for (const [what, t] of [['Action', run], ['Rollback', rollback], ['Read-back', verify]] as const) {
    if (what === 'Read-back' && tplEmpty(t)) continue
    const k = kindProblem(kind, t, what); if (k) return bad(k)
  }
  if (isMcp(kind)) {
    tool = typeof b.tool === 'string' ? b.tool : null; rollback_tool = typeof b.rollback_tool === 'string' && b.rollback_tool ? b.rollback_tool : null
    if (!tool || !writeToolsOf(conn).includes(tool)) return bad(`Pick one of the write tools of ${conn.name}.`)
    if (!rollback_tool || !writeToolsOf(conn).includes(rollback_tool)) return bad(`Rollback: pick one of the write tools of ${conn.name} that undoes the action.`)
    const mcp = (t: Tpl, what: string) => validateTpl({ ...t, method: 'POST', path: '/mcp' }, what)
    const e = mcp(run, 'Action') ?? mcp(rollback, 'Rollback'); if (e) return bad(e)
    if (!tplEmpty(verify)) return bad('Read-back: not available for MCP servers.')
    const pe = validatePrecheck(precheck, refuse, kind, expect); if (pe) return bad(pe)
  } else {
    if (b.tool != null && b.tool !== '') return bad('A tool is only chosen for an MCP server.')
    const e = validateTpl(run, 'Action') ?? validateTpl(rollback, 'Rollback') ?? (tplEmpty(verify) ? null : validateTpl(verify, 'Read-back')) ?? readBackProblem(verify) ?? validatePrecheck(precheck, refuse, kind, expect); if (e) return bad(e)
  }
  const cp = cliProblem(CLI_BAN, { run, rollback, verify, pre: precheck }, true); if (cp) return bad(cp)
  if (needsPrecheck(run, rollback, verify, precheck, refuse, true)) return bad(isMcp(kind) ? 'Action: {interface} needs a check before it, and an MCP server cannot run one yet.' : 'Action: a command or API path that uses {interface}, {port}, {id} or {name} can name a port, so it needs a check before it, with at least one text that makes it refuse (a trunk or uplink port must never be touched). {interface} is the placeholder for a port name; {port} is a TCP or UDP number, {id} a whole number and {name} a free name, and they cannot be told apart from a port in a command.')
  const used = tplParams(run)
  if (!used.length) return bad('Action: use at least one placeholder, for example {ip}, {domain} or {interface}.')
  const extra = tplParams(rollback, verify, precheck).filter((p) => !used.includes(p))
  if (extra.length) return bad(`Rollback or read-back uses {${extra[0]}}, which the action does not have, so it could not be filled in.`)
  if (!KIND_FIELDS[kind]) return bad('Unknown connection kind.')
  return { name: b.name, description: b.description, connection_id: conn.id, tool, rollback_tool, run, rollback, verify, precheck, precheck_refuse: refuse, precheck_expect: expect, risk: b.risk, enabled: b.enabled, ai_may_propose: b.ai_may_propose }
}

/** Exact change for one catalog action and validated values. Each value is escaped for the place it lands in. */
export function buildChange(c: StoredCat, values: Partial<Record<ParamType, string>>, conn: Connector | undefined, why: string): Change {
  const api = conn && isHttpKind(conn.kind)
  const mcp = conn && isMcp(conn.kind)
  const call = (t: Tpl) => (api && t.method && t.path ? { method: t.method as 'GET' | 'PUT' | 'PATCH' | 'POST' | 'DELETE', url: `${conn.target}${fill(t.path, values, 'url')}`, body: t.body ? fill(t.body, values, 'json') : null } : null)
  const cli = (t: Tpl, tool: string | null) => (mcp ? `${tool ?? ''}(${t.body ? fill(t.body, values, 'json') : ''})` : conn?.kind === 'ssh' || !conn ? fill(t.cli, values, 'cli') : api && t.method && t.path ? '' : fill(t.cli, values, 'cli'))
  const what = Object.entries(values).filter(([k]) => paramsOf(c).includes(k as ParamType)).map(([k, v]) => `${k} ${v}`).join(', ')
  /** The exact read-only step: the stored method and URL of an API call, or the command lines. */
  const step = (t: Tpl) => (t.method && t.path && api ? `${t.method} ${conn.target}${fill(t.path, values, 'url')}` : t.cli ? fill(t.cli, values, 'cli') : '')
  const pre = preOf(c)
  const quoted = (l: string[]) => l.map((x) => `"${x}"`).join(', ')
  const precheckRules = tplEmpty(pre) ? '' : [refuseOf(c).length ? `Nothing is changed if its output contains ${quoted(refuseOf(c))}` : '', expectOf(c) ? `nothing is changed unless its output contains "${expectOf(c)}"` : '', 'nothing is changed if it prints nothing'].filter(Boolean).join('; ') + '.'
  return {
    before: c.kind === 'box' && c.id === 'blocklist_add' ? `${values.ip ?? what} is not on the block list.` : c.kind === 'box' ? 'Nothing changes on any device.' : 'The current state is read from the device when the action runs.',
    after: c.id === 'blocklist_add' ? `${values.ip} is published on the block list your firewall pulls. Reason: ${why}` : `${c.name} (${what}). ${c.description}`,
    cli: cli(c.run, c.tool), rest: call(c.run),
    rollback: { title: reversible(c) ? `Undo: ${c.name} (${what})` : 'This action cannot be undone', cli: reversible(c) ? cli(c.rollback, c.rollback_tool) : '', rest: reversible(c) ? call(c.rollback) : null },
    verify: step(c.verify), precheck: step(pre), precheck_rules: precheckRules,
    verify_rule: c.verify.expect ? `After the change the read-back must contain "${fill(c.verify.expect, values, 'cli')}"; after the undo it must not.` : '',
  }
}
export const callText = (ch: Change['rest'], cli: string) => (ch ? `${ch.method} ${ch.url} ${ch.body ?? ''}`.trim() : `command: ${cli.split('\n')[0] ?? ''}`)
export const targetCount = (values: Partial<Record<ParamType, string>>) => { const c = values.cidr; return c ? 2 ** (32 - Number(c.split('/')[1])) : 1 }

// ---- Requests ----
export interface SeedBits { id: string; source: 'ai' | 'rule'; rule_id?: string; rule_name?: string; trigger?: Trigger; summary: string; asset_id?: string | null; asset_name: string; title: string; items: RequestItem[]; status: ActionRequest['status']; at: string; decided?: string; approvals?: ActionRequest['approvals']; note?: string; pre?: boolean; ai?: ActionRequest['ai']; pending_min?: number }
const catItem = (catId: string, values: Partial<Record<ParamType, string>>, why: string, o: Partial<RequestItem> & { ttl: number | null }): RequestItem => {
  const c = catById(catId)!, conn = connById(c.connection_id)
  return { id: newId('it'), action_id: c.id, title: c.kind === 'box' && c.id === 'blocklist_add' ? `Add ${values.ip} to the block list` : c.id === 'msg_send' ? 'Send a message to your alert channels' : `${c.name}: ${Object.values(values)[0]}`, risk: c.risk, reversible: reversible(c),
    connector_id: c.kind === 'device' ? c.connection_id : null, connection: c.kind === 'device' ? conn?.name ?? null : null, tool: c.tool ?? c.id, targets: 1, change: buildChange(c, values, conn, why),
    ttl_min: o.ttl, status: 'pending', executed_at: null, remove_at: null, rolled_back_at: null, result: null, verified: null, ...o }
}
const done = (at: string, ttl: number, verified = true): Partial<RequestItem> => ({ status: 'executed', executed_at: at, remove_at: new Date(Date.parse(at) + ttl * 60e3).toISOString(), result: 'Added to the block list. Your firewall picks it up on its next fetch.', verified: { ok: verified, detail: 'Read back from the block list: the entry is present.' } })
const person = (id: string, name: string, email: string, via: ActionRequest['approvals'][number]['via'], at: string, items: RequestItem[]) => ({ user_id: id, name, email, via, at, items: items.map((i) => i.id) })

function buildSeed(o: SeedBits): ActionRequest {
  const maxRisk = (['high', 'medium', 'low'] as Risk[]).find((r) => o.items.some((i) => i.risk === r)) ?? 'low'
  const exp = o.status === 'pending' ? new Date(Date.now() + (o.pending_min ?? 27) * 60e3).toISOString() : new Date(Date.parse(o.at) + 15 * 60e3).toISOString()
  return {
    id: o.id, source: o.source, proposal_id: `${o.source}:${o.id}`, rule_id: o.rule_id ?? null, rule_name: o.rule_name ?? null, trigger: o.trigger ?? null, trigger_summary: o.summary,
    finding_id: null, cve: null, asset_id: o.asset_id ?? null, asset_name: o.asset_name, title: o.title, items: o.items, risk: maxRisk,
    status: o.status, requested_at: o.at, expires_at: exp, decided_at: o.decided ?? null, requires_approvals: 1, two_because: null, approvals: o.approvals ?? [],
    sent_to: [], email_links: [], note: o.note ?? null, pre_approved: o.pre ?? false, ai: o.ai ?? null,
  }
}
export const actionsStore = collection<ActionRequest[]>('resp_actions', () => {
  const t1 = daysAgo(0, 2), t2 = daysAgo(0, 5), t3 = daysAgo(0, 6), t4 = daysAgo(2), t5 = daysAgo(1)
  const why1 = 'PC-SALES-02 connected to 185.220.101.47 (Tor exit list, confidence 0.92)'
  const i1 = catItem('blocklist_add', { ip: '185.220.101.47' }, why1, { ttl: 1440, ...done(t1, 1440) })
  const i2 = catItem('blocklist_add', { ip: '45.9.148.20' }, 'PC-ACC-04 connected to 45.9.148.20 (IPsum, confidence 0.85)', { ttl: 720, ...done(t2, 720) })
  const i3 = catItem('blocklist_add', { ip: '198.51.100.23' }, 'AI: scanning our public address range, confidence 0.88', { ttl: 1440, ...done(t3, 1440) })
  const i4 = catItem('blocklist_add', { ip: '203.0.113.77' }, 'AI: repeated probes of port 3389', { ttl: 1440, status: 'pending' })
  const i5a = catItem('blocklist_add', { ip: '91.92.240.12' }, 'PC-HR-01 connected to 91.92.240.12 (URLhaus, confidence 0.6)', { ttl: 720 })
  const i5b = catItem('msg_send', { text: 'Known-bad connection from PC-HR-01 to 91.92.240.12' }, '', { ttl: null })
  const i6 = catItem('blocklist_add', { ip: '45.148.10.95' }, 'AI: PC-FIN-02 connected to 45.148.10.95 (ET Open compromised, IPsum), confidence 0.86', { ttl: 1440 })
  const i7 = catItem('msg_send', { text: 'Unknown device 3c:22:fb:10:aa:01, vendor Unknown vendor, at 192.168.10.157' }, '', { ttl: null })
  return [
    buildSeed({ id: 'act-seed-5', source: 'rule', rule_id: 'r-ioc-ask', rule_name: 'Ask before blocking medium-confidence matches', trigger: 'ioc_connection', summary: 'PC-HR-01 connected to 91.92.240.12 (URLhaus, confidence 0.6)', asset_id: 'a-pc07', asset_name: 'PC-HR-01', title: 'Block 91.92.240.12 and tell the team', items: [i5a, i5b], status: 'pending', at: new Date(Date.now() - 60e3).toISOString(), pending_min: 28 }),
    buildSeed({ id: 'act-seed-6', source: 'ai', trigger: 'ioc_connection', summary: 'AI request', asset_name: 'PC-FIN-02', title: 'Add 45.148.10.95 to the block list', items: [i6], status: 'pending', at: new Date(Date.now() - 3 * 60e3).toISOString(), pending_min: 26,
      ai: { confidence: 0.86, why: 'PC-FIN-02 connected to 45.148.10.95, which two threat feeds list as a command-and-control server. Blocking the address stops the connection without touching the PC.', evidence: [{ kind: 'ioc_hit', id: 'b-3', summary: 'PC-FIN-02 to 45.148.10.95 via the firewall log, 2 feeds, confidence 0.6 in the hit list' }], second_check: null, in_app_only: false } }),
    buildSeed({ id: 'act-seed-1', source: 'rule', rule_id: 'r-ioc', rule_name: 'Block destinations of known-bad connections', trigger: 'ioc_connection', summary: why1, asset_id: 'a-pc05', asset_name: 'PC-SALES-02', title: 'Add 185.220.101.47 to the block list', items: [i1], status: 'executed', at: t1, decided: t1,
      pre: true, approvals: [{ user_id: 'rule:r-ioc', name: 'Rule: Block destinations of known-bad connections', email: 'rule@vedette', via: 'auto', at: t1, items: [i1.id] }] }),
    buildSeed({ id: 'act-seed-2', source: 'rule', rule_id: 'r-ioc-ask', rule_name: 'Ask before blocking medium-confidence matches', trigger: 'ioc_connection', summary: 'PC-ACC-04 connected to 45.9.148.20 (IPsum, confidence 0.85)', asset_name: 'PC-ACC-04', title: 'Add 45.9.148.20 to the block list', items: [i2], status: 'executed', at: t2, decided: t2,
      approvals: [person('u-op', 'IT Operator', 'it@acme.example', 'slack', t2, [i2])] }),
    buildSeed({ id: 'act-seed-3', source: 'ai', trigger: 'ioc_connection', summary: 'AI request', asset_name: 'Public address range', title: 'Add 198.51.100.23 to the block list', items: [i3], status: 'executed', at: t3, decided: t3,
      approvals: [person('u-admin', 'Admin', 'admin@acme.example', 'app', t3, [i3])],
      ai: { confidence: 0.88, why: 'The address scanned our public range 40 times in an hour and is on two feeds.', evidence: [{ kind: 'ioc_hit', id: 'b-1', summary: 'Known-bad connection list entry' }], second_check: null, in_app_only: false } }),
    buildSeed({ id: 'act-seed-4', source: 'ai', trigger: 'ioc_connection', summary: 'AI request', asset_name: 'Public address range', title: 'Add 203.0.113.77 to the block list', items: [{ ...i4, status: 'skipped' }], status: 'rejected', at: t4, decided: t4,
      approvals: [], note: 'Rejected by IT Operator: Our own vulnerability scanner',
      ai: { confidence: 0.83, why: 'Repeated probes of port 3389 from this address.', evidence: [{ kind: 'ioc_hit', id: 'b-1', summary: 'Known-bad connection list entry' }], second_check: null, in_app_only: false } }),
    buildSeed({ id: 'act-seed-7', source: 'rule', rule_id: 'r-unknown', rule_name: 'Unknown device: message only', trigger: 'unknown_device', summary: 'Unknown device at 192.168.10.157', asset_id: 'a-unk01', asset_name: '192.168.10.157', title: 'Send a message to your alert channels', items: [{ ...i7, status: 'skipped' }], status: 'expired', at: t5, decided: new Date(Date.parse(t5) + 15 * 60e3).toISOString(), note: 'Expired without a decision' }),
  ]
}, () => [])
export const doneStore = collection<string[]>('resp_done', () => ['r-ioc:det-s-ioc-1'], () => [])

export function patchAction(id: string, fn: (a: ActionRequest) => ActionRequest): ActionRequest {
  let out!: ActionRequest
  actionsStore.update((l) => l.map((a) => (a.id === id ? (out = fn(a)) : a)))
  return out
}
const patchItem = (a: ActionRequest, itemId: string, p: Partial<RequestItem>) => patchAction(a.id, (x) => ({ ...x, items: x.items.map((i) => (i.id === itemId ? { ...i, ...p } : i)) }))
export const findAction = (id: string) => (ID_RE.test(id) ? actionsStore.get().find((a) => a.id === id) : undefined)
export const isOpen = (a: ActionRequest) => a.status === 'pending' || a.status === 'approved'

// ---- Safety envelope ----
export function maintenanceNow() { const n = Date.now(); return settings().maintenance.find((w) => Date.parse(w.start) <= n && n < Date.parse(w.end)) }
export const notifyNames = () => { const n = chanList().map(chanLabel); return n.length ? n : ['the app'] }
/** Actions requested in the last hour, rules and AI together (what the global circuit breaker counts). */
export const actionsLastHour = () => actionsStore.get().filter((a) => Date.now() - Date.parse(a.requested_at) < HOUR).reduce((n, a) => n + a.items.length, 0)
export function breakerOpen() { return settings().breaker_tripped_at !== null }
/** More actions than the limit in one hour: pause everything and notify. Returns true when it tripped. */
export function checkBreaker(adding: number): boolean {
  const s = settings()
  if (s.breaker_tripped_at) return true
  if (actionsLastHour() + adding <= s.breaker_max_per_hour) return false
  const names = notifyNames()
  settingsStore.update((x) => ({ ...x, breaker_tripped_at: nowIso(), breaker_notified: names }))
  step('response.breaker', 'response', 'breaker', `Circuit breaker tripped: more than ${s.breaker_max_per_hour} actions in one hour. All rules and AI requests are paused. Notified: ${names.join(', ')}`, 'system')
  return true
}
export const BREAKER_MSG = 'The circuit breaker is open: too many actions in one hour, so everything is paused. An admin can resume it in Settings, AI response.'

/** Two different approvers: a high-risk action, or an action that touches more targets than the limit. */
export function requiredApprovals(items: { risk: Risk; targets: number }[]): { n: 1 | 2; why: string | null } {
  if (items.some((i) => i.risk === 'high')) return { n: 2, why: 'High-risk actions need two different approvers.' }
  const total = items.reduce((n, i) => n + i.targets, 0), max = settings().multi_target_max
  if (items.some((i) => i.targets > max) || total > max) return { n: 2, why: `This request touches ${total} targets, more than the limit of ${max}, so a second approver is needed.` }
  return { n: 1, why: null }
}

export type ReqInit = Pick<ActionRequest, 'source' | 'proposal_id' | 'rule_id' | 'rule_name' | 'trigger' | 'trigger_summary' | 'finding_id' | 'cve' | 'asset_id' | 'asset_name' | 'title' | 'items' | 'ai'>
/** Create a pending request and send it: tokens for link channels (email, Zalo OA), names of every channel. One bundle per rule run. */
export function newRequest(o: ReqInit, notify: boolean): ActionRequest {
  const s = settings()
  const now = Date.now()
  const id = newId('act')
  const sending = notify ? rawChans().filter((c) => c.configured && c.enabled && s.approval_channels.includes(c.type) && chanReady(c)) : []
  for (const c of sending.filter((x) => LINK_TYPES.includes(x.type))) {
    for (const ap of approversOf(c).filter((x) => userCanApprove(x.user_id))) {
      tokensStore.update((l) => [...l, { token: approvalToken(), action_id: id, user_id: ap.user_id, address: ap.address, channel: c.type, expires_at: new Date(now + TOKEN_MIN * 60e3).toISOString(), used_at: null }])
    }
  }
  const req = requiredApprovals(o.items)
  const risk = (['high', 'medium', 'low'] as Risk[]).find((r) => o.items.some((i) => i.risk === r)) ?? 'low'
  const a: ActionRequest = {
    ...o, id, risk, status: 'pending', requested_at: new Date(now).toISOString(), expires_at: new Date(now + s.expiry_min * 60e3).toISOString(), decided_at: null,
    requires_approvals: req.n, two_because: req.why, approvals: [], sent_to: sending.map(chanLabel), email_links: [], note: null, pre_approved: false,
  }
  actionsStore.update((l) => [a, ...l])
  step('response.request', a.id, 'request', `${a.title}: ${a.items.map((i) => callText(i.change.rest, i.change.cli)).join(' | ')}; expires ${a.expires_at}; needs ${req.n} approver${req.n === 1 ? '' : 's'}; sent to ${a.sent_to.join(', ') || 'the app only'}`, a.source === 'ai' ? 'ai:response' : a.rule_name ? `rule:${a.rule_name}` : undefined)
  return a
}

/** Pending requests past their expiry become "expired" and a notice goes out; executed changes past their TTL are undone. Runs at the start of every handler. */
export function sweep() {
  const now = Date.now()
  for (const a of actionsStore.get()) {
    if (a.status === 'pending' && Date.parse(a.expires_at) <= now) {
      step('response.expire', a.id, 'expired', `Request expired without a decision, nothing was changed: ${a.title}. Notice sent to ${notifyNames().join(', ')}`, 'system')
      patchAction(a.id, (x) => ({ ...x, status: 'expired', decided_at: nowIso(), note: 'Expired without a decision. Nothing was changed.', items: x.items.map((i) => ({ ...i, status: 'skipped' as const })) }))
    }
    for (const i of a.items) {
      if (i.status === 'executed' && i.remove_at && Date.parse(i.remove_at) <= now) {
        // Removing a change is the safe direction: no execution switch, no approval.
        step('response.ttl_remove', a.id, 'ttl_removed', `${i.change.rollback.title}: undo time of ${i.ttl_min} minutes ended; ${callText(i.change.rollback.rest, i.change.rollback.cli)}`, 'system')
        const cur = patchItem(a, i.id, { status: 'rolled_back', rolled_back_at: nowIso(), result: 'Undone automatically (undo time ended).' })
        if (!cur.items.some((x) => x.status === 'executed')) patchAction(a.id, (x) => ({ ...x, status: 'rolled_back', note: 'Undone automatically when the undo time ended' }))
      }
    }
  }
}

/** Gates every execution path shares (approve in app, chat, email, rule; rollback), per item: switch (device), catalog entry enabled, connection and tool. */
function gate(a: ActionRequest, i: RequestItem): Response | null {
  const device = i.connector_id !== null
  if (device && !settings().execution) return refuse(409, 'execution_off', OFF_MSG, a.id)
  const cat = catById(i.action_id)
  if (!cat || !cat.enabled) return refuse(403, 'tool_not_allowed', `The action "${cat?.name ?? i.tool}" is not enabled in the action catalog (Settings, AI response).`, a.id)
  // A request made from a sample plan names the write tool of the sample connection (a built-in HTTP action has no tool of its own, D-94): that tool must still be on.
  const conn = connById(i.connector_id), planTool = device && i.tool !== cat.id && i.tool !== cat.tool ? i.tool : null
  const why = unavailable(cat) ?? (device && cat.connection_id !== i.connector_id ? 'The connection for this action was changed after the request was made.' : null)
    ?? (planTool && conn && !writeToolsOf(conn).includes(planTool) ? `The write tool ${planTool} on ${conn.name} is turned off or missing.` : null)
  if (why) return refuse(409, 'tool_unavailable', why, a.id)
  return null
}

export type Via = ActionRequest['approvals'][number]['via']
export type Who = { id: string; name: string; email: string; via: Via; chatId?: string }
export const who = (u: { id: string; name: string; email: string }, via: Via, chatId?: string): Who => ({ id: u.id, name: u.name, email: u.email, via, chatId })

/** The in-app two-step code. An authenticator secret is checked by the core module in a real box; the mock accepts a 6-digit code once the user has two-step on. */
export function checkTwoStep(userId: string, code: string | undefined): { code: string; message: string } | null {
  const u = usersStore.get().find((x) => x.id === userId)
  if (!u?.twofa) return { code: 'twofa_required', message: 'This approval needs your two-step code. Turn on two-step sign-in in My account first.' }
  if (code === undefined || code === '') return { code: 'code_required', message: 'Type the 6-digit two-step code to approve a high-risk AI request.' }
  if (!/^\d{6}$/.test(code)) return { code: 'invalid_code', message: 'The two-step code is 6 digits.' }
  return null
}

function execItem(a: ActionRequest, i: RequestItem): void {
  const device = i.connector_id !== null
  if (device) {
    const conn = connById(i.connector_id)
    if (!conn || conn.status === 'error') {
      step('response.fail', a.id, 'failed', `${i.title}: connection ${i.connection} did not answer; nothing was changed`, 'system')
      patchItem(a, i.id, { status: 'failed', result: `The connection ${i.connection} did not answer (status: error). Nothing was changed.` })
      return
    }
  }
  const removeAt = i.ttl_min ? new Date(Date.now() + i.ttl_min * 60e3).toISOString() : null
  const verified = i.change.verify ? { ok: true, detail: `Read back: ${i.change.verify}. The change is in place.` } : null
  step('response.execute', a.id, 'executed', `${callText(i.change.rest, i.change.cli)}${removeAt ? `; undone automatically at ${removeAt}` : ''}${verified ? '; read back: ok' : ''}`, 'system')
  patchItem(a, i.id, { status: 'executed', executed_at: nowIso(), remove_at: removeAt, verified,
    result: device ? (i.change.rest ? `${i.change.rest.method} ${i.change.rest.url} answered 200 {"status":"success"}` : `Command sent through ${i.connection}: accepted.`) : i.action_id === 'blocklist_add' ? 'Added to the block list. Your firewall picks it up on its next fetch.' : 'Sent.' })
}

/** Approve a request: all actions or the picked ones. Gates in order: switch, state, expiry, selection, in-app 2FA (AI high risk), distinct approvers, catalog/tool, rate limit. */
export function approve(a: ActionRequest, w: Who, pick?: string[], code?: string): Response | ActionRequest {
  const first = a.approvals[0]
  const ids = pick && pick.length ? pick : first ? first.items : a.items.map((i) => i.id)
  const chosen = a.items.filter((i) => ids.includes(i.id))
  if (a.status === 'expired') return refuse(409, 'expired', 'This request has expired. Nothing was changed. Ask for a new one.', a.id)
  if (a.status !== 'pending') return refuse(409, 'not_pending', `This request is already ${a.status.replace('_', ' ')}. One approval covers one request.`, a.id)
  if (!chosen.length || chosen.length !== new Set(ids).size) return refuse(400, 'invalid_items', 'Pick at least one action of this request.', a.id)
  if (chosen.some((i) => i.connector_id !== null) && !settings().execution) return refuse(409, 'execution_off', OFF_MSG, a.id)
  if (first && pick && pick.length && (pick.length !== first.items.length || !pick.every((p) => first.items.includes(p)))) return refuse(409, 'selection_differs', 'The second approver must approve the same actions as the first.', a.id)
  if (a.approvals.some((x) => x.user_id === w.id)) return refuse(409, 'same_approver', 'You already approved this request. A second, different person must approve it.', a.id)
  if (a.ai?.in_app_only && w.via !== 'auto') {
    if (w.via !== 'app') return refuse(403, 'in_app_required', 'A high-risk AI request can only be approved in the app with your two-step code, not from chat or email.', a.id)
    const bad = checkTwoStep(w.id, code); if (bad) return refuse(403, bad.code, bad.message, a.id)
  }
  for (const i of chosen) { const blocked = gate(a, i); if (blocked) return blocked }
  const s = settings()
  const device = chosen.filter((i) => i.connector_id !== null).length
  const recent = actionsStore.get().flatMap((x) => x.items).filter((i) => i.connector_id !== null && i.executed_at && Date.now() - Date.parse(i.executed_at) < HOUR).length
  if (device && recent + device > s.max_per_hour) return refuse(429, 'rate_limited', `Limit reached: ${s.max_per_hour} approved device actions per hour. Try again later or raise the limit in Settings.`, a.id)
  const at = nowIso()
  const need = requiredApprovals(chosen)
  const approvals = [...a.approvals, { user_id: w.id, name: w.name, email: w.email, via: w.via, at, items: chosen.map((i) => i.id) }]
  step('response.approve', a.id, 'approved', `${a.title}, approved by ${w.email} via ${w.via}${w.chatId ? ` (${w.via} id ${w.chatId})` : ''}: ${chosen.map((i) => i.title).join('; ')} (approval ${approvals.length} of ${need.n})`, `${w.email} (${w.via})`)
  const cur = patchAction(a.id, (x) => ({ ...x, approvals, requires_approvals: need.n, two_because: need.why }))
  if (approvals.length < need.n) return cur
  patchAction(a.id, (x) => ({ ...x, status: 'approved', decided_at: at, items: x.items.map((i) => (ids.includes(i.id) ? i : { ...i, status: 'skipped' as const })) }))
  for (const i of chosen) execItem(a, i)
  return patchAction(a.id, (x) => ({ ...x, status: x.items.some((i) => i.status === 'executed') ? 'executed' : 'failed' }))
}

export function reject(a: ActionRequest, w: Who, note: string): Response | ActionRequest {
  if (a.status === 'expired') return refuse(409, 'expired', 'This request has already expired.', a.id)
  if (a.status !== 'pending') return refuse(409, 'not_pending', `This request is already ${a.status.replace('_', ' ')}.`, a.id)
  step('response.reject', a.id, 'rejected', `${a.title}, rejected by ${w.email} via ${w.via}: ${oneLine(note, 300)}`, `${w.email} (${w.via})`)
  return patchAction(a.id, (x) => ({ ...x, status: 'rejected', decided_at: nowIso(), note, items: x.items.map((i) => ({ ...i, status: 'skipped' as const })) }))
}

export function rollbackRequest(a: ActionRequest): Response | ActionRequest {
  const run = a.items.filter((i) => i.status === 'executed')
  if (!run.length) return refuse(409, 'not_executed', 'Only an executed action can be rolled back.', a.id)
  for (const i of run) { const blocked = gate(a, i); if (blocked) return blocked }
  for (const i of run) {
    step('response.rollback', a.id, 'rolled_back', `${i.change.rollback.title}; ${callText(i.change.rollback.rest, i.change.rollback.cli)}`)
    patchItem(a, i.id, { status: 'rolled_back', rolled_back_at: nowIso(), result: i.change.rollback.rest ? `${i.change.rollback.rest.method} ${i.change.rollback.rest.url} answered 200 {"status":"success"}` : 'Removed.' })
  }
  return patchAction(a.id, (x) => ({ ...x, status: 'rolled_back' }))
}

export const notFound = () => fail(404, 'not_found', 'No such request.')
export const isResp = (v: Response | ActionRequest): v is Response => v instanceof Response

// ---- Views ----
export function actionsView(): ActionRequest[] {
  const u = currentUser()
  const showLinks = previewBuild() && u?.role === 'admin'
  const toks = tokensStore.get()
  return [...actionsStore.get()].sort((a, b) => b.requested_at.localeCompare(a.requested_at)).map((a) => ({
    ...a,
    email_links: showLinks ? toks.filter((t) => t.action_id === a.id).map((t) => ({ approver: usersStore.get().find((x) => x.id === t.user_id)?.name ?? t.user_id, address: t.address, url: linkUrl(t.token), expires_at: t.expires_at, used: !!t.used_at })) : [],
  }))
}
export function settingsView(): SettingsView {
  return {
    ...settings(),
    channels: APPROVAL_TYPES.flatMap((type) => { const c = rawChans().find((x) => x.type === type && x.configured); return c ? [{ type, label: chanLabel(c), ready: chanReady(c), approvers: approversOf(c).length, link: LINK_TYPES.includes(type) }] : [] }),
  }
}
