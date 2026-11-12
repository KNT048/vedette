// Pure helpers for the response module: tamper-evident log hash, action templates, allowlist matching, tokens.
// No imports from mocks: the UI uses these too (log verification, form checks). The server (M2) re-implements them in Go.

// ---- SHA-256: one implementation for every chain, see src/lib/chain.ts (the UI verifies with crypto.subtle when it exists) ----
import { GENESIS, respLogHash, sha256 as sha256Sync } from '@/lib/chain'
import { isMcpKind, type ConnectionKindId } from '@/lib/connections'
export { sha256Sync }

/** Browser: crypto.subtle. Where it is missing (some test environments): the same digest from the JS version. */
export async function sha256Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return sha256Sync(text)
  const d = await subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

// ---- Tamper-evident log (D-48) ----
export { GENESIS }
export interface LogCore { id: string; ts: string; kind: string; actor: string; detail: string; prev_hash: string }
/** One formula for every chain (D-57 (14)): SHA-256( prev_hash + "\n" + canonical JSON of the entry without hash ), see src/lib/chain.ts. */
export const logHashSync = (e: LogCore) => respLogHash(e)

/** Walk the chain oldest to newest. `broken_at` = index of the first entry whose link or hash does not match. */
export async function verifyChain(entries: (LogCore & { hash: string })[]): Promise<{ ok: boolean; broken_at: number | null }> {
  let prev = GENESIS
  for (const [i, e] of entries.entries()) {
    const { hash, ...rest } = e
    if (e.prev_hash !== prev || hash !== logHashSync(rest)) return { ok: false, broken_at: i }
    prev = e.hash
  }
  return { ok: true, broken_at: null }
}

// ---- Typed placeholders (D-47, D-51, SYS-1: no free shell text). Trigger data is attacker-controlled: every value is checked by type. ----
export type ParamType = 'ip' | 'cidr' | 'domain' | 'port' | 'mac' | 'vlan' | 'interface' | 'id' | 'name' | 'text'
export const PARAM_TYPES: ParamType[] = ['ip', 'cidr', 'domain', 'port', 'mac', 'vlan', 'interface', 'id', 'name', 'text']
/** Values Vedette reads from the device or derives when it runs (action-templates §1.1 precheck, §1.4 ttl). Rules never supply them: they are not parameters, and a request shows them as <name>. */
export const RUNTIME_VALUES = ['seq', 'previous_vlan', 'found_id', 'expiry_s', 'timeout', 'rules_before'] as const
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
export const isIpv4 = (v: string) => IPV4.test(v)
export const isDomain = (v: string) => DOMAIN.test(v)
export const isCidr = (v: string) => /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v) && IPV4.test(v.split('/')[0]!) && Number(v.split('/')[1]) <= 32
/** Safe text: letters, numbers, space and . , : @ # / _ - only. No quotes, no shell characters, no newlines. */
const TEXT = /^[A-Za-z0-9][A-Za-z0-9 _.,:@#/-]{0,79}$/
export const PARAM_CHECK: Record<ParamType, (v: string) => boolean> = {
  ip: isIpv4, cidr: isCidr, domain: isDomain,
  port: (v) => /^\d{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535,
  mac: (v) => /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(v),
  vlan: (v) => /^\d{1,4}$/.test(v) && Number(v) >= 1 && Number(v) <= 4094,
  interface: (v) => /^[A-Za-z0-9][A-Za-z0-9/.:-]{0,31}$/.test(v),
  id: (v) => /^\d{1,10}$/.test(v) && Number(v) >= 1 && Number(v) <= 2147483647,
  name: (v) => /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(v),
  text: (v) => TEXT.test(v),
}
export const PARAM_LABEL: Record<ParamType, string> = { ip: 'an IP address', cidr: 'an address range', domain: 'a domain', port: 'a port number', mac: 'a MAC address', vlan: 'a VLAN number', interface: 'a port or interface name', id: 'a whole number (for example a policy number)', name: 'a name of letters, numbers, . _ and - (up to 64)', text: 'a short plain-text value' }

/** `expect` (D-95) only means something on the read-back: after the action its output must contain it, after the undo it must not. */
export interface Tpl { cli: string; method: '' | 'GET' | 'PUT' | 'PATCH' | 'POST' | 'DELETE'; path: string; body: string; headers: string; expect?: string }
export const EMPTY_TPL: Tpl = { cli: '', method: '', path: '', body: '', headers: '', expect: '' }
export const MAX_REFUSE = 8
export const MAX_REFUSE_LEN = 80
export const MAX_EXPECT = 200
/** Headers count: a step that holds only headers is not empty, so it is validated like any other. */
export const tplEmpty = (t: Tpl) => !t.cli.trim() && !t.method && !t.path && !t.body.trim() && !t.headers.trim()

/** Characters a template may contain. Shell metacharacters (; | & $ ` < > ( ) \ ! ~ ^) are never allowed, even in the fixed text. */
const SAFE_TEXT = /^[A-Za-z0-9 _.,:/"'{}=\n\t@#%+*?[\]-]*$/
const PLACEHOLDER = /\{([a-z_]+)\}/g
const isRuntime = (k: string) => (RUNTIME_VALUES as readonly string[]).includes(k)
const HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]{0,40}: [A-Za-z0-9 _.,:/@#=+{}*-]{0,200}$/

export function templateParams(...texts: string[]): ParamType[] {
  const found = new Set<ParamType>()
  for (const t of texts) for (const m of t.matchAll(PLACEHOLDER)) if ((PARAM_TYPES as string[]).includes(m[1]!)) found.add(m[1] as ParamType)
  return PARAM_TYPES.filter((p) => found.has(p))
}
export const tplParams = (...t: Tpl[]) => templateParams(...t.flatMap((x) => [x.cli, x.path, x.body, x.headers, x.expect ?? '']))
/** Header names a template may never set (D-94): the connection sets the credentials and the address, and hop-by-hop headers belong to the connection. */
const FORBIDDEN_HEADERS = ['authorization', 'cookie', 'host', 'connection', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'forwarded', 'via', 'x-forwarded',
  'x-http-method-override', 'x-http-method', 'x-method-override', 'x-real-ip', 'x-original-url', 'x-rewrite-url']
export const forbiddenHeader = (name: string) => { const n = name.toLowerCase(); return FORBIDDEN_HEADERS.includes(n) || n.startsWith('proxy-') || n.startsWith('x-forwarded-') }
/** A single line of plain text, placeholders allowed: what a read-back must contain. */
const EXPECT_TEXT = /^[A-Za-z0-9 _.,:/"'{}=@#%+*?[\]-]*$/

/** null = acceptable. Otherwise a one-line reason in plain words. */
export function validateTpl(t: Tpl, what: string): string | null {
  if (!t.cli.trim() && !(t.method && t.path)) return `${what}: give a command or an API call.`
  if (t.cli.length > 2000 || t.body.length > 2000 || t.path.length > 300 || t.headers.length > 600) return `${what}: too long.`
  for (const [field, v] of [['command', t.cli], ['API path', t.path], ['API body', t.body], ['headers', t.headers]] as const) {
    if (!SAFE_TEXT.test(v)) return `${what}: the ${field} contains a character that is not allowed (shell characters such as ; | & $ \` < > ( ) \\ are refused).`
    for (const m of v.matchAll(PLACEHOLDER)) {
      if (m[1] === 'text') return `${what}: {text} is only for message actions. In a command or API call use a typed placeholder such as {ip}, {domain}, {name} or {id}.`
      if (!(PARAM_TYPES as string[]).includes(m[1]!) && !isRuntime(m[1]!)) return `${what}: unknown placeholder {${m[1]}}. Use {ip}, {cidr}, {domain}, {port}, {mac}, {vlan}, {interface}, {id} or {name}.`
    }
  }
  if (t.headers && !t.headers.split('\n').every((l) => HEADER_LINE.test(l))) return `${what}: each header must look like "Name: value".`
  const banned = t.headers.split('\n').map((l) => l.split(':')[0]!).find((n) => n && forbiddenHeader(n))
  if (banned) return `${what}: the header ${banned} is set by the connection and cannot be part of a template.`
  const ex = t.expect ?? ''
  if (ex.length > MAX_EXPECT) return `${what}: the text to look for is too long (up to ${MAX_EXPECT} characters).`
  if (ex) {
    if (!EXPECT_TEXT.test(ex)) return `${what}: the text to look for contains a character that is not allowed.`
    for (const m of ex.matchAll(PLACEHOLDER)) if (!(PARAM_TYPES as string[]).includes(m[1]!) && !isRuntime(m[1]!)) return `${what}: unknown placeholder {${m[1]}} in the text to look for.`
    if (/\{text\}/.test(ex)) return `${what}: {text} is only for message actions.`
  }
  if (t.method && !t.path) return `${what}: an API call needs a path.`
  if (t.path && !t.method) return `${what}: choose the API method.`
  if (t.path && (!/^\/[A-Za-z0-9/_.{}-]*$/.test(t.path) || t.path.includes('..'))) return `${what}: the API path must start with / and cannot contain .. or a query.`
  if (t.body) { try { JSON.parse(t.body.replace(PLACEHOLDER, '0')) } catch { return `${what}: the API body must be valid JSON.` } }
  return null
}

// ---- Connection kinds: the form and the server both follow the kind of the chosen connection ----
export type ConnKind = ConnectionKindId
export type TplField = 'cli' | 'method' | 'path' | 'body' | 'headers'
export const isMcp = isMcpKind
/** Which template fields a kind uses. HTTP-carried kinds: method, path, headers, body. MCP: the tool is chosen separately and the arguments are the body (JSON). */
export const KIND_FIELDS: Record<ConnKind, TplField[]> = {
  http: ['method', 'path', 'headers', 'body'], 'netconf-restconf': ['method', 'path', 'headers', 'body'], automation: ['method', 'path', 'headers', 'body'],
  ssh: ['cli'], 'mcp-http': ['body'], 'mcp-stdio': ['body'],
}
/** null = the template only uses fields of this kind. */
export function kindProblem(kind: ConnKind, t: Tpl, what: string): string | null {
  const extra = (['cli', 'method', 'path', 'body', 'headers'] as TplField[]).filter((f) => !KIND_FIELDS[kind].includes(f) && String(t[f]).trim() !== '')
  if (extra.length) return `${what}: ${extra.join(', ')} does not apply to this kind of connection and must be empty.`
  return null
}
const REFUSE_TEXT = /^[\x20-\x7e]{1,80}$/
/** The check before the action (D-95): a read-only template plus up to 8 texts that refuse it and one text its output must contain; when the output holds a refusal text, or lacks the required one, nothing is written. null = acceptable (or none given). */
export function validatePrecheck(pre: Tpl, refuse: string[], kind: ConnKind, expect = ''): string | null {
  const what = 'Check before'
  if (tplEmpty(pre) && refuse.length === 0 && !expect) return null
  if (isMcp(kind)) return `${what}: not available for MCP servers.`
  if (tplEmpty(pre)) return `${what}: give the read-only command or API call, or remove the texts that make it refuse.`
  if (refuse.length === 0 && !expect) return `${what}: add at least one text that makes it refuse, or a text the output must contain.`
  if (refuse.length > MAX_REFUSE) return `${what}: up to ${MAX_REFUSE} texts that make it refuse.`
  if (refuse.some((r) => !REFUSE_TEXT.test(r) || !r.trim())) return `${what}: each text that makes it refuse is 1 to ${MAX_REFUSE_LEN} plain characters.`
  if (expect && (!REFUSE_TEXT.test(expect) || !expect.trim())) return `${what}: the text the output must contain is 1 to ${MAX_REFUSE_LEN} plain characters.`
  if ((pre.method && pre.method !== 'GET') || pre.body.trim()) return `${what}: an API call can only be a GET without a body. It must not change anything.`
  if (pre.expect) return `${what}: the text to look for belongs to the read-back, not here.`
  return kindProblem(kind, pre, what) ?? validateTpl(pre, what)
}
/** The read-back runs after the action and after the undo, so it only reads: an API call is a GET without a body (spec 1.6, 9.1 (3)). */
export function readBackProblem(t: Tpl): string | null {
  if (tplEmpty(t)) return null
  if ((t.method && t.method !== 'GET') || t.body.trim()) return 'Read-back: an API call can only be a GET without a body. It must not change anything.'
  return null
}
/** Placeholders that can name a port: {interface} always; in a customer's command or API path also {port}, {id} and {name}, because the type system has no "port name" type for them ({port} is a TCP or UDP number, {id} a whole number, {name} a free name, and "interface Gi1/0/{port}" or "interface {name}" names a port all the same). */
const PORT_LIKE: ParamType[] = ['interface', 'port', 'id', 'name']
const usesPortLike = (run: Tpl, rollback: Tpl, verify: Tpl, pre: Tpl, custom: boolean) =>
  tplParams(run, rollback, verify, pre).includes('interface') || (custom && templateParams(run.cli, run.path, rollback.cli, rollback.path).some((p) => PORT_LIKE.includes(p)))
/** An action that can name a port needs the check before with at least one refusal text, so a trunk or uplink is never touched (D-95 (3)). custom: a customer's action. */
export const needsPrecheck = (run: Tpl, rollback: Tpl, verify: Tpl, pre: Tpl, refuse: string[], custom = false) => usesPortLike(run, rollback, verify, pre, custom) && (tplEmpty(pre) || refuse.length === 0)

// ---- Command lines of the steps that must only read (D-95): the refused commands are data (templates/cli-ban.sample.json, D-58) ----
export interface CliBan { everywhere: string[]; read_only_steps: string[] }
const banRegexps = (patterns: string[]) => patterns.map((p) => new RegExp(`^${p.toLowerCase().split(/\s+/).filter(Boolean).map((w) => w.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')).join(' ')}(\\s|$)`))
export const cliLines = (s: string) => s.split('\n').map((l) => l.trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ')).filter(Boolean)
/** null = acceptable. custom: the lines of a customer's action (run and rollback too, spec 9.3); a built-in action is reviewed data, so only its reads are checked. The check before and the read-back may not contain a change command and may share no line with the run or the rollback, except a first line that is the same in both (a pager or terminal setup line). */
export function cliProblem(ban: CliBan, s: { run: Tpl; rollback: Tpl; verify: Tpl; pre: Tpl }, custom: boolean): string | null {
  const every = banRegexps(ban.everywhere), ro = banRegexps(ban.read_only_steps)
  const hit = (lines: string[], res: RegExp[]) => lines.find((l) => res.some((r) => r.test(l)))
  for (const [what, t, readOnly, write] of [['Action', s.run, false, true], ['Rollback', s.rollback, false, true], ['Read-back', s.verify, true, false], ['Check before', s.pre, true, false]] as const) {
    const lines = cliLines(t.cli)
    if (!lines.length || (write && !custom)) continue
    const bad = hit(lines, every); if (bad) return `${what}: the command "${bad.slice(0, 60)}" is not allowed in a template.`
    const change = readOnly ? hit(lines, ro) : undefined; if (change) return `${what}: the command "${change.slice(0, 60)}" can change the device. This step may only read.`
  }
  const written = new Set([...cliLines(s.run.cli), ...cliLines(s.rollback.cli)])
  const firsts = [cliLines(s.run.cli)[0], cliLines(s.rollback.cli)[0]].filter(Boolean)
  for (const [what, t] of [['Read-back', s.verify], ['Check before', s.pre]] as const) {
    for (const [i, l] of cliLines(t.cli).entries()) {
      if (i === 0 && firsts.includes(l)) continue
      if (written.has(l)) return `${what}: the line "${l.slice(0, 60)}" is also a line of the action or its rollback. This step may only read.`
    }
  }
  return null
}

/** Reason a connection cannot carry out actions, or null. */
export const READ_ONLY = 'Read-only: this connection has no write tools'
/** Starting hint for a new action by kind. Generic only (D-58): device examples live in the template library, not here. */
export function kindHint(kind: ConnKind | null): { run: Partial<Tpl>; rollback: Partial<Tpl>; hint: string } {
  if (kind === 'ssh') return { run: {}, rollback: {}, hint: 'One command per line. Use typed placeholders such as {ip}, {interface} or {vlan}. Each line is sent on its own.' }
  if (kind === 'netconf-restconf') return { run: {}, rollback: {}, hint: 'RESTCONF: choose the method and the path under the device address. NETCONF: put the request in the body.' }
  if (kind === 'automation') return { run: {}, rollback: {}, hint: 'Start a job or workflow on the platform: choose the method, the path of the job and give its variables as the JSON body.' }
  if (isMcp(kind)) return { run: {}, rollback: {}, hint: 'Pick one write tool of this server, then give its arguments as JSON. Values may use {ip}, {domain} and the other typed placeholders.' }
  if (kind === 'http') return { run: {}, rollback: {}, hint: 'Choose the method and the path under the connection address, and give the JSON body. Values may use {ip}, {domain}, {name} and the other typed placeholders.' }
  return { run: {}, rollback: {}, hint: '' }
}

/** Escape a validated value for the place it lands in. Values are already type-checked; this is the second layer. */
export type Transport = 'cli' | 'json' | 'url' | 'header'
export const escapeFor = (t: Transport, v: string) => (t === 'json' ? JSON.stringify(v).slice(1, -1) : t === 'url' ? encodeURIComponent(v) : t === 'header' ? v.replace(/[\r\n]/g, ' ') : v)

/** null = every value present and valid for the placeholders the templates use. */
export function checkValues(params: ParamType[], values: Partial<Record<ParamType, string>>): string | null {
  for (const p of params) {
    const v = values[p]
    if (v === undefined || v === '') return `This action needs ${PARAM_LABEL[p]}, which this trigger does not provide.`
    if (!PARAM_CHECK[p](v)) return `The ${p} value is not valid (it must be ${PARAM_LABEL[p]}). Nothing was changed.`
  }
  return null
}

/** Fill placeholders. Throws on anything unchecked: callers run checkValues first. */
export function fill(text: string, values: Partial<Record<ParamType, string>>, transport: Transport = 'cli'): string {
  return text.replace(PLACEHOLDER, (_, k: string) => {
    if (isRuntime(k)) return `<${k}>`
    const v = values[k as ParamType]
    if (v === undefined || !PARAM_CHECK[k as ParamType]?.(v)) throw new Error(`unchecked placeholder ${k}`)
    return escapeFor(transport, v)
  })
}

// ---- Trigger fields in parameters: {{trigger.source_ip}} ----
const TRIGGER_REF = /\{\{\s*trigger\.([a-z_]+)\s*\}\}/g
export const refsIn = (spec: string) => [...spec.matchAll(TRIGGER_REF)].map((m) => m[1]!)
/** Replace each reference by the event value (empty when the event has none). Whatever comes out is checked by type afterwards. */
export const resolveParam = (spec: string, fields: Record<string, string>) => spec.replace(TRIGGER_REF, (_, k: string) => fields[k] ?? '')
/** A name of a rule or a custom action: the box's catTextRE. */
export const TEXT_RE = /^[A-Za-z0-9 _.,:'()/-]{1,80}$/
export const oneLine = (s: string, max = 80) => s.replace(/[\r\n\t]+/g, ' ').slice(0, max)

// ---- Conditions (IF) ----
export interface Cond { field: string; op: string; value: string; n: number | null; window_min: number | null }
export interface Ev { id: string; ts: string; fields: Record<string, string>; device_kind: string | null; trigger?: string }
/** The counted signature of a log_threshold rule (D-287): pasted from the Logs digest, compared and counted, never filled into an action. */
export const logSignature = (trigger: string | undefined, c: { op: string; field: string }) => trigger === 'log_threshold' && c.op === 'count_window' && c.field === 'signature'
const lc = (s: string) => s.trim().toLowerCase()
const OPS = ['eq', 'in', 'in_cidr', 'gte', 'lte', 'device_type', 'count_window', 'first_time']
const TEXT_VAL = /^[\w .,:/@#-]{0,200}$/
/** A plain decimal number, the same pattern as the box (D-390): no hex, exponent, Infinity or NaN. */
const DECIMAL = /^[-+]?(\d+\.?\d*|\.\d+)$/
/** The spaces Go's strings.TrimSpace removes (unicode.IsSpace), so a pasted signature is trimmed like the box does: not U+FEFF, which JS trim() would. */
const GO_SPACE = /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g
export const goTrim = (s: string) => s.replace(GO_SPACE, '')
export interface CondField { key: string; label: string; type: string; choices: string[]; min: number | null; max: number | null }
/** Why the value of a condition does not fit its field, or null (D-390): "at least"/"at most" only on a field with a range (number,
 * port) and inside it; "equals"/"is one of" take numbers inside the range of such a field, or one of the choices of a field that has
 * them (without case, like evalCondition). The box's condValueProblem says the same words. */
export function condValueProblem(f: CondField, op: string, value: string): string | null {
  const ranged = f.min !== null && f.max !== null
  const inRange = (v: string) => DECIMAL.test(v.trim()) && Number(v) >= f.min! && Number(v) <= f.max!
  const bounds = () => `${f.min} to ${f.max}`
  const items = op === 'in' ? value.split(',').map(lc).filter(Boolean) : [value]
  if (op === 'gte' || op === 'lte') {
    if (!ranged) return 'At least / at most: only for a number field.'
    if (!inRange(value)) return `${f.label}: give a number from ${bounds()}.`
  } else if (op === 'eq' || op === 'in') {
    if (ranged && (!items.length || !items.every(inRange))) return op === 'in' ? `${f.label}: give numbers from ${bounds()}, separated by commas.` : `${f.label}: give a number from ${bounds()}.`
    if (!ranged && f.choices.length && (!items.length || !items.every((v) => f.choices.includes(lc(v))))) return `${f.label}: use one of ${f.choices.join(', ')}.`
  }
  return null
}
/** Why one condition of a rule is refused, or null: the checks of the box's checkRule, in its order. `c.value` is as sent (a signature
 * is trimmed here first). */
export function condProblem(trigger: { id: string; fields: CondField[] }, c: Cond, kinds: string[]): string | null {
  if (!OPS.includes(c.op)) return c.op ? 'Unknown condition test.' : 'Each condition needs a field, a test and a value.'
  const f = trigger.fields.find((x) => x.key === c.field)
  if (c.op === 'device_type') { if (!c.value.split(',').every((k) => kinds.includes(k.trim()))) return 'Device type: use device types such as camera, nvr, iot.' } else if (!f) return `The field "${oneLine(c.field, 30)}" does not exist for this trigger.`
  const value = logSignature(trigger.id, c) ? goTrim(c.value) : c.value
  if (logSignature(trigger.id, c)) { if (!value || /[\u0000-\u001f\u007f\u0085\u2028\u2029]/.test(value) || [...value].length > 200) return 'Log signature: one line of up to 200 characters, as the Logs digest shows it.' } else if (!TEXT_VAL.test(value)) return 'Condition values: letters, numbers and . , : / @ # - only.'
  if (c.op === 'in_cidr' && !isCidr(value)) return 'In range: give a CIDR range such as 192.168.10.0/24.'
  if ((c.op === 'gte' || c.op === 'lte') && !DECIMAL.test(value)) return 'At least / at most: give a number.'
  if (c.op === 'count_window' && (c.n === null || c.n < 1 || c.n > 1000 || c.window_min === null || c.window_min < 1 || c.window_min > 1440)) return 'Count in window: give how many (1 to 1000) and the minutes (1 to 1440).'
  if (c.op === 'first_time' && (c.n === null || c.n < 1 || c.n > 720)) return 'First time: give the hours (1 to 720).'
  return f && c.op !== 'device_type' ? condValueProblem(f, c.op, value) : null
}
/** Pure test of one condition. `others` = the other events of the same trigger (for the counting tests). */
export function evalCondition(c: Cond, ev: Ev, others: Ev[]): boolean {
  const f = ev.fields[c.field] ?? ''
  const list = () => c.value.split(',').map(lc).filter(Boolean)
  switch (c.op) {
    case 'eq': return lc(f) === lc(c.value)
    case 'in': return list().includes(lc(f))
    case 'in_cidr': return isCidr(c.value) && isIpv4(f) && allowMatches(c.value, f)
    case 'gte': return f !== '' && Number(f) >= Number(c.value)
    case 'lte': return f !== '' && Number(f) <= Number(c.value)
    case 'device_type': return !!ev.device_kind && list().includes(lc(ev.device_kind))
    case 'count_window': {
      // a log count event is the count itself, made for exactly this signature, window and threshold (the box's PollLogs)
      if (logSignature(ev.trigger, c)) return f !== '' && f === c.value && ev.fields.window === String(c.window_min ?? 0) && ev.fields.threshold === String(c.n ?? 0)
      const end = Date.parse(ev.ts), start = end - (c.window_min ?? 0) * 60e3
      const same = others.filter((o) => o.id !== ev.id && lc(o.fields[c.field] ?? '') === lc(f) && Date.parse(o.ts) >= start && Date.parse(o.ts) <= end).length + 1
      return f !== '' && same >= (c.n ?? 1)
    }
    case 'first_time': {
      const end = Date.parse(ev.ts), start = end - (c.n ?? 1) * 3600e3
      return f !== '' && !others.some((o) => o.id !== ev.id && lc(o.fields[c.field] ?? '') === lc(f) && Date.parse(o.ts) >= start && Date.parse(o.ts) < end)
    }
    default: return false
  }
}
export function condText(c: Cond): string {
  const f = c.field || 'device'
  switch (c.op) {
    case 'eq': return `${f} is ${c.value}`
    case 'in': return `${f} is one of ${c.value}`
    case 'in_cidr': return `${f} is inside ${c.value}`
    case 'gte': return `${f} is at least ${c.value}`
    case 'lte': return `${f} is at most ${c.value}`
    case 'device_type': return `device type is one of ${c.value}`
    case 'count_window': return `${f} seen at least ${c.n} times within ${c.window_min} minutes`
    case 'first_time': return `first time ${f} is seen in ${c.n} hours`
    default: return c.op
  }
}

// ---- Allowlist: never block ----
const ipInt = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
export function allowMatches(entry: string, value: string): boolean {
  const v = value.toLowerCase(), e = entry.toLowerCase()
  if (isCidr(e)) { if (!isIpv4(v)) return false; const [base, bits] = e.split('/') as [string, string]; const size = 2 ** (32 - Number(bits)); const start = Math.floor(ipInt(base) / size) * size; return ipInt(v) >= start && ipInt(v) < start + size }
  if (isIpv4(e)) return v === e
  return v === e || v.endsWith(`.${e}`)
}

/** A value is touched by a never-touch entry when it matches the entry, or (for a range) contains an entry that is an address. */
export const touches = (entry: string, value: string) => allowMatches(entry, value) || (isCidr(value) && isIpv4(entry.toLowerCase()) && allowMatches(value, entry))

// ---- Tokens ----
function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n)
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(a)
  else for (let i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256) // ponytail: test environments without WebCrypto only
  return a
}
export const randomToken = (bytes = 16): string => [...randomBytes(bytes)].map((x) => x.toString(16).padStart(2, '0')).join('')
const b64url = (a: Uint8Array) => btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
/** An approval link token in the signed form of approval-tokens.md 4.1: "v1." + 16 random bytes + "." + a 16 byte tag, both base64url. The mock cannot hold the HMAC key, so the tag is random and the mock store is the source of truth. */
export const approvalToken = (): string => `v1.${b64url(randomBytes(16))}.${b64url(randomBytes(16))}`
export const TOKEN_RE = /^v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22}$/
