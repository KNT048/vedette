// Pure helpers for the response module: tamper-evident log hash, action templates, allowlist matching, tokens.
// No imports from mocks: the UI uses these too (log verification, form checks). The server (M2) re-implements them in Go.

// ---- SHA-256 (sync, for the mock that appends log lines; the UI verifies with crypto.subtle when it exists) ----
const K = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])
const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))

export function sha256Sync(text: string): string {
  const msg = new TextEncoder().encode(text)
  const total = Math.ceil((msg.length + 9) / 64) * 64
  const buf = new Uint8Array(total)
  buf.set(msg)
  buf[msg.length] = 0x80
  const view = new DataView(buf.buffer)
  view.setUint32(total - 8, Math.floor((msg.length * 8) / 2 ** 32))
  view.setUint32(total - 4, (msg.length * 8) >>> 0)
  const h = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4)
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!, b = w[i - 2]!
      w[i] = (w[i - 16]! + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7]! + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>> 0
    }
    const v = [...h]
    let a = v[0]!, b = v[1]!, c = v[2]!, d = v[3]!, e = v[4]!, f = v[5]!, g = v[6]!, hh = v[7]!
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) >>> 0
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    const add = [a, b, c, d, e, f, g, hh]
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + add[i]!) >>> 0
  }
  return [...h].map((x) => x.toString(16).padStart(8, '0')).join('')
}

/** Browser: crypto.subtle. Where it is missing (some test environments): the same digest from the JS version. */
export async function sha256Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return sha256Sync(text)
  const d = await subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

// ---- Tamper-evident log (D-48) ----
export const GENESIS = '0'.repeat(64)
export interface LogCore { id: string; ts: string; kind: string; actor: string; detail: string; prev_hash: string }
/** hash = SHA-256( prev_hash + "\n" + JSON([id, ts, kind, actor, detail]) ) as lowercase hex. */
export const logPreimage = (e: LogCore) => `${e.prev_hash}\n${JSON.stringify([e.id, e.ts, e.kind, e.actor, e.detail])}`
export const logHashSync = (e: LogCore) => sha256Sync(logPreimage(e))

/** Walk the chain oldest to newest. `broken_at` = index of the first entry whose link or hash does not match. */
export async function verifyChain(entries: (LogCore & { hash: string })[]): Promise<{ ok: boolean; broken_at: number | null }> {
  let prev = GENESIS
  for (const [i, e] of entries.entries()) {
    if (e.prev_hash !== prev || e.hash !== (await sha256Hex(logPreimage(e)))) return { ok: false, broken_at: i }
    prev = e.hash
  }
  return { ok: true, broken_at: null }
}

// ---- Typed placeholders (D-47, D-51, SYS-1: no free shell text). Trigger data is attacker-controlled: every value is checked by type. ----
export type ParamType = 'ip' | 'cidr' | 'domain' | 'port' | 'mac' | 'vlan' | 'interface' | 'text'
export const PARAM_TYPES: ParamType[] = ['ip', 'cidr', 'domain', 'port', 'mac', 'vlan', 'interface', 'text']
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
  interface: (v) => /^[A-Za-z][A-Za-z0-9/._-]{0,31}$/.test(v),
  text: (v) => TEXT.test(v),
}
export const PARAM_LABEL: Record<ParamType, string> = { ip: 'an IP address', cidr: 'an address range', domain: 'a domain', port: 'a port number', mac: 'a MAC address', vlan: 'a VLAN number', interface: 'a port or interface name', text: 'a short plain-text value' }

export interface Tpl { cli: string; method: '' | 'GET' | 'PUT' | 'POST' | 'DELETE'; path: string; body: string; headers: string }
export const EMPTY_TPL: Tpl = { cli: '', method: '', path: '', body: '', headers: '' }
export const tplEmpty = (t: Tpl) => !t.cli.trim() && !t.method && !t.path && !t.body.trim()

/** Characters a template may contain. Shell metacharacters (; | & $ ` < > ( ) \ ! ~ ^) are never allowed, even in the fixed text. */
const SAFE_TEXT = /^[A-Za-z0-9 _.,:/"'{}=\n\t@#%+*?[\]-]*$/
const PLACEHOLDER = /\{([a-z_]+)\}/g
const HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]{0,40}: [A-Za-z0-9 _.,:/@#=+{}*-]{0,200}$/

export function templateParams(...texts: string[]): ParamType[] {
  const found = new Set<ParamType>()
  for (const t of texts) for (const m of t.matchAll(PLACEHOLDER)) if ((PARAM_TYPES as string[]).includes(m[1]!)) found.add(m[1] as ParamType)
  return PARAM_TYPES.filter((p) => found.has(p))
}
export const tplParams = (...t: Tpl[]) => templateParams(...t.flatMap((x) => [x.cli, x.path, x.body, x.headers]))

/** null = acceptable. Otherwise a one-line reason in plain words. */
export function validateTpl(t: Tpl, what: string): string | null {
  if (!t.cli.trim() && !(t.method && t.path)) return `${what}: give a command or an API call.`
  if (t.cli.length > 2000 || t.body.length > 2000 || t.path.length > 300 || t.headers.length > 600) return `${what}: too long.`
  for (const [field, v] of [['command', t.cli], ['API path', t.path], ['API body', t.body], ['headers', t.headers]] as const) {
    if (!SAFE_TEXT.test(v)) return `${what}: the ${field} contains a character that is not allowed (shell characters such as ; | & $ \` < > ( ) \\ are refused).`
    for (const m of v.matchAll(PLACEHOLDER)) if (!(PARAM_TYPES as string[]).includes(m[1]!)) return `${what}: unknown placeholder {${m[1]}}. Use {ip}, {cidr}, {domain}, {port}, {mac}, {vlan}, {interface} or {text}.`
  }
  if (t.headers && !t.headers.split('\n').every((l) => HEADER_LINE.test(l))) return `${what}: each header must look like "Name: value".`
  if (t.method && !t.path) return `${what}: an API call needs a path.`
  if (t.path && !t.method) return `${what}: choose the API method.`
  if (t.path && (!/^\/[A-Za-z0-9/_.{}-]*$/.test(t.path) || t.path.includes('..'))) return `${what}: the API path must start with / and cannot contain .. or a query.`
  if (t.body) { try { JSON.parse(t.body.replace(PLACEHOLDER, 'x')) } catch { return `${what}: the API body must be valid JSON.` } }
  return null
}

// ---- Connection kinds: the form and the server both follow the kind of the chosen connection ----
export type ConnKind = 'device-api' | 'ssh' | 'http' | 'mcp-http' | 'mcp-stdio'
export type TplField = 'cli' | 'method' | 'path' | 'body' | 'headers'
export const isMcp = (k: ConnKind | null | undefined) => k === 'mcp-http' || k === 'mcp-stdio'
/** Which template fields a kind uses. MCP: the tool is chosen separately and the arguments are the body (JSON). */
export const KIND_FIELDS: Record<ConnKind, TplField[]> = {
  'device-api': ['method', 'path', 'body'], http: ['method', 'path', 'headers', 'body'], ssh: ['cli'], 'mcp-http': ['body'], 'mcp-stdio': ['body'],
}
/** null = the template only uses fields of this kind. */
export function kindProblem(kind: ConnKind, t: Tpl, what: string): string | null {
  const extra = (['cli', 'method', 'path', 'body', 'headers'] as TplField[]).filter((f) => !KIND_FIELDS[kind].includes(f) && String(t[f]).trim() !== '')
  if (extra.length) return `${what}: ${extra.join(', ')} does not apply to this kind of connection and must be empty.`
  return null
}
/** Reason a connection cannot carry out actions, or null. */
export const READ_ONLY = 'Read-only: this connection has no write tools'
/** Vendor-specific starting point. Only a known vendor gets a prefill; any other connection starts empty. */
export function vendorExample(kind: ConnKind | null, vendor: string | null): { run: Partial<Tpl>; rollback: Partial<Tpl>; hint: string } {
  if ((kind === 'device-api') && vendor === 'fortinet') return { run: { method: 'PUT', path: '/api/v2/cmdb/firewall/vip/{text}', body: '{"status":"disable"}' }, rollback: { method: 'PUT', path: '/api/v2/cmdb/firewall/vip/{text}', body: '{"status":"enable"}' }, hint: 'FortiOS REST example: turn a virtual IP off and on again.' }
  if (kind === 'device-api' && vendor === 'mikrotik') return { run: { method: 'PUT', path: '/rest/ip/firewall/address-list', body: '{"list":"vedette-block","address":"{ip}","timeout":"1d"}' }, rollback: {}, hint: 'RouterOS REST example: add an address to an address list.' }
  if (kind === 'device-api' && vendor === 'pfsense') return { run: { method: 'POST', path: '/api/v1/firewall/alias/entry', body: '{"name":"Vedette_Blocklist","address":["{ip}"]}' }, rollback: { method: 'DELETE', path: '/api/v1/firewall/alias/entry', body: '{"name":"Vedette_Blocklist","address":["{ip}"]}' }, hint: 'pfSense API example: add an address to an alias.' }
  if (kind === 'ssh') return { run: {}, rollback: {}, hint: 'Cisco: "ip access-list extended VEDETTE" then "deny ip host {ip} any". Aruba/HPE: "ip access-list extended VEDETTE" then "deny any {ip} 0.0.0.0". MikroTik: "/ip firewall address-list add list=vedette address={ip}".' }
  if (isMcp(kind)) return { run: {}, rollback: {}, hint: 'Pick one write tool of this server, then give its arguments as JSON. Values may use {ip}, {domain} and the other typed placeholders.' }
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
export const oneLine = (s: string, max = 80) => s.replace(/[\r\n\t]+/g, ' ').slice(0, max)

// ---- Conditions (IF) ----
export interface Cond { field: string; op: string; value: string; n: number | null; window_min: number | null }
export interface Ev { id: string; ts: string; fields: Record<string, string>; device_kind: string | null }
const lc = (s: string) => s.trim().toLowerCase()
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
export function randomToken(bytes = 16): string {
  const a = new Uint8Array(bytes)
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(a)
  else for (let i = 0; i < bytes; i++) a[i] = Math.floor(Math.random() * 256) // ponytail: test environments without WebCrypto only
  return [...a].map((x) => x.toString(16).padStart(2, '0')).join('')
}
export const TOKEN_RE = /^[a-f0-9]{32}$/
