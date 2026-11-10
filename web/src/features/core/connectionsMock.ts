// Mock API of Settings → Connections (D-93, D-94; S-AI-7, S-RESP-4). Admin only. A secret is never stored: only its last 4 characters (SYS-4).
// Moved from the AI harness mock: the same checks, plus `username`, the read-only `pin` (trust on first use) and the errors
// `kind_unsupported`, `in_use` and `pin_mismatch`. The backend answers 501 for these routes until slice 13b-4.
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { newId, nowIso } from '@/mocks/db'
import { assetsStore } from '@/mocks/stores'
import { networkStore } from '@/mocks/network'
import { connectorsStore, type Connector, type ConnectorKind, type ConnectorTool } from '@/mocks/connectors'
import { actionsStore } from '@/features/response/state'
import { CONNECTION_KINDS, hostPort, usesUsername } from '@/lib/connections'
import { CONNECTOR_AUTH } from './contract'
import type { ConnectorInput, ConnectorPin } from './types'

const ok204 = () => new HttpResponse(null, { status: 204 })
const notFound = () => fail(404, 'not_found', 'This connection no longer exists.')
const TIDY = (s: string) => s.replace(/\s+/g, ' ').trim()
const KINDS: readonly string[] = CONNECTION_KINDS
const AUTHS = ['none', 'token', 'basic', 'ssh-key']
export const USER_RE = /^[^\s:\p{Cc}\p{Cf}]{1,64}$/u

const T = (name: string, access: ConnectorTool['access'], description: string): ConnectorTool => ({ name, access, description, enabled: true })
// Tools a new connection offers by kind. Generic only (D-58): what a particular device can do is described by the action templates.
// Every write tool starts OFF (D-41, D-51): an administrator turns it on, and it then runs only through a response action that people approve.
const W = (name: string, description: string): ConnectorTool => ({ ...T(name, 'write', description), enabled: false })
// A read tool of an HTTP kind starts OFF too (D-127): some devices change state on a GET (reboot, configuration), so an administrator turns it on
// for endpoints that only read. An SSH read tool is an exact command of the allow-list and stays on.
const R = (name: string, access: ConnectorTool['access'], description: string): ConnectorTool => ({ ...T(name, access, description), enabled: false })
function discover(kind: ConnectorKind): ConnectorTool[] {
  switch (kind) {
    case 'ssh': return [T('run_allowed_command', 'read', 'Run one command from the allow list and return its output'), W('run_approved_command', 'Run one command that an approved action defines')]
    case 'http': return [R('fetch_url', 'read', 'Fetch a page from an allowed address and return its text'), W('send_request', 'Send one API request that an approved action defines')]
    case 'netconf-restconf': return [R('get_config', 'read', 'Read configuration or status data'), W('apply_config', 'Apply one configuration change that an approved action defines')]
    case 'automation': return [R('list_jobs', 'read', 'List the jobs or workflows the platform offers'), W('launch_job', 'Start one job or workflow that an approved action defines')]
    // D-94 (3): a tool found on an MCP server is a write tool and starts off; an administrator may mark it read (the input's `access`) and turn it on.
    default: return [W('list_resources', 'List what the MCP server offers'), W('search_docs', 'Search the documentation the server holds'), W('run_action', 'Run an action the server defines')]
  }
}

const hostOf = (c: Pick<Connector, 'kind' | 'target'>) => { try { return c.kind === 'ssh' ? c.target.split(':')[0]! : new URL(c.target).hostname } catch { return '' } }
/** What the first Test records (D-94): the SSH host key; for HTTPS the public key of a certificate that no public authority vouches for (an address on the LAN, a .local name), or `tls_roots`: a public authority did vouch for it, and every later Test requires that again. */
function pinFor(c: Connector): Omit<ConnectorPin, 'first_seen'> | null {
  const host = hostOf(c)
  if (c.kind === 'ssh') return { kind: 'ssh_hostkey', value: `ssh-ed25519 SHA256:${fakeHash(host, 43)}` }
  if (c.kind === 'mcp-stdio' || !c.target.startsWith('https:')) return null
  return /^[\d.]+$/.test(host) || /\.(local|lan|internal|home\.arpa)$/i.test(host) || !host.includes('.') ? { kind: 'tls_sha256', value: fakeHash(host, 64, true) } : { kind: 'tls_roots', value: 'system roots' }
}
function fakeHash(seed: string, len: number, hex = false) {
  const chars = hex ? '0123456789abcdef' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let h = 2166136261, out = ''
  for (let i = 0; out.length < len; i++) { h = Math.imul(h ^ (seed.charCodeAt(i % Math.max(seed.length, 1)) || 7) ^ i, 16777619) >>> 0; out += chars[h % chars.length] }
  return out
}

/** The fields that decide what a request may do (D-93 (4)): a change in any of them while a Test runs makes its result void. */
const securityKey = (c: Connector) => JSON.stringify([c.id, c.kind, c.target, c.auth.type, c.auth.last4, c.auth.key_fingerprint, c.username, c.allow, c.tools.map((t) => [t.name, t.access, t.enabled]), c.pin?.value ?? null])

const bad = (code: string, message: string, field: string) => fail(400, code, message, { field })

// ---- Address policy (D-94): the box never connects to itself, to loopback, link-local (cloud metadata), multicast or unspecified addresses.
/** The 8 groups of an IPv6 address (`::` expanded, a dotted IPv4 tail read as two groups), or null when it is not one. */
function v6groups(h: string): number[] | null {
  let s = h.split('%')[0]!
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s)
  if (dotted) {
    const p = dotted.slice(1).map(Number)
    if (p.some((x) => x > 255)) return null
    s = `${s.slice(0, dotted.index)}${((p[0]! << 8) | p[1]!).toString(16)}:${((p[2]! << 8) | p[3]!).toString(16)}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const side = (t: string) => (t === '' ? [] : t.split(':'))
  const head = side(halves[0]!), tail = halves.length === 2 ? side(halves[1]!) : []
  if (halves.length === 1 && head.length !== 8) return null
  const fill = 8 - head.length - tail.length
  if (fill < (halves.length === 2 ? 1 : 0)) return null
  const all = [...head, ...Array<string>(fill).fill('0'), ...tail]
  return all.every((g) => /^[0-9a-f]{1,4}$/.test(g)) ? all.map((g) => parseInt(g, 16)) : null
}
const EMBEDDED_V4 = 'Vedette does not connect to IPv6 addresses that carry an IPv4 address; use the IPv4 address.'
/** IPv6 forms that carry an IPv4 address: mapped, NAT64 64:ff9b::/96, 6to4 2002::/16, compatible ::/96, translated ::ffff:0:0:0/96, Teredo 2001::/32. */
function carriesV4(g: number[]): boolean {
  const zero = (a: number, b: number) => g.slice(a, b).every((x) => x === 0)
  return (zero(0, 5) && g[5] === 0xffff) || (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) || g[0] === 0x2002 || zero(0, 6) || (zero(0, 4) && g[4] === 0xffff && g[5] === 0) || (g[0] === 0x2001 && g[1] === 0)
}

const NUMERIC_HOST = /^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$/i
const canonicalV4 = (h: string): number[] | null => {
  const p = h.split('.')
  return p.length === 4 && p.every((x) => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255) ? p.map(Number) : null
}
/** Why the host is refused (in plain words), or null when it may be used. */
export function refusedHost(raw: string): string | null {
  const h = raw.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '')
  if (h === 'localhost' || h.endsWith('.localhost')) return 'a loopback address'
  if (h.includes(':')) {
    if (h === '::1') return 'a loopback address'
    if (h === '::') return 'an unspecified address'
    if (/^fe[89ab]/.test(h)) return 'a link-local address'
    if (/^ff/.test(h)) return 'a multicast address'
    const g = v6groups(h)
    if (!g) return 'an address that is not valid'
    if (g.slice(0, 7).every((x) => x === 0) && g[7]! <= 1) return g[7] === 1 ? 'a loopback address' : 'an unspecified address'
    if (carriesV4(g)) return EMBEDDED_V4
    return null
  }
  if (NUMERIC_HOST.test(h)) {
    const v = canonicalV4(h)
    if (!v) return 'a numeric host name written in a non-standard way (use the usual dotted form, like 192.168.10.1)'
    if (v[0] === 127) return 'a loopback address'
    if (v[0] === 0) return 'an unspecified address'
    if (v[0] === 169 && v[1] === 254) return 'a link-local address (the cloud metadata service lives there)'
    if (v[0]! >= 224 && v[0]! <= 239) return 'a multicast address'
    if (h === networkStore.get().mgmt.address) return 'the box itself'
  }
  return null
}
const typedHost = (target: string, ssh: boolean) => (ssh ? target.replace(/:\d{1,5}$/, '') : /^[a-z][a-z0-9+.-]*:\/\/(?:[^/@?#]*@)?(\[[^\]]*\]|[^/:?#]*)/i.exec(target)?.[1] ?? '')
const under = (entry: string, target: string) => {
  if (entry.includes('\\') || /%(2f|5c|2e)/i.test(entry)) return false // a backslash or an encoded slash, backslash or dot may be read as a separator or a dot segment further on
  try {
    const e = new URL(entry), b = new URL(target), bp = b.pathname.replace(/\/+$/, '')
    return e.origin === b.origin && (e.pathname === bp || e.pathname === `${bp}/` || e.pathname.startsWith(`${bp}/`))
  } catch { return false }
}

/** A private key protected by a passphrase cannot be used: Vedette has nobody to type the passphrase. */
function encryptedKey(k: string): boolean {
  if (/Proc-Type:\s*4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY/.test(k)) return true
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(k)
  if (!m) return false
  try { return atob(m[1]!.replace(/\s+/g, '')).slice(19, 23) !== 'none' } catch { return false }
}
/** Mock stand-in for the public-key fingerprint the backend computes in 13b-4: SHA-256 of the key body, base64 without padding. */
export async function keyFingerprint(secret: string): Promise<string> {
  const body = secret.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '')
  let bytes: Uint8Array
  try { bytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0)) } catch { bytes = new TextEncoder().encode(secret) }
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))
  return `SHA256:${btoa(String.fromCharCode(...d)).replace(/=+$/, '')}`
}
export const hasSecret = (c: Pick<Connector, 'auth'>) => c.auth.last4 !== null || c.auth.key_fingerprint !== null

type Checked = { input: ConnectorInput; allow: string[]; last4: string | null; username: string | null; secret: string | null; retarget: boolean; moved: boolean }
function check(b: Partial<ConnectorInput>, existing?: Connector): Response | Checked {
  const name = TIDY(String(b.name ?? ''))
  if ([...name].length < 1 || [...name].length > 40) return bad('invalid_name', 'Give the connection a name of 1 to 40 characters, for example "Office firewall API".', 'name')
  if (connectorsStore.get().some((c) => c.id !== existing?.id && c.name.toLowerCase() === name.toLowerCase())) return bad('duplicate_name', 'Another connection already has this name. Pick a different one.', 'name')
  if (!b.kind || !KINDS.includes(b.kind)) return bad('invalid_kind', 'Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server.', 'kind')
  if (b.kind === 'mcp-stdio') return bad('kind_unsupported', 'An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)").', 'kind')
  const ssh = b.kind === 'ssh'
  const target = String(b.target ?? '').trim()
  if ([...target].length > 2048) return bad('invalid_target', 'The address is too long: at most 2048 characters.', 'target')
  if (ssh) {
    const hostOnly = target.replace(/:\d{1,5}$/, '').replace(/\.+$/, '')
    const port = /:(\d{1,5})$/.exec(target)
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}(:\d{1,5})?$/.test(target) || !/^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(hostOnly) || (port && (Number(port[1]) < 1 || Number(port[1]) > 65535))) return bad('invalid_target', 'Enter the SSH server as host or host:port, for example 192.168.10.30:22.', 'target')
  }
  else {
    let u: URL
    try { u = new URL(target) } catch { return bad('invalid_target', 'The address is not valid. Enter it in full, for example https://192.168.10.1.', 'target') }
    if (u.protocol !== 'https:') return bad('invalid_target', 'The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.', 'target')
    if (u.username || u.password) return bad('invalid_target', 'The address must not contain a user name or password. Enter the secret in its own field.', 'target')
    if (/[?#]/.test(target)) return bad('invalid_target', 'The address must not include ? or #.', 'target')
  }
  // The policy is applied to the host as typed and to the host after the URL parser normalised it (2130706433 becomes 127.0.0.1).
  const why = refusedHost(typedHost(target, ssh)) ?? (ssh ? null : refusedHost(new URL(target).hostname))
  if (why) return bad('invalid_target', why === EMBEDDED_V4 ? why : `Vedette never connects to ${why}. Enter the address of the device or service itself.`, 'target')
  const auth = b.auth_type ?? 'none'
  if (!AUTHS.includes(auth)) return bad('invalid_auth', 'Pick how the box signs in: none, token, user and password, or SSH key.', 'auth_type')
  if (!CONNECTOR_AUTH[b.kind].includes(auth)) return bad('invalid_auth', `${ssh ? 'An SSH server' : 'This kind of connection'} cannot sign in that way. Pick one of the options the form offers.`, 'auth_type')
  const needsUser = usesUsername(b.kind, auth)
  const username = needsUser ? TIDY(String(b.username ?? '')) : ''
  if (needsUser && !username) return bad('username_required', 'Enter the user name the box signs in with.', 'username')
  if (username && !USER_RE.test(username)) return bad('invalid', 'The user name is 1 to 64 characters, with no spaces, colons or control characters.', 'username')
  const secret = b.secret === undefined || b.secret === '' ? null : String(b.secret)
  if (secret !== null && [...secret].length < 8) return bad('invalid_secret', 'The secret is too short. Copy the whole token, password or key again.', 'secret')
  if (secret !== null && auth === 'ssh-key' && encryptedKey(secret)) return bad('invalid_secret', 'This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that.', 'secret')
  const sameKind = !!existing && existing.kind === b.kind
  const moved = sameKind && hostPort(existing.kind, existing.target) !== hostPort(b.kind, target)
  const keep = sameKind && !moved && !!existing && hasSecret(existing) && existing.auth.type === auth
  if (auth !== 'none' && secret === null && !keep) {
    return moved && existing && hasSecret(existing) && existing.auth.type === auth
      ? bad('secret_required', 'Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for.', 'secret')
      : bad('secret_required', 'Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards.', 'secret')
  }
  const allow = [...new Set((b.allow ?? []).map((a) => a.trim()).filter(Boolean))]
  if (allow.length === 0) return bad('allow_required', 'Add at least one entry to the allow-list. Only hosts, addresses or commands on this list may be used.', 'allow')
  if (allow.length > 30 || allow.some((a) => [...a].length > 200 || /[\n\r]/.test(a))) return bad('invalid_allow', 'The allow-list holds up to 30 entries of 200 characters each, one per line.', 'allow')
  if (!ssh && allow.some((a) => /\s/.test(a))) return bad('invalid_allow', 'A host or address in the allow-list cannot contain spaces.', 'allow')
  if (!ssh && !allow.every((a) => under(a, target))) { const t = target.replace(/\/+$/, ''); return bad('invalid_allow', `Each allow-list entry must be an address under ${t}, for example ${t}/api/.`, 'allow') }
  if (b.asset_id && !assetsStore.get().some((a) => a.id === b.asset_id)) return bad('unknown_asset', 'The device you linked is not in the inventory.', 'asset_id')
  if (b.clear_pin !== undefined && typeof b.clear_pin !== 'boolean') return bad('invalid', 'Send clear_pin as true or false.', 'clear_pin')
  if (b.kind !== 'mcp-http' && (b.tools ?? []).some((x) => x.access !== undefined)) return bad('invalid_tool_access', 'Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed.', 'tools')
  return { input: { ...b, name, target, auth_type: auth, allow, enabled: b.enabled !== false } as ConnectorInput, allow, username: username || null, secret, last4: auth === 'none' || auth === 'ssh-key' ? null : secret ? secret.slice(-4) : existing!.auth.last4, retarget: !!existing && (existing.kind !== b.kind || existing.target !== target), moved: !sameKind || moved }
}
/** The auth block of a saved connection: an SSH key is told apart by its fingerprint, anything else by its last 4 characters. */
async function authOf(r: Checked, existing?: Connector): Promise<Connector['auth']> {
  const keyFp = r.input.auth_type !== 'ssh-key' ? null : r.secret ? await keyFingerprint(r.secret) : existing?.auth.key_fingerprint ?? null
  return { type: r.input.auth_type, last4: r.last4, key_fingerprint: keyFp }
}
const toolsOf = (base: ConnectorTool[], input: ConnectorInput['tools'], mcp: boolean): ConnectorTool[] =>
  base.map((t) => { const x = input?.find((y) => y.name === t.name); return { ...t, enabled: x?.enabled ?? t.enabled, access: mcp && x?.access ? x.access : t.access } })

/** A response change made through the connection is still in force (an executed item that was not rolled back). The real box asks the response module through a port (D-93). */
const inForce = (id: string) => actionsStore.get().some((a) => a.items.some((i) => i.connector_id === id && i.status === 'executed'))

export const connectionsHandlers = [
  http.get(`${API}/core/connections`, () => guard('admin') ?? HttpResponse.json({ items: connectorsStore.get() })),
  http.post(`${API}/core/connections`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = check(await body<ConnectorInput>(request)); if (r instanceof Response) return r
    if (connectorsStore.get().length >= 20) return fail(400, 'too_many', 'A box holds up to 20 connections. Delete one you no longer use.')
    const tools = toolsOf(discover(r.input.kind), r.input.tools, r.input.kind === 'mcp-http')
    const c: Connector = { id: newId('cn'), name: r.input.name, kind: r.input.kind, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: await authOf(r), username: r.username, pin: null, allow: r.allow, tools, enabled: r.input.enabled, status: 'untested', last_test: null }
    connectorsStore.update((l) => [...l, c]); audit('core.connection.add', c.name, `${c.kind}, ${c.tools.filter((t) => t.access === 'write').length} write tools${r.secret ? ', secret set' : ''}`)
    return HttpResponse.json(c, { status: 201 })
  }),
  http.post(`${API}/core/connections/:id/test`, async ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound()
    if (cur.kind === 'mcp-stdio') return fail(400, 'kind_unsupported', 'This kind of connection is not supported, so it cannot be tested. Delete it and add an MCP server with a web address.')
    // Privacy flow 12: nothing is sent to a connection that is off, and a Test is a request.
    if (!cur.enabled) return fail(409, 'connection_off', 'This connection is turned off, so nothing is sent to it. Turn it on, then test it.')
    const stamp = (patch: Partial<Connector>) => connectorsStore.update((l) => l.map((c) => (c.id === cur.id ? { ...c, ...patch } : c)))
    const snapshot = securityKey(cur)
    // A device is slow to answer: the connection can be edited meanwhile, and a result for the old configuration is not saved.
    await new Promise((r) => setTimeout(r, /slow/i.test(cur.target) ? 80 : 0))
    // The address policy runs at dial time on what the name resolves to now (D-94): a name that now points at loopback, the metadata service or the box is not dialled.
    if (/rebound/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      return fail(502, 'address_refused', `${cur.target} now points to a loopback address, so Vedette did not connect. Check the name in your DNS.`)
    }
    if (/unreachable/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      return fail(502, 'unreachable', `Could not connect to ${cur.target}. Check the address, the box's network and the firewall.`)
    }
    // A pinned certificate or host key that no longer matches is refused before any credential is sent (D-94).
    if (cur.pin && /changed/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      const what = cur.pin.kind === 'ssh_hostkey' ? 'The SSH host key' : 'The certificate'
      const rest = cur.pin.kind === 'tls_roots' ? 'is not one that a public certificate authority vouches for, as it was at the first test' : 'is not the one pinned at the first test'
      return fail(502, 'pin_mismatch', `${what} of ${cur.target} ${rest}. Nothing was sent. If you changed the device, edit this connection, turn on "Forget pinned key", save, then test again.`)
    }
    // The device answered and said no.
    if (/denied/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      return fail(502, 'device_error', `${cur.target} was reached, but the device refused the sign-in (HTTP 401).`)
    }
    const now = connectorsStore.get().find((c) => c.id === cur.id)
    if (!now) return notFound()
    if (!now.enabled) return fail(409, 'connection_off', 'This connection is turned off, so nothing is sent to it. Turn it on, then test it.')
    if (securityKey(now) !== snapshot) return fail(409, 'connection_changed', 'This connection was edited while the test ran, so the result was not saved. Test it again.')
    const found = discover(cur.kind)
    const pin = cur.pin ?? (() => { const p = pinFor(cur); return p ? { ...p, first_seen: nowIso() } : null })()
    const c: Connector = { ...cur, status: 'ok', last_test: nowIso(), pin, tools: [...cur.tools, ...found.filter((t) => !cur.tools.some((x) => x.name === t.name))] }
    connectorsStore.update((l) => l.map((x) => (x.id === c.id ? c : x))); audit('core.connection.test', c.name, !cur.pin && pin ? `pinned ${pin.kind === 'ssh_hostkey' ? 'host key' : pin.kind === 'tls_roots' ? 'public trust' : 'certificate'}` : undefined)
    const pinnedNow = !cur.pin && pin ? (pin.kind === 'ssh_hostkey' ? ' The host key is now pinned.' : pin.kind === 'tls_roots' ? ' Later tests require a certificate that a public authority vouches for.' : ' The certificate is now pinned.') : ''
    return HttpResponse.json({ ok: true, latency_ms: c.kind === 'ssh' ? 90 : 240, tools_found: c.tools.length, message: `Connected. ${c.tools.length} ${c.tools.length === 1 ? 'tool' : 'tools'} found (${c.tools.filter((t) => t.access === 'write').length} can change something).${pinnedNow}`, connector: c })
  }),
  http.put(`${API}/core/connections/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound()
    const b = await body<ConnectorInput>(request)
    // An old row of the unsupported kind can still be turned off, and nothing else about it can change.
    if (cur.kind === 'mcp-stdio' && b.kind === 'mcp-stdio' && b.enabled === false) {
      const off: Connector = { ...cur, enabled: false }
      connectorsStore.update((l) => l.map((x) => (x.id === off.id ? off : x))); audit('core.connection.edit', off.name, 'turned off')
      return HttpResponse.json(off)
    }
    const r = check(b, cur); if (r instanceof Response) return r
    // The pin is the identity of the server (D-94): forgotten on clear_pin, on another kind, or on another host or port; never because the sign-in changed.
    const forget = r.input.clear_pin === true || r.moved
    const tools = toolsOf(r.input.kind === cur.kind ? cur.tools : discover(r.input.kind), r.input.tools, r.input.kind === 'mcp-http')
    const c: Connector = { ...cur, name: r.input.name, kind: r.input.kind, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: await authOf(r, cur), username: r.username, pin: forget ? null : cur.pin, allow: r.allow, tools, enabled: r.input.enabled, status: r.retarget ? 'untested' : cur.status }
    connectorsStore.update((l) => l.map((x) => (x.id === c.id ? c : x))); audit('core.connection.edit', c.name, cur.pin && !c.pin ? 'pin forgotten' : undefined)
    return HttpResponse.json(c)
  }),
  http.delete(`${API}/core/connections/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound()
    if (inForce(cur.id)) return fail(409, 'in_use', `A change made through ${cur.name} is still in force. Roll it back in Response, or wait until it expires, then delete the connection.`)
    connectorsStore.update((l) => l.filter((x) => x.id !== cur.id)); audit('core.connection.remove', cur.name)
    return ok204()
  }),
]
