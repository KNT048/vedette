// Mock API of Settings → Connections (D-93, D-94; S-AI-7, S-RESP-4). Admin only. A secret is never stored: only its last 4 characters (SYS-4).
// Moved from the AI harness mock: the same checks, plus `username`, the read-only `pin` (trust on first use) and the errors
// `kind_unsupported`, `in_use` and `pin_mismatch`. The backend answers 501 for these routes until slice 13b-4.
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { newId, nowIso } from '@/mocks/db'
import { assetsStore } from '@/mocks/stores'
import { connectorsStore, type Connector, type ConnectorKind, type ConnectorTool } from '@/mocks/connectors'
import { actionsStore } from '@/features/response/state'
import { CONNECTION_KINDS, usesUsername } from '@/lib/connections'
import { CONNECTOR_AUTH } from './contract'
import type { ConnectorInput, ConnectorPin } from './types'

const ok204 = () => new HttpResponse(null, { status: 204 })
const notFound = () => fail(404, 'not_found', 'This connection no longer exists.')
const TIDY = (s: string) => s.replace(/\s+/g, ' ').trim()
const KINDS: readonly string[] = CONNECTION_KINDS
const AUTHS = ['none', 'token', 'basic', 'ssh-key']
const USER_RE = /^[^\s:\p{Cc}]{1,64}$/u

const T = (name: string, access: ConnectorTool['access'], description: string): ConnectorTool => ({ name, access, description, enabled: true })
// Tools a new connection offers by kind. Generic only (D-58): what a particular device can do is described by the action templates.
// Every write tool starts OFF (D-41, D-51): an administrator turns it on, and it then runs only through a response action that people approve.
const W = (name: string, description: string): ConnectorTool => ({ ...T(name, 'write', description), enabled: false })
function discover(kind: ConnectorKind): ConnectorTool[] {
  switch (kind) {
    case 'ssh': return [T('run_allowed_command', 'read', 'Run one command from the allow list and return its output'), W('run_approved_command', 'Run one command that an approved action defines')]
    case 'http': return [T('fetch_url', 'read', 'Fetch a page from an allowed address and return its text'), W('send_request', 'Send one API request that an approved action defines')]
    case 'netconf-restconf': return [T('get_config', 'read', 'Read configuration or status data'), W('apply_config', 'Apply one configuration change that an approved action defines')]
    case 'automation': return [T('list_jobs', 'read', 'List the jobs or workflows the platform offers'), W('launch_job', 'Start one job or workflow that an approved action defines')]
    default: return [T('list_resources', 'read', 'List what the MCP server offers'), T('search_docs', 'read', 'Search the documentation the server holds'), W('run_action', 'Run an action the server defines')]
  }
}

const hostOf = (c: Pick<Connector, 'kind' | 'target'>) => { try { return c.kind === 'ssh' ? c.target.split(':')[0]! : new URL(c.target).hostname } catch { return '' } }
/** What the first Test pins (D-94): the SSH host key, or the leaf certificate of an HTTPS device that no public authority vouches for (an address on the LAN, a .local name). */
function pinFor(c: Connector): Omit<ConnectorPin, 'first_seen'> | null {
  const host = hostOf(c)
  if (c.kind === 'ssh') return { kind: 'ssh_hostkey', value: `ssh-ed25519 SHA256:${fakeHash(host, 43)}` }
  if (c.kind === 'mcp-stdio' || !c.target.startsWith('https:')) return null
  return /^[\d.]+$/.test(host) || /\.(local|lan|internal|home\.arpa)$/i.test(host) || !host.includes('.') ? { kind: 'tls_sha256', value: fakeHash(host, 64, true) } : null
}
function fakeHash(seed: string, len: number, hex = false) {
  const chars = hex ? '0123456789abcdef' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let h = 2166136261, out = ''
  for (let i = 0; out.length < len; i++) { h = Math.imul(h ^ (seed.charCodeAt(i % Math.max(seed.length, 1)) || 7) ^ i, 16777619) >>> 0; out += chars[h % chars.length] }
  return out
}

type Checked = { input: ConnectorInput; allow: string[]; last4: string | null; username: string | null }
function check(b: Partial<ConnectorInput>, existing?: Connector): Response | Checked {
  const name = TIDY(String(b.name ?? ''))
  if (name.length < 1 || name.length > 40) return fail(400, 'invalid_name', 'Give the connection a name of 1 to 40 characters, for example "Office firewall API".')
  if (connectorsStore.get().some((c) => c.id !== existing?.id && c.name.toLowerCase() === name.toLowerCase())) return fail(400, 'duplicate_name', 'Another connection already has this name. Pick a different one.')
  if (!b.kind || !KINDS.includes(b.kind)) return fail(400, 'invalid_kind', 'Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server.')
  if (b.kind === 'mcp-stdio') return fail(400, 'kind_unsupported', 'An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)").')
  const target = String(b.target ?? '').trim()
  if (b.kind === 'ssh') { if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}(:\d{1,5})?$/.test(target)) return fail(400, 'invalid_target', 'Enter the SSH server as host or host:port, for example 192.168.10.30:22.') }
  else {
    let u: URL
    try { u = new URL(target) } catch { return fail(400, 'invalid_target', 'The address is not valid. Enter it in full, for example https://192.168.10.1.') }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return fail(400, 'invalid_target', 'The address must start with https:// or http://.')
    if (u.username || u.password) return fail(400, 'invalid_target', 'The address must not contain a user name or password. Enter the secret in its own field.')
  }
  const auth = b.auth_type ?? 'none'
  if (!AUTHS.includes(auth)) return fail(400, 'invalid_auth', 'Pick how the box signs in: none, token, user and password, or SSH key.')
  if (!CONNECTOR_AUTH[b.kind].includes(auth)) return fail(400, 'invalid_auth', `${b.kind === 'ssh' ? 'An SSH server' : 'This kind of connection'} cannot sign in that way. Pick one of the options the form offers.`)
  const username = usesUsername(b.kind, auth) ? TIDY(String(b.username ?? '')) : ''
  if (usesUsername(b.kind, auth) && !username) return fail(400, 'username_required', 'Enter the user name the box signs in with.')
  if (username && !USER_RE.test(username)) return fail(400, 'invalid_username', 'The user name is 1 to 64 characters, with no spaces or colons.')
  const secret = b.secret === undefined || b.secret === '' ? null : String(b.secret)
  if (secret !== null && secret.length < 8) return fail(400, 'invalid_secret', 'The secret is too short. Copy the whole token, password or key again.')
  const keep = !!existing && existing.auth.last4 !== null && existing.auth.type === auth && existing.kind === b.kind
  if (auth !== 'none' && secret === null && !keep) return fail(400, 'secret_required', 'Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards.')
  const allow = [...new Set((b.allow ?? []).map((a) => a.trim()).filter(Boolean))]
  if (allow.length === 0) return fail(400, 'allow_required', 'Add at least one entry to the allow-list. Only hosts, addresses or commands on this list may be used.')
  if (allow.length > 30 || allow.some((a) => a.length > 200 || /[\n\r]/.test(a))) return fail(400, 'invalid_allow', 'The allow-list holds up to 30 entries of 200 characters each, one per line.')
  if (b.kind !== 'ssh' && allow.some((a) => /\s/.test(a))) return fail(400, 'invalid_allow', 'A host or address in the allow-list cannot contain spaces.')
  if (b.asset_id && !assetsStore.get().some((a) => a.id === b.asset_id)) return fail(400, 'unknown_asset', 'The device you linked is not in the inventory.')
  if (b.clear_pin !== undefined && typeof b.clear_pin !== 'boolean') return fail(400, 'invalid', 'Send clear_pin as true or false.')
  return { input: { ...b, name, target, auth_type: auth, allow, enabled: b.enabled !== false } as ConnectorInput, allow, username: username || null, last4: auth === 'none' ? null : secret ? secret.slice(-4) : existing!.auth.last4 }
}

/** A response change made through the connection is still in force (an executed item that was not rolled back). The real box asks the response module through a port (D-93). */
const inForce = (id: string) => actionsStore.get().some((a) => a.items.some((i) => i.connector_id === id && i.status === 'executed'))

export const connectionsHandlers = [
  http.get(`${API}/core/connections`, () => guard('admin') ?? HttpResponse.json({ items: connectorsStore.get() })),
  http.post(`${API}/core/connections`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = check(await body<ConnectorInput>(request)); if (r instanceof Response) return r
    if (connectorsStore.get().length >= 20) return fail(400, 'too_many', 'A box holds up to 20 connections. Delete one you no longer use.')
    const tools = discover(r.input.kind).map((t) => ({ ...t, enabled: r.input.tools?.find((x) => x.name === t.name)?.enabled ?? t.enabled }))
    const c: Connector = { id: newId('cn'), name: r.input.name, kind: r.input.kind, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: { type: r.input.auth_type, last4: r.last4 }, username: r.username, pin: null, allow: r.allow, tools, enabled: r.input.enabled, status: 'untested', last_test: null }
    connectorsStore.update((l) => [...l, c]); audit('core.connection.add', c.name, `${c.kind}, ${c.tools.filter((t) => t.access === 'write').length} write tools${r.last4 ? ', secret set' : ''}`)
    return HttpResponse.json(c, { status: 201 })
  }),
  http.post(`${API}/core/connections/:id/test`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound()
    if (cur.kind === 'mcp-stdio') return fail(400, 'kind_unsupported', 'This kind of connection is not supported, so it cannot be tested. Delete it and add an MCP server with a web address.')
    const stamp = (patch: Partial<Connector>) => connectorsStore.update((l) => l.map((c) => (c.id === cur.id ? { ...c, ...patch } : c)))
    if (/unreachable/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      return fail(502, 'unreachable', `Could not connect to ${cur.target}. Check the address, the box's network and the firewall.`)
    }
    // A pinned certificate or host key that no longer matches is refused before any credential is sent (D-94).
    if (cur.pin && /changed/i.test(cur.target)) {
      stamp({ status: 'error', last_test: nowIso() })
      return fail(502, 'pin_mismatch', `${cur.pin.kind === 'ssh_hostkey' ? 'The SSH host key' : 'The certificate'} of ${cur.target} is not the one pinned at the first test. Nothing was sent. If you changed the device, edit this connection and tick "Forget pinned key", then test again.`)
    }
    const found = discover(cur.kind)
    const pin = cur.pin ?? (() => { const p = pinFor(cur); return p ? { ...p, first_seen: nowIso() } : null })()
    const c: Connector = { ...cur, status: 'ok', last_test: nowIso(), pin, tools: [...cur.tools, ...found.filter((t) => !cur.tools.some((x) => x.name === t.name))] }
    connectorsStore.update((l) => l.map((x) => (x.id === c.id ? c : x))); audit('core.connection.test', c.name, !cur.pin && pin ? `pinned ${pin.kind === 'ssh_hostkey' ? 'host key' : 'certificate'}` : undefined)
    return HttpResponse.json({ ok: true, latency_ms: c.kind === 'ssh' ? 90 : 240, tools_found: c.tools.length, message: `Connected. ${c.tools.length} ${c.tools.length === 1 ? 'tool' : 'tools'} found (${c.tools.filter((t) => t.access === 'write').length} can change something).${!cur.pin && pin ? ` ${pin.kind === 'ssh_hostkey' ? 'The host key' : 'The certificate'} is now pinned.` : ''}`, connector: c })
  }),
  http.put(`${API}/core/connections/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound()
    const r = check(await body<ConnectorInput>(request), cur); if (r instanceof Response) return r
    const retarget = r.input.kind !== cur.kind || r.input.target !== cur.target
    // The pin belongs to the address and the way of signing in: another address, kind or sign-in starts without one, and so does "Forget pinned key".
    const forget = r.input.clear_pin === true || retarget || r.input.auth_type !== cur.auth.type
    const base = r.input.kind === cur.kind ? cur.tools : discover(r.input.kind)
    const tools = base.map((t) => ({ ...t, enabled: r.input.tools?.find((x) => x.name === t.name)?.enabled ?? t.enabled }))
    const c: Connector = { ...cur, name: r.input.name, kind: r.input.kind, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: { type: r.input.auth_type, last4: r.last4 }, username: r.username, pin: forget ? null : cur.pin, allow: r.allow, tools, enabled: r.input.enabled, status: retarget ? 'untested' : cur.status }
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
