// Mock API của harness AI (D-39, S-AI-7). Mọi endpoint cần quản trị viên. Khoá/secret không bao giờ lưu: chỉ 4 ký tự cuối (SYS-4).
// Handler nối vào `handlers` của module ai (mocks.ts). Thứ tự quan trọng: đường dẫn cố định ("settings", "test") đứng trước ":id".
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { newId, nowIso } from '@/mocks/db'
import { assetsStore, aiProfilesStore } from '@/mocks/stores'
import { connectorsStore, type Connector, type ConnectorKind, type ConnectorTool } from '@/mocks/connectors'
import { activeDefs, BUILTIN_HOOKS, BUILTIN_RULES, builtinHookState, builtinHooksView, buildMatch, chunksOf, customHooksStore, docView, draftDef, knowledgeSettings, knowledgeStore, memorySettings, memoryStore, newHookId, newRuleId, rulesStore, runHooks, skillsStore, skillsView, suggestionsStore } from './harness'
import { AiJob, CONNECTOR_AUTH } from './contract'
import type { ConnectorInput, CustomHook, HookInput, KnowledgeInput, MemoryEntry, MemoryView, Rule, RuleInput } from './types'

const ok204 = () => new HttpResponse(null, { status: 204 })
const notFound = (what: string) => fail(404, 'not_found', `This ${what} no longer exists.`)
const jobsOk = (jobs: unknown): jobs is string[] => Array.isArray(jobs) && jobs.every((j) => AiJob.safeParse(j).success)
const text = (v: unknown, min: number, max: number) => typeof v === 'string' && v.trim().length >= min && v.trim().length <= max
const TIDY = (s: string) => s.replace(/\s+/g, ' ').trim()

// ---- Rules
function checkRule(b: Partial<RuleInput>): Response | RuleInput {
  if (!text(b.text, 3, 300)) return fail(400, 'invalid_rule', 'Write the rule in 3 to 300 characters, for example "Always name devices by hostname and IP address".')
  if (b.jobs !== undefined && !jobsOk(b.jobs)) return fail(400, 'invalid_jobs', 'One of the chosen jobs is not an AI job. Pick from the list.')
  return { text: TIDY(b.text!), jobs: [...new Set(b.jobs ?? [])] as RuleInput['jobs'], enabled: b.enabled !== false }
}

// ---- Memory
const memoryView = (): MemoryView => ({ suggest_enabled: memorySettings.get().suggest_enabled, items: memoryStore.get(), suggestions: suggestionsStore.get() })
const memoryText = (v: unknown) => text(v, 3, 300)

// ---- Knowledge
const DOC_RE = /\.(pdf|md|txt|docx)$/i
const MAX_DOC = 10 * 1024 * 1024
const indexProfile = () => { const id = knowledgeSettings.get().index_profile; return id && aiProfilesStore.get().some((p) => p.id === id) ? id : null }
const knowledgeView = () => ({ index_profile: indexProfile(), items: knowledgeStore.get().map((d) => docView(d)) })

// ---- Connections: công cụ "phát hiện" theo loại kết nối
const T = (name: string, access: ConnectorTool['access'], description: string): ConnectorTool => ({ name, access, description, enabled: true })
function discover(kind: ConnectorKind, vendor: Connector['vendor']): ConnectorTool[] {
  if (kind === 'ssh') return [T('run_allowed_command', 'read', 'Run one command from the allow list and return its output')]
  if (kind === 'http') return [T('fetch_url', 'read', 'Fetch a page from an allowed address and return its text')]
  if (kind === 'device-api') {
    if (vendor === 'fortinet') return [T('get_virtual_ips', 'read', 'List virtual IPs and the internal device each one points to'), T('get_firewall_policies', 'read', 'List firewall policies'), T('get_system_status', 'read', 'Firmware version, model and uptime'), T('disable_virtual_ip', 'write', 'Turn off one virtual IP'), T('disable_firewall_policy', 'write', 'Turn off one firewall policy'), T('block_address', 'write', 'Add an IP address to a block address group')]
    if (vendor === 'mikrotik') return [T('get_nat_rules', 'read', 'List NAT rules (port forwarding)'), T('get_firewall_rules', 'read', 'List firewall filter rules'), T('get_resource', 'read', 'RouterOS version, board and uptime'), T('disable_nat_rule', 'write', 'Turn off one NAT rule'), T('add_address_list_entry', 'write', 'Add an IP address to a block address list')]
    if (vendor === 'pfsense') return [T('get_nat_port_forwards', 'read', 'List port forwards'), T('get_firewall_rules', 'read', 'List firewall rules'), T('get_system_status', 'read', 'Version and uptime'), T('disable_port_forward', 'write', 'Turn off one port forward'), T('add_alias_entry', 'write', 'Add an IP address to a block alias')]
    return [T('get_config_summary', 'read', 'Read a summary of the device configuration'), T('get_status', 'read', 'Version, model and uptime')]
  }
  return [T('list_resources', 'read', 'List what the MCP server offers'), T('search_docs', 'read', 'Search the documentation the server holds'), T('run_action', 'write', 'Run an action the server defines')]
}
const KINDS: ConnectorKind[] = ['device-api', 'ssh', 'http', 'mcp-http', 'mcp-stdio']
const AUTHS = ['none', 'token', 'basic', 'ssh-key']
const SHELL = /[;&|`$<>\\\n\r]/
function checkConnector(b: Partial<ConnectorInput>, existing?: Connector): Response | { input: ConnectorInput; allow: string[]; last4: string | null } {
  const name = TIDY(String(b.name ?? ''))
  if (name.length < 1 || name.length > 40) return fail(400, 'invalid_name', 'Give the connection a name of 1 to 40 characters, for example "Office FortiGate API".')
  if (connectorsStore.get().some((c) => c.id !== existing?.id && c.name.toLowerCase() === name.toLowerCase())) return fail(400, 'duplicate_name', 'Another connection already has this name. Pick a different one.')
  if (!b.kind || !KINDS.includes(b.kind)) return fail(400, 'invalid_kind', 'Pick a kind: device API, SSH, HTTP or MCP server.')
  if (b.kind === 'device-api' && !(['fortinet', 'mikrotik', 'pfsense', 'other'] as const).includes(b.vendor as never)) return fail(400, 'invalid_vendor', 'Pick which device API this is: FortiOS, RouterOS, pfSense or other.')
  const target = String(b.target ?? '').trim()
  if (b.kind === 'ssh') { if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}(:\d{1,5})?$/.test(target)) return fail(400, 'invalid_target', 'Enter the SSH server as host or host:port, for example 192.168.10.30:22.') }
  else if (b.kind === 'mcp-stdio') { if (!target || target.length > 200 || SHELL.test(target)) return fail(400, 'invalid_target', 'Enter the command to start the MCP server, for example "npx some-mcp-server". Characters that chain shell commands (; & | ` $ < >) are not allowed.') }
  else {
    let u: URL
    try { u = new URL(target) } catch { return fail(400, 'invalid_target', 'The address is not valid. Enter it in full, for example https://192.168.10.1.') }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return fail(400, 'invalid_target', 'The address must start with https:// or http://.')
    if (u.username || u.password) return fail(400, 'invalid_target', 'The address must not contain a user name or password. Enter the secret in its own field.')
  }
  const auth = b.auth_type ?? 'none'
  if (!AUTHS.includes(auth)) return fail(400, 'invalid_auth', 'Pick how the box signs in: none, token, user and password, or SSH key.')
  if (!CONNECTOR_AUTH[b.kind].includes(auth)) return fail(400, 'invalid_auth', `${b.kind === 'ssh' ? 'An SSH server' : b.kind === 'device-api' ? 'A device API' : b.kind === 'mcp-stdio' ? 'A local MCP command' : 'This kind of connection'} cannot sign in that way. Pick one of the options the form offers.`)
  const secret = b.secret === undefined || b.secret === '' ? null : String(b.secret)
  if (secret !== null && secret.length < 8) return fail(400, 'invalid_secret', 'The secret is too short. Copy the whole token, password or key again.')
  const keep = !!existing && existing.auth.last4 !== null && existing.auth.type === auth && existing.kind === b.kind
  if (auth !== 'none' && secret === null && !keep) return fail(400, 'secret_required', 'Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards.')
  const allow = [...new Set((b.allow ?? []).map((a) => a.trim()).filter(Boolean))]
  if (allow.length === 0) return fail(400, 'allow_required', 'Add at least one entry to the allow-list. The AI may only use hosts, addresses or commands on this list.')
  if (allow.length > 30 || allow.some((a) => a.length > 200 || /[\n\r]/.test(a))) return fail(400, 'invalid_allow', 'The allow-list holds up to 30 entries of 200 characters each, one per line.')
  if (b.kind !== 'ssh' && b.kind !== 'mcp-stdio' && allow.some((a) => /\s/.test(a))) return fail(400, 'invalid_allow', 'A host or address in the allow-list cannot contain spaces.')
  if (b.asset_id && !assetsStore.get().some((a) => a.id === b.asset_id)) return fail(400, 'unknown_asset', 'The device you linked is not in the inventory.')
  return { input: { ...b, name, target, auth_type: auth, allow, enabled: b.enabled !== false } as ConnectorInput, allow, last4: auth === 'none' ? null : secret ? secret.slice(-4) : existing!.auth.last4 }
}

// ---- Hooks
function checkHook(b: Partial<HookInput>, existing?: CustomHook): Response | HookInput {
  const name = TIDY(String(b.name ?? ''))
  if (name.length < 1 || name.length > 40) return fail(400, 'invalid_name', 'Give the hook a name of 1 to 40 characters, for example "Block admin passwords".')
  if (customHooksStore.get().some((h) => h.id !== existing?.id && h.name.toLowerCase() === name.toLowerCase())) return fail(400, 'duplicate_name', 'Another hook already has this name. Pick a different one.')
  if (!b.when || !['before_ai', 'after_ai', 'before_tool'].includes(b.when)) return fail(400, 'invalid_when', 'Pick when the hook runs: before sending to the AI, after the AI answers, or before a tool call.')
  if (!b.action || !['block', 'mask', 'approve'].includes(b.action)) return fail(400, 'invalid_action', 'Pick what the hook does: block, mask or require approval.')
  if (!b.match || !['keywords', 'regex'].includes(b.match.type) || !text(b.match.pattern, 1, 200)) return fail(400, 'invalid_match', 'Enter the words (comma-separated) or the regular expression to look for, 200 characters at most.')
  if (!buildMatch(b.match)) return fail(400, 'invalid_match', b.match.type === 'regex' ? 'This regular expression is not valid. Check brackets and escapes, for example \\d{9}.' : 'Enter at least one word.')
  if (!text(b.message, 3, 200)) return fail(400, 'invalid_message', 'Write the message people will see, 3 to 200 characters.')
  return { name, when: b.when, match: { type: b.match.type, pattern: b.match.pattern.trim() }, action: b.action, message: TIDY(b.message!), enabled: b.enabled !== false }
}

export const harnessHandlers = [
  // Rules
  http.get(`${API}/ai/rules`, () => guard('admin') ?? HttpResponse.json({ builtin: BUILTIN_RULES, custom: rulesStore.get() })),
  http.post(`${API}/ai/rules`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const r = checkRule(await body<RuleInput>(request)); if (r instanceof Response) return r
    if (rulesStore.get().length >= 30) return fail(400, 'too_many', 'A box holds up to 30 custom rules. Delete one you no longer need.')
    const rule: Rule = { id: newRuleId(), ...r }
    rulesStore.update((l) => [...l, rule]); audit('ai.rule.add', rule.id, rule.text.slice(0, 60))
    return HttpResponse.json(rule)
  }),
  http.put(`${API}/ai/rules/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    if (!rulesStore.get().some((r) => r.id === params.id)) return notFound('rule')
    const r = checkRule(await body<RuleInput>(request)); if (r instanceof Response) return r
    const rule: Rule = { id: String(params.id), ...r }
    rulesStore.update((l) => l.map((x) => (x.id === rule.id ? rule : x))); audit('ai.rule.edit', rule.id)
    return HttpResponse.json(rule)
  }),
  http.delete(`${API}/ai/rules/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    if (!rulesStore.get().some((r) => r.id === params.id)) return notFound('rule')
    rulesStore.update((l) => l.filter((x) => x.id !== params.id)); audit('ai.rule.remove', String(params.id))
    return ok204()
  }),

  // Memory
  http.get(`${API}/ai/memory`, () => guard('admin') ?? HttpResponse.json(memoryView())),
  http.post(`${API}/ai/memory`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ text: string }>(request)
    if (!memoryText(b.text)) return fail(400, 'invalid_memory', 'Write what the AI should remember in 3 to 300 characters, for example "NAS-PHOTOS is reachable from the Internet".')
    if (memoryStore.get().length >= 100) return fail(400, 'too_many', 'A box holds up to 100 memories. Delete the ones that are out of date.')
    const m: MemoryEntry = { id: newId('mem'), text: TIDY(b.text!), source: 'user', created_at: nowIso(), last_used_at: null, enabled: true }
    memoryStore.update((l) => [m, ...l]); audit('ai.memory.add', m.id)
    return HttpResponse.json(m)
  }),
  http.put(`${API}/ai/memory/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ suggest_enabled: boolean }>(request)
    if (typeof b.suggest_enabled !== 'boolean') return fail(400, 'invalid_setting', 'Say whether the AI may suggest new memories: on or off.')
    memorySettings.set({ suggest_enabled: b.suggest_enabled }); audit('ai.memory.settings', 'suggest', b.suggest_enabled ? 'on' : 'off')
    return HttpResponse.json(memoryView())
  }),
  http.post(`${API}/ai/memory/suggestions/:id/accept`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = suggestionsStore.get().find((x) => x.id === params.id)
    if (!s) return notFound('suggestion')
    const m: MemoryEntry = { id: newId('mem'), text: s.text, source: 'ai', created_at: nowIso(), last_used_at: null, enabled: true }
    memoryStore.update((l) => [m, ...l]); suggestionsStore.update((l) => l.filter((x) => x.id !== s.id)); audit('ai.memory.accept', m.id)
    return HttpResponse.json(m)
  }),
  http.post(`${API}/ai/memory/suggestions/:id/reject`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    if (!suggestionsStore.get().some((x) => x.id === params.id)) return notFound('suggestion')
    suggestionsStore.update((l) => l.filter((x) => x.id !== params.id)); audit('ai.memory.reject', String(params.id))
    return ok204()
  }),
  http.put(`${API}/ai/memory/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = memoryStore.get().find((m) => m.id === params.id)
    if (!cur) return notFound('memory')
    const b = await body<{ text: string; enabled: boolean }>(request)
    if (b.text !== undefined && !memoryText(b.text)) return fail(400, 'invalid_memory', 'Write what the AI should remember in 3 to 300 characters.')
    const m: MemoryEntry = { ...cur, text: b.text !== undefined ? TIDY(b.text) : cur.text, enabled: typeof b.enabled === 'boolean' ? b.enabled : cur.enabled }
    memoryStore.update((l) => l.map((x) => (x.id === m.id ? m : x))); audit('ai.memory.edit', m.id)
    return HttpResponse.json(m)
  }),
  http.delete(`${API}/ai/memory/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    if (!memoryStore.get().some((m) => m.id === params.id)) return notFound('memory')
    memoryStore.update((l) => l.filter((x) => x.id !== params.id)); audit('ai.memory.remove', String(params.id))
    return ok204()
  }),

  // Skills
  http.get(`${API}/ai/skills`, () => guard('admin') ?? HttpResponse.json({ items: skillsView() })),
  http.put(`${API}/ai/skills/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = skillsView().find((x) => x.id === params.id)
    if (!s) return notFound('skill')
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'invalid_setting', 'Say whether the skill is on or off.')
    skillsStore.update((m) => ({ ...m, [s.id]: b.enabled! })); audit('ai.skill', s.id, b.enabled ? 'on' : 'off')
    return HttpResponse.json({ ...s, enabled: b.enabled })
  }),

  // Knowledge
  http.get(`${API}/ai/knowledge`, () => guard('admin') ?? HttpResponse.json(knowledgeView())),
  http.put(`${API}/ai/knowledge/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ index_profile: string | null }>(request)
    const id = b.index_profile ?? null
    if (id !== null) {
      const p = aiProfilesStore.get().find((x) => x.id === id)
      if (!p) return fail(400, 'unknown_profile', 'This AI profile no longer exists. Pick another.')
      if (p.key_last4 === null && p.location === 'cloud') return fail(400, 'profile_unusable', `"${p.name}" has no API key yet, so it cannot build the index. Edit the profile and add the key.`)
    }
    knowledgeSettings.set({ index_profile: id }); audit('ai.knowledge.index', id ?? 'none')
    return HttpResponse.json(knowledgeView())
  }),
  http.post(`${API}/ai/knowledge`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<KnowledgeInput>(request)
    const name = TIDY(String(b.name ?? ''))
    if (!name || name.length > 120 || /[\\/]/.test(name)) return fail(400, 'invalid_name', 'The file name is missing or contains a slash.')
    if (!DOC_RE.test(name)) return fail(400, 'invalid_type', 'Only PDF, MD, TXT and DOCX files can be added.')
    const size = Number(b.size)
    if (!Number.isInteger(size) || size < 1) return fail(400, 'invalid_size', 'The file is empty.')
    if (size > MAX_DOC) return fail(400, 'too_large', 'The file is larger than 10 MB. Split it or remove pictures, then upload again.')
    if (b.jobs !== undefined && !jobsOk(b.jobs)) return fail(400, 'invalid_jobs', 'One of the chosen jobs is not an AI job. Pick from the list.')
    if (!indexProfile()) return fail(400, 'no_index_profile', 'Choose which AI profile builds the index before adding documents.')
    if (knowledgeStore.get().length >= 50) return fail(400, 'too_many', 'A box holds up to 50 documents. Delete the ones you no longer use.')
    const d = { id: newId('kd'), name, size, jobs: (b.jobs ?? ['explain-finding', 'ask-my-data']) as KnowledgeInput['jobs'] & string[], uploaded_at: nowIso() }
    knowledgeStore.update((l) => [d, ...l]); audit('ai.knowledge.add', name, `${size} bytes, ~${chunksOf(size)} chunks`)
    return HttpResponse.json(docView(d))
  }),
  http.put(`${API}/ai/knowledge/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = knowledgeStore.get().find((d) => d.id === params.id)
    if (!cur) return notFound('document')
    const b = await body<{ jobs: string[] }>(request)
    if (!jobsOk(b.jobs)) return fail(400, 'invalid_jobs', 'One of the chosen jobs is not an AI job. Pick from the list.')
    const d = { ...cur, jobs: [...new Set(b.jobs)] as typeof cur.jobs }
    knowledgeStore.update((l) => l.map((x) => (x.id === d.id ? d : x))); audit('ai.knowledge.jobs', d.name)
    return HttpResponse.json(docView(d))
  }),
  http.delete(`${API}/ai/knowledge/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = knowledgeStore.get().find((d) => d.id === params.id)
    if (!cur) return notFound('document')
    knowledgeStore.update((l) => l.filter((x) => x.id !== cur.id)); audit('ai.knowledge.remove', cur.name)
    return ok204()
  }),

  // Connections
  http.get(`${API}/ai/connections`, () => guard('admin') ?? HttpResponse.json({ items: connectorsStore.get() })),
  http.post(`${API}/ai/connections`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<ConnectorInput>(request)
    const r = checkConnector(b); if (r instanceof Response) return r
    if (connectorsStore.get().length >= 20) return fail(400, 'too_many', 'A box holds up to 20 connections. Delete one you no longer use.')
    const vendor = r.input.kind === 'device-api' ? r.input.vendor : null
    const tools = discover(r.input.kind, vendor).map((t) => ({ ...t, enabled: r.input.tools?.find((x) => x.name === t.name)?.enabled ?? t.enabled }))
    const c: Connector = { id: newId('cn'), name: r.input.name, kind: r.input.kind, vendor, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: { type: r.input.auth_type, last4: r.last4 }, allow: r.allow, tools, enabled: r.input.enabled, status: 'untested', last_test: null }
    connectorsStore.update((l) => [...l, c]); audit('ai.connection.add', c.name, `${c.kind}, ${c.tools.filter((t) => t.access === 'write').length} write tools${r.last4 ? ', secret set' : ''}`)
    return HttpResponse.json(c)
  }),
  http.post(`${API}/ai/connections/:id/test`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound('connection')
    if (/unreachable/i.test(cur.target)) {
      connectorsStore.update((l) => l.map((c) => (c.id === cur.id ? { ...c, status: 'error' as const, last_test: nowIso() } : c)))
      return fail(502, 'unreachable', `Could not connect to ${cur.target}. Check the address, the box's network and the firewall.`)
    }
    const found = discover(cur.kind, cur.vendor)
    const c: Connector = { ...cur, status: 'ok', last_test: nowIso(), tools: [...cur.tools, ...found.filter((t) => !cur.tools.some((x) => x.name === t.name))] }
    connectorsStore.update((l) => l.map((x) => (x.id === c.id ? c : x))); audit('ai.connection.test', c.name)
    return HttpResponse.json({ ok: true, latency_ms: c.kind === 'ssh' ? 90 : 240, tools_found: c.tools.length, message: `Connected. ${c.tools.length} ${c.tools.length === 1 ? 'tool' : 'tools'} found (${c.tools.filter((t) => t.access === 'write').length} can change something).`, connector: c })
  }),
  http.put(`${API}/ai/connections/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound('connection')
    const r = checkConnector(await body<ConnectorInput>(request), cur); if (r instanceof Response) return r
    const vendor = r.input.kind === 'device-api' ? r.input.vendor : null
    const retarget = r.input.kind !== cur.kind || r.input.target !== cur.target
    const base = r.input.kind === cur.kind && vendor === cur.vendor ? cur.tools : discover(r.input.kind, vendor)
    const tools = base.map((t) => ({ ...t, enabled: r.input.tools?.find((x) => x.name === t.name)?.enabled ?? t.enabled }))
    const c: Connector = { ...cur, name: r.input.name, kind: r.input.kind, vendor, target: r.input.target, asset_id: r.input.asset_id ?? null, auth: { type: r.input.auth_type, last4: r.last4 }, allow: r.allow, tools, enabled: r.input.enabled, status: retarget ? 'untested' : cur.status }
    connectorsStore.update((l) => l.map((x) => (x.id === c.id ? c : x))); audit('ai.connection.edit', c.name)
    return HttpResponse.json(c)
  }),
  http.delete(`${API}/ai/connections/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = connectorsStore.get().find((c) => c.id === params.id)
    if (!cur) return notFound('connection')
    connectorsStore.update((l) => l.filter((x) => x.id !== cur.id)); audit('ai.connection.remove', cur.name)
    return ok204()
  }),

  // Hooks
  http.get(`${API}/ai/hooks`, () => guard('admin') ?? HttpResponse.json({ builtin: builtinHooksView(), custom: customHooksStore.get() })),
  http.put(`${API}/ai/hooks/builtin/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const def = BUILTIN_HOOKS.find((h) => h.id === params.id)
    if (!def) return notFound('hook')
    if (def.locked) return fail(400, 'locked', '"Write tools need approval" is always on. A tool that changes something can only run through an action a person approves.')
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'invalid_setting', 'Say whether the hook is on or off.')
    builtinHookState.update((m) => ({ ...m, [def.id]: b.enabled! })); audit('ai.hook.builtin', def.id, b.enabled ? 'on' : 'off')
    return HttpResponse.json(builtinHooksView().find((h) => h.id === def.id))
  }),
  http.post(`${API}/ai/hooks/test`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ text: string; when: HookInput['when']; hook: HookInput }>(request)
    if (!text(b.text, 1, 1000)) return fail(400, 'invalid_text', 'Type a sample text of up to 1,000 characters.')
    if (!b.when || !['before_ai', 'after_ai', 'before_tool'].includes(b.when)) return fail(400, 'invalid_when', 'Pick the stage to test.')
    let defs = activeDefs()
    if (b.hook) {
      const h = checkHook({ ...b.hook, name: b.hook.name || 'Draft' }); if (h instanceof Response) return h
      defs = [draftDef({ ...h, when: b.when })!]
    }
    const r = runHooks(b.text!, b.when, defs)
    return HttpResponse.json({ outcome: r.outcome, output: r.text, hits: r.hits })
  }),
  http.post(`${API}/ai/hooks`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const h = checkHook(await body<HookInput>(request)); if (h instanceof Response) return h
    if (customHooksStore.get().length >= 30) return fail(400, 'too_many', 'A box holds up to 30 custom hooks. Delete one you no longer need.')
    const hook: CustomHook = { id: newHookId(), ...h }
    customHooksStore.update((l) => [...l, hook]); audit('ai.hook.add', hook.name, `${hook.when}, ${hook.action}`)
    return HttpResponse.json(hook)
  }),
  http.put(`${API}/ai/hooks/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = customHooksStore.get().find((h) => h.id === params.id)
    if (!cur) return notFound('hook')
    const h = checkHook(await body<HookInput>(request), cur); if (h instanceof Response) return h
    const hook: CustomHook = { id: cur.id, ...h }
    customHooksStore.update((l) => l.map((x) => (x.id === hook.id ? hook : x))); audit('ai.hook.edit', hook.name)
    return HttpResponse.json(hook)
  }),
  http.delete(`${API}/ai/hooks/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = customHooksStore.get().find((h) => h.id === params.id)
    if (!cur) return notFound('hook')
    customHooksStore.update((l) => l.filter((x) => x.id !== cur.id)); audit('ai.hook.remove', cur.name)
    return ok204()
  }),
]
