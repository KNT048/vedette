// Mock API của harness AI (D-39, S-AI-7). Mọi endpoint cần quản trị viên. Khoá/secret không bao giờ lưu: chỉ 4 ký tự cuối (SYS-4).
// Handler nối vào `handlers` của module ai (mocks.ts). Thứ tự quan trọng: đường dẫn cố định ("settings", "test") đứng trước ":id".
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { newId, nowIso } from '@/mocks/db'
import { aiProfilesStore } from '@/mocks/stores'
import { activeDefs, BUILTIN_HOOKS, BUILTIN_RULES, builtinHookState, builtinHooksView, buildMatch, chunksOf, customHooksStore, docView, draftDef, knowledgeSettings, knowledgeStore, memorySettings, memoryStore, newHookId, rejectedTexts, newRuleId, rulesStore, runHooks, skillsStore, skillsView, suggestionsStore } from './harness'
import { AiJob } from './contract'
import type { CustomHook, HookInput, KnowledgeInput, MemoryEntry, MemoryView, Rule, RuleInput } from './types'

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
// Bytes a base64 text decodes to; -1 when it is not base64 (standard alphabet, padded or not).
const base64Len = (c: unknown) => (typeof c === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(c) ? Math.floor((c.replace(/=+$/, '').length * 3) / 4) : -1)
const indexProfile = () => { const id = knowledgeSettings.get().index_profile; return id && aiProfilesStore.get().some((p) => p.id === id) ? id : null }
const knowledgeView = () => ({ index_profile: indexProfile(), items: knowledgeStore.get().map((d) => docView(d)) })

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
    const text = suggestionsStore.get().find((x) => x.id === params.id)!.text
    rejectedTexts.update((l) => [...l, text]) // the box refuses the same text for 30 days (ai_memory_rejected)
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
    if (typeof b.content !== 'string') return fail(400, 'invalid', 'The field "content" is missing or has a value that is not allowed. Fix it and try again.')
    if (base64Len(b.content) !== size) return fail(400, 'invalid_size', 'The file arrived damaged or cut short. Pick it again.')
    // the quick look of the box (sniffDoc): the bytes must look like the type the name claims, and the sentence names the file
    const head = (() => { try { return atob(b.content.slice(0, 1368)) } catch { return '' } })()
    const notIt = /\.pdf$/i.test(name) && !head.includes('%PDF-') ? 'a PDF file' : /\.docx$/i.test(name) && !head.startsWith('PK\x03\x04') ? 'a Word (DOCX) file' : null
    if (notIt) return fail(400, 'invalid_content', `${name} is not ${notIt}. Only PDF, MD, TXT and DOCX files can be added.`)
    if (b.jobs !== undefined && !jobsOk(b.jobs)) return fail(400, 'invalid_jobs', 'One of the chosen jobs is not an AI job. Pick from the list.')
    if (!indexProfile()) return fail(400, 'no_index_profile', 'Choose an AI profile for the index before adding documents.')
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
