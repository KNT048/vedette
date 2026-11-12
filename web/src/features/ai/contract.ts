// Hợp đồng API module ai (D-18). Kiểu UI suy ra từ schema ở đây (types.ts).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

export const AiTier = z.enum(['min', 'med', 'max'])
const iso = z.iso.datetime()
const Tokens = z.object({ input: z.number().int(), output: z.number().int() })
const Citation = z.object({ title: z.string(), url: z.string().optional() })

export const AiJob = z.enum(['explain-finding', 'mitigation-config', 'cve-news', 'log-digest', 'log-investigate', 'ask-my-data', 'weekly-report', 'pdpl-assessment', 'translate-advisory', 'response-plan'])
export const ProfileKind = z.enum(['anthropic', 'openai', 'gemini', 'openai-compatible', 'custom'])
export const ApiStyle = z.enum(['openai', 'anthropic', 'gemini']).describe('openai = Chat Completions, anthropic = Messages, gemini = generateContent')
export const Location = z.enum(['internal', 'cloud']).describe('internal = runs inside the company network, data never leaves it; cloud = cloud provider')
export const AiProfile = z.object({
  id: z.string(), name: z.string(), kind: ProfileKind, api_style: ApiStyle, base_url: z.string(), model: z.string(),
  key_last4: z.string().nullable().describe('Last 4 characters of the key; the full key is never returned (SYS-4). null = no key yet (valid for internal profiles)'),
  location: Location, daily_cap: z.number().int().describe('Daily token cap for this profile alone; when reached, jobs switch to the fallback profile'),
  usable: z.boolean(), used_today: z.number().int(),
})
export const ProfileInput = z.object({
  id: z.string().optional().describe('Present when editing or testing a saved profile: leave the key blank to keep the old key, only while the provider type and the server address (scheme, host and port) stay the same; another address needs the key entered again'),
  name: z.string().min(1).max(40), kind: ProfileKind, api_style: ApiStyle, base_url: z.string(), model: z.string(),
  api_key: z.string().optional(), location: Location, daily_cap: z.number().int().min(1000).max(5_000_000),
})
export const TestInput = ProfileInput.omit({ daily_cap: true, name: true }).extend({ name: z.string().optional(), daily_cap: z.number().int().optional() })
export const TestResult = z.object({ ok: z.literal(true), latency_ms: z.number(), tokens_in: z.number(), tokens_out: z.number(), capabilities: z.object({ tools: z.boolean(), structured: z.boolean() }) })
const Slot = z.object({ primary: z.string().nullable(), fallback: z.string().nullable() })
export const Assignments = z.object({ internal_only: z.boolean().describe('On: jobs that send logs/device data may only be assigned internal profiles'), jobs: z.record(AiJob, Slot) })
export const AiConfigView = z.object({
  configured: z.boolean().describe('At least one usable profile exists'), tier: AiTier, daily_cap: z.number().int().describe('Shared daily token cap, summed across all profiles'), redact_pii: z.boolean(),
  tier_estimates: z.record(AiTier, z.number().nullable()).describe('Estimated tokens/day per tier (no money, D-6). null = depends on alert count'),
  jobs_ready: z.record(AiJob, z.boolean()).describe('Which jobs have a usable, permitted profile'),
})
export const ConfigInput = z.object({ tier: AiTier, daily_cap: z.number().int().min(1000).max(5_000_000), redact_pii: z.boolean() })

export const Usage = z.object({
  tier: AiTier, daily_cap: z.number(),
  today: z.object({ input: z.number(), output: z.number(), total: z.number() }),
  month: z.object({ input: z.number(), output: z.number(), total: z.number() }),
  by_skill: z.array(z.object({ skill: z.string(), runs: z.number(), tokens: z.number() })),
  downgrades: z.array(z.object({ id: z.string(), ts: iso, from: AiTier, to: AiTier, reason: z.string() })),
})
export const AiRun = z.object({ id: z.string(), ts: iso, skill: z.string(), model: z.string(), tokens_in: z.number(), tokens_out: z.number(), status: z.enum(['ok', 'schema_error', 'capped', 'failed']), target: z.string().optional(), profile: z.string().optional().describe('AI profile that answered'), fallback: z.boolean().optional().describe('true = ran on the fallback profile') })
// ---- Activity log (S-AI-8, D-48): guaranteed record of what the AI did, hash-chained
export const ActivityResult = z.enum(['ok', 'blocked_by_hook', 'fallback_used', 'error'])
export const ActivityTool = z.object({ name: z.string(), access: z.enum(['read', 'write']), args: z.string().describe('Arguments summarised, never secrets') })
export const ActivityEntry = z.object({
  id: z.string(), ts: iso, job: z.string(), profile: z.string(), model: z.string(),
  trigger: z.string().describe('Who or what started the call, like user:it@acme.example or system:schedule'),
  hooks: z.array(z.string()).describe('Names of the hooks that acted on this call'),
  tools: z.array(ActivityTool),
  input_hash: z.string().describe('SHA-256 of what was sent to the AI (the content itself is not stored)'),
  output_hash: z.string().describe('SHA-256 of what the AI answered'),
  summary: z.string(), tokens_in: z.number().int(), tokens_out: z.number().int(), result: ActivityResult,
  links: z.array(z.object({ kind: z.enum(['proposal', 'action']), id: z.string() })).optional().describe('Response proposal or action this call produced'),
  prev_hash: z.string(), hash: z.string().describe('SHA-256 of prev_hash + canonical JSON (sorted keys) of this entry without hash'),
})
export const ActivityList = z.object({ items: z.array(ActivityEntry), total: z.number().int(), retention_days: z.number().int() })
export const ActivityVerify = z.object({ ok: z.boolean(), count: z.number().int(), broken_at: z.number().int().nullable().describe('1-based position of the first entry that does not match, null when the chain is intact'), entry_id: z.string().nullable() })
export const ActivitySettings = z.object({ retention_days: z.number().int().min(90).describe('Entries are kept at least this long; default 365, minimum 90') })
export const ToolCall = z.object({ tool: z.string(), args: z.string(), result: z.string() })
export const AskTable = z.object({ columns: z.array(z.string()), rows: z.array(z.object({ href: z.string().optional(), cells: z.array(z.string()) })) })
export const HookWhen = z.enum(['before_ai', 'after_ai', 'before_tool']).describe('before_ai = on the text sent to the AI, after_ai = on the AI answer, before_tool = on a tool call the AI wants to make')
export const HookAction = z.enum(['block', 'mask', 'approve']).describe('block = refuse, mask = replace the matching text, approve = hold until a person approves')
export const HookHit = z.object({ id: z.string(), name: z.string(), kind: z.enum(['builtin', 'custom']), when: HookWhen, action: HookAction, message: z.string() })
export const AskResult = z.object({
  id: z.string(), question: z.string(), asked_at: iso, answer: z.array(z.string()), table: AskTable.nullable(),
  tool_calls: z.array(ToolCall), citations: z.array(Citation), model: z.string(), profile: z.string(), tokens: Tokens,
  downgraded: z.object({ from: AiTier, to: AiTier }).nullable(),
  hooks: z.array(HookHit).describe('Hooks that acted on this question, answer or tool call; empty when none did'),
  memories_suggested: z.number().int().min(0).describe('memories the AI suggested with this answer (0 when read back); they wait for an administrator (S-AI-7, D-225)'),
})
export const ExplainResult = z.object({
  cve: z.string(), generated_at: iso, cached: z.boolean(), affected: z.enum(['yes', 'no', 'unknown']), why: z.string(),
  patch_steps: z.array(z.string()), temp_mitigations: z.array(z.string()), detection_hints: z.array(z.string()),
  citations: z.array(Citation), model: z.string(), profile: z.string(), tokens: Tokens,
})
export const FetchedSource = z.object({ kind: z.enum(['advisory', 'github', 'rss']), title: z.string(), url: z.string(), status: z.enum(['ok', 'failed']), note: z.string() })
export const NewsResult = z.object({ cve: z.string(), generated_at: iso, sources: z.array(FetchedSource), lines: z.array(z.string()), citations: z.array(Citation), model: z.string(), profile: z.string(), tokens: Tokens })
export const DigestItem = z.object({ severity: z.enum(['high', 'medium', 'info']), title: z.string(), evidence: z.array(z.string()), recommendation: z.string(), asset_id: z.string().optional() })
export const LogDigest = z.object({
  tier: AiTier, generated_at: iso, cadence: z.string(), summary: z.string(), items: z.array(DigestItem), tool_calls: z.array(ToolCall), model: z.string(), profile: z.string(), tokens: Tokens,
  empty: z.boolean().describe('true = no log events to summarize yet; AI not called, no tokens spent'),
  memories_suggested: z.number().int().min(0).describe('memories the AI suggested while making this digest (0 when read back); they wait for an administrator (S-AI-7, D-223)'),
})

// ---- AI harness (D-39, S-AI-7): rules, memory, skills, knowledge, hooks (connections moved to core, D-93)
export const BuiltinRule = z.object({ id: z.string(), text: z.string() })
export const Rule = z.object({ id: z.string(), text: z.string(), jobs: z.array(AiJob).describe('Empty = applies to every job'), enabled: z.boolean() })
export const RuleInput = z.object({ text: z.string().min(3).max(300), jobs: z.array(AiJob), enabled: z.boolean() })
export const RulesView = z.object({ builtin: z.array(BuiltinRule), custom: z.array(Rule) })

export const MemoryEntry = z.object({ id: z.string(), text: z.string(), source: z.enum(['ai', 'user']), created_at: iso, last_used_at: iso.nullable(), enabled: z.boolean() })
export const MemorySuggestion = z.object({ id: z.string(), text: z.string(), created_at: iso, evidence: z.string().describe('Where the AI noticed this, for example "From the log summary of 7 Nov"') })
export const MemoryView = z.object({ suggest_enabled: z.boolean(), items: z.array(MemoryEntry), suggestions: z.array(MemorySuggestion) })
export const MemoryInput = z.object({ text: z.string().min(3).max(300) })
export const MemoryPatch = z.object({ text: z.string().min(3).max(300).optional(), enabled: z.boolean().optional() })

export const Skill = z.object({ id: z.string(), name: z.string(), what: z.string(), jobs: z.array(AiJob).describe('AI jobs that use this skill; empty = runs in batches, not tied to a job'), enabled: z.boolean() })

export const KnowledgeStatus = z.enum(['uploading', 'indexing', 'ready'])
export const KnowledgeDoc = z.object({ id: z.string(), name: z.string(), size: z.number().int(), status: KnowledgeStatus, chunks: z.number().int().nullable().describe('null until the document is indexed'), jobs: z.array(AiJob), uploaded_at: iso })
export const KnowledgeView = z.object({ index_profile: z.string().nullable().describe('AI profile id chosen for the index (required; it builds nothing until embeddings exist, D-209); null = none chosen'), items: z.array(KnowledgeDoc) })
export const KnowledgeInput = z.object({ name: z.string().min(1).max(120), size: z.number().int().min(1).describe('Bytes of the file; 10 MB at most. PDF, MD, TXT or DOCX'), content: z.string().min(1).describe('The file itself, base64 (standard alphabet, no line breaks); it decodes to exactly `size` bytes. The box keeps only the text it finds in it, never the file'), jobs: z.array(AiJob).optional() })
export const KnowledgeSettings = z.object({ index_profile: z.string().nullable() })
export const KnowledgePatch = z.object({ jobs: z.array(AiJob) })

export const BuiltinHook = z.object({ id: z.string(), name: z.string(), description: z.string(), enabled: z.boolean(), locked: z.boolean().describe('true = always on, cannot be turned off') })
export const HookMatch = z.object({ type: z.enum(['keywords', 'regex']), pattern: z.string().min(1).max(200).describe('keywords: comma-separated words; regex: RE2 regular expression (Go syntax; no lookahead, lookbehind or backreferences)') })
export const CustomHook = z.object({ id: z.string(), name: z.string(), when: HookWhen, match: HookMatch, action: HookAction, message: z.string(), enabled: z.boolean() })
export const HookInput = z.object({ name: z.string().min(1).max(40), when: HookWhen, match: HookMatch, action: HookAction, message: z.string().min(3).max(200), enabled: z.boolean() })
export const HooksView = z.object({ builtin: z.array(BuiltinHook), custom: z.array(CustomHook) })
export const HookTestInput = z.object({ text: z.string().min(1).max(1000), when: HookWhen, hook: HookInput.optional().describe('Test only this draft hook; omitted = run every enabled hook for the stage') })
export const HookTestResult = z.object({ outcome: z.enum(['pass', 'masked', 'blocked', 'held']), output: z.string().describe('Text after the hooks ran (masked text, or the refusal message)'), hits: z.array(HookHit) })

const cve = z.string().regex(/^CVE-\d{4}-\d{4,}$/i)
const CachedCve = z.object({ explain: ExplainResult.nullable(), news: NewsResult.nullable() })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/ai/config', summary: 'Usage tier, shared token cap, PII redaction; which jobs are ready', stories: ['S-AI-1', 'S-AI-4'], role: 'viewer', response: AiConfigView },
  { method: 'put', path: '/ai/config', summary: 'Save token tier, shared cap and PII redaction', stories: ['S-AI-4'], role: 'admin', body: ConfigInput, response: AiConfigView },
  { method: 'get', path: '/ai/profiles', summary: 'List AI profiles (no full keys)', stories: ['S-AI-1'], role: 'viewer', response: z.object({ items: z.array(AiProfile) }) },
  { method: 'post', path: '/ai/profiles', summary: 'Add an AI profile: Anthropic, OpenAI, Gemini, OpenAI-compatible or custom', stories: ['S-AI-1'], role: 'admin', body: ProfileInput, response: AiProfile },
  { method: 'put', path: '/ai/profiles/{id}', summary: 'Edit an AI profile (blank key = keep the old key)', stories: ['S-AI-1'], role: 'admin', params: z.object({ id: z.string() }), body: ProfileInput, response: AiProfile },
  { method: 'delete', path: '/ai/profiles/{id}', summary: 'Delete an AI profile; jobs using it lose their assignment', stories: ['S-AI-1'], role: 'admin', params: z.object({ id: z.string() }), response: z.object({ cleared_jobs: z.array(AiJob) }) },
  { method: 'post', path: '/ai/profiles/test', summary: 'Test the connection of a profile (saved or in draft) with a tiny request', stories: ['S-AI-1'], role: 'admin', body: TestInput, response: TestResult },
  { method: 'get', path: '/ai/assignments', summary: 'Job assignments: each AI job has a primary and fallback profile; privacy rule', stories: ['S-AI-1', 'S-AI-4'], role: 'viewer', response: Assignments },
  { method: 'put', path: '/ai/assignments', summary: 'Save job assignments and the "internal data only to internal profiles" rule', stories: ['S-AI-1', 'S-AI-4'], role: 'admin', body: Assignments, response: Assignments },
  { method: 'get', path: '/ai/assignments/suggestion', summary: 'Suggested assignments: fast model for bulk jobs, strong model for reasoning jobs', stories: ['S-AI-1'], role: 'viewer', query: z.object({ internal_only: z.enum(['true', 'false']) }), response: Assignments, example: { query: { internal_only: 'false' } } },
  { method: 'get', path: '/ai/usage', summary: 'Token meter: today, 30 days, per job, tier downgrades', stories: ['S-AI-4'], role: 'viewer', response: Usage },
  { method: 'get', path: '/ai/runs', summary: 'Log of AI calls (sent content is not stored)', stories: ['S-AI-4'], role: 'viewer', response: z.object({ items: z.array(AiRun) }) },
  { method: 'get', path: '/ai/asks', summary: 'Recent "Ask your data" questions', stories: ['S-AI-5'], role: 'viewer', response: z.object({ items: z.array(AskResult) }) },
  { method: 'post', path: '/ai/ask', summary: 'Ask about my data; the AI uses read-only tools', stories: ['S-AI-5', 'S-AI-6'], role: 'operator', body: z.object({ question: z.string().min(3).max(500) }), response: AskResult },
  { method: 'get', path: '/ai/activity', summary: 'AI activity log: every AI call with hooks, tools, hashes and result; filter by job, result and date. Entries cannot be edited or deleted', stories: ['S-AI-8'], role: 'operator', query: z.object({ job: z.string().optional(), result: ActivityResult.optional(), from: iso.optional(), to: iso.optional() }), response: ActivityList },
  { method: 'get', path: '/ai/activity/verify', summary: 'Check the hash chain of the activity log: intact, or the first broken entry', stories: ['S-AI-8'], role: 'operator', response: ActivityVerify },
  { method: 'get', path: '/ai/activity/settings', summary: 'Activity log retention (days)', stories: ['S-AI-8'], role: 'admin', response: ActivitySettings },
  { method: 'put', path: '/ai/activity/settings', summary: 'Set retention: default 365 days, minimum 90', stories: ['S-AI-8'], role: 'admin', body: ActivitySettings, response: ActivitySettings },
  // ---- AI harness (D-39)
  { method: 'get', path: '/ai/rules', summary: 'Rules sent with every AI call: built-in (read-only) and custom', stories: ['S-AI-7'], role: 'admin', response: RulesView },
  { method: 'post', path: '/ai/rules', summary: 'Add a custom rule for all jobs or chosen jobs', stories: ['S-AI-7'], role: 'admin', body: RuleInput, response: Rule },
  { method: 'put', path: '/ai/rules/{id}', summary: 'Edit or enable/disable a custom rule', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: RuleInput, response: Rule },
  { method: 'delete', path: '/ai/rules/{id}', summary: 'Delete a custom rule', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'get', path: '/ai/memory', summary: 'What the AI remembers about this network, plus memories it suggests', stories: ['S-AI-7'], role: 'admin', response: MemoryView },
  { method: 'post', path: '/ai/memory', summary: 'Add a memory by hand', stories: ['S-AI-7'], role: 'admin', body: MemoryInput, response: MemoryEntry },
  { method: 'put', path: '/ai/memory/settings', summary: 'Allow or forbid the AI to suggest new memories', stories: ['S-AI-7'], role: 'admin', body: z.object({ suggest_enabled: z.boolean() }), response: MemoryView },
  { method: 'put', path: '/ai/memory/{id}', summary: 'Edit or enable/disable a memory', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: MemoryPatch, response: MemoryEntry },
  { method: 'delete', path: '/ai/memory/{id}', summary: 'Delete a memory', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/ai/memory/suggestions/{id}/accept', summary: 'Accept a suggested memory; it becomes a memory entry', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: MemoryEntry },
  { method: 'post', path: '/ai/memory/suggestions/{id}/reject', summary: 'Reject a suggested memory', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'get', path: '/ai/skills', summary: 'Product skills the AI uses, with the jobs that use them', stories: ['S-AI-7'], role: 'admin', response: z.object({ items: z.array(Skill) }) },
  { method: 'put', path: '/ai/skills/{id}', summary: 'Turn a skill on or off', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: z.object({ enabled: z.boolean() }), response: Skill },
  { method: 'get', path: '/ai/knowledge', summary: 'Knowledge base documents with indexing status, and the AI profile chosen for the index', stories: ['S-AI-7'], role: 'admin', response: KnowledgeView },
  { method: 'post', path: '/ai/knowledge', summary: 'Upload a document (PDF, MD, TXT, DOCX up to 10 MB) as base64 content; the box reads and indexes it in the background', stories: ['S-AI-7'], role: 'admin', body: KnowledgeInput, response: KnowledgeDoc },
  { method: 'put', path: '/ai/knowledge/settings', summary: 'Choose the AI profile for the index (required; the index is built on the box)', stories: ['S-AI-7'], role: 'admin', body: KnowledgeSettings, response: KnowledgeView },
  { method: 'put', path: '/ai/knowledge/{id}', summary: 'Choose which jobs may use a document', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: KnowledgePatch, response: KnowledgeDoc },
  { method: 'delete', path: '/ai/knowledge/{id}', summary: 'Delete a document and its index', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'get', path: '/ai/hooks', summary: 'Checks that run before and after every AI call: built-in and custom', stories: ['S-AI-7'], role: 'admin', response: HooksView },
  { method: 'put', path: '/ai/hooks/builtin/{id}', summary: 'Turn a built-in hook on or off; "write tools need approval" is locked on', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: z.object({ enabled: z.boolean() }), response: BuiltinHook },
  { method: 'post', path: '/ai/hooks/test', summary: 'Try a sample text against one draft hook or every enabled hook', stories: ['S-AI-7'], role: 'admin', body: HookTestInput, response: HookTestResult },
  { method: 'post', path: '/ai/hooks', summary: 'Add a custom hook: when, match (keywords or regex), action, message', stories: ['S-AI-7'], role: 'admin', body: HookInput, response: CustomHook },
  { method: 'put', path: '/ai/hooks/{id}', summary: 'Edit or enable/disable a custom hook', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), body: HookInput, response: CustomHook },
  { method: 'delete', path: '/ai/hooks/{id}', summary: 'Delete a custom hook', stories: ['S-AI-7'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'get', path: '/ai/cve/{id}/cached', summary: 'Previously generated explanation and news for a CVE', stories: ['S-AI-2', 'S-AI-3'], role: 'viewer', params: z.object({ id: cve }), response: CachedCve, example: { params: { id: 'CVE-2022-27593' } } },
  { method: 'post', path: '/ai/cve/{id}/explain', summary: 'AI explains a CVE in terms of my devices', stories: ['S-AI-2'], role: 'operator', params: z.object({ id: cve }), response: ExplainResult },
  { method: 'post', path: '/ai/cve/{id}/news', summary: 'Box fetches advisories/PoC/RSS for a CVE, then the AI summarizes them', stories: ['S-AI-3'], role: 'operator', params: z.object({ id: cve }), response: NewsResult },
  { method: 'get', path: '/ai/logs/digest', summary: 'AI log digest for the selected tier (null = none generated yet; no AI call, INV-6)', stories: ['S-AI-4'], role: 'viewer', response: z.object({ digest: LogDigest.nullable() }) },
  { method: 'post', path: '/ai/logs/digest', summary: 'Regenerate the log digest now', stories: ['S-AI-4'], role: 'operator', response: z.object({ digest: LogDigest }) },
])
