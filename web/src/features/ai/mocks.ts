// Mock API module ai (S-AI-1, S-AI-3..6). Cấu hình chung, hồ sơ, phân việc, đồng hồ dùng chung nằm ở mocks/stores.ts.
// Khoá API KHÔNG bao giờ được lưu hay trả lại: chỉ giữ 4 ký tự cuối (SYS-4). Toàn bộ chữ hiển thị là tiếng Anh (D-28).
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { collection, dataMode, newId, nowIso } from '@/mocks/db'
import { AI_JOBS, aiAssignStore, aiAvailable, aiCandidates, aiConfigStore, aiProfilesStore, aiProfileUsable, aiRunsStore, assetsStore, findingsStore, isOn, recordAiRun } from '@/mocks/stores'
import type { AiAssign, AiJob, AiProfile as StoredProfile } from '@/mocks/stores'
import { answerQuestion, boxApart } from './ask'
import { activeDefs, memorySettings, memoryStore, rejectedTexts, runHooks, skillsView, suggestionsStore } from './harness'
import { harnessHandlers } from './harness-mocks'
import { activityHandlers, recordActivity } from './activity'
import type { ActivityInput } from './activity'
import type { AiConfigView, AiProfile, HookHit, AiRun, AiTier, AskResult, Assignments, ConfigInput, DigestItem, ExplainResult, FetchedSource, LogDigest, NewsResult, ProfileInput, ToolCall, Usage } from './types'
import { fmtDate } from '@/lib/format'

interface Kev { cve: string; vendor: string; product: string; name: string; description: string; required_action: string; links: string[]; date_added: string; ransomware: boolean; has_template: boolean }
const vulns = (kev as { vulns: Kev[] }).vulns
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i
const DAY = 864e5
const fmtDay = (iso: string) => fmtDate(iso) // one date format (D-389)
const num = (n: number) => n.toLocaleString('en-US')
const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`

const ESTIMATES: AiConfigView['tier_estimates'] = { min: 10_000, med: 60_000, max: null }
const startOfToday = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime() }

// Lịch sử mẫu để đồng hồ và nhật ký có số liệu ngay (dữ liệu mẫu, không phải lần gọi thật). Cài sạch: rỗng.
const sampleRuns = collection<AiRun[]>('ai_sample_runs', () => {
  const at = (back: number, min: number) => new Date(Math.min(Date.now() - 60_000 * (back + 1), startOfToday() - back * DAY + min * 6e4)).toISOString()
  const r = (back: number, min: number, skill: string, i: number, o: number, target?: string, profile = 'Claude Haiku', model = 'claude-haiku-5-5'): AiRun => ({ id: newId('ai'), ts: at(back, min), skill, model, tokens_in: i, tokens_out: o, status: 'ok', target, profile })
  const S = (back: number, min: number, skill: string, i: number, o: number, target?: string) => r(back, min, skill, i, o, target, 'Claude Sonnet', 'claude-sonnet-5-5')
  const L = (back: number, min: number, skill: string, i: number, o: number, target?: string) => r(back, min, skill, i, o, target, 'Company Ollama server', 'qwen3:8b')
  return [
    L(0, 420, 'log-digest', 4800, 900), L(0, 360, 'log-digest', 4600, 880), L(0, 300, 'log-digest', 4900, 910),
    S(0, 250, 'explain-finding', 2300, 1100, 'CVE-2022-27593'),
    { ...r(1, 900, 'explain-finding', 0, 0, 'CVE-2026-96951', ''), model: 'claude-sonnet-5-5', profile: undefined, status: 'failed' as const }, // the provider did not answer
    r(1, 800, 'weekly-report', 3900, 1500), S(1, 600, 'ask-my-data', 1100, 320, 'Which machines still expose RDP?'),
    r(2, 700, 'cve-news', 3400, 700, 'CVE-2026-119977'), S(3, 900, 'explain-finding', 2500, 1200, 'CVE-2026-96951'),
    L(5, 500, 'log-digest', 21000, 3900), S(9, 480, 'ask-my-data', 1300, 450, 'Which devices are not approved yet?'), S(14, 300, 'pdpl-assessment', 11000, 4200),
    S(20, 700, 'explain-finding', 2400, 1000, 'CVE-2026-94418'), L(26, 600, 'log-digest', 18500, 3300),
  ]
}, () => [])
const downgrades = collection<Usage['downgrades']>('ai_downgrades', () => [{ id: 'dg-1', ts: new Date(Date.now() - 3 * DAY).toISOString(), from: 'med', to: 'min', reason: 'Over the 60,000 tokens/day cap' }], () => [])

const allRuns = () => [...aiRunsStore.get(), ...sampleRuns.get()].sort((a, b) => b.ts.localeCompare(a.ts))
const todayRuns = () => allRuns().filter((r) => new Date(r.ts).getTime() >= startOfToday())
const todayTokens = () => todayRuns().reduce((n, r) => n + r.tokens_in + r.tokens_out, 0)
const profileUsed = (p: StoredProfile) => todayRuns().filter((r) => r.profile === p.name && r.status === 'ok').reduce((n, r) => n + r.tokens_in + r.tokens_out, 0)

function usage(): Usage {
  const cfg = aiConfigStore.get()
  const s = startOfToday()
  const month = allRuns().filter((r) => new Date(r.ts).getTime() >= Date.now() - 30 * DAY)
  const sum = (rs: AiRun[]) => { const input = rs.reduce((n, r) => n + r.tokens_in, 0); const output = rs.reduce((n, r) => n + r.tokens_out, 0); return { input, output, total: input + output } }
  const by = new Map<string, { runs: number; tokens: number }>()
  for (const r of month) { const e = by.get(r.skill) ?? { runs: 0, tokens: 0 }; by.set(r.skill, { runs: e.runs + 1, tokens: e.tokens + r.tokens_in + r.tokens_out }) }
  return { tier: cfg.tier, daily_cap: cfg.daily_cap, today: sum(month.filter((r) => new Date(r.ts).getTime() >= s)), month: sum(month), by_skill: [...by.entries()].map(([skill, v]) => ({ skill, ...v })).sort((a, b) => b.tokens - a.tokens), downgrades: downgrades.get() }
}

// Lần thử kết nối gần nhất của hồ sơ như đã lưu (S-AI-1), theo id; hồ sơ đổi địa chỉ/model/khoá thì mất. Mẫu: hai hồ sơ đám mây đã thử được.
type LastTest = NonNullable<AiProfile['last_test']>
const lastTests = collection<Record<string, LastTest>>('ai_last_tests', () => ({
  'p-haiku': { at: new Date(Date.now() - 2 * DAY).toISOString(), ok: true, detail: '' }, 'p-sonnet': { at: new Date(Date.now() - 2 * DAY).toISOString(), ok: true, detail: '' },
}), () => ({}))
const setLastTest = (id: string, t: LastTest | null) => lastTests.update((m) => { const n = { ...m }; if (t) n[id] = t; else delete n[id]; return n })
const sameConnection = (a: StoredProfile, b: StoredProfile) => a.kind === b.kind && a.api_style === b.api_style && a.base_url === b.base_url && a.model === b.model && a.key_last4 === b.key_last4
const profileView = (p: StoredProfile): AiProfile => ({ ...p, usable: aiProfileUsable(p), used_today: profileUsed(p), last_test: lastTests.get()[p.id] ?? null })
const jobsReady = () => Object.fromEntries(AI_JOBS.map((j) => [j.id, aiCandidates(j.id).length > 0])) as Record<AiJob, boolean>
const view = (): AiConfigView => { const c = aiConfigStore.get(); return { configured: c.configured, tier: c.tier, daily_cap: c.daily_cap, redact_pii: c.redact_pii, tier_estimates: ESTIMATES, jobs_ready: jobsReady() } }

/** `configured` (dùng chung với module khác) = có ít nhất một hồ sơ dùng được; provider/model/khoá phản chiếu hồ sơ dùng được đầu tiên. */
function syncConfig() {
  const first = aiProfilesStore.get().find(aiProfileUsable)
  aiConfigStore.update((c) => ({ ...c, configured: !!first, provider: first ? (first.kind === 'custom' ? 'openai-compatible' : first.kind) : c.provider, base_url: first?.base_url ?? c.base_url, model: first?.model ?? '', key_last4: first?.key_last4 ?? null }))
}

const JOB_NAME: Record<AiJob, string> = { 'explain-finding': 'explaining findings', 'mitigation-config': 'writing mitigation configs', 'cve-news': 'CVE news', 'log-digest': 'log summaries', 'log-investigate': 'log investigation', 'ask-my-data': 'asking your data', 'weekly-report': 'the weekly report', 'pdpl-assessment': 'the data protection assessment', 'translate-advisory': 'translating advisories', 'response-plan': 'response plans' }
function notReady(job: AiJob) {
  if (!isOn('ai')) return fail(409, 'ai_unavailable', 'The AI assistant module is off. Turn it on in Settings, Modules.')
  if (!aiConfigStore.get().configured) return fail(409, 'ai_unavailable', 'No AI profile is set up. An administrator adds one in Settings, AI assistant.')
  const a = aiAssignStore.get()
  const internalData = AI_JOBS.find((j) => j.id === job)?.data === 'internal'
  const slots = [a.jobs[job]?.primary, a.jobs[job]?.fallback].filter(Boolean)
  if (a.internal_only && internalData && slots.length > 0) return fail(409, 'ai_unavailable', `This job sends internal data, but the privacy rule only allows internal AI profiles for it. Assign an internal profile for ${JOB_NAME[job]} or switch the rule off in Settings, AI assistant.`)
  return fail(409, 'ai_unavailable', `No AI profile is assigned to ${JOB_NAME[job]}. Assign one in Settings, AI assistant.`)
}

/** Chọn hồ sơ trả lời một việc: chính, rồi dự phòng khi hồ sơ chính lỗi, hết trần riêng hoặc bị luật riêng tư loại. Ghi lần chạy; vượt trần chung → hạ mức (S-AI-4). */
/** What the activity log needs to know about one call (S-AI-8). Missing parts get a plain default. */
type Act = Partial<Pick<ActivityInput, 'hooks' | 'tools' | 'links' | 'input' | 'output' | 'summary' | 'result' | 'trigger'>>
function runJob(job: AiJob, tin: number, tout: number, target?: string, act: Act = {}) {
  if (!aiAvailable(job)) return { error: notReady(job) }
  const cfg = aiConfigStore.get()
  const used = todayTokens()
  const cap = num(cfg.daily_cap)
  // status capped = a cap stopped the call before anything was sent; failed = a profile was asked and did not answer (POST-5)
  const capped = (reason: string, status: 'capped' | 'failed' = 'capped') => {
    aiRunsStore.update((l) => [{ id: newId('ai'), ts: nowIso(), skill: job, model: cfg.model, tokens_in: 0, tokens_out: 0, status, target }, ...l])
    recordActivity({ job, profile: '', model: cfg.model, hooks: act.hooks ?? [], tools: act.tools ?? [], input: act.input ?? `${job}:${target ?? ''}`, output: '', summary: `${status === 'capped' ? 'Not sent' : 'No profile answered'}: ${reason}`, tokens_in: 0, tokens_out: 0, result: 'error', trigger: act.trigger })
    return { error: fail(429, 'daily_cap', reason) }
  }
  if (used >= cfg.daily_cap && cfg.tier === 'min') return capped(`Today's ${cap} token cap is used up and the tier is already the minimum. Raise the cap in Settings, AI assistant, or wait until tomorrow.`)
  const cands = aiCandidates(job)
  let pick: StoredProfile | undefined
  let idx = -1
  const why: string[] = []
  for (const [i, p] of cands.entries()) {
    if (/unreachable|timeout/.test(p.base_url)) { why.push(`${p.name}: no answer`); continue }
    if (profileUsed(p) + tin + tout > p.daily_cap) { why.push(`${p.name}: daily cap reached`); continue }
    pick = p; idx = i; break
  }
  if (!pick) return capped(`No AI profile could answer ${JOB_NAME[job]} (${why.join('; ')}). Check the profiles in Settings, AI assistant, or add a fallback.`, why.every((w) => w.endsWith('daily cap reached')) ? 'capped' : 'failed')
  recordAiRun(job, tin, tout, target, pick, idx > 0)
  recordActivity({ job, profile: pick.name, model: pick.model, hooks: act.hooks ?? [], tools: act.tools ?? [], links: act.links, input: act.input ?? `${job}:${target ?? ''}`, output: act.output ?? `${job}:${target ?? ''}:${tin}:${tout}`, summary: act.summary ?? `${JOB_NAME[job]}${target ? ` for ${target}` : ''}`, tokens_in: tin, tokens_out: tout, result: act.result ?? (idx > 0 ? 'fallback_used' : 'ok'), trigger: act.trigger })
  let downgraded: { from: AiTier; to: AiTier } | null = null
  if (used + tin + tout > cfg.daily_cap && cfg.tier !== 'min') {
    const to: AiTier = cfg.tier === 'max' ? 'med' : 'min'
    downgraded = { from: cfg.tier, to }
    aiConfigStore.update((c) => ({ ...c, tier: to }))
    downgrades.update((l) => [{ id: newId('dg'), ts: nowIso(), from: cfg.tier, to, reason: `Over the ${cap} tokens/day cap` }, ...l])
    audit('ai.downgrade', `${cfg.tier}->${to}`, 'over the daily token cap')
  }
  return { error: null, profile: pick, fallback: idx > 0, downgraded }
}

// ---- Hồ sơ
const KIND_STYLE: Record<string, ProfileInput['api_style']> = { anthropic: 'anthropic', openai: 'openai', gemini: 'gemini', 'openai-compatible': 'openai' }
function checkProfile(b: Partial<ProfileInput>, existing?: StoredProfile): Response | { name: string; url: URL; key: string | null; keepOld: boolean; style: ProfileInput['api_style'] } {
  const name = String(b.name ?? '').trim()
  if (!b.kind || !['anthropic', 'openai', 'gemini', 'openai-compatible', 'custom'].includes(b.kind)) return fail(400, 'invalid_kind', 'Pick a provider type: Anthropic, OpenAI, Gemini, OpenAI-compatible or Custom.')
  if (name.length < 1 || name.length > 40) return fail(400, 'invalid_name', 'Give the profile a name of 1 to 40 characters, for example "Claude Sonnet".')
  if (aiProfilesStore.get().some((p) => p.id !== existing?.id && p.name.toLowerCase() === name.toLowerCase())) return fail(400, 'duplicate_name', 'Another profile already has this name. Pick a different one.')
  const style = b.kind === 'custom' ? b.api_style : KIND_STYLE[b.kind]
  if (!style || !['openai', 'anthropic', 'gemini'].includes(style)) return fail(400, 'invalid_style', 'Pick the API style the server speaks: OpenAI Chat Completions, Anthropic Messages or Gemini.')
  const location = b.location
  if (location !== 'internal' && location !== 'cloud') return fail(400, 'invalid_location', 'Say where the model runs: inside the company network or in the cloud.')
  if (['anthropic', 'openai', 'gemini'].includes(b.kind) && location === 'internal') return fail(400, 'invalid_location', 'Anthropic, OpenAI and Gemini run in the cloud. Use OpenAI-compatible or Custom for a server on your own network.')
  let url: URL
  try { url = new URL(String(b.base_url ?? '').trim()) } catch { return fail(400, 'invalid_base_url', 'The server address is not valid. Enter it in full, for example https://api.anthropic.com or http://localhost:11434/v1.') }
  if (url.username || url.password) return fail(400, 'invalid_base_url', 'The address must not contain a user name or password. Enter the API key in its own field.')
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && location === 'internal')) return fail(400, 'invalid_base_url', 'The address must start with https://. Only a server inside your own network may use http://.')
  if (!/^[\w.:/-]{1,80}$/.test(String(b.model ?? ''))) return fail(400, 'invalid_model', 'The model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most), for example claude-haiku-5-5.')
  const key = b.api_key === undefined || b.api_key === '' ? null : String(b.api_key)
  if (key !== null && (key.length < 8 || /\s/.test(key))) return fail(400, 'invalid_key', 'The API key is too short or contains spaces. Copy the whole key again from the provider\'s console.')
  // The stored key goes only where it was saved for: the same kind and the same origin (scheme, host, port). Another address gets no key.
  const moved = !!existing && existing.key_last4 !== null && new URL(existing.base_url).origin !== url.origin
  const keepOld = !!existing && existing.key_last4 !== null && existing.kind === b.kind && !moved
  if (key === null && location === 'cloud' && !keepOld) return fail(400, 'key_required', moved ? 'Changing the address needs the API key entered again.' : existing && existing.kind !== b.kind ? 'Changing the provider type needs the API key entered again.' : 'Enter the API key. It stays on this box and is encrypted.')
  return { name, url, key, keepOld, style }
}
function toStored(b: ProfileInput, ok: { name: string; url: URL; key: string | null; keepOld: boolean; style: ProfileInput['api_style'] }, id: string, existing?: StoredProfile): StoredProfile {
  const cap = Number(b.daily_cap)
  return { id, name: ok.name, kind: b.kind, api_style: ok.style, base_url: ok.url.toString().replace(/\/$/, ''), model: b.model, key_last4: ok.key ? ok.key.slice(-4) : ok.keepOld ? existing!.key_last4 : null, location: b.location, daily_cap: cap }
}
const capError = (b: Partial<ProfileInput>) => { const c = Number(b.daily_cap); return !Number.isInteger(c) || c < 1000 || c > 5_000_000 ? fail(400, 'invalid_cap', 'The profile\'s daily token cap must be a whole number from 1,000 to 5,000,000.') : null }

// ---- Phân việc
const allowed = (p: StoredProfile, job: AiJob, internalOnly: boolean) => aiProfileUsable(p) && !(internalOnly && AI_JOBS.find((j) => j.id === job)?.data === 'internal' && p.location !== 'internal')
function checkAssign(b: Partial<Assignments>): Response | Assignments {
  const profiles = aiProfilesStore.get()
  const internalOnly = b.internal_only === true
  const jobs = {} as AiAssign
  for (const j of AI_JOBS) {
    const s = b.jobs?.[j.id] ?? { primary: null, fallback: null }
    const primary = s.primary || null, fallback = s.fallback || null
    for (const [slot, id] of [['primary', primary], ['fallback', fallback]] as const) {
      if (id === null) continue
      const p = profiles.find((x) => x.id === id)
      if (!p) return fail(400, 'unknown_profile', `The ${slot} profile for ${JOB_NAME[j.id]} no longer exists. Pick another.`)
      if (!aiProfileUsable(p)) return fail(400, 'profile_unusable', `"${p.name}" has no API key yet, so it cannot be assigned to ${JOB_NAME[j.id]}. Edit the profile and add the key.`)
      if (!allowed(p, j.id, internalOnly)) return fail(400, 'privacy_rule', `"${p.name}" runs in the cloud, but ${JOB_NAME[j.id]} sends internal data and the privacy rule only allows internal profiles. Pick an internal profile or switch the rule off.`)
    }
    if (fallback && !primary) return fail(400, 'fallback_without_primary', `Set a primary profile for ${JOB_NAME[j.id]} before adding a fallback.`)
    if (primary && primary === fallback) return fail(400, 'same_profile', `The fallback for ${JOB_NAME[j.id]} must be a different profile from the primary.`)
    jobs[j.id] = { primary, fallback }
  }
  return { internal_only: internalOnly, jobs }
}
const FAST = /haiku|mini|luna|flash|lite|nano|\b[1-9]b\b|:[1-9]b\b/i
const BATCH: AiJob[] = ['log-digest', 'translate-advisory', 'cve-news', 'weekly-report']
/** Gợi ý: model nhanh cho việc hàng loạt, model mạnh cho việc cần suy luận; việc dữ liệu nội bộ ưu tiên hồ sơ nội bộ, việc dữ liệu công khai ưu tiên đám mây. */
function suggest(internalOnly: boolean): Assignments {
  const profiles = aiProfilesStore.get()
  const jobs = {} as AiAssign
  for (const j of AI_JOBS) {
    const ok = profiles.filter((p) => allowed(p, j.id, internalOnly))
    const wantFast = BATCH.includes(j.id)
    const rank = (p: StoredProfile) => (FAST.test(p.model) === wantFast ? 0 : 1) * 2 + ((j.data === 'internal') === (p.location === 'internal') ? 0 : 1)
    const sorted = [...ok].sort((a, b) => rank(a) - rank(b))
    jobs[j.id] = { primary: sorted[0]?.id ?? null, fallback: sorted[1]?.id ?? null }
  }
  return { internal_only: internalOnly, jobs }
}

// ---- Kết quả lưu (khoá: CVE hoặc mức)
const explains = collection<Record<string, ExplainResult>>('ai_explains', () => ({}))
const news = collection<Record<string, NewsResult>>('ai_news', () => ({}))
const asks = collection<AskResult[]>('ai_asks', () => [])
const digests = collection<Record<string, LogDigest>>('ai_log_digests', () => ({}))

const vulnOf = (id: string) => vulns.find((v) => v.cve === id.toUpperCase())
const kevKey = (v: Kev) => `${v.vendor.toLowerCase()}|${v.product.toLowerCase()}`

function buildExplain(v: Kev): Omit<ExplainResult, 'cached' | 'generated_at' | 'model' | 'profile' | 'tokens'> {
  const matched = assetsStore.get().filter((a) => a.software.some((s) => s.kev.includes(kevKey(v))))
  const names = matched.map((a) => a.hostname ?? a.ip)
  const confirmed = findingsStore.get().some((f) => f.cve === v.cve && f.status === 'confirmed')
  const kinds = new Set(matched.map((a) => a.kind))
  const temp: string[] = []
  if (kinds.has('nas')) temp.push('Cut NAS access from the Internet: remove the port forward on the firewall and use the VPN only.')
  if (kinds.has('server') && v.vendor === 'WordPress') temp.push('Block /wp-content/upgrade and /wp-admin/ from the Internet until the update is done.')
  if (kinds.has('server') && v.vendor === 'Microsoft') temp.push('Only allow RDP and SMB to this server from the admin network or VPN.')
  if (!temp.length) temp.push('Limit access to the affected service to the IPs that need it until it is patched.')
  const none = matched.length === 0
  return {
    cve: v.cve,
    affected: none ? 'no' : confirmed ? 'yes' : 'unknown',
    why: none
      ? `Your inventory has no ${v.vendor} ${v.product}, so this vulnerability affects no device the box knows about. If you have a device that is not listed, add it under Devices so Vedette matches again.`
      : `You have ${v.vendor} ${v.product} on ${names.join(', ')}. ${confirmed ? 'A safe scan sample confirmed the vulnerability exists.' : 'It is not confirmed whether the version is in the affected range, so treat it as suspected until checked.'} This vulnerability is being exploited in the wild (CISA KEV, added ${fmtDay(v.date_added)}).`,
    patch_steps: none ? [] : [`Open the vendor advisory (${v.links[0] ?? 'vendor page'}) and update to the patched build for the version you run.`, 'Back up the configuration or take a snapshot before updating.', 'After updating, rescan the device on the Vulnerability scans page to confirm the finding is gone.'],
    temp_mitigations: none ? [] : temp,
    detection_hints: none ? [] : [v.ransomware ? 'This vulnerability has been used for ransomware: look for files with odd new extensions and ransom notes in shared folders.' : 'Review the service access log for the last 7 days: odd requests from foreign IPs and new files in the web or system folders.', 'If you see signs, isolate the device from the network before anything else.'],
    citations: [...v.links.slice(0, 2).map((url) => ({ title: new URL(url).hostname.replace(/^www\./, ''), url })), { title: `Inventory: ${boxApart(matched)} matching` }],
  }
}

function buildNews(v: Kev): Omit<NewsResult, 'generated_at' | 'model' | 'profile' | 'tokens'> {
  const advisory = v.links[0] ?? `https://nvd.nist.gov/vuln/detail/${v.cve}`
  const host = new URL(advisory).hostname.replace(/^www\./, '')
  const sources: FetchedSource[] = [
    { kind: 'advisory', title: `Vendor advisory (${host})`, url: advisory, status: 'ok', note: 'Fetched, 14 KB' },
    { kind: 'github', title: `GitHub: search ${v.cve}`, url: `https://github.com/search?q=${v.cve}&type=repositories`, status: 'ok', note: v.has_template ? 'A check template exists in nuclei-templates and public repositories' : 'No public exploit repository found' },
    { kind: 'rss', title: 'watchTowr Labs (RSS)', url: 'https://labs.watchtowr.com/rss/', status: 'ok', note: 'No post mentions this CVE' },
    { kind: 'rss', title: 'GreyNoise (RSS)', url: 'https://www.greynoise.io/blog/rss.xml', status: 'failed', note: 'Timed out after 15 seconds, source skipped' },
  ]
  const lines = [
    `Exploited: yes. CISA added ${v.cve} to the exploited list on ${fmtDay(v.date_added)}${v.ransomware ? ' and recorded it in ransomware campaigns' : ''}.`,
    v.has_template ? 'Public exploit code or check template: yes. Attackers do not need to write their own tools, so act early.' : 'Public exploit code: not seen in the sources fetched. That does not mean safe: exploitation may be circulating privately.',
    `Vendor mitigation: see the advisory at ${host}. While waiting to patch, limit Internet access to the affected service.`,
    'The GreyNoise source could not be fetched, so the summary has no real Internet scanning data.',
  ]
  return { cve: v.cve, sources, lines, citations: sources.filter((s) => s.status === 'ok').map((s) => ({ title: s.title, url: s.url })) }
}

function buildDigest(tier: AiTier): Omit<LogDigest, 'generated_at' | 'model' | 'profile' | 'tokens'> {
  // the same words as the box (modules/ai/logdigest.go digestCadence): every digest is made when someone asks (D-221, D-223)
  const cadence = tier === 'min' ? 'A short summary of the most serious points, made when you ask' : tier === 'med' ? 'A full summary of new kinds of line, spikes and bad connections, made when you ask' : 'A full summary made when you ask, with the AI checking points through read-only tools (what the logs counted for an address, devices, threat feeds, the exploited list)'
  // Cài sạch: chưa có nguồn log nào gửi về nên không có gì để tóm tắt; không gọi AI, không tốn token.
  if (dataMode() === 'clean') return { tier, cadence, empty: true, summary: 'There are no log events to summarise yet. Add a log source on the Logs page; once events arrive, the summary appears here.', items: [], tool_calls: [], memories_suggested: 0 }
  const as = assetsStore.get()
  const nm = (id: string, fb: string) => as.find((a) => a.id === id)?.hostname ?? fb
  const ipOf = (id: string, fb: string) => as.find((a) => a.id === id)?.ip ?? fb
  const unapproved = as.filter((a) => !a.approved)
  const rdp: DigestItem = { severity: 'high', title: `${nm('a-srvad', 'SRV-AD')} is under RDP password guessing from 103.75.190.12`, asset_id: 'a-srvad', evidence: [`EventID 4625 ${nm('a-srvad', 'SRV-AD')} user=administrator src=103.75.190.12 (1,240 times in the last hour)`], recommendation: 'Close port 3389 to the Internet, allow RDP only through the VPN and lock accounts after 5 failures.' }
  const tor: DigestItem = { severity: 'high', title: `${nm('a-pc03', 'PC-ACCOUNTS-03')} connects to an IP on the bad list`, asset_id: 'a-pc03', evidence: [`FW-HQ allow ${ipOf('a-pc03', '192.168.10.103')} -> 185.220.101.47:443 (Tor exit node), 14 times`], recommendation: 'Isolate the device from the network, scan for malware and change the passwords used on it.' }
  const cam: DigestItem = { severity: 'medium', title: `${nm('a-cam01', 'CAM-GATE')} outbound traffic spiked`, asset_id: 'a-cam01', evidence: [`${ipOf('a-cam01', '192.168.20.11')} -> 45.148.10.95:80, 4.2 GB in 6 hours (normally about 120 MB)`], recommendation: 'Change the camera default password and block it from the Internet; the destination 45.148.10.95 is on the bad IP list.' }
  // the blocked hit of the logs mock (b-3): the box tells the AI it was a blocked attempt (D-227), so the AI does not call it a connection
  const tried: DigestItem = { severity: 'medium', title: '192.168.10.157 tried to reach 45.148.10.95; FW-HQ blocked it', evidence: ['FW-HQ deny 192.168.10.157 -> 45.148.10.95 (ET Open compromised, IPsum), a blocked attempt'], recommendation: 'Nothing got through, but a device that tries to reach a listed address may be infected: find out what on 192.168.10.157 made the request.' }
  const fresh: DigestItem = { severity: 'info', title: `${plural(unapproved.length, 'new unapproved device')} in 7 days`, evidence: unapproved.map((a) => `DHCP ${a.ip} mac=${a.mac ?? 'unknown'} (${a.hostname ?? 'no name'})`), recommendation: 'Open Devices to approve or mark as unknown.' }
  const items = tier === 'min' ? [rdp, tor] : tier === 'med' ? [rdp, tor, cam, tried, ...(unapproved.length ? [fresh] : [])] : [{ ...rdp, recommendation: `${rdp.recommendation} Checked: no successful logon (4624) from this IP within ±1 hour.` }, tor, cam, tried, ...(unapproved.length ? [fresh] : [])]
  const tool_calls: ToolCall[] = tier === 'max' ? [
    { tool: 'events_around', args: '{"ip": "103.75.190.12", "window": "±1h"}', result: '1,240 events 4625, 0 events 4624' },
    { tool: 'lookup_ioc', args: '{"value": "185.220.101.47"}', result: 'Tor exit node, score 0.92, should be blocked' },
    { tool: 'search_assets', args: '{"ip": "192.168.20.11"}', result: '1 device: CAM-GATE (Hikvision)' },
  ] : []
  const high = items.filter((i) => i.severity === 'high').length
  return { tier, cadence, empty: false, summary: `${plural(items.length, 'point')} worth a look, ${high} high. Handle the first two today.`, items, tool_calls, memories_suggested: 0 }
}
const DIGEST_TOKENS: Record<AiTier, [number, number]> = { min: [2100, 420], med: [4800, 900], max: [9600, 2300] }
const nameOfJob = (job: AiJob) => aiCandidates(job)[0]

export const handlers = [
  ...harnessHandlers,
  ...activityHandlers,
  http.get(`${API}/ai/config`, () => guard('viewer') ?? HttpResponse.json(view())),
  http.put(`${API}/ai/config`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<ConfigInput>(request)
    if (!['min', 'med', 'max'].includes(String(b.tier))) return fail(400, 'invalid_tier', 'Pick a tier: minimum, medium or maximum.')
    const cap = Number(b.daily_cap)
    if (!Number.isInteger(cap) || cap < 1000 || cap > 5_000_000) return fail(400, 'invalid_cap', 'The daily token cap must be a whole number from 1,000 to 5,000,000.')
    aiConfigStore.update((c) => ({ ...c, tier: b.tier as AiTier, daily_cap: cap, redact_pii: b.redact_pii !== false }))
    audit('ai.config', 'tier', `tier=${b.tier}, cap=${cap}`)
    return HttpResponse.json(view())
  }),

  http.get(`${API}/ai/profiles`, () => guard('viewer') ?? HttpResponse.json({ items: aiProfilesStore.get().map(profileView) })),
  http.post(`${API}/ai/profiles`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<ProfileInput>(request)
    const ok = checkProfile(b); if (ok instanceof Response) return ok
    const bad = capError(b); if (bad) return bad
    if (aiProfilesStore.get().length >= 12) return fail(400, 'too_many', 'A box holds up to 12 AI profiles. Remove one you no longer use.')
    const p = toStored(b as ProfileInput, ok, newId('p'))
    aiProfilesStore.update((l) => [...l, p])
    // Việc nào chưa có hồ sơ chính thì lấy hồ sơ mới (nếu được phép) để thêm xong dùng được ngay.
    aiAssignStore.update((a) => ({ ...a, jobs: Object.fromEntries(AI_JOBS.map((j) => [j.id, !a.jobs[j.id].primary && allowed(p, j.id, a.internal_only) ? { ...a.jobs[j.id], primary: p.id } : a.jobs[j.id]])) as AiAssign }))
    syncConfig()
    audit('ai.profile.add', p.name, `${p.kind}, ${p.location}, model=${p.model}${ok.key ? ', key set' : ''}`)
    return HttpResponse.json(profileView(p))
  }),
  http.put(`${API}/ai/profiles/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = aiProfilesStore.get().find((p) => p.id === params.id)
    if (!cur) return fail(404, 'not_found', 'This AI profile no longer exists.')
    const b = await body<ProfileInput>(request)
    const ok = checkProfile(b, cur); if (ok instanceof Response) return ok
    const bad = capError(b); if (bad) return bad
    const p = toStored(b as ProfileInput, ok, cur.id, cur)
    // Đổi sang đám mây khi luật riêng tư bật: bỏ khỏi các việc dữ liệu nội bộ để không gửi nhầm.
    const a = aiAssignStore.get()
    const dropped = AI_JOBS.filter((j) => (a.jobs[j.id].primary === p.id || a.jobs[j.id].fallback === p.id) && !allowed(p, j.id, a.internal_only))
    if (dropped.length) return fail(400, 'privacy_rule', `This profile is assigned to ${dropped.map((j) => JOB_NAME[j.id]).join(', ')}, which send internal data, and the privacy rule only allows internal profiles. Unassign it there first or switch the rule off.`)
    aiProfilesStore.update((l) => l.map((x) => (x.id === p.id ? p : x)))
    if (!sameConnection(cur, p)) setLastTest(p.id, null) // another address, model or key (the mock keeps only its last 4) : the old test does not hold
    syncConfig()
    audit('ai.profile.edit', p.name, `${p.kind}, ${p.location}, model=${p.model}${ok.key ? ', key changed' : ''}`)
    return HttpResponse.json(profileView(p))
  }),
  http.delete(`${API}/ai/profiles/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const cur = aiProfilesStore.get().find((p) => p.id === params.id)
    if (!cur) return fail(404, 'not_found', 'This AI profile no longer exists.')
    const cleared: AiJob[] = []
    aiAssignStore.update((a) => ({ ...a, jobs: Object.fromEntries(AI_JOBS.map((j) => {
      const s = a.jobs[j.id]
      if (s.primary !== cur.id && s.fallback !== cur.id) return [j.id, s]
      cleared.push(j.id)
      // hồ sơ chính bị xoá thì hồ sơ dự phòng lên làm chính
      return [j.id, s.primary === cur.id ? { primary: s.fallback, fallback: null } : { primary: s.primary, fallback: null }]
    })) as AiAssign }))
    aiProfilesStore.update((l) => l.filter((p) => p.id !== cur.id))
    setLastTest(cur.id, null)
    syncConfig()
    audit('ai.profile.remove', cur.name)
    return HttpResponse.json({ cleared_jobs: cleared })
  }),
  http.post(`${API}/ai/profiles/test`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<ProfileInput>(request)
    const cur = b.id ? aiProfilesStore.get().find((p) => p.id === b.id) : undefined
    const ok = checkProfile({ ...b, name: b.name || cur?.name || 'Test', daily_cap: 1000 }, cur); if (ok instanceof Response) return ok
    // only a test of the profile exactly as saved is its last test (the saved key typed again counts, like the box); a draft or another key is not
    const asSaved = cur && sameConnection(cur, toStored({ ...(b as ProfileInput), daily_cap: cur.daily_cap }, ok, cur.id, cur)) ? cur : undefined
    const failed = (code: string, msg: string) => { if (asSaved) setLastTest(asSaved.id, { at: nowIso(), ok: false, detail: msg }); return fail(502, code, msg) }
    if (ok.url.hostname.includes('unreachable')) return failed('unreachable', `Could not connect to ${ok.url.hostname}. Check the address, the box's network and the firewall.`)
    if (ok.key?.startsWith('bad')) return failed('key_rejected', 'The provider rejected the key (HTTP 401). Check the key has not expired and belongs to this provider.')
    if (asSaved) setLastTest(asSaved.id, { at: nowIso(), ok: true, detail: '' })
    recordAiRun('connection-test', 42, 9, b.model, { id: cur?.id ?? 'draft', name: ok.name, kind: b.kind!, api_style: ok.style, base_url: ok.url.toString(), model: b.model!, key_last4: null, location: b.location!, daily_cap: 1000 })
    recordActivity({ job: 'connection-test', profile: ok.name, model: b.model!, hooks: [], tools: [], input: 'ping', output: 'pong', summary: `Connection test of ${ok.name}`, tokens_in: 42, tokens_out: 9, result: 'ok' }) // three requests: plain, tools, JSON format
    audit('ai.test', ok.name, `model=${b.model}`)
    return HttpResponse.json({ ok: true, latency_ms: b.location === 'internal' ? 180 : 420, tokens_in: 42, tokens_out: 9, capabilities: { tools: true, structured: true } })
  }),

  http.get(`${API}/ai/assignments`, () => guard('viewer') ?? HttpResponse.json(aiAssignStore.get())),
  http.put(`${API}/ai/assignments`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const ok = checkAssign(await body<Assignments>(request)); if (ok instanceof Response) return ok
    aiAssignStore.set(ok)
    audit('ai.assign', 'jobs', `privacy rule ${ok.internal_only ? 'on' : 'off'}`)
    return HttpResponse.json(ok)
  }),
  http.get(`${API}/ai/assignments/suggestion`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(suggest(new URL(request.url).searchParams.get('internal_only') === 'true'))
  }),

  http.get(`${API}/ai/usage`, () => guard('viewer') ?? HttpResponse.json(usage())),
  http.get(`${API}/ai/runs`, () => guard('viewer') ?? HttpResponse.json({ items: allRuns().slice(0, 200) })),
  http.get(`${API}/ai/asks`, () => guard('viewer') ?? HttpResponse.json({ items: asks.get() })),

  http.post(`${API}/ai/ask`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ question: string }>(request)
    const q = String(b.question ?? '').trim()
    if (!aiAvailable('ask-my-data')) return notReady('ask-my-data')
    if (q.length < 3 || q.length > 500) return fail(400, 'invalid_question', 'The question must be 3 to 500 characters. For example: "Which machines still expose RDP?"')
    if (skillsView().find((k) => k.id === 'ask-my-data')?.enabled === false) return fail(409, 'skill_off', 'The "Ask your data" skill is turned off. Turn it on in Settings, AI assistant, Skills.')
    // Hook trước khi gửi AI (S-AI-7): chặn/giữ thì không gọi AI, không tốn token; che thì câu hỏi đã che mới đi tiếp và mới được lưu.
    const defs = activeDefs()
    const pre = runHooks(q, 'before_ai', defs)
    const hooks: HookHit[] = [...pre.hits]
    if (pre.outcome === 'blocked' || pre.outcome === 'held') {
      const refused: AskResult = { id: newId('ask'), question: pre.hits.some((h) => h.id === 'block-pii') ? '[question hidden: contains personal data]' : q, asked_at: nowIso(), answer: [pre.text], table: null, tool_calls: [], citations: [], model: '', profile: '', tokens: { input: 0, output: 0 }, downgraded: null, hooks, memories_suggested: 0 }
      asks.update((l) => [refused, ...l].slice(0, 10))
      recordActivity({ job: 'ask-my-data', profile: '', model: '', hooks: pre.hits.map((h) => h.name), tools: [], input: q, output: pre.text, summary: `Question not sent: ${pre.text}`, tokens_in: 0, tokens_out: 0, result: 'blocked_by_hook' })
      return HttpResponse.json(refused)
    }
    const sent = pre.text
    const ans = answerQuestion(sent)
    // Hook trước khi gọi công cụ và sau khi AI trả lời
    ans.tool_calls = ans.tool_calls.map((tc) => {
      const r = runHooks(tc.args, 'before_tool', defs)
      hooks.push(...r.hits)
      return r.outcome === 'blocked' ? { ...tc, result: `Blocked: ${r.text}` } : r.outcome === 'held' ? { ...tc, result: `Waiting for approval: ${r.text}` } : { ...tc, args: r.text }
    })
    const lines = ans.answer.map((line) => runHooks(line, 'after_ai', defs))
    for (const l of lines) hooks.push(...l.hits)
    const stop = lines.find((l) => l.outcome === 'blocked' || l.outcome === 'held')
    ans.answer = stop ? [stop.text] : lines.map((l) => l.text)
    if (stop) ans.table = null
    const rows = ans.table?.rows.length ?? 0
    const tin = 820 + rows * 35, tout = 140 + rows * 22
    const uniqNames = [...new Set(hooks.map((h) => h.name))]
    const tools = ans.tool_calls.map((tc) => ({ name: tc.tool, access: 'read' as const, args: tc.args.slice(0, 120) }))
    const c = runJob('ask-my-data', tin, tout, sent.slice(0, 80), { hooks: uniqNames, tools, input: sent, output: ans.answer.join('\n'), summary: `Answered: ${sent.slice(0, 80)}`, result: stop || ans.tool_calls.some((tc) => /^(Blocked|Waiting for approval)/.test(tc.result)) ? 'blocked_by_hook' : undefined }); if (c.error) return c.error
    // Memory được dùng thì ghi lần dùng cuối
    const words = new Set(sent.toLowerCase().split(/[^a-z0-9-]+/).filter((w) => w.length >= 5))
    memoryStore.update((l) => l.map((m) => (m.enabled && m.text.toLowerCase().split(/[^a-z0-9-]+/).some((w) => words.has(w)) ? { ...m, last_used_at: nowIso() } : m)))
    const uniq = hooks.filter((h, i) => hooks.findIndex((x) => x.id === h.id && x.action === h.action && x.when === h.when && x.message === h.message) === i)
    const res: AskResult = { id: newId('ask'), question: sent, asked_at: nowIso(), ...ans, model: c.profile!.model, profile: c.profile!.name, tokens: { input: tin, output: tout }, downgraded: c.downgraded!, hooks: uniq, memories_suggested: 0 }
    asks.update((l) => [res, ...l].slice(0, 10))
    // memory suggestions (S-AI-7, D-225): at most one per answer that used a tool, only while allowed, never the same text twice; history reads back 0
    const fact = 'FW-HQ is the only firewall and the gateway of the office network.'
    const fresh = !stop && ans.tool_calls.length > 0 && memorySettings.get().suggest_enabled && !suggestionsStore.get().some((x) => x.text === fact) && !memoryStore.get().some((x) => x.text === fact) && !rejectedTexts.get().includes(fact)
    if (fresh) suggestionsStore.update((l) => [...l, { id: newId('sg'), text: fact, created_at: nowIso(), evidence: `From the question "${sent.slice(0, 150)}"; tools read: ${[...new Set(ans.tool_calls.map((tc) => tc.tool))].join(', ')}` }])
    return HttpResponse.json({ ...res, memories_suggested: fresh ? 1 : 0 })
  }),

  http.get(`${API}/ai/cve/:id/cached`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const id = String(params.id).toUpperCase()
    const ex = explains.get()[id]
    return HttpResponse.json({ explain: ex ? { ...ex, cached: true } : null, news: news.get()[id] ?? null })
  }),

  http.post(`${API}/ai/cve/:id/explain`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiAvailable('explain-finding')) return notReady('explain-finding')
    const id = String(params.id)
    if (!CVE_RE.test(id)) return fail(400, 'invalid_cve', 'A CVE ID looks like CVE-2022-27593.')
    const v = vulnOf(id)
    if (!v) return fail(404, 'unknown_cve', 'This CVE is not on the exploited list the box holds. The AI only explains CVEs the box has data for.')
    const hit = explains.get()[v.cve]
    if (hit) return HttpResponse.json({ ...hit, cached: true })
    const base = buildExplain(v)
    const tin = 1800 + (base.affected === 'no' ? 0 : 450), tout = base.affected === 'no' ? 180 : 780
    const c = runJob('explain-finding', tin, tout, v.cve, { input: `explain ${v.cve}`, output: JSON.stringify(base), summary: `Explained ${v.cve} for the devices on this network` }); if (c.error) return c.error
    const res: ExplainResult = { ...base, cached: false, generated_at: nowIso(), model: c.profile!.model, profile: c.profile!.name, tokens: { input: tin, output: tout } }
    explains.update((m) => ({ ...m, [v.cve]: res }))
    return HttpResponse.json(res)
  }),

  http.post(`${API}/ai/cve/:id/news`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiAvailable('cve-news')) return notReady('cve-news')
    const id = String(params.id)
    if (!CVE_RE.test(id)) return fail(400, 'invalid_cve', 'A CVE ID looks like CVE-2022-27593.')
    const v = vulnOf(id)
    if (!v) return fail(404, 'unknown_cve', 'This CVE is not on the exploited list the box holds, so the box has no source to fetch.')
    const tin = 3400, tout = 700
    const news0 = buildNews(v)
    const c = runJob('cve-news', tin, tout, v.cve, { input: `news ${v.cve}`, output: JSON.stringify(news0), summary: `Summarised advisories for ${v.cve}` }); if (c.error) return c.error // the box fetches the sources itself: the job has no tool (INV-3, FORBID-6)
    const res: NewsResult = { ...news0, generated_at: nowIso(), model: c.profile!.model, profile: c.profile!.name, tokens: { input: tin, output: tout } }
    news.update((m) => ({ ...m, [v.cve]: res }))
    return HttpResponse.json(res)
  }),

  http.get(`${API}/ai/logs/digest`, () => {
    const denied = guard('viewer'); if (denied) return denied
    if (!aiAvailable('log-digest')) return notReady('log-digest')
    const tier = aiConfigStore.get().tier
    const stored = digests.get()[tier]
    if (stored) return HttpResponse.json({ digest: stored })
    const [i, o] = DIGEST_TOKENS[tier]
    const d = buildDigest(tier)
    const p = nameOfJob('log-digest')!
    return HttpResponse.json({ digest: { ...d, generated_at: new Date(Date.now() - (d.empty ? 0 : 36e5)).toISOString(), model: p.model, profile: p.name, tokens: d.empty ? { input: 0, output: 0 } : { input: i, output: o } } })
  }),

  http.post(`${API}/ai/logs/digest`, () => {
    const denied = guard('operator'); if (denied) return denied
    if (!aiAvailable('log-digest')) return notReady('log-digest')
    const tier0 = aiConfigStore.get().tier
    if (buildDigest(tier0).empty) {
      const p = nameOfJob('log-digest')!
      return HttpResponse.json({ digest: { ...buildDigest(tier0), generated_at: nowIso(), model: p.model, profile: p.name, tokens: { input: 0, output: 0 } } satisfies LogDigest })
    }
    const [i, o] = DIGEST_TOKENS[tier0]
    const c = runJob('log-digest', i, o, `tier ${tier0}`, { input: `digest tier ${tier0}`, output: JSON.stringify(buildDigest(tier0)), summary: 'Log digest regenerated', tools: [{ name: 'query_logs', access: 'read', args: `tier=${tier0}` }] }); if (c.error) return c.error
    const t = aiConfigStore.get().tier // có thể vừa bị hạ mức
    const d: LogDigest = { ...buildDigest(t), generated_at: nowIso(), model: c.profile!.model, profile: c.profile!.name, tokens: { input: i, output: o } }
    digests.update((m) => ({ ...m, [t]: d }))
    // memory suggestions (S-AI-7, D-223): only while allowed, never the same text twice; the stored digest reads back 0
    const fact = 'SRV-AD receives RDP only through the VPN.'
    const fresh = memorySettings.get().suggest_enabled && !suggestionsStore.get().some((x) => x.text === fact) && !memoryStore.get().some((x) => x.text === fact) && !rejectedTexts.get().includes(fact)
    if (fresh) suggestionsStore.update((l) => [...l, { id: newId('sg'), text: fact, created_at: nowIso(), evidence: `From the log summary of ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}` }])
    return HttpResponse.json({ digest: { ...d, memories_suggested: fresh ? 1 : 0 } })
  }),
]
