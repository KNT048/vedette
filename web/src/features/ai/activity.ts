// AI activity log (S-AI-8, D-48): every AI call is written to `ai_activity` as a hash chain, so nothing can be changed or removed unnoticed.
// hash = SHA-256(prev_hash + canonical JSON of the entry without `hash`), see src/lib/chain.ts (DATA_MODEL §5.3). Tests cross-check it against Node's webcrypto.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import { canonHash, canonical, firstBrokenCanon, GENESIS, sha256 } from '@/lib/chain'
import type { ActivityEntry, ActivityResult, ActivityTool, ActivityVerify } from './types'

export { canonical, GENESIS, sha256 }
export const entryHash = (e: Omit<ActivityEntry, 'hash'>) => canonHash(e)

/** Walk the chain oldest to newest. The first entry is the anchor (older ones may have aged out under retention). */
export function verifyChain(entries: ActivityEntry[]): ActivityVerify {
  const at = firstBrokenCanon(entries)
  if (at === null) return { ok: true, count: entries.length, broken_at: null, entry_id: null }
  return { ok: false, count: entries.length, broken_at: at, entry_id: entries[at - 1]!.id }
}
export const DEFAULT_RETENTION = 365
export const MIN_RETENTION = 90

// ---- Store (oldest first)
export type ActivityInput = Omit<ActivityEntry, 'id' | 'ts' | 'prev_hash' | 'hash' | 'input_hash' | 'output_hash'> & { input: string; output: string; ts?: string }
function seal(prev: string, a: ActivityInput): ActivityEntry {
  const { input, output, ts, ...rest } = a
  const e = { ...rest, id: newId('act'), ts: ts ?? nowIso(), input_hash: sha256(input), output_hash: sha256(output), prev_hash: prev }
  return { ...e, hash: entryHash(e) }
}
const sample = (days: number, job: string, profile: string, model: string, trigger: string, result: ActivityResult, summary: string, tin: number, tout: number, tools: ActivityTool[] = [], hooks: string[] = []): ActivityInput =>
  ({ ts: daysAgo(days), job, profile, model, trigger, result, summary, tokens_in: tin, tokens_out: tout, tools, hooks, input: `${job}:${summary}`, output: summary })
const seedEntries = (): ActivityEntry[] => {
  let prev = GENESIS
  return [
    sample(6, 'ask-my-data', 'Claude Sonnet', 'claude-sonnet-5-5', 'user:it@acme.example', 'ok', 'Listed machines that expose RDP: 3 found', 1180, 310, [{ name: 'list_assets', access: 'read', args: 'filter=service:rdp' }]),
    sample(5, 'explain-finding', 'Claude Sonnet', 'claude-sonnet-5-5', 'user:it@acme.example', 'ok', 'Explained CVE-2022-27593 for the NAS', 2250, 780),
    sample(4, 'log-digest', 'Company Ollama server', 'qwen3:8b', 'system:schedule', 'ok', 'Daily log digest: 2 items need a look', 4800, 900, [{ name: 'query_logs', access: 'read', args: 'since=24h' }]),
    sample(3, 'ask-my-data', '', '', 'user:it@acme.example', 'blocked_by_hook', 'Question refused before sending: contained personal data', 0, 0, [], ['Block personal data']),
    sample(2, 'cve-news', 'Claude Haiku', 'claude-haiku-5-5', 'user:admin@acme.example', 'fallback_used', 'Advisories summarised on the fallback profile', 4100, 700), // no tool: the box fetches, the AI only summarises
    sample(1, 'weekly-report', 'Claude Haiku', 'claude-haiku-5-5', 'system:schedule', 'error', 'Monthly AI budget used up; nothing was sent', 0, 0),
  ].map((s) => { const e = seal(prev, s); prev = e.hash; return e })
}
export const activityStore = collection<ActivityEntry[]>('ai_activity', seedEntries, () => [])
export const retentionStore = collection<{ retention_days: number }>('ai_activity_settings', () => ({ retention_days: DEFAULT_RETENTION }))

/** Append one entry to the chain. Called wherever the mock records an AI call. Entries are never edited; only age removes the oldest. */
export function recordActivity(a: Omit<ActivityInput, 'trigger'> & { trigger?: string }): ActivityEntry {
  const list = activityStore.get()
  const trigger = a.trigger ?? (currentUser() ? `user:${currentUser()!.email}` : 'system')
  const e = seal(list.at(-1)?.hash ?? GENESIS, { ...a, trigger })
  const cutoff = Date.now() - retentionStore.get().retention_days * 864e5
  activityStore.set([...list, e].filter((x) => Date.parse(x.ts) >= cutoff))
  return e
}

const inRange = (ts: string, from: string | null, to: string | null) => (!from || ts >= from) && (!to || ts <= to)

export const activityHandlers = [
  http.get(`${API}/ai/activity`, ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const q = new URL(request.url).searchParams
    const job = q.get('job'), result = q.get('result'), from = q.get('from'), to = q.get('to')
    const all = activityStore.get()
    const items = all.filter((e) => (!job || e.job === job) && (!result || e.result === result) && inRange(e.ts, from, to)).reverse()
    return HttpResponse.json({ items, total: all.length, retention_days: retentionStore.get().retention_days })
  }),
  http.get(`${API}/ai/activity/verify`, () => guard('operator') ?? HttpResponse.json(verifyChain(activityStore.get()))),
  http.get(`${API}/ai/activity/settings`, () => guard('admin') ?? HttpResponse.json(retentionStore.get())),
  http.put(`${API}/ai/activity/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ retention_days: number }>(request)
    const d = Number(b.retention_days)
    if (!Number.isInteger(d) || d < MIN_RETENTION || d > 3650) return fail(400, 'invalid_retention', `Keep the AI activity log for at least ${MIN_RETENTION} days (up to 3650).`)
    retentionStore.set({ retention_days: d })
    audit('ai.activity_retention', `${d} days`)
    return HttpResponse.json({ retention_days: d })
  }),
]
