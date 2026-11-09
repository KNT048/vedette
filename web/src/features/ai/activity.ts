// AI activity log (S-AI-8, D-48): every AI call is written to `ai_activity` as a hash chain, so nothing can be changed or removed unnoticed.
// hash = SHA-256(prev_hash + canonical JSON of the entry without `hash`). The mock uses a small synchronous SHA-256 so entries are written
// in the same tick as the call; a real backend uses the platform crypto. Tests cross-check it against Node's webcrypto.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import type { ActivityEntry, ActivityResult, ActivityTool, ActivityVerify } from './types'

export const GENESIS = '0'.repeat(64)
export const DEFAULT_RETENTION = 365
export const MIN_RETENTION = 90

// ---- SHA-256 (FIPS 180-4), text in, lowercase hex out
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])
export function sha256(text: string): string {
  const data = new TextEncoder().encode(text)
  const len = data.length
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6)
  padded.set(data)
  padded[len] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, Math.floor((len * 8) / 2 ** 32))
  dv.setUint32(padded.length - 4, (len * 8) >>> 0)
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  const rr = (x: number, n: number) => (x >>> n) | (x << (32 - n))
  for (let o = 0; o < padded.length; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4)
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!, b = w[i - 2]!
      w[i] = (w[i - 16]! + (rr(a, 7) ^ rr(a, 18) ^ (a >>> 3)) + w[i - 7]! + (rr(b, 17) ^ rr(b, 19) ^ (b >>> 10))) >>> 0
    }
    let [a, b, c, d, e, f, g, hh] = h as unknown as number[]
    for (let i = 0; i < 64; i++) {
      const t1 = (hh! + (rr(e!, 6) ^ rr(e!, 11) ^ rr(e!, 25)) + ((e! & f!) ^ (~e! & g!)) + K[i]! + w[i]!) >>> 0
      const t2 = ((rr(a!, 2) ^ rr(a!, 13) ^ rr(a!, 22)) + ((a! & b!) ^ (a! & c!) ^ (b! & c!))) >>> 0
      hh = g; g = f; f = e; e = (d! + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    ;[a, b, c, d, e, f, g, hh].forEach((v, i) => { h[i] = (h[i]! + v!) >>> 0 })
  }
  return [...h].map((v) => v.toString(16).padStart(8, '0')).join('')
}

/** JSON with keys sorted at every level, so the same entry always hashes the same. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

export const entryHash = (e: Omit<ActivityEntry, 'hash'>) => sha256(e.prev_hash + canonical(e))

/** Walk the chain oldest to newest. The first entry is the anchor (older ones may have aged out under retention). */
export function verifyChain(entries: ActivityEntry[]): ActivityVerify {
  for (let i = 0; i < entries.length; i++) {
    const { hash, ...rest } = entries[i]!
    const linked = i === 0 || rest.prev_hash === entries[i - 1]!.hash
    if (!linked || entryHash(rest) !== hash) return { ok: false, count: entries.length, broken_at: i + 1, entry_id: rest.id }
  }
  return { ok: true, count: entries.length, broken_at: null, entry_id: null }
}

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
    sample(2, 'cve-news', 'Claude Haiku', 'claude-haiku-5-5', 'user:admin@acme.example', 'fallback_used', 'Advisories summarised on the fallback profile', 4100, 700, [{ name: 'http_get', access: 'read', args: 'host=cisa.gov' }]),
    sample(1, 'weekly-report', 'Claude Haiku', 'claude-haiku-5-5', 'system:schedule', 'error', 'Daily token cap reached; nothing was sent', 0, 0),
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
