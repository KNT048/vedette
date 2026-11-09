import { describe, expect, it } from 'vitest'
const webcrypto = globalThis.crypto // Web Crypto có sẵn trong Node 20+ và jsdom
import { sessionStore } from '@/mocks/stores'
import { activityStore, canonical, GENESIS, recordActivity, sha256, verifyChain } from './activity'

const base = { job: 'ask-my-data', profile: 'p', model: 'm', hooks: [], tools: [], summary: 's', tokens_in: 1, tokens_out: 2, result: 'ok' as const, input: 'in', output: 'out', trigger: 'system' }

describe('ai activity chain (S-AI-8)', () => {
  it('sha256 matches Node webcrypto', async () => {
    for (const s of ['', 'abc', 'x'.repeat(200), 'tiếng Việt']) {
      const d = new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))
      expect(sha256(s)).toBe([...d].map((b) => b.toString(16).padStart(2, '0')).join(''))
    }
  })
  it('records a linked chain that verifies, and detects tampering', () => {
    sessionStore.set({ userId: 'u-admin' })
    activityStore.set([])
    recordActivity(base); recordActivity({ ...base, summary: 'second' }); recordActivity({ ...base, summary: 'third' })
    const list = activityStore.get()
    expect(list[0]!.prev_hash).toBe(GENESIS)
    expect(list[1]!.prev_hash).toBe(list[0]!.hash)
    expect(verifyChain(list)).toMatchObject({ ok: true, count: 3, broken_at: null })
    const edited = structuredClone(list); edited[1]!.summary = 'changed'
    expect(verifyChain(edited)).toMatchObject({ ok: false, broken_at: 2 })
    expect(verifyChain([list[0]!, list[2]!])).toMatchObject({ ok: false, broken_at: 2 })
  })
  it('canonical JSON ignores key order', () => {
    expect(canonical({ b: 1, a: { d: 1, c: 2 } })).toBe(canonical({ a: { c: 2, d: 1 }, b: 1 }))
  })
})
