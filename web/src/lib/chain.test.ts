// The three hash chains (DATA_MODEL §5.3) and the vectors the Go side verifies against (modules/core/testdata/chain_vectors.json).
import { describe, expect, it } from 'vitest'
import vectorsFile from '../../../modules/core/testdata/chain_vectors.json'
import { canonHash, canonical, firstBrokenCanon, GENESIS, respLogHash, sha256 } from './chain'
import { chainVectors } from './chainVectors'
import { auditStore, sessionStore, audit } from '@/mocks/stores'
import { verifyChain as verifyResp } from '@/features/response/logic'

const hexOf = async (s: string) => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('')

describe('hash chains (D-57 (14), DATA_MODEL §5.3)', () => {
  it('the committed vector file is the mock output (run `pnpm chain-vectors` after a change)', () => {
    expect(vectorsFile).toEqual(JSON.parse(JSON.stringify(chainVectors())))
  })

  it('sha256 matches the platform crypto on every vector input', async () => {
    for (const v of chainVectors().sha256) expect(await hexOf(v.input)).toBe(v.hex)
  })

  it('one formula for all three chains: SHA-256(prev_hash + "\\n" + canonical JSON with code-point sorted keys, without hash)', async () => {
    const e = { id: 'x', ts: 't', user: 'u', action: 'a.b', target: 'c', detail: null, prev_hash: GENESIS }
    expect(canonical(e)).toBe(`{"action":"a.b","detail":null,"id":"x","prev_hash":"${GENESIS}","target":"c","ts":"t","user":"u"}`)
    expect(canonHash(e)).toBe(await hexOf(`${GENESIS}\n${canonical(e)}`))
    expect(canonical({ b: 1, a: undefined })).toBe('{"b":1}')
    const r = { id: 'i', ts: 't', kind: 'k', actor: 'a', detail: 'd', prev_hash: GENESIS }
    expect(respLogHash(r)).toBe(await hexOf(`${GENESIS}\n{"actor":"a","detail":"d","id":"i","kind":"k","prev_hash":"${GENESIS}","ts":"t"}`)) // no positional form any more
  })

  it('keys sort by code point, not by UTF-16 unit; special characters are escaped like JSON.stringify', () => {
    expect(canonical({ '😀': 1, '\uff5e': 2, a: 3 })).toBe('{"a":3,"\uff5e":2,"😀":1}')
    expect(canonical('a\u2028b "q" \\ \u0001 <>&')).toBe(JSON.stringify('a\u2028b "q" \\ \u0001 <>&'))
  })

  it('the vector chains link from GENESIS, every entry hashes as stated, and the tampered cases break where stated', () => {
    const v = chainVectors()
    for (const chain of ['core_audit', 'ai_activity', 'resp_log']) {
      const list = v.vectors.filter((x) => x.chain === chain)
      expect(list.length, chain).toBeGreaterThanOrEqual(3)
      expect(list[0]!.prev).toBe(GENESIS)
      list.forEach((x, i) => {
        expect(x.entry.prev_hash).toBe(x.prev)
        expect(x.prev).toBe(i === 0 ? GENESIS : list[i - 1]!.hash)
        expect(canonHash(x.entry as { prev_hash: string })).toBe(x.hash)
      })
      expect(firstBrokenCanon(list.map((x) => ({ ...x.entry, hash: x.hash })) as never)).toBeNull()
    }
    for (const t of v.tampered) expect(firstBrokenCanon(t.entries as never), t.description).toBe(t.broken_at)
  })

  it('the response log verifier uses the same formula', async () => {
    const rows = chainVectors().vectors.filter((x) => x.chain === 'resp_log').map((x) => ({ ...x.entry, hash: x.hash })) as never
    expect(await verifyResp(rows)).toEqual({ ok: true, broken_at: null })
    expect((await verifyResp((rows as { detail: string }[]).map((r, i) => (i === 1 ? { ...r, detail: 'edited' } : r)) as never)).ok).toBe(false)
  })

  it('the mock core_audit store writes a verifiable chain (newest first in the store)', () => {
    sessionStore.set({ userId: 'u-admin' })
    auditStore.set([])
    audit('module.enable', 'scan')
    audit('feeds.fetch', 'cisa-kev', 'added 3')
    audit('user.create', 'hana@acme.example')
    const oldestFirst = [...auditStore.get()].reverse()
    expect(oldestFirst[0]!.prev_hash).toBe(GENESIS)
    expect(oldestFirst[0]!.detail).toBeNull()
    expect(oldestFirst[1]!.prev_hash).toBe(oldestFirst[0]!.hash)
    expect(firstBrokenCanon(oldestFirst)).toBeNull()
    expect(firstBrokenCanon(oldestFirst.map((e, i) => (i === 1 ? { ...e, target: 'x' } : e)))).toBe(2)
  })

  it('sha256 of the empty string is the well-known value', () => {
    expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })
})
