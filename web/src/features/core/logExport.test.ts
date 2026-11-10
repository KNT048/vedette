import { describe, expect, it } from 'vitest'
import { CHAIN_NOTE, chainsOf, collect, isSecretKey, missing, scrub, toCsv } from './logExport'
import { collection } from '@/mocks/db'

describe('log export (S-CORE-6)', () => {
  it('removes secrets at any depth but keeps hashes and token counts', () => {
    const out = scrub([{ id: 1, password: 'p', api_key: 'k', hash: 'h', prev_hash: 'ph', tokens_in: 5, key_last4: '7Qk2', nested: { webhook_url: 'https://x', bot_token: 't', ok: 1 } }]) as Record<string, unknown>[]
    expect(JSON.stringify(out)).not.toMatch(/"p"|"k"|https:\/\/x|"t"/)
    expect(out[0]).toMatchObject({ hash: 'h', prev_hash: 'ph', tokens_in: 5, key_last4: '7Qk2', nested: { ok: 1 } })
  })
  it('tolerates absent collections, filters by date, and keeps chain hashes', () => {
    collection<unknown[]>('ai_activity', () => []).set([{ id: 'a', ts: '2026-01-01T00:00:00Z', hash: 'h1', prev_hash: 'h0' }, { id: 'b', ts: '2026-03-01T00:00:00Z', hash: 'h2', prev_hash: 'h1' }])
    const d = collect(['ai_activity', 'scan_probes', 'honeypot'], '2026-02-01T00:00:00Z', null)
    expect(d.scan_probes).toEqual([])
    expect(d.ai_activity).toEqual([{ id: 'b', ts: '2026-03-01T00:00:00Z', hash: 'h2', prev_hash: 'h1' }])
  })
  it('a whole day is inclusive at the end, and a category with no log is listed as missing', () => {
    collection<unknown[]>('ai_activity', () => []).set([{ id: 'a', ts: '2026-03-01T23:30:00.000Z' }, { id: 'b', ts: '2026-03-02T00:00:00.000Z' }])
    expect(collect(['ai_activity'], '2026-03-01', '2026-03-01').ai_activity).toEqual([{ id: 'a', ts: '2026-03-01T23:30:00.000Z' }])
    expect(missing(['ai_activity', 'audit', 'honeypot'])).toEqual(['honeypot'])
  })
  it('CSV marks a category without source and defuses formulas', () => {
    expect(toCsv({ alerts: [] }, ['alerts'])).toBe('# alerts (no source)\n\n')
    expect(toCsv({ hp: [{ a: '=1+1', n: -5 }] })).toBe("# hp\na,n\n'=1+1,-5\n")
  })
  it('matches secret words in any spelling, keeps hashes and counts, and scrubs JSON held in a string', () => {
    for (const k of ['sessionId', 'Set-Cookie', 'x-jwt', 'dbDSN', 'bearer_x', 'connection_string', 'slack-webhook', 'API-Key', 'key', 'client_secret', 'Authorization']) expect(isSecretKey(k), k).toBe(true)
    for (const k of ['key_last4', 'tokens_in', 'tokens_out', 'token_id', 'prev_hash', 'head_hash', 'hash', 'keyboard', 'id', 'src_ip']) expect(isSecretKey(k), k).toBe(false)
    expect(scrub({ events: '{"text":"x","api_token":"t","n":[{"password":"p","ok":1}]}', plain: 'a {not json', list: '[1,{"secret":2}]' })).toEqual({ events: '{"text":"x","n":[{"ok":1}]}', plain: 'a {not json', list: '[1,{}]' })
  })
  it('does not scrub a chained category: that would break its hashes; and says where each chain sits', () => {
    const h = (n: number) => String(n).repeat(64)
    collection<unknown[]>('ai_activity', () => []).set([
      { id: 'a', ts: '2026-03-01T00:00:00.000Z', prev_hash: '0'.repeat(64), hash: h(1), token: 'kept-as-stored' },
      { id: 'b', ts: '2026-03-02T00:00:00.000Z', prev_hash: h(1), hash: h(2) },
      { id: 'c', ts: '2026-03-03T00:00:00.000Z', prev_hash: h(2), hash: h(3) },
    ])
    const all = collect(['ai_activity'], null, null)
    expect(all.ai_activity[0]).toMatchObject({ token: 'kept-as-stored' })
    expect(chainsOf(['ai_activity'], all).ai_activity).toEqual({ anchor: '0'.repeat(64), anchor_kind: 'genesis', head_hash: h(3), count: 3, complete: true })
    const mid = collect(['ai_activity'], '2026-03-02', '2026-03-02')
    expect(mid.ai_activity.map((r) => (r as { id: string }).id)).toEqual(['b'])
    expect(chainsOf(['ai_activity'], mid).ai_activity).toEqual({ anchor: h(1), anchor_kind: 'row', head_hash: h(3), count: 3, complete: false })
    expect(CHAIN_NOTE).toContain('"\\n"')
    expect(CHAIN_NOTE).not.toContain('first entry')
  })
  it('CSV guards header cells as well as values', () => {
    expect(toCsv({ x: [{ '=cmd': 1 }] })).toBe("# x\n'=cmd\n1\n")
  })
  it('CSV has one headed block per category and quotes commas', () => {
    expect(toCsv({ audit: [{ a: 'x,y', b: 1 }], alerts: [] })).toBe('# audit\na,b\n"x,y",1\n\n# alerts\n\n')
  })
})
