import { describe, expect, it } from 'vitest'
import { collect, missing, scrub, toCsv } from './logExport'
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
  it('CSV has one headed block per category and quotes commas', () => {
    expect(toCsv({ audit: [{ a: 'x,y', b: 1 }], alerts: [] })).toBe('# audit\na,b\n"x,y",1\n\n# alerts\n\n')
  })
})
