import { describe, expect, it } from 'vitest'
import { collect, scrub, toCsv } from './logExport'
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
  it('CSV has one headed block per category and quotes commas', () => {
    expect(toCsv({ audit: [{ a: 'x,y', b: 1 }], alerts: [] })).toBe('# audit\na,b\n"x,y",1\n\n# alerts\n\n')
  })
})
