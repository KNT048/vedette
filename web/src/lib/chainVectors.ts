// Shared test vectors for the tamper-evident logs (DATA_MODEL §5.3, D-57 (14)). Built from the mock implementation in ./chain.ts and written to
// `modules/core/testdata/chain_vectors.json` by `pnpm chain-vectors`; `chain.test.ts` fails when the committed file is out of date.
// The Go side (`core/audit`) must reproduce every `hash` below and report `broken_at` the same way (1-based, first bad entry).
import { canonHash, canonical, firstBrokenCanon, GENESIS, sha256 } from './chain'

type Row = Record<string, unknown>

const seal = (prev: string, e: Row) => { const core = { ...e, prev_hash: prev } as Row & { prev_hash: string }; return { ...core, hash: canonHash(core) } }
const sealAll = (rows: Row[]) => { let prev = GENESIS; return rows.map((r) => { const e = seal(prev, r); prev = e.hash; return e }) }

const nasty = 'quote " backslash \\ ctrl \u0001\u001f tab\t nl\n cr\r <script>&amp;</script> ls\u2028 ps\u2029 Tiếng Việt: đường, Ơ ơ ư 😀 \u007f \u0000 end'
const audit = sealAll([
  { id: 'au-1', ts: '2026-11-09T01:00:00.000Z', user: 'admin@acme.example', action: 'module.enable', target: 'scan', detail: null },
  { id: 'au-2', ts: '2026-11-09T01:00:05.250Z', user: 'system', action: 'feeds.fetch', target: 'cisa-kev', detail: 'added 3, changed 0' },
  { id: 'au-3', ts: '2026-11-09T01:02:00.000Z', user: 'it@acme.example', action: 'inventory.add_manual', target: 'Máy in "Tầng 2" <b>&</b>', detail: nasty },
])

const tool = (name: string, access: string, args: string) => ({ name, access, args })
const ai = sealAll([
  { id: 'act-1', ts: '2026-11-03T08:00:00.000Z', job: 'ask-my-data', profile: 'Claude Sonnet', model: 'claude-sonnet-5-5', trigger: 'user:it@acme.example', hooks: [], tools: [tool('list_assets', 'read', 'filter=service:rdp')], input_hash: sha256('ask-my-data:input'), output_hash: sha256('ask-my-data:output'), summary: 'Listed machines that expose RDP: 3 found', tokens_in: 1180, tokens_out: 310, result: 'ok' },
  { id: 'act-2', ts: '2026-11-06T09:30:00.000Z', job: 'ask-my-data', profile: '', model: '', trigger: 'user:it@acme.example', hooks: ['Block personal data'], tools: [], input_hash: sha256('blocked'), output_hash: sha256(''), summary: 'Question refused before sending', tokens_in: 0, tokens_out: 0, result: 'blocked_by_hook', links: [{ kind: 'proposal', id: 'rp-9' }] },
  { id: 'act-3', ts: '2026-11-08T23:59:59.999Z', job: 'weekly-report', profile: 'Claude Haiku', model: 'claude-haiku-5-5', trigger: 'system:schedule', hooks: [], tools: [tool('query_logs', 'read', 'since=24h'), tool('http_get', 'read', 'host=cisa.gov')], input_hash: sha256('x'), output_hash: sha256('y'), summary: nasty, tokens_in: 4100, tokens_out: 700, result: 'fallback_used' },
  // key order edge cases: an astral key (U+1F600) sorts after a BMP key above U+D800 (U+FF5E) by code point and by UTF-8 bytes, not by UTF-16 units; nested objects; null values
  { id: 'act-4', ts: '2026-11-09T00:00:00.000Z', job: 'x', profile: 'p', model: 'm', trigger: 'system', hooks: [], tools: [], input_hash: sha256('4'), output_hash: sha256('4'), summary: 's', tokens_in: 1, tokens_out: 2, result: 'ok', links: [{ kind: 'action', id: 'a-1', '😀': 1, '\uff5e': { z: null, a: [1, { b: null, B: 'upper' }] }, 'é': 2, e: 3 }] },
])

const resp = sealAll([
  { id: 'rl-1', ts: '2026-11-09T02:00:00.000Z', kind: 'rule_fired', actor: 'rule:Block known-bad destinations', detail: 'PC-SALES-02 connected to 185.220.101.47 (Tor exit list, confidence 0.92)' },
  { id: 'rl-2', ts: '2026-11-09T02:00:01.000Z', kind: 'request', actor: 'system', detail: 'Add 185.220.101.47 to the block list; needs approval' },
  { id: 'rl-3', ts: '2026-11-09T02:05:00.000Z', kind: 'approved', actor: 'admin@acme.example (app)', detail: nasty },
])

const vec = (chain: string, rows: (Row & { prev_hash: string; hash: string })[]) => rows.map(({ hash, ...entry }) => ({ chain, prev: entry.prev_hash, entry, hash }))

const rehash = ({ hash: _old, ...rest }: Row & { hash: unknown }, prev: string) => canonHash({ ...rest, prev_hash: prev })
const tamper = (rows: Row[], i: number, patch: Row) => rows.map((r, j) => (j === i ? { ...r, ...patch } : r))
const missing = (rows: Row[], i: number) => rows.filter((_, j) => j !== i)

export function chainVectors() {
  const canonCases: unknown[] = [
    { b: 1, a: { d: 1, c: [2, { z: null, y: 'x' }] } }, [], {}, null, 'é"\\\n', 0, 2147483647, true, { k: '' },
    { '😀': 1, '\uff5e': 2, a: 3, 'é': 4, B: 5 }, 'a\u2028b\u2029c <>&', 'ctrl \u0001 \u001f \u007f \u0000 "q" \\',
  ]
  return {
    version: 2,
    notes: [
      'genesis: prev_hash of the first entry of a chain.',
      'ONE formula for core_audit, ai_activity and resp_log (D-57 (14)): hash = lowercase hex SHA-256( prev_hash + "\\n" + canon(entry) ) over UTF-8 bytes, where entry = every field of the row except `hash` (prev_hash stays inside the entry; the DB-only `seq` is never part of it).',
      'canon: JSON, object keys sorted ascending by Unicode code point (same as UTF-8 byte order, NOT UTF-16 order: U+1F600 sorts after U+FF5E) at every depth, no whitespace, strings escaped like JS JSON.stringify (so \\u0000-\\u001f as \\u00XX or short form, `"` and `\\` escaped, U+007F, U+2028, U+2029, <, >, & and non-ASCII written raw: Go must disable HTML escaping and keep U+2028/2029 raw), null kept, absent keys omitted, integers without a decimal point.',
      'vectors: entries of one chain are in order; each `prev` equals the previous entry hash (genesis for the first) and also appears inside `entry.prev_hash`.',
      'tampered cases: broken_at is the 1-based index of the first entry whose prev_hash does not equal the previous hash, or whose hash does not match its recomputation; the first entry is only checked against its own hash (it may follow pruned entries).',
    ],
    genesis: GENESIS,
    sha256: ['', 'abc', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', 'tiếng Việt', 'a'.repeat(1000)].map((input) => ({ input, hex: sha256(input) })),
    canon: canonCases.map((value) => ({ value, canon: canonical(value) })),
    vectors: [...vec('core_audit', audit), ...vec('ai_activity', ai), ...vec('resp_log', resp)],
    tampered: [
      { chain: 'core_audit', description: 'detail edited in entry 2', entries: tamper(audit, 1, { detail: 'added 4, changed 0' }), broken_at: 2 },
      { chain: 'core_audit', description: 'entry 2 removed (entry 3 no longer links)', entries: missing(audit, 1), broken_at: 2 },
      { chain: 'ai_activity', description: 'tokens edited in entry 1', entries: tamper(ai, 0, { tokens_in: 1 }), broken_at: 1 },
      { chain: 'ai_activity', description: 'prev_hash of entry 3 replaced with a valid-looking value and re-hashed', entries: tamper(ai, 2, { prev_hash: GENESIS, hash: rehash(ai[2]!, GENESIS) }), broken_at: 3 },
      { chain: 'resp_log', description: 'detail edited in entry 2', entries: tamper(resp, 1, { detail: 'edited' }), broken_at: 2 },
    ].map((c) => { const at = firstBrokenCanon(c.entries as never); if (at !== c.broken_at) throw new Error(`vector "${c.description}" breaks at ${at}, not ${c.broken_at}`); return c }),
  }
}
