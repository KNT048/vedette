// One place for the tamper-evident log hashes of the mock (DATA_MODEL §5.3, D-57 (14)). The Go side verifies against the same vectors:
// `modules/core/testdata/chain_vectors.json`, generated from this file by `src/lib/chain.test.ts`.
//
//   all three chains (core_audit, ai_activity, resp_log), D-57 (14):
//     hash = lowercase hex SHA-256( prev_hash + "\n" + canon(entry) ), entry = every field of the row except `hash` (prev_hash stays in; the DB-only `seq` never)
//     canon = JSON, object keys sorted by Unicode code point (= UTF-8 byte order), no whitespace, strings escaped like JSON.stringify
//   first entry: prev_hash = GENESIS (64 zeros)
// The mock uses a small synchronous SHA-256 so entries are written in the same tick as the call; a real backend uses the platform crypto.

export const GENESIS = '0'.repeat(64)

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

const byCodePoint = (a: string, b: string) => { const x = [...a], y = [...b]; for (let i = 0; i < Math.min(x.length, y.length); i++) { const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!; if (d) return d } return x.length - y.length }
/** JSON with keys sorted at every level, so the same entry always hashes the same. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort(byCodePoint).map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

/** hash of one chain entry (core_audit, ai_activity, resp_log): the entry carries `prev_hash`, `hash` is not part of it. */
export const canonHash = (e: { prev_hash: string }) => sha256(`${e.prev_hash}\n${canonical(e)}`)
export const respLogHash = canonHash

/** Walk a chain oldest to newest. Returns the 1-based index of the first entry whose link or hash is wrong, or null.
 *  The first entry is the anchor: it may follow entries that aged out under retention, so only its own hash is checked. */
export function firstBrokenCanon(entries: { prev_hash: string; hash: string }[]): number | null {
  for (let i = 0; i < entries.length; i++) {
    const { hash, ...rest } = entries[i]!
    if ((i > 0 && rest.prev_hash !== entries[i - 1]!.hash) || canonHash(rest) !== hash) return i + 1
  }
  return null
}
