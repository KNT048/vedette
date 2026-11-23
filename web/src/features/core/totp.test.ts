import { describe, expect, it } from 'vitest'
import { base32Decode, base32Encode, newSecret, totpAt, verifyTotp } from './totp'

// RFC 6238 Appendix B, SHA-1, ASCII key "12345678901234567890". The RFC lists 8 digits; an authenticator app uses 6 = the last 6 digits.
const KEY = base32Encode(new TextEncoder().encode('12345678901234567890'))
const VECTORS: [number, string][] = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]

describe('TOTP theo RFC 6238', () => {
  it('base32 key of the RFC test string', () => { expect(KEY).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ') })
  it.each(VECTORS)('T=%i gives %s (last 6 digits)', async (t, full) => {
    expect(await totpAt(KEY, t * 1000)).toBe(full.slice(2))
  })
  it('base32 encodes then decodes to the same bytes, a new key is 32 characters long (20 bytes)', () => {
    const s = newSecret()
    expect(s).toMatch(/^[A-Z2-7]{32}$/)
    expect(base32Encode(base32Decode(s))).toBe(s)
  })
  it('accepts a drift of one 30 second step, refuses a drift of two steps', async () => {
    const now = 1_700_000_000_000
    expect(await verifyTotp(KEY, await totpAt(KEY, now - 30_000), now)).toBe(true)
    expect(await verifyTotp(KEY, await totpAt(KEY, now + 30_000), now)).toBe(true)
    expect(await verifyTotp(KEY, await totpAt(KEY, now - 90_000), now)).toBe(false)
  })
})
