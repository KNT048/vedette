import { describe, expect, it } from 'vitest'
import { base32Decode, base32Encode, newSecret, totpAt, verifyTotp } from './totp'

// RFC 6238 Appendix B, SHA-1, khoá ASCII "12345678901234567890". Bản RFC dùng 8 chữ số; ứng dụng xác thực dùng 6 = 6 chữ số cuối.
const KEY = base32Encode(new TextEncoder().encode('12345678901234567890'))
const VECTORS: [number, string][] = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]

describe('TOTP theo RFC 6238', () => {
  it('khoá base32 của chuỗi thử RFC', () => { expect(KEY).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ') })
  it.each(VECTORS)('T=%i cho %s (6 số cuối)', async (t, full) => {
    expect(await totpAt(KEY, t * 1000)).toBe(full.slice(2))
  })
  it('base32 mã hoá rồi giải mã ra đúng byte, khoá mới dài 32 ký tự (20 byte)', () => {
    const s = newSecret()
    expect(s).toMatch(/^[A-Z2-7]{32}$/)
    expect(base32Encode(base32Decode(s))).toBe(s)
  })
  it('chấp nhận lệch một bước 30 giây, từ chối lệch hai bước', async () => {
    const now = 1_700_000_000_000
    expect(await verifyTotp(KEY, await totpAt(KEY, now - 30_000), now)).toBe(true)
    expect(await verifyTotp(KEY, await totpAt(KEY, now + 30_000), now)).toBe(true)
    expect(await verifyTotp(KEY, await totpAt(KEY, now - 90_000), now)).toBe(false)
  })
})
