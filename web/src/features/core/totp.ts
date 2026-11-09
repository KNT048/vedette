// TOTP thật (RFC 6238, SHA-1, 6 số, 30 giây) bằng Web Crypto: ứng dụng xác thực thật cũng quét/nhập được khoá này.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5 }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export function base32Decode(s: string): Uint8Array {
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of s.replace(/[\s=]/g, '').toUpperCase()) {
    const i = ALPHABET.indexOf(ch)
    if (i < 0) continue
    value = (value << 5) | i
    bits += 5
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  return Uint8Array.from(out)
}

export function newSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)))
}

export async function totpAt(secret: string, ms: number): Promise<string> {
  const counter = Math.floor(ms / 30000)
  const msg = new ArrayBuffer(8)
  new DataView(msg).setUint32(4, counter >>> 0)
  new DataView(msg).setUint32(0, Math.floor(counter / 2 ** 32))
  const key = await crypto.subtle.importKey('raw', base32Decode(secret) as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg))
  const off = (h[19] ?? 0) & 15
  const bin = (((h[off] ?? 0) & 127) << 24) | (((h[off + 1] ?? 0) & 255) << 16) | (((h[off + 2] ?? 0) & 255) << 8) | ((h[off + 3] ?? 0) & 255)
  return String(bin % 1_000_000).padStart(6, '0')
}

/** Chấp nhận lệch ±1 bước (30 giây) như ứng dụng xác thực thông thường. */
export async function verifyTotp(secret: string, code: string, now = Date.now()): Promise<boolean> {
  for (const d of [-1, 0, 1]) if ((await totpAt(secret, now + d * 30000)) === code) return true
  return false
}
