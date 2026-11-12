
/** Tách ra để test thay được (jsdom không cho đổi location.reload). */
export const nav = { reload: () => window.location.reload(), toSetup: () => window.location.assign('/setup') }

/** Dải LAN phải là địa chỉ nội bộ (khớp luật của module kiểm kê): 10/8, 172.16/12, 192.168/16. Tiền tố ngắn hơn
 * (ví dụ 10.0.0.0/0) bao trùm cả Internet nên bị từ chối. */
export function isPrivateCidr(c: string): boolean {
  const [ip = '', p = ''] = c.split('/')
  const [a = 0, b = 0] = ip.split('.').map(Number)
  const bits = Number(p)
  return (a === 10 && bits >= 8) || (a === 172 && b >= 16 && b <= 31 && bits >= 12) || (a === 192 && b === 168 && bits >= 16)
}

export const CIDR_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
export const MIN_PASSWORD = 12
export const MAX_UPLOAD = 5 * 1024 * 1024

const IPV4_BARE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export interface NormalisedCidr { value: string; note: 'prefix' | 'network' | null }
/** Địa chỉ trần, thiếu độ dài tiền tố: KHÔNG tự đoán /24 (dải có thể là /25, /23…) — kien 2026-11-06. */
export const isBareIp = (raw: string) => IPV4_BARE.test(raw.trim())
/**
 * Chuẩn hoá một dải mạng người dùng gõ. Bắt buộc có tiền tố ("192.168.18.0/24"); thiếu tiền tố → null
 * (dùng isBareIp để báo đúng lỗi). "192.168.18.5/24" có bit máy → "192.168.18.0/24" (note 'network', giữ nguyên tiền tố).
 */
export function normaliseCidr(raw: string): NormalisedCidr | null {
  const s = raw.trim()
  let note: NormalisedCidr['note'] = null
  if (!CIDR_RE.test(s)) return null
  const [ip = '', p = ''] = s.split('/')
  const bits = Number(p)
  const n = ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0)
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  const net = (n & mask) >>> 0
  if (net !== n) note = 'network'
  return { value: `${[24, 16, 8, 0].map((sh) => (net >>> sh) & 255).join('.')}/${bits}`, note }
}

/** Every IANA zone the browser knows, plus UTC (supportedValuesOf leaves it out). */
export const TIMEZONES: string[] = [...new Set([...Intl.supportedValuesOf('timeZone'), 'UTC'])].sort()
export const browserTimeZone = (): string | null => {
  const z = Intl.DateTimeFormat().resolvedOptions().timeZone
  return TIMEZONES.includes(z) ? z : null
}

export async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let s = ''
  bytes.forEach((b) => { s += String.fromCharCode(b) })
  return btoa(s)
}
export function fromBase64(b64: string): string {
  const s = atob(b64)
  return new TextDecoder().decode(Uint8Array.from(s, (c) => c.charCodeAt(0)))
}

/** So sánh phiên bản dạng 1.2.3 / 20261106.08 / 0.10.0-beta.1 (bản beta nhỏ hơn bản chính thức cùng số). */
export function compareVersion(a: string, b: string): number {
  const [ma = '', pa] = a.split('-')
  const [mb = '', pb] = b.split('-')
  const xa = ma.split('.').map(Number)
  const xb = mb.split('.').map(Number)
  for (let i = 0; i < Math.max(xa.length, xb.length); i++) {
    const d = (xa[i] ?? 0) - (xb[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  if (pa === pb) return 0
  if (pa === undefined) return 1
  if (pb === undefined) return -1
  return pa < pb ? -1 : 1
}
