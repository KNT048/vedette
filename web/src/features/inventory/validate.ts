// Kiểm tra nhanh phía trình duyệt để báo lỗi sớm; máy chủ (mock, rồi backend) vẫn validate lại (SYS-2).
export const IPV4_RE_UI = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export const CIDR_RE_UI = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/

const toInt = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const toIp = (n: number) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.')
/** CIDR đã qua CIDR_RE_UI → khoảng [base, base + size). */
export function cidrRange(c: string) {
  const [ip, len] = c.split('/') as [string, string]
  const size = 2 ** (32 - Number(len))
  return { base: toInt(ip), size, network: `${toIp(Math.floor(toInt(ip) / size) * size)}/${len}` }
}
const PRIVATE_BLOCKS = [cidrRange('10.0.0.0/8'), cidrRange('172.16.0.0/12'), cidrRange('192.168.0.0/16'), cidrRange('100.64.0.0/10')]
/** Cả dải nằm trong 10/8, 172.16/12, 192.168/16 (RFC 1918) hoặc 100.64/10 (RFC 6598, CGNAT/Tailscale, D-461; phần còn lại
 * của 100/8 là công cộng). Cùng luật với `core/localnet` của backend. */
export const isPrivateCidr = (c: string) => { const r = cidrRange(c); const base = Math.floor(r.base / r.size) * r.size; return PRIVATE_BLOCKS.some((b) => base >= b.base && base + r.size <= b.base + b.size) }
/** Tên các dải nội bộ trong câu báo lỗi `public_range` (giống `localnet.Names` của backend). */
export const LOCAL_RANGE_NAMES = '10.x, 172.16-31.x, 192.168.x, 100.64-127.x'
export const hasHostBits = (c: string) => { const r = cidrRange(c); return r.base % r.size !== 0 }
/** Dải đầu tiên trong `list` chồng lên `c` (trùng một phần hoặc lồng nhau), nếu có. */
export function overlapping(c: string, list: string[]): string | undefined {
  const r = cidrRange(c)
  return list.find((o) => { if (o === c) return false; const q = cidrRange(o); return r.base < q.base + q.size && q.base < r.base + r.size })
}

/**
 * Chuẩn hoá một dải mạng người dùng gõ. CHỈ xoá bit máy: "192.168.18.5/24" → "192.168.18.0/24" (note 'network', giao diện nói rõ).
 * Địa chỉ không có /prefix KHÔNG được đoán (mạng có thể là /23, /24 hay /25): giữ nguyên để báo lỗi 'noPrefix' (chủ dự án, D-28).
 */
export function normalizeRange(raw: string): { value: string; note: 'network' | null } {
  const v = raw.trim()
  if (CIDR_RE_UI.test(v) && hasHostBits(v)) return { value: cidrRange(v).network, note: 'network' }
  return { value: v, note: null }
}
/** Lý do một dải không dùng được, hoặc null nếu hợp lệ. `others` để phát hiện chồng lấn. */
export function rangeProblem(v: string, others: string[]): 'noPrefix' | 'format' | 'hostBits' | 'notPrivate' | 'overlap' | null {
  if (IPV4_RE_UI.test(v)) return 'noPrefix'
  if (!CIDR_RE_UI.test(v)) return 'format'
  if (hasHostBits(v)) return 'hostBits'
  if (!isPrivateCidr(v)) return 'notPrivate'
  return overlapping(v, others) ? 'overlap' : null
}
