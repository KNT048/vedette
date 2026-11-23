// A quick check in the browser to report errors early; the server (mock, then the backend) validates again (SYS-2).
export const IPV4_RE_UI = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export const CIDR_RE_UI = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/

const toInt = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const toIp = (n: number) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.')
/** A CIDR that passed CIDR_RE_UI → the range [base, base + size). */
export function cidrRange(c: string) {
  const [ip, len] = c.split('/') as [string, string]
  const size = 2 ** (32 - Number(len))
  return { base: toInt(ip), size, network: `${toIp(Math.floor(toInt(ip) / size) * size)}/${len}` }
}
const PRIVATE_BLOCKS = [cidrRange('10.0.0.0/8'), cidrRange('172.16.0.0/12'), cidrRange('192.168.0.0/16'), cidrRange('100.64.0.0/10')]
/** The whole range is inside 10/8, 172.16/12, 192.168/16 (RFC 1918) or 100.64/10 (RFC 6598, CGNAT/Tailscale; the rest
 * of 100/8 is public). The same rule as the backend's `core/localnet`. */
export const isPrivateCidr = (c: string) => { const r = cidrRange(c); const base = Math.floor(r.base / r.size) * r.size; return PRIVATE_BLOCKS.some((b) => base >= b.base && base + r.size <= b.base + b.size) }
/** The names of the internal ranges in the `public_range` error sentence (same as the backend's `localnet.Names`). */
export const LOCAL_RANGE_NAMES = '10.x, 172.16-31.x, 192.168.x, 100.64-127.x'
export const hasHostBits = (c: string) => { const r = cidrRange(c); return r.base % r.size !== 0 }
/** The first range in `list` that overlaps `c` (partly the same or nested), if any. */
export function overlapping(c: string, list: string[]): string | undefined {
  const r = cidrRange(c)
  return list.find((o) => { if (o === c) return false; const q = cidrRange(o); return r.base < q.base + q.size && q.base < r.base + r.size })
}

/**
 * Normalise a network range the user typed. ONLY clears the host bits: "192.168.142.5/24" → "192.168.142.0/24" (note 'network', the UI says so plainly).
 * An address without /prefix is NOT guessed (the network could be /23, /24 or /25): kept as is to report the 'noPrefix' error (a product decision).
 */
export function normalizeRange(raw: string): { value: string; note: 'network' | null } {
  const v = raw.trim()
  if (CIDR_RE_UI.test(v) && hasHostBits(v)) return { value: cidrRange(v).network, note: 'network' }
  return { value: v, note: null }
}
/** The reason a range cannot be used, or null if valid. `others` is for detecting overlaps. */
export function rangeProblem(v: string, others: string[]): 'noPrefix' | 'format' | 'hostBits' | 'notPrivate' | 'overlap' | null {
  if (IPV4_RE_UI.test(v)) return 'noPrefix'
  if (!CIDR_RE_UI.test(v)) return 'format'
  if (hasHostBits(v)) return 'hostBits'
  if (!isPrivateCidr(v)) return 'notPrivate'
  return overlapping(v, others) ? 'overlap' : null
}

/** At most 8 SNMP credentials (409 too_many on the server). */
export const SNMP_MAX = 8
