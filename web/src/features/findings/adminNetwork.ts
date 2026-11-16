// M2-1: the admin network the person types for the general hardening configs (mitigation INV-8).

const MIN_PREFIX4 = 8 // r1 L1: /0 would make every config a no-op; anything wider than a /8 is not an admin network
const MIN_PREFIX6 = 16

/** IPv4 address as a number, or null. */
function v4(addr: string): number | null {
  const parts = addr.split('.')
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null
  return parts.reduce((n, p) => n * 256 + Number(p), 0)
}

/** IPv6 address: 8 groups of at most 4 hex digits, or fewer with exactly one "::". */
function v6ok(addr: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(addr)) return false
  const halves = addr.split('::')
  if (halves.length > 2) return false
  const groups = (s: string) => (s === '' ? [] : s.split(':'))
  const all = halves.flatMap(groups)
  if (all.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false
  return halves.length === 2 ? all.length < 8 : all.length === 8
}

/** The admin network as the configs take it (a network with its host bits cleared, or one address made /32 or /128), or null. */
export function adminNetwork(raw: string, isV6: boolean): string | null {
  const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(raw.trim())
  if (!m) return null
  const addr = m[1]!
  const bits = m[2] === undefined ? (isV6 ? 128 : 32) : Number(m[2])
  if (!isV6) {
    const n = v4(addr)
    if (n === null || bits > 32 || bits < MIN_PREFIX4) return null
    const net = bits === 0 ? 0 : (n - (n % 2 ** (32 - bits)))
    return `${[24, 16, 8, 0].map((s) => Math.floor(net / 2 ** s) % 256).join('.')}/${bits}`
  }
  if (!v6ok(addr) || bits > 128 || bits < MIN_PREFIX6) return null
  return `${addr.toLowerCase()}/${bits}`
}
