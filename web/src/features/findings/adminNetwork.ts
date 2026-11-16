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
  const n = v6(addr)
  if (n === null || bits > 128 || bits < MIN_PREFIX6) return null
  return `${v6text(mask(n, bits, 128))}/${bits}` // r2 L3: host bits cleared, like IPv4
}

/** IPv6 address as a number, or null. */
function v6(addr: string): bigint | null {
  if (!v6ok(addr)) return null
  const halves = addr.split('::')
  const groups = (x: string) => (x === '' ? [] : x.split(':'))
  const head = groups(halves[0]!)
  const tail = halves.length === 2 ? groups(halves[1]!) : []
  const all = [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail]
  return all.reduce((n, g) => (n << 16n) + BigInt(parseInt(g, 16)), 0n)
}

/** The shortest IPv6 text of a number (RFC 5952: the longest run of zero groups as "::"). */
function v6text(n: bigint): string {
  const g = Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(16 * (7 - i))) & 0xffffn))
  let best = -1, len = 0
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue }
    let j = i
    while (j < 8 && g[j] === 0) j++
    if (j - i > len && j - i > 1) { best = i; len = j - i }
    i = j
  }
  const hex = g.map((x) => x.toString(16))
  if (best < 0) return hex.join(':')
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + len).join(':')}`
}

function mask(n: bigint, bits: number, width: number): bigint {
  const host = (1n << BigInt(width - bits)) - 1n
  return n & ~host
}

/** Whether addr is inside the network ("10.0.0.0/24", as adminNetwork gives it); null when the families differ or addr is not one. */
export function inNetwork(addr: string, network: string): boolean | null {
  const [base, b] = network.split('/')
  const bits = Number(b)
  if (base!.includes(':') !== addr.includes(':')) return null
  if (!addr.includes(':')) {
    const a = v4(addr), n = v4(base!)
    if (a === null || n === null) return null
    return mask(BigInt(a), bits, 32) === BigInt(n)
  }
  const a = v6(addr), n = v6(base!)
  if (a === null || n === null) return null
  return mask(a, bits, 128) === n
}
