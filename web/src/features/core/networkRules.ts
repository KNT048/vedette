// Validation shared by the Box network form and its mock API (S-CORE-8). The real backend repeats these checks; vedette-host re-checks again before touching the OS (D-55).
import { isBareIp, normaliseCidr } from './util'

export type FilterType = 'cidr' | 'host' | 'port'
export const FILTER_TYPES: FilterType[] = ['cidr', 'host', 'port']
export const HOST_RE = /^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

export const ipInt = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const mask = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0)
export const sameSubnet = (a: string, b: string, prefix: number) => ((ipInt(a) & mask(prefix)) >>> 0) === ((ipInt(b) & mask(prefix)) >>> 0)
const isUsable = (ip: string, prefix: number) => {
  const n = ipInt(ip)
  const first = ip.split('.').map(Number)[0] ?? 0
  if (first === 0 || first === 127 || first >= 224) return false
  const net = (n & mask(prefix)) >>> 0
  return n !== net && n !== (net | (~mask(prefix) >>> 0)) >>> 0
}

export interface StaticInput { address?: unknown; prefix?: unknown; gateway?: unknown; dns?: unknown }
/** Problem with a static management configuration, as a sentence, or null. */
export function staticProblem(v: StaticInput): string | null {
  if (typeof v.address !== 'string' || !isBareIp(v.address)) return 'The IP address must be an IPv4 address like 192.168.10.250.'
  const prefix = typeof v.prefix === 'number' ? v.prefix : Number(v.prefix)
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) return 'The prefix length must be a whole number from 8 to 30 (24 means 255.255.255.0).'
  if (!isUsable(v.address, prefix)) return 'That address is the network or broadcast address of its range, or a reserved address. Pick a host address.'
  if (typeof v.gateway !== 'string' || !isBareIp(v.gateway)) return 'The gateway must be an IPv4 address like 192.168.10.1.'
  if (v.gateway === v.address) return 'The gateway cannot be the same as the box address.'
  if (!sameSubnet(v.address, v.gateway, prefix)) return `The gateway ${v.gateway} is outside ${v.address}/${prefix}. The gateway must be in the same range as the box.`
  const dns = Array.isArray(v.dns) ? v.dns : null
  if (!dns || dns.length < 1 || dns.length > 3) return 'Give 1 to 3 DNS servers.'
  if (dns.some((d) => typeof d !== 'string' || !isBareIp(d))) return 'Each DNS server must be an IPv4 address.'
  if (new Set(dns).size !== dns.length) return 'A DNS server is listed twice.'
  return null
}

/** Problem with one exclusion filter, or null. `value` is normalised by `normaliseFilter`. */
export function filterProblem(type: unknown, value: unknown): string | null {
  const v = typeof value === 'string' ? value.trim() : ''
  if (type !== 'cidr' && type !== 'host' && type !== 'port') return 'The filter type must be a network range, a host or a port.'
  if (!v) return 'Enter a value to exclude.'
  if (type === 'cidr') {
    if (!normaliseCidr(v)) return `"${v}" is not a network range. Write it like 10.0.5.0/24, with the prefix length.`
    if (Number(v.split('/')[1]) < 8) return 'Ranges larger than a /8 cannot be excluded: that would hide almost everything.'
  }
  if (type === 'host' && !isBareIp(v) && !HOST_RE.test(v)) return `"${v}" is not a host. Use an IPv4 address like 10.0.5.20 or a name like backup.lan.`
  if (type === 'port' && !(/^\d{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535)) return `"${v}" is not a port. Use a number from 1 to 65535.`
  return null
}
export const normaliseFilter = (type: FilterType, value: string) => (type === 'cidr' ? (normaliseCidr(value.trim())?.value ?? value.trim()) : type === 'host' ? value.trim().toLowerCase() : String(Number(value.trim())))

/** NTP servers: 1 to 4 hostnames or IPv4 addresses. */
export function ntpProblem(servers: unknown): string | null {
  if (!Array.isArray(servers) || servers.length < 1 || servers.length > 4) return 'Give 1 to 4 NTP servers.'
  for (const s of servers) if (typeof s !== 'string' || (!isBareIp(s) && !HOST_RE.test(s))) return `"${String(s)}" is not a server name or IPv4 address.`
  if (new Set(servers).size !== servers.length) return 'An NTP server is listed twice.'
  return null
}
