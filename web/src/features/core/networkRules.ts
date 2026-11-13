// Validation shared by the Box network form and its mock API (S-CORE-8). The real backend repeats these checks; vedette-host re-checks again before touching the OS (D-55).
import { isBareIp, normaliseCidr } from './util'

export type FilterType = 'cidr' | 'host' | 'port'
export const FILTER_TYPES: FilterType[] = ['cidr', 'host', 'port']
export const HOST_RE = /^(?=.{1,64}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

export const ipInt = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const mask = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0)
export const sameSubnet = (a: string, b: string, prefix: number) => ((ipInt(a) & mask(prefix)) >>> 0) === ((ipInt(b) & mask(prefix)) >>> 0)
const octets = (ip: string) => ip.split('.').map(Number)
/** The host's rule for an address of the box, a gateway or an NTP server: not 0/8, loopback, link-local (169.254/16), multicast and above. */
const isUnicast = (ip: string) => { const [a = 0, b = 0] = octets(ip); return a !== 0 && a !== 127 && a < 224 && !(a === 169 && b === 254) }
/** A host address of its range: neither the network nor the broadcast address. */
const isHostIn = (ip: string, prefix: number) => { const n = ipInt(ip); const net = (n & mask(prefix)) >>> 0; return n !== net && n !== ((net | (~mask(prefix) >>> 0)) >>> 0) }
const isUsable = (ip: string, prefix: number) => isUnicast(ip) && isHostIn(ip, prefix)
/** A DNS server: global unicast (not 0.0.0.0, loopback, link-local, multicast or 255.255.255.255). */
const isDnsServer = (ip: string) => { const [a = 0, b = 0] = octets(ip); return ip !== '0.0.0.0' && a !== 127 && a < 224 && !(a === 169 && b === 254) }

export interface StaticInput { address?: unknown; prefix?: unknown; gateway?: unknown; dns?: unknown }
/** What is wrong with a static management configuration: the API code, and a sentence for the person. */
export interface StaticProblem { code: 'invalid_static' | 'gateway_outside_subnet' | 'gateway_not_host'; message: string }
const bad = (message: string): StaticProblem => ({ code: 'invalid_static', message })
/** Problem with a static management configuration, or null. The gateway outside the range is its own code (D-100). */
export function staticProblem(v: StaticInput): StaticProblem | null {
  if (typeof v.address !== 'string' || !isBareIp(v.address)) return bad('The IP address must be an IPv4 address like 192.168.10.250.')
  const prefix = typeof v.prefix === 'number' ? v.prefix : Number(v.prefix)
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) return bad('The prefix length must be a whole number from 8 to 30 (24 means 255.255.255.0).')
  if (!isUsable(v.address, prefix)) return bad('That address is the network or broadcast address of its range, or a reserved address. Pick a host address.')
  if (typeof v.gateway !== 'string' || !isBareIp(v.gateway)) return bad('The gateway must be an IPv4 address like 192.168.10.1.')
  if (v.gateway === v.address) return bad('The gateway cannot be the same as the box address.')
  if (!sameSubnet(v.address, v.gateway, prefix)) return { code: 'gateway_outside_subnet', message: 'The gateway must be inside the address range you entered.' }
  if (!isHostIn(v.gateway, prefix)) return { code: 'gateway_not_host', message: 'The gateway cannot be the network or broadcast address of the range. Use the address of your router.' }
  const dns = Array.isArray(v.dns) ? v.dns : null
  if (!dns || dns.length < 1 || dns.length > 3) return bad('Give 1 to 3 DNS servers.')
  if (dns.some((d) => typeof d !== 'string' || !isBareIp(d))) return bad('Each DNS server must be an IPv4 address.')
  if (dns.some((d) => !isDnsServer(d as string))) return bad('A DNS server cannot be a loopback, link-local (169.254.x.x) or multicast address.')
  if (new Set(dns).size !== dns.length) return bad('A DNS server is listed twice.')
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

/** The Box address in its normal form (D-465): trimmed, lower case, no trailing dot; '' = use the default. */
export const normaliseBoxAddress = (v: string) => v.trim().toLowerCase().replace(/\.$/, '')
/** The Box address (D-465): a host name (the NTP rule) or a unicast IPv4 address; no URL, port, path or space. Takes the normal form. */
export function boxAddressProblem(v: string): string | null {
  if (v === '') return null
  const numeric = v.split('.').every((l) => /^(\d+|0[xX][0-9a-fA-F]*)$/.test(l))
  if (isBareIp(v) ? !isUnicast(v) : (!HOST_RE.test(v) || numeric)) return 'Enter a host name like vedette.office.lan or an IPv4 address like 192.168.1.10, without https:// and without a port.'
  return null
}

/** NTP servers: 1 to 4 hostnames or IPv4 addresses. */
export function ntpProblem(servers: unknown): string | null {
  if (!Array.isArray(servers) || servers.length < 1 || servers.length > 4) return 'Give 1 to 4 NTP servers.'
  // A name whose every part is a number (1.2.3, 0x7f) is read as an address by the resolver: the box refuses it.
  const numeric = (s: string) => s.split('.').every((l) => /^(\d+|0[xX][0-9a-fA-F]*)$/.test(l))
  for (const s of servers) if (typeof s !== 'string' || (isBareIp(s) ? !isUnicast(s) : (!HOST_RE.test(s) || numeric(s)))) return `"${String(s)}" is not a server name or IPv4 address.`
  if (new Set(servers).size !== servers.length) return 'An NTP server is listed twice.'
  return null
}
