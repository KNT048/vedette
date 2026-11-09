// Network state of the box, shared by the core mock (Settings → Box network, S-CORE-8) and the inventory mock (sensor status, S-INV-1).
// Real box: read from the OS and changed only through the fixed command list of `vedette-host` (D-55, D-56). Mock: one table.
import { collection } from './db'
import { boxInfo } from './stores'

export type IfaceRole = 'management' | 'span' | 'unused'
/** What the port hears in the mock: a working mirror, only the box's own packets, or nothing. */
export type Hears = 'mirror' | 'own' | 'nothing'
export interface NetIface { name: string; role: IfaceRole; link: boolean; speed: string | null; mac: string; hears: Hears }
export interface Management { mode: 'dhcp' | 'static'; address: string | null; prefix: number | null; gateway: string | null; dns: string[] }
export interface SpanConfig {
  enabled: boolean; interface: string | null
  extract: { dns: boolean; tls_sni: boolean; http_host: boolean; flows: boolean }
  filters: { type: 'cidr' | 'host' | 'port'; value: string }[]
  cpu_percent: number; memory_mb: number
}
export interface NetStore {
  ifaces: NetIface[]; mgmt: Management; span: SpanConfig
  ntp: { mode: 'default' | 'custom'; servers: string[] }
  pending: { previous: Management; expires_at: string; reboot_at?: string } | null
  /** Set by a test to play a box whose network files the installer did not set up (host code net_backend_unsupported). */
  unsupported?: boolean
}
export type SpanVerdict = 'off' | 'ok' | 'own_only' | 'no_traffic' | 'no_link'
export interface SpanStatus { verdict: SpanVerdict; interface: string | null; packets_per_s: number; other_macs: number; last_packet_at: string | null }

export const DEFAULT_NTP = 'pool.ntp.org'
/** A device that is switched on but not in the inventory (a printer nobody scanned yet): the box finds it with an ARP probe before it takes an address (D-101). */
export const SILENT_DEVICES = ['192.168.10.77']
export const CONFIRM_SECONDS = 120
const EXTRACT = { dns: true, tls_sni: true, http_host: true, flows: true }
const LIMITS = { cpu_percent: 25, memory_mb: 512 }
const ifaces = (span: boolean): NetIface[] => [
  { name: 'eth0', role: 'management', link: true, speed: '1 Gb/s', mac: '02:42:ac:11:00:a0', hears: 'own' },
  { name: 'eth1', role: span ? 'span' : 'unused', link: true, speed: '1 Gb/s', mac: '02:42:ac:11:00:a1', hears: span ? 'mirror' : 'own' },
  { name: 'eth2', role: 'unused', link: false, speed: null, mac: '02:42:ac:11:00:a2', hears: 'nothing' },
]

export const networkStore = collection<NetStore>('core_network', () => ({
  ifaces: ifaces(true),
  mgmt: { mode: 'static', address: '192.168.10.250', prefix: 24, gateway: '192.168.10.1', dns: ['192.168.10.1'] },
  span: { enabled: true, interface: 'eth1', extract: { ...EXTRACT }, filters: [{ type: 'cidr', value: '192.168.10.0/28' }], ...LIMITS },
  ntp: { mode: 'default', servers: [] }, pending: null,
}), () => {
  // Clean install: management from the LAN range given at setup (boxInfo); the mirror port is plugged in but not yet used.
  const b = boxInfo()
  const prefix = b.lan ? Number(b.lan.split('/')[1]) : null
  const base = b.lan?.split('/')[0]
  const gw = base ? base.replace(/\d+$/, (n) => String(Number(n) + 1)) : null
  const mgmt: Management = b.ip && prefix && gw ? { mode: 'static', address: b.ip, prefix, gateway: gw, dns: [gw] } : { mode: 'dhcp', address: null, prefix: null, gateway: null, dns: [] }
  return { ifaces: ifaces(false), mgmt, span: { enabled: false, interface: null, extract: { ...EXTRACT }, filters: [], ...LIMITS }, ntp: { mode: 'default', servers: [] }, pending: null }
})

/** Mirrored-traffic health for the chosen port. Jitter follows the clock so the numbers look alive. */
export function spanStatusOf(s: NetStore = networkStore.get()): SpanStatus {
  const none = { interface: s.span.interface, packets_per_s: 0, other_macs: 0, last_packet_at: null }
  const i = s.ifaces.find((x) => x.name === s.span.interface)
  if (!s.span.enabled || !i) return { verdict: 'off', ...none }
  if (!i.link) return { verdict: 'no_link', ...none }
  const tick = Math.floor(Date.now() / 5000)
  const last = new Date(Date.now() - 300 - (tick % 5) * 120).toISOString()
  if (i.hears === 'mirror') return { verdict: 'ok', interface: i.name, packets_per_s: 1800 + (tick % 9) * 37, other_macs: 24 + (tick % 3), last_packet_at: last }
  if (i.hears === 'own') return { verdict: 'own_only', interface: i.name, packets_per_s: 2 + (tick % 3), other_macs: 0, last_packet_at: last }
  return { verdict: 'no_traffic', ...none }
}

/** A pending management change that nobody confirmed in time goes back to the old settings. Returns true when it reverted. */
export function settlePending(): boolean {
  const s = networkStore.get()
  if (!s.pending || new Date(s.pending.expires_at).getTime() > Date.now()) return false
  networkStore.set({ ...s, mgmt: s.pending.previous, pending: null })
  return true
}
