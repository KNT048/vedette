// Mock API: box network and SPAN (D-56, S-CORE-8). The real box applies every change through `vedette-host` (root, fixed command list, local socket); the web app never runs a shell.
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { assetsStore } from '@/mocks/stores'
import { dataMode, peek } from '@/mocks/db'
import { CONFIRM_SECONDS, networkStore, SILENT_DEVICES, settlePending, spanStatusOf, type IfaceRole, type Management, type NetStore, type SpanConfig } from '@/mocks/network'
import { filterProblem, normaliseFilter, ntpProblem, staticProblem, type FilterType } from './networkRules'

const ROLES: IfaceRole[] = ['management', 'span', 'unused']

/** Honeypot addresses (the enabled Trap IPs, D-466), read across modules without seeding (same pattern as emailChannelReady). Unseeded sample data has the seeded ones. */
function decoyIps(): string[] {
  const list = peek<{ ip: string; enabled: boolean }[]>('hp_trap_ips')
  if (list) return list.filter((x) => x.enabled).map((x) => x.ip)
  return dataMode() === 'sample' ? ['192.168.10.240', '192.168.10.241', '192.168.10.242'] : []
}

export function networkView() {
  const s = networkStore.get()
  const m = s.mgmt
  return {
    interfaces: s.ifaces.map(({ hears: _h, ...i }) => ({ ...i, address: i.role === 'management' && m.address && m.prefix ? `${m.address}/${m.prefix}` : null })),
    management: m, span: s.span, span_status: spanStatusOf(s), ntp: s.ntp, default_ntp: 'pool.ntp.org', decoy_ips: decoyIps(),
    pending: s.pending ? { expires_at: s.pending.expires_at, previous_address: s.pending.previous.address, window_s: CONFIRM_SECONDS, reboot_at: s.pending.reboot_at ?? null } : null,
  }
}
const ok = () => HttpResponse.json(networkView())
const guardRead = () => { const d = guard('viewer'); if (d) return d; if (settlePending()) audit('network.management_reverted', 'management interface', 'not confirmed in time'); return null }
const UNSUPPORTED = 'This box\'s network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself.'
/** Every change goes through the host's network backend; a box the installer did not set up refuses all of them (D-99). */
const backendRefusal = () => (networkStore.get().unsupported ? fail(409, 'net_backend_unsupported', UNSUPPORTED) : null)
const lease = (m: Management) => (m.address ? m.address.replace(/\d+$/, '131') : '192.168.1.131')

type Body = { roles: Record<string, IfaceRole> }
type MgmtBody = { mode: 'dhcp' | 'static'; address: string; prefix: number; gateway: string; dns: string[]; confirm: boolean }

export const networkHandlers = [
  http.get(`${API}/core/network`, () => guardRead() ?? ok()),
  http.get(`${API}/core/network/span/status`, () => guardRead() ?? HttpResponse.json(spanStatusOf())),

  http.put(`${API}/core/network/interfaces`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = networkStore.get()
    const roles = (await body<Body>(request)).roles
    if (!roles || typeof roles !== 'object' || s.ifaces.some((i) => !ROLES.includes(roles[i.name] as IfaceRole)) || Object.keys(roles).length !== s.ifaces.length) return fail(400, 'invalid_roles', 'Give a role (management, span or unused) for every interface.')
    const mgmt = s.ifaces.filter((i) => roles[i.name] === 'management')
    if (mgmt.length !== 1) return fail(409, 'management_count', `Exactly one interface must be the management interface; you set ${mgmt.length}. The management interface is the one you reach this page through.`)
    const cur = s.ifaces.find((i) => i.role === 'management')!
    if (mgmt[0]!.name !== cur.name) return fail(409, 'management_fixed', `${cur.name} is the management interface and you are using this page through it. It cannot be changed here; set the management address instead.`)
    const spans = s.ifaces.filter((i) => roles[i.name] === 'span')
    if (spans.length > 1) return fail(409, 'span_count', 'Only one interface can capture mirrored traffic. Set the others to unused.')
    const spanName = spans[0]?.name ?? null
    if (spanName !== s.span.interface) { const refused = backendRefusal(); if (refused) return refused }
    const next: NetStore = { ...s, ifaces: s.ifaces.map((i) => ({ ...i, role: roles[i.name]! })), span: { ...s.span, interface: spanName, enabled: spanName ? s.span.enabled : false } }
    networkStore.set(next)
    audit('network.interfaces', 'interface roles', s.ifaces.map((i) => `${i.name}=${roles[i.name]}`).join(', '))
    return ok()
  }),

  http.put(`${API}/core/network/management`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = networkStore.get()
    if (s.pending) return fail(409, 'change_pending', 'A change is waiting for confirmation. Confirm it from the new address or cancel it first.')
    const b = await body<MgmtBody>(request)
    let next: Management
    if (b.mode === 'dhcp') {
      if (b.address !== undefined || b.prefix !== undefined || b.gateway !== undefined || b.dns !== undefined) return fail(400, 'dhcp_no_static', 'With DHCP the address, gateway and DNS come from your DHCP server. Remove the static fields.')
      next = s.mgmt.mode === 'dhcp' ? s.mgmt : { mode: 'dhcp', address: lease(s.mgmt), prefix: s.mgmt.prefix ?? 24, gateway: s.mgmt.gateway, dns: s.mgmt.dns }
    } else if (b.mode === 'static') {
      const problem = staticProblem(b)
      if (problem) return fail(400, problem.code, problem.message)
      const ip = b.address!
      if (ip !== s.mgmt.address && (assetsStore.get().some((a) => a.ip === ip) || decoyIps().includes(ip))) return fail(409, 'ip_in_use', `${ip} is already used by a device in the inventory or by a decoy. Pick a free address.`)
      next = { mode: 'static', address: ip, prefix: Number(b.prefix), gateway: b.gateway!, dns: b.dns! }
    } else return fail(400, 'invalid_mode', 'The mode must be dhcp or static.')
    const m = s.mgmt
    const moves = next.mode !== m.mode || next.address !== m.address || next.prefix !== m.prefix || next.gateway !== m.gateway
    if (!moves) { if (next.dns.join() !== m.dns.join()) { const refused = backendRefusal(); if (refused) return refused } networkStore.set({ ...s, mgmt: next }); if (next.dns.join() !== m.dns.join()) audit('network.dns', 'management interface', next.dns.join(', ')); return ok() }
    if (b.confirm !== true) {
      // With DHCP the box does not know the new address until the server answers: new_ip is null and the page says where to look.
      const where = next.mode === 'static' ? `Open https://${next.address}:8443` : 'Find the new address your DHCP server gives the box, open it on port 8443'
      return HttpResponse.json({ error: { code: 'confirm_required', message: `This changes the address you use to reach the box. ${where} within ${CONFIRM_SECONDS / 60} minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address.`, new_ip: next.mode === 'static' ? next.address : null } }, { status: 409 })
    }
    const refused = backendRefusal(); if (refused) return refused
    // Before it takes the address the box asks the network whether anybody answers for it (ARP probe, D-101).
    if (next.mode === 'static' && next.address && SILENT_DEVICES.includes(next.address)) return fail(409, 'address_conflict', 'Another device already uses this address.')
    networkStore.set({ ...s, mgmt: next, pending: { previous: m, expires_at: new Date(Date.now() + CONFIRM_SECONDS * 1000).toISOString() } })
    audit('network.management', 'management interface', `${m.mode} ${m.address ?? '-'} -> ${next.mode} ${next.address}, waiting for confirmation`)
    return ok()
  }),

  http.post(`${API}/core/network/management/confirm`, () => {
    const denied = guard('admin'); if (denied) return denied
    const reverted = settlePending()
    const s = networkStore.get()
    if (!s.pending) return fail(409, 'nothing_pending', reverted ? 'The time to confirm ran out and the box went back to the old settings. Make the change again.' : 'No management change is waiting for confirmation.')
    networkStore.set({ ...s, pending: null })
    audit('network.management_confirmed', 'management interface', s.mgmt.address ?? 'dhcp')
    return ok()
  }),

  http.post(`${API}/core/network/management/revert`, () => {
    const denied = guard('admin'); if (denied) return denied
    const s = networkStore.get()
    if (!s.pending) return fail(409, 'nothing_pending', 'No management change is waiting for confirmation.')
    networkStore.set({ ...s, mgmt: s.pending.previous, pending: null })
    audit('network.management_reverted', 'management interface', 'cancelled by administrator')
    return ok()
  }),

  http.put(`${API}/core/network/span`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const s = networkStore.get()
    const b = await body<SpanConfig>(request)
    const x = b.extract
    if (typeof b.enabled !== 'boolean' || !x || (['dns', 'tls_sni', 'http_host', 'flows'] as const).some((k) => typeof x[k] !== 'boolean') || !Array.isArray(b.filters)) return fail(400, 'invalid_span', 'The SPAN settings are incomplete.')
    const iface = b.interface === null || b.interface === undefined ? null : s.ifaces.find((i) => i.name === b.interface)
    if (b.interface && !iface) return fail(400, 'bad_interface', `Network interface must be one of: ${s.ifaces.map((i) => i.name).join(', ')}.`)
    if (iface?.role === 'management') return fail(409, 'span_on_management', `${iface.name} is the management interface. SPAN needs its own port: it listens with no IP address, and mirrored packets would reach your management network.`)
    if (b.enabled && !iface) return fail(400, 'no_interface', 'Choose the port that receives the mirrored traffic before turning SPAN on.')
    if (b.enabled && !(x.dns || x.tls_sni || x.http_host || x.flows)) return fail(400, 'nothing_selected', 'Choose at least one thing to read from the mirrored traffic, or turn SPAN off.')
    for (const f of b.filters) { const p = filterProblem(f?.type, f?.value); if (p) return fail(400, 'bad_filter', p) }
    const filters = b.filters.map((f) => ({ type: f.type as FilterType, value: normaliseFilter(f.type as FilterType, f.value) }))
    if (new Set(filters.map((f) => `${f.type}:${f.value}`)).size !== filters.length) return fail(400, 'bad_filter', 'A filter is listed twice.')
    if (filters.length > 50) return fail(400, 'bad_filter', 'At most 50 filters.')
    const cpu = b.cpu_percent, mem = b.memory_mb
    if (!Number.isInteger(cpu) || cpu! < 5 || cpu! > 50) return fail(400, 'bad_limit', 'The CPU cap must be a whole number from 5 to 50 percent.')
    if (!Number.isInteger(mem) || mem! < 128 || mem! > 2048) return fail(400, 'bad_limit', 'The memory cap must be a whole number from 128 to 2048 MB.')
    const name = iface?.name ?? null
    if (name !== s.span.interface) { const refused = backendRefusal(); if (refused) return refused }
    networkStore.set({ ...s, ifaces: s.ifaces.map((i) => (i.role === 'management' ? i : { ...i, role: i.name === name ? 'span' : 'unused' })), span: { enabled: b.enabled, interface: name, extract: { dns: x.dns, tls_sni: x.tls_sni, http_host: x.http_host, flows: x.flows }, filters, cpu_percent: cpu!, memory_mb: mem! } })
    audit('network.span', 'SPAN capture', `${b.enabled ? `on, ${name}` : 'off'}, ${filters.length} filters`)
    return ok()
  }),

  http.put(`${API}/core/network/ntp`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ mode: 'default' | 'custom'; servers: string[] }>(request)
    if ((b.mode === 'default' || b.mode === 'custom') && JSON.stringify(networkStore.get().ntp) !== JSON.stringify(b.mode === 'default' ? { mode: 'default', servers: [] } : { mode: 'custom', servers: (b.servers ?? []).map((x) => String(x).trim().toLowerCase()) })) { const refused = backendRefusal(); if (refused) return refused }
    if (b.mode === 'default') {
      if (b.servers && b.servers.length) return fail(400, 'default_no_servers', 'The default pool takes no server list. Choose "your own servers" to enter some.')
      networkStore.update((s) => ({ ...s, ntp: { mode: 'default', servers: [] } }))
    } else if (b.mode === 'custom') {
      const servers = (b.servers ?? []).map((x) => String(x).trim().toLowerCase())
      const p = ntpProblem(servers)
      if (p) return fail(400, 'bad_ntp', p)
      networkStore.update((s) => ({ ...s, ntp: { mode: 'custom', servers } }))
    } else return fail(400, 'invalid_mode', 'The mode must be default or custom.')
    audit('network.ntp', 'NTP servers', b.mode === 'default' ? 'default pool' : b.servers!.join(', '))
    return ok()
  }),
]
