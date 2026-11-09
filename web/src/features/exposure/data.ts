// Sample data and scan-result generator of the exposure mock. 203.0.113.0/24 is the documentation range (RFC 5737), not real IPs.
import { daysAgo } from '@/mocks/db'
import { CERT_WARN_DAYS, type AdminRow, type BoxIpSettings, type CertRow, type Counts, type HostRow, type PortRow, type Snapshot, type Target, type TargetKind } from './types'

export const BOX_EGRESS_IP = '203.0.113.10'
/** The sample company has two public IPs behind a load balancer: the box leaves through both. */
export const BOX_EGRESS_IP_2 = '203.0.113.11'

export interface Content { hosts: HostRow[]; ports: PortRow[]; admin_panels: AdminRow[]; certs: CertRow[] }
/** txt_ok = the DNS TXT record is currently present (domains). expires_at = verified_at + 30 days (IPs; verified_at is the last time the box saw the IP). The scan module reads this shape. */
export interface StoredTarget { id: string; kind: TargetKind; value: string; token: string; method: Target['method']; verified_at: string | null; expires_at: string | null; txt_ok: boolean; checks: number; last_check: Target['last_check']; created_at: string; last_scan_at: string | null }
export const VERIFY_DAYS = 30
export const EXPIRING_DAYS = 5
/** Auto-detect (kien 2026-11-09): check interval bounds and default, in minutes. */
export const MIN_INTERVAL = 1
export const MAX_INTERVAL = 1440
export const DEFAULT_INTERVAL = 60

// Snapshot day in local time: a scan at 01:00 (default scan window 22:00-05:00) still belongs to the day the user sees.
export function dateOf(iso: string) {
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}
// Rounded to the end of the day so two scans of the same certificate give the same value.
const inDays = (d: number) => `${new Date(Date.now() + d * 864e5).toISOString().slice(0, 10)}T23:59:59.000Z`

export function randomToken() {
  return `${Math.random().toString(16).slice(2, 10)}${Math.random().toString(16).slice(2, 10)}`.padEnd(16, '0')
}

export function countsOf(c: Content, extraIp?: string): Counts {
  const ips = new Set([...c.hosts.map((h) => h.ip), ...c.ports.map((p) => p.ip), ...(extraIp ? [extraIp] : [])])
  const limit = Date.now() + CERT_WARN_DAYS * 864e5
  return { subdomains: c.hosts.length, ips: ips.size, ports: c.ports.length, admin_panels: c.admin_panels.length, certs_expiring: c.certs.filter((x) => new Date(x.expires_at).getTime() <= limit).length }
}

// acme.example: latest result before today's scan. The two older snapshots are trimmed copies of it.
const P = (ip: string, port: number, service: string, product?: string): PortRow => ({ ip, port, service, product })
function acmeNow(): Content {
  const mailExp = inDays(9), vpnExp = inDays(21)
  return {
    hosts: [
      { name: 'acme.example', ip: '203.0.113.20' }, { name: 'www.acme.example', ip: '203.0.113.20' }, { name: 'mail.acme.example', ip: '203.0.113.21' },
      { name: 'vpn.acme.example', ip: '203.0.113.22' }, { name: 'nas.acme.example', ip: '203.0.113.23' },
    ],
    ports: [
      P('203.0.113.20', 80, 'http', 'nginx 1.24'), P('203.0.113.20', 443, 'https', 'nginx 1.24'),
      P('203.0.113.21', 25, 'smtp', 'Postfix'), P('203.0.113.21', 443, 'https', 'Roundcube'), P('203.0.113.21', 993, 'imaps', 'Dovecot'),
      P('203.0.113.22', 443, 'https', 'FortiGate SSL-VPN'), P('203.0.113.22', 10443, 'https', 'FortiGate admin'),
      P('203.0.113.23', 5001, 'https', 'Synology DSM'),
    ],
    admin_panels: [
      { url: 'https://vpn.acme.example:10443', product: 'FortiGate (admin)', ip: '203.0.113.22', port: 10443, risk: 'danger' },
      { url: 'https://nas.acme.example:5001', product: 'Synology DiskStation Manager', ip: '203.0.113.23', port: 5001, risk: 'warn' },
    ],
    certs: [
      { host: 'acme.example', issuer: "Let's Encrypt R11", expires_at: inDays(62) }, { host: 'mail.acme.example', issuer: "Let's Encrypt R11", expires_at: mailExp },
      { host: 'vpn.acme.example', issuer: 'Fortinet (self-signed)', expires_at: vpnExp }, { host: 'nas.acme.example', issuer: 'Synology (Let\'s Encrypt)', expires_at: inDays(75) },
    ],
  }
}

function hash(s: string) { let h = 7; for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return h }

/** The mock's "real" scan result. acme.example: same as the latest snapshot plus a new staging host; other targets: generated from the name. */
export function scanContent(t: { kind: TargetKind; value: string }): Content {
  if (t.value === 'acme.example') {
    const c = acmeNow()
    c.hosts.push({ name: 'staging.acme.example', ip: '203.0.113.24' })
    c.ports.push(P('203.0.113.24', 8080, 'http', 'Jenkins 2.426'), P('203.0.113.24', 22, 'ssh', 'OpenSSH 8.9'))
    c.admin_panels.push({ url: 'http://staging.acme.example:8080', product: 'Jenkins (HTTP)', ip: '203.0.113.24', port: 8080, risk: 'danger' })
    return c
  }
  const h = hash(t.value)
  const ip = (n: number) => `203.0.113.${100 + ((h + n) % 100)}`
  if (t.kind === 'ip') {
    const ports = [P(t.value, 443, 'https', 'nginx 1.22')]
    const admin: AdminRow[] = []
    if (h % 2 === 0) { ports.push(P(t.value, 8443, 'https', 'pfSense')); admin.push({ url: `https://${t.value}:8443`, product: 'pfSense (admin)', ip: t.value, port: 8443, risk: 'danger' }) }
    return { hosts: [], ports, admin_panels: admin, certs: [{ host: t.value, issuer: 'Self-signed', expires_at: inDays(40 + (h % 200)) }] }
  }
  const apex = ip(0), mail = ip(1)
  const hosts: HostRow[] = [{ name: t.value, ip: apex }, { name: `www.${t.value}`, ip: apex }, { name: `mail.${t.value}`, ip: mail }]
  const admin: AdminRow[] = h % 3 === 0 ? [{ url: `https://mail.${t.value}/admin`, product: 'Mail admin', ip: mail, port: 443, risk: 'warn' }] : []
  return {
    hosts, admin_panels: admin,
    ports: [P(apex, 80, 'http', 'nginx'), P(apex, 443, 'https', 'nginx'), P(mail, 25, 'smtp', 'Postfix'), P(mail, 443, 'https')],
    certs: hosts.map((x, i) => ({ host: x.name, issuer: "Let's Encrypt R11", expires_at: inDays(i === 2 ? 12 + (h % 10) : 50 + (h % 30)) })),
  }
}

export function makeSnapshot(id: string, at: string, c: Content, extraIp?: string): Snapshot {
  return { id, date: dateOf(at), scanned_at: at, ...c, counts: countsOf(c, extraIp) }
}

const plusDays = (iso: string, d: number) => new Date(Date.parse(iso) + d * 864e5).toISOString()

export function seedTargets(): StoredTarget[] {
  const ok = (value: string, at: string) => ({ at, ok: true, message: `Found the TXT record on ${value}.` })
  const ipOk = (ip: string, at: string) => ({ at, ok: true, message: `The box reaches the Internet via ${ip}. Verified until ${plusDays(at, VERIFY_DAYS).slice(0, 10)}.` })
  const v1 = daysAgo(21), v4 = daysAgo(40), v5 = daysAgo(40)
  const seen = daysAgo(0, 0.7) // the box saw its two IPs 40 minutes ago (auto-detect, every 60 minutes)
  const standby = daysAgo(26) // an old failover link: not seen for 26 days
  return [
    { id: 'xt-1', kind: 'domain', value: 'acme.example', token: 'a3f9c2e17b4d8a60', method: 'dns_txt', verified_at: v1, expires_at: null, txt_ok: true, checks: 2, last_check: ok('acme.example', v1), created_at: daysAgo(21, 1), last_scan_at: daysAgo(1) },
    // The two public IPs of the sample company (behind a load balancer): both seen 40 minutes ago, so both are valid for 30 days from then.
    { id: 'xt-2', kind: 'ip', value: BOX_EGRESS_IP, token: '', method: 'box_egress', verified_at: seen, expires_at: plusDays(seen, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: ipOk(BOX_EGRESS_IP, seen), created_at: daysAgo(30), last_scan_at: null },
    { id: 'xt-3', kind: 'domain', value: 'acme-demo.example', token: '9be41c0a77d2e358', method: 'dns_txt', verified_at: null, expires_at: null, txt_ok: false, checks: 0, last_check: null, created_at: daysAgo(0, 2), last_scan_at: null },
    // Last seen 40 days ago, never renewed since: expired (30 days), cannot be scanned until the box uses it again.
    { id: 'xt-4', kind: 'ip', value: '203.0.113.55', token: '', method: 'box_egress', verified_at: v4, expires_at: plusDays(v4, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: ipOk('203.0.113.55', v4), created_at: daysAgo(70), last_scan_at: null },
    // Verified before, but the TXT record has since been removed: scanning is blocked.
    { id: 'xt-5', kind: 'domain', value: 'old-site.example', token: '4c77d1e09ab2f538', method: 'dns_txt', verified_at: v5, expires_at: null, txt_ok: false, checks: 1, last_check: { at: daysAgo(0, 3), ok: false, message: 'The TXT record vedette-verify=4c77d1e09ab2f538 was not found on old-site.example.' }, created_at: v5, last_scan_at: null },
    { id: 'xt-6', kind: 'ip', value: BOX_EGRESS_IP_2, token: '', method: 'box_egress', verified_at: seen, expires_at: plusDays(seen, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: ipOk(BOX_EGRESS_IP_2, seen), created_at: daysAgo(2), last_scan_at: null },
    // Last seen 26 days ago: 4 days left, so it shows the "expiring" state. If the box keeps not using it, it expires.
    { id: 'xt-7', kind: 'ip', value: '203.0.113.12', token: '', method: 'box_egress', verified_at: standby, expires_at: plusDays(standby, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: ipOk('203.0.113.12', standby), created_at: daysAgo(60), last_scan_at: null },
  ]
}

/** Sample auto-detect state: on, every 60 minutes, the last check saw both IPs. */
export function seedBoxIp(): BoxIpSettings {
  return { auto: true, interval_min: DEFAULT_INTERVAL, last_run: { at: daysAgo(0, 0.7), ok: true, message: `The box reaches the Internet via 2 public IPs: ${BOX_EGRESS_IP}, ${BOX_EGRESS_IP_2}.` } }
}

export function seedSnapshots(): Record<string, Snapshot[]> {
  const full = acmeNow()
  const mid: Content = {
    ...full,
    ports: full.ports.filter((p) => p.port !== 10443),
    admin_panels: full.admin_panels.filter((a) => a.port !== 10443),
  }
  const old: Content = {
    hosts: full.hosts.filter((h) => h.name !== 'nas.acme.example'),
    ports: mid.ports.filter((p) => p.ip !== '203.0.113.23'),
    admin_panels: mid.admin_panels.filter((a) => a.ip !== '203.0.113.23'),
    certs: full.certs.filter((c) => c.host !== 'nas.acme.example'),
  }
  return { 'xt-1': [makeSnapshot('sn-1', daysAgo(14), old), makeSnapshot('sn-2', daysAgo(7), mid), makeSnapshot('sn-3', daysAgo(1), full)] }
}
