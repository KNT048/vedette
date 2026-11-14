// Sample data and scan-result generator of the exposure mock. 203.0.113.0/24 is the documentation range (RFC 5737), not real IPs.
import { daysAgo } from '@/mocks/db'
import { dateText } from './dates'
import { CERT_WARN_DAYS, type AdminRow, type BoxIpSettings, type CertRow, type Counts, type GapRow, type HostRow, type IgnoredIp, type NotCheckedRow, type OutsideView, type PortRow, type ServiceRow, type Snapshot, type Target, type TargetKind, type VulnRow } from './types'

export const BOX_EGRESS_IP = '203.0.113.10'
/** The sample company has two public IPs behind a load balancer: the box leaves through both. */
export const BOX_EGRESS_IP_2 = '203.0.113.11'

/** What one scan found; services: what nmap -sV read on the box's own IP (S-EXP-2). The mock plays a box whose nmap -sV is set up. */
export interface Content { hosts: HostRow[]; ports: PortRow[]; admin_panels: AdminRow[]; certs: CertRow[]; services?: ServiceRow[] }
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
    if (t.value === BOX_EGRESS_IP) return boxIpNow()
    const ports = [P(t.value, 443, 'https', 'nginx 1.22')]
    const services: ServiceRow[] = [S(t.value, 443, 'http', 'nginx', '1.22.1', 'cpe:/a:igor_sysoev:nginx:1.22.1')]
    const admin: AdminRow[] = []
    if (h % 2 === 0) {
      ports.push(P(t.value, 8443, 'https', 'pfSense'))
      services.push(S(t.value, 8443, 'http', 'nginx', '', 'cpe:/a:igor_sysoev:nginx'))
      admin.push({ url: `https://${t.value}:8443`, product: 'pfSense (admin)', ip: t.value, port: 8443, risk: 'danger' })
    }
    return { hosts: [], ports, admin_panels: admin, certs: [{ host: t.value, issuer: 'Self-signed', expires_at: inDays(40 + (h % 200)) }], services }
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

const S = (ip: string, port: number, name: string, product = '', version = '', cpe = '', extra = ''): ServiceRow => ({ ip, port, name, product, version, cpe, extra })

/** The box's own IP (203.0.113.10): a FortiGate SSL VPN that hides its version, an old Apache forwarded to a LAN server, and a port
 * that closes every connection. The sample of S-EXP-2: two exploited CVEs by version and one service that needs its version. */
function boxIpNow(): Content {
  const ip = BOX_EGRESS_IP
  return {
    hosts: [], admin_panels: [], certs: [{ host: ip, issuer: 'Fortinet (self-signed)', expires_at: inDays(120) }],
    ports: [P(ip, 443, 'https', 'FortiGate SSL-VPN'), P(ip, 8443, 'https'), P(ip, 18443, 'http', 'Apache/2.4.49 (Unix)')],
    services: [S(ip, 443, 'https', 'Fortinet FortiGate SSL VPN', '', 'cpe:/o:fortinet:fortios'), S(ip, 8443, 'tcpwrapped'), S(ip, 18443, 'http', 'Apache httpd', '2.4.49', 'cpe:/a:apache:http_server:2.4.49', '(Unix)')],
  }
}

// The mock's matcher (INV-20): real CISA KEV entries for the sample products, decided as the box does with the NVD ranges.
const APACHE_TRAVERSAL = 'Apache HTTP Server Path Traversal Vulnerability'
const FORTIOS_KEV = ['CVE-2018-13379', 'CVE-2022-42475', 'CVE-2023-27997', 'CVE-2024-21762']
function matchServices(services: ServiceRow[]): { vulns: VulnRow[]; version_gaps: GapRow[]; compared: number } {
  const vulns: VulnRow[] = [], version_gaps: GapRow[] = []
  const apache = (s: ServiceRow, cve: string, range: string): VulnRow => ({
    ip: s.ip, port: s.port, cve, name: APACHE_TRAVERSAL, basis: 'version', date_added: '2021-11-03', ransomware: false, backport: '',
    summary: `${s.ip} runs ${s.product} ${s.version}. Its version is inside the range affected by ${cve} (${range}); no scan has confirmed it yet, so this is only suspected.`,
  })
  for (const s of services) {
    if (s.cpe.startsWith('cpe:/a:apache:http_server') && s.version === '2.4.49') vulns.push(apache(s, 'CVE-2021-41773', '= 2.4.49'), apache(s, 'CVE-2021-42013', '= 2.4.49'))
    if (s.cpe.startsWith('cpe:/a:apache:http_server') && s.version === '2.4.50') vulns.push(apache(s, 'CVE-2021-42013', '= 2.4.50'))
    if (s.cpe.startsWith('cpe:/o:fortinet:fortios') && !s.version) version_gaps.push({ ip: s.ip, port: s.port, software: s.product, cves: FORTIOS_KEV })
  }
  return { vulns, version_gaps, compared: services.filter((s) => s.cpe).length }
}

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`
const NOT_UDP = 'UDP ports: the scan connects over TCP only.'
const NOT_EXPLOITED = 'Vulnerabilities that are not known to be exploited: only the CISA list of exploited vulnerabilities (KEV) is compared.'

/** What the scan checked and did not check, in the box's sentences (INV-19, INV-20). */
function lines(c: Content, at: string, ip: boolean, m: ReturnType<typeof matchServices>): Pick<Snapshot, 'checks' | 'not_checked'> {
  const services = c.services ?? []
  if (!ip) {
    return {
      checks: [{ kind: 'names', at, text: `Names under the domain from certificate-transparency logs (crt.sh): ${plural(c.hosts.length, 'name')}; each checked by name on ports 80 and 443 (one GET / and the certificate on 443). ${plural(c.ports.length, 'port')} open in all.` }],
      not_checked: [
        { kind: 'udp', text: NOT_UDP },
        { kind: 'ports', text: "Other ports of the names under this domain: names get web checks by name only; ports are scanned only on the box's own verified public IP." },
        { kind: 'services', text: "Service identification (nmap -sV): it runs on the box's own verified public IP only, not on the names of a domain." },
        { kind: 'non_exploited', text: NOT_EXPLOITED },
      ],
    }
  }
  const not_checked: NotCheckedRow[] = [{ kind: 'udp', text: NOT_UDP }, { kind: 'ports', text: 'TCP ports outside the fixed list of commonly exposed ports.' }, { kind: 'non_exploited', text: NOT_EXPLOITED }]
  let cve = `${plural(m.compared, 'identified service')} of ${services.length} compared with today's CISA list of exploited vulnerabilities (1484 entries) and its NVD version ranges: ${plural(m.vulns.length, 'exploited CVE')} matched.`
  if (m.version_gaps.length > 0) cve += ` ${plural(m.version_gaps.length, 'service')} could not be checked: no version was read.`
  if (services.length > m.compared) cve += ` ${plural(services.length - m.compared, 'service')} gave no product to look up, so not compared.`
  return {
    checks: [
      { kind: 'ports', at, text: `TCP connect to the fixed list of commonly exposed ports, then one GET / on each open web port and a TLS handshake on each TLS port: ${plural(c.ports.length, 'port')} open.` },
      { kind: 'services', at, text: `Service identification (nmap -sV) on 98 TCP ports: ${plural(services.length, 'service')} identified.` },
      ...(services.length > 0 ? [{ kind: 'cve', at, text: cve }] : []),
    ],
    not_checked,
  }
}

export function makeSnapshot(id: string, at: string, c: Content, extraIp?: string): Snapshot {
  const services = c.services ?? []
  const m = matchServices(services)
  return { id, date: dateOf(at), scanned_at: at, hosts: c.hosts, ports: c.ports, admin_panels: c.admin_panels, certs: c.certs, services, ...lines(c, at, extraIp !== undefined, m), vulns: m.vulns, version_gaps: m.version_gaps, counts: countsOf(c, extraIp) }
}

const plusDays = (iso: string, d: number) => new Date(Date.parse(iso) + d * 864e5).toISOString()

export function seedTargets(): StoredTarget[] {
  const ok = (value: string, at: string) => ({ at, ok: true, message: `Found the TXT record on ${value}.` })
  const ipOk = (ip: string, at: string) => ({ at, ok: true, message: `The box reaches the Internet via ${ip}. Verified until ${dateText(plusDays(at, VERIFY_DAYS))}.` })
  const v1 = daysAgo(21), v4 = daysAgo(40), v5 = daysAgo(40)
  const seen = daysAgo(0, 0.7) // the box saw its two IPs 40 minutes ago (auto-detect, every 60 minutes)
  const standby = daysAgo(26) // an old failover link: not seen for 26 days
  return [
    { id: 'xt-1', kind: 'domain', value: 'acme.example', token: 'a3f9c2e17b4d8a60', method: 'dns_txt', verified_at: v1, expires_at: null, txt_ok: true, checks: 2, last_check: ok('acme.example', v1), created_at: daysAgo(21, 1), last_scan_at: daysAgo(1) },
    // The two public IPs of the sample company (behind a load balancer): both seen 40 minutes ago, so both are valid for 30 days from then.
    { id: 'xt-2', kind: 'ip', value: BOX_EGRESS_IP, token: '', method: 'box_egress', verified_at: seen, expires_at: plusDays(seen, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: ipOk(BOX_EGRESS_IP, seen), created_at: daysAgo(30), last_scan_at: daysAgo(1) },
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
export function seedBoxIp(): Omit<BoxIpSettings, 'retry_in_min'> {
  return { auto: true, interval_min: DEFAULT_INTERVAL, last_run: { at: daysAgo(0, 0.7), ok: true, message: `The box reaches the Internet via 2 public IPs: ${BOX_EGRESS_IP}, ${BOX_EGRESS_IP_2}.` } }
}

/** Sample Ignored list: the address of a mobile backup line that the box sometimes uses; it is the carrier's, not the company's (D-79). */
export function seedIgnored(): IgnoredIp[] {
  return [{ value: '203.0.113.77', ignored_by: 'admin@acme.example', ignored_at: daysAgo(3) }]
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
  // The box's own IP, scanned a week ago and yesterday: the router forward to the old Apache on 18443 is new since then.
  const box = boxIpNow()
  const boxOld: Content = { ...box, ports: box.ports.filter((p) => p.port !== 18443), services: box.services!.filter((s) => s.port !== 18443) }
  // INV-22: yesterday's scan did not see the TCP-wrapped 8443 (a slow answer): it still counts as open and says so until the next scan agrees.
  const boxMissed: Content = { ...box, ports: box.ports.map((p) => (p.port === 8443 ? { ...p, last_seen: dateOf(daysAgo(8)), misses: 1 } : p)) }
  return {
    'xt-1': [makeSnapshot('sn-1', daysAgo(14), old), makeSnapshot('sn-2', daysAgo(7), mid), makeSnapshot('sn-3', daysAgo(1), full)],
    'xt-2': [makeSnapshot('sn-4', daysAgo(8), boxOld, BOX_EGRESS_IP), makeSnapshot('sn-5', daysAgo(1), boxMissed, BOX_EGRESS_IP)],
  }
}

/** D-558: what the mock's Shodan InternetDB knows. The box's own IP: the FortiGate on 443, the TCP-wrapped 8443, and its admin page on 10443
 * that the router shows only to the outside (our scan from inside does not see it); 18443 opened after Shodan's last pass. Any other IP: no record. */
export function outsideAnswer(ip: string): Pick<OutsideView, 'found' | 'ports' | 'hostnames' | 'cpes' | 'tags' | 'vulns'> {
  if (ip !== BOX_EGRESS_IP) return { found: false, ports: [], hostnames: [], cpes: [], tags: [], vulns: [] }
  return { found: true, ports: [443, 8443, 10443], hostnames: ['vpn.acme.example'], cpes: ['cpe:/o:fortinet:fortios'], tags: ['self-signed', 'vpn'], vulns: ['CVE-2023-27997', 'CVE-2024-21762'] }
}

/** Sample: an administrator asked Shodan about the box's own IP two days ago; the other IP was never sent. */
export function seedOutside(): Record<string, Omit<OutsideView, 'scan_ports' | 'scan_at'>> {
  return { 'xt-2': { ip: BOX_EGRESS_IP, checked_at: daysAgo(2), checked_by: 'admin@acme.example', ...outsideAnswer(BOX_EGRESS_IP) } }
}
