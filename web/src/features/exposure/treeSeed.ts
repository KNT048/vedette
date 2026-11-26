// Sample rows of the target tree for the mock API: two domains (one with a name that is its own target under it, one not
// proven yet with a chosen scope), the box's own public IP and an IP typed in but not proven. Shapes follow a real scan,
// with names and addresses replaced by example.com and 198.51.100.0/24.
import { daysAgo } from '@/mocks/db'
import { dayOf } from '@/lib/format'
import { NOTICE_TEMPLATE, NOTICE_VERSION, TERMS_KEPT_VERSIONS, TERMS_TEMPLATE, TERMS_TEMPLATE_DOMAIN, TERMS_VERSION } from './contract'
import type { Address, Consent, Host, Issue, NodeOrigin, ProofCheck, Scan, ScopeMode, Service, TargetKind, VerifyMethod } from './types'

/** A node as the mock stores it; proof state, blocked, counts and the newest scan are worked out on read. */
export interface StoredNode {
  id: string
  parent_id: string | null
  kind: TargetKind
  value: string
  origin: NodeOrigin
  scope_mode: ScopeMode | null
  enabled: boolean
  created_at: string
  /** The node's own proof; null method = no own proof (covered by an ancestor, or not proven yet). */
  method: VerifyMethod | null
  token: string
  verified_at: string | null
  last_check: ProofCheck | null
  /** Checks made so far: the mock finds a new record or file from the second check on. */
  checks: number
  commitment: Consent | null
  terms: Consent | null
}

export interface TreeRows {
  hosts: Record<string, Host[]>
  addresses: Record<string, Address[]>
  services: Record<string, Service[]>
  issues: Issue[]
  scans: Scan[]
}

export const TREE_BOX_IP = '198.51.100.2'
const ADMIN = 'admin@example.com'

const commitment = (value: string, d: number): Consent => ({ version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', value), by: ADMIN, at: daysAgo(d), disruptive: false })
// without the disruptive checks: an acceptance of the previous version made without its tick (still valid, the deep scan only)
const terms = (value: string, kind: TargetKind, d: number, disruptive: boolean): Consent => ({
  version: disruptive ? TERMS_VERSION : TERMS_KEPT_VERSIONS[0], text: (kind === 'domain' ? TERMS_TEMPLATE_DOMAIN : TERMS_TEMPLATE).replaceAll('{value}', value), by: ADMIN, at: daysAgo(d), disruptive,
})

export function seedTree(): StoredNode[] {
  return [
    { id: 'xt-11', parent_id: null, kind: 'domain', value: 'example.com', origin: 'person', scope_mode: 'all', enabled: true, created_at: daysAgo(40),
      method: 'dns_txt', token: '5d1c09a7e2b84f36', verified_at: daysAgo(1, 2), last_check: { at: daysAgo(1, 2), ok: true, message: 'The TXT record vedette-verify=5d1c09a7e2b84f36 was found on example.com.' }, checks: 6,
      commitment: commitment('example.com', 39), terms: terms('example.com', 'domain', 39, false) },
    { id: 'xt-12', parent_id: 'xt-11', kind: 'domain', value: 'git.example.com', origin: 'person', scope_mode: 'self', enabled: true, created_at: daysAgo(30),
      method: null, token: 'b7e4a90c13d65f28', verified_at: null, last_check: null, checks: 0,
      commitment: commitment('git.example.com', 30), terms: null },
    { id: 'xt-13', parent_id: null, kind: 'domain', value: 'shop.example.net', origin: 'person', scope_mode: 'selected', enabled: true, created_at: daysAgo(0, 3),
      method: 'dns_txt', token: '0f3b6c2d9a8e7145', verified_at: null, last_check: { at: daysAgo(0, 2), ok: false, message: 'The TXT record vedette-verify=0f3b6c2d9a8e7145 was not found on shop.example.net.' }, checks: 1,
      commitment: null, terms: null },
    { id: 'xt-14', parent_id: null, kind: 'ip', value: TREE_BOX_IP, origin: 'box', scope_mode: null, enabled: true, created_at: daysAgo(60),
      method: 'box_egress', token: '', verified_at: daysAgo(0, 1), last_check: { at: daysAgo(0, 1), ok: true, message: `The box reaches the Internet via ${TREE_BOX_IP}.` }, checks: 30,
      commitment: commitment(TREE_BOX_IP, 50), terms: terms(TREE_BOX_IP, 'ip', 50, true) },
    { id: 'xt-15', parent_id: null, kind: 'ip', value: '198.51.100.3', origin: 'person', scope_mode: null, enabled: true, created_at: daysAgo(2),
      method: null, token: 'c94e1b7d02a6f853', verified_at: null, last_check: { at: daysAgo(2), ok: false, message: 'No proof file at http://198.51.100.3/.well-known/vedette-verify.txt or https://198.51.100.3/.well-known/vedette-verify.txt, and no reverse DNS name under a proven domain.' }, checks: 1,
      commitment: null, terms: null },
  ]
}

const host = (id: string, name: string, source: Host['source'], first: number, last: number, extra: Partial<Host> = {}): Host =>
  ({ id, name, source, selected: false, child: null, cname: null, first_seen: daysAgo(first), last_seen: daysAgo(last), ...extra })
const addr = (host_id: string | null, ip: string, first: number, last: number, cls: Address['class'] = 'public'): Address =>
  ({ host_id, ip, family: ip.includes(':') ? 'ipv6' : 'ipv4', class: cls, first_seen: daysAgo(first), last_seen: daysAgo(last) })
const svc = (id: string, ip: string, port: number, s: Partial<Service> & { first: number; last: number }): Service => {
  const { first, last, ...rest } = s
  return { id, ip, port, proto: 'tcp', name: '', product: '', version: '', cpe: '', title: '', cert: null, is_web: false, ident: 'none', state: 'open', first_seen: daysAgo(first), last_seen: daysAgo(last), ...rest }
}
const issue = (id: string, target_id: string, service_id: string | null, i: Pick<Issue, 'engine' | 'key' | 'title' | 'severity'> & Partial<Issue> & { first: number; last: number }): Issue => {
  const { first, last, ...rest } = i
  return { id, target_id, service_id, cves: [], detail: { description: '', solution: '', evidence: [] }, state: 'open', resolution: null, resolved_by: null, resolved_at: null, note: null, accepted_until: null, first_seen: daysAgo(first), last_seen: daysAgo(last), ...rest }
}
const cert = (names: string[], issuer: string, days: number) => ({ names, issuer, expires_at: new Date(Date.now() + days * 864e5).toISOString() })
const dayIso = (ahead: number) => dayOf(new Date(Date.now() + ahead * 864e5).toISOString())
const scan = (run_id: string, target_id: string, s: Partial<Scan> & { queuedDaysAgo: number; minutes: number }): Scan => {
  const { queuedDaysAgo, minutes, ...rest } = s
  const q = daysAgo(queuedDaysAgo)
  const end = new Date(Date.parse(q) + minutes * 60_000).toISOString()
  return { run_id, target_id, status: 'done', trigger: 'schedule', requested_by: 'system', mode: 'deep', queued_at: q, started_at: q, ended_at: end, waiting_for: null, stop_reason: null, error: null,
    counts: { hosts: 0, services: 0, new_services: 0, closed_services: 0, issues: 0, new_issues: 0 }, web_steps: [], ...rest }
}

/** The web steps of a scheduled deep scan: the passive pass ran, the active one waits for a person's Scan now. */
const SCHEDULED_WEB = 'Active web checks run when a person presses Scan now; scheduled scans read the pages without attacking them.'
const scheduledWeb = (pages: number, alerts: number): Scan['web_steps'] => [
  { step: 'zap_passive', state: 'done', pages_done: pages, pages_total: pages, alerts, cut_short: false, disruptive: false, note: SCHEDULED_WEB },
  { step: 'zap_active', state: 'skipped', pages_done: 0, pages_total: pages, alerts: 0, cut_short: false, disruptive: false, note: SCHEDULED_WEB },
]

export function seedTreeRows(): TreeRows {
  const gitlab = svc('xs-12-1', TREE_BOX_IP, 10443, { name: 'https', product: 'nginx', cpe: 'cpe:/a:igor_sysoev:nginx', title: 'Sign in · GitLab', cert: cert(['git.example.com'], "Let's Encrypt E6", 47), is_web: true, ident: 'probed', first: 30, last: 1 })
  const gitSsh = svc('xs-12-2', TREE_BOX_IP, 10022, { name: 'ssh', product: 'OpenSSH', version: '9.6p1 Ubuntu 3ubuntu13.20', cpe: 'cpe:/a:openbsd:openssh:9.6p1', ident: 'probed', first: 30, last: 1 })
  return {
    hosts: {
      'xt-11': [
        host('xh-1', 'example.com', 'dns', 40, 1),
        host('xh-2', 'www.example.com', 'ct', 40, 1, { cname: 'example.com' }),
        host('xh-3', 'mail.example.com', 'mx', 40, 1),
        host('xh-4', 'git.example.com', 'ct', 38, 1, { child: { id: 'xt-12', value: 'git.example.com' } }),
        host('xh-5', 'vpn.example.com', 'wordlist', 40, 12),
      ],
      'xt-13': [
        host('xh-6', 'shop.example.net', 'dns', 0, 0, { selected: true }),
        host('xh-7', 'api.shop.example.net', 'ct', 0, 0, { selected: true }),
        host('xh-8', 'staging.shop.example.net', 'ct', 0, 0),
      ],
    },
    addresses: {
      'xt-11': [addr('xh-1', '198.51.100.20', 40, 1), addr('xh-2', '198.51.100.20', 40, 1), addr('xh-3', '198.51.100.21', 40, 1), addr('xh-4', TREE_BOX_IP, 38, 1, 'box'), addr('xh-5', '198.51.100.22', 40, 12)],
      'xt-12': [addr(null, TREE_BOX_IP, 30, 1, 'box')],
      'xt-13': [addr('xh-6', '198.51.100.40', 0, 0), addr('xh-7', '198.51.100.41', 0, 0), addr('xh-8', '10.20.0.15', 0, 0, 'private')],
      'xt-14': [addr(null, TREE_BOX_IP, 60, 0, 'box')],
    },
    services: {
      'xt-11': [
        svc('xs-11-1', '198.51.100.20', 80, { name: 'http', product: 'nginx', cpe: 'cpe:/a:igor_sysoev:nginx', title: '301 Moved Permanently', is_web: true, ident: 'probed', first: 40, last: 1 }),
        svc('xs-11-2', '198.51.100.20', 443, { name: 'https', product: 'nginx', cpe: 'cpe:/a:igor_sysoev:nginx', title: 'Example Corp', cert: cert(['example.com', 'www.example.com'], "Let's Encrypt R11", 63), is_web: true, ident: 'probed', first: 40, last: 1 }),
        svc('xs-11-3', '198.51.100.21', 25, { name: 'smtp', product: 'Postfix smtpd', cpe: 'cpe:/a:postfix:postfix', cert: cert(['mail.example.com'], "Let's Encrypt R10", 12), ident: 'probed', first: 40, last: 1 }),
        svc('xs-11-4', '198.51.100.22', 443, { name: 'ssl/unknown', cert: cert(['FortiGate'], 'FortiGate', 300), ident: 'none', state: 'closed', first: 40, last: 12 }),
      ],
      'xt-12': [gitlab, gitSsh],
      'xt-14': [
        svc('xs-14-1', TREE_BOX_IP, 2000, { name: 'cisco-sccp', ident: 'table', first: 60, last: 0 }),
        svc('xs-14-2', TREE_BOX_IP, 5060, { name: 'sip', ident: 'table', first: 60, last: 0 }),
        { ...gitSsh, id: 'xs-14-3', first_seen: daysAgo(60), last_seen: daysAgo(0) },
        { ...gitlab, id: 'xs-14-4', first_seen: daysAgo(60), last_seen: daysAgo(0) },
        svc('xs-14-5', TREE_BOX_IP, 11080, { ident: 'none', first: 9, last: 0 }),
        svc('xs-14-6', TREE_BOX_IP, 11443, { name: 'ssl/unknown', cert: cert(['FortiGate'], 'FortiGate', 280), ident: 'none', first: 60, last: 0 }),
      ],
    },
    issues: [
      issue('xi-1', 'xt-11', 'xs-11-2', { engine: 'zap', key: '10038', title: 'Content Security Policy (CSP) header not set', severity: 'medium', first: 40, last: 1,
        detail: { description: 'The page sets no Content-Security-Policy header, which helps to detect and limit cross-site scripting and data injection.', solution: 'Set a Content-Security-Policy header on every page.', evidence: ['https://www.example.com/'] } }),
      issue('xi-2', 'xt-11', 'xs-11-3', { engine: 'surface', key: 'cert_expiring', title: 'TLS certificate expires in 12 days', severity: 'medium', first: 2, last: 1,
        detail: { description: 'The certificate of mail.example.com on port 25 expires soon.', solution: 'Renew the certificate before it expires.', evidence: ['mail.example.com:25'] } }),
      issue('xi-3', 'xt-11', 'xs-11-4', { engine: 'surface', key: 'admin_page', title: 'FortiGate sign-in page reachable from the Internet', severity: 'high', state: 'gone', first: 40, last: 12,
        detail: { description: 'The administration page of a FortiGate answered on a public address.', solution: 'Allow administration only from the internal network or a VPN.', evidence: ['https://198.51.100.22/'] } }),
      issue('xi-4', 'xt-11', 'xs-11-1', { engine: 'zap', key: '10035', title: 'Strict-Transport-Security header not set', severity: 'low', state: 'handled', resolution: 'accepted', resolved_by: ADMIN, resolved_at: daysAgo(10), note: 'Port 80 only redirects to HTTPS; header set on 443 after the next release.', accepted_until: dayIso(50), first: 40, last: 1,
        detail: { description: 'The response does not set Strict-Transport-Security.', solution: 'Send Strict-Transport-Security on HTTPS responses.', evidence: ['http://example.com/'] } }),
      issue('xi-5', 'xt-12', 'xs-12-1', { engine: 'zap', key: '10003', title: 'Vulnerable JS library: DOMPurify 3.2.3', severity: 'high', cves: [{ cve: 'CVE-2025-26791', severity: { band: 'medium', score: 4.5, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N' } }], first: 30, last: 1,
        detail: { description: 'The page loads a version of DOMPurify with known flaws.', solution: 'Update GitLab, which ships the library.', evidence: ['https://git.example.com:10443/assets/webpack/main.chunk.js'] } }),
      issue('xi-6', 'xt-12', 'xs-12-1', { engine: 'nuclei', key: 'oidc-detect', title: 'OpenID Connect provider detected', severity: 'info', first: 30, last: 1,
        detail: { description: 'The service publishes an OpenID Connect discovery document.', solution: '', evidence: ['https://git.example.com:10443/.well-known/openid-configuration'] } }),
      issue('xi-7', 'xt-14', 'xs-14-3', { engine: 'openvas', key: '1.3.6.1.4.1.25623.1.0.105610', title: 'Weak host key algorithms supported (SSH)', severity: 'low', first: 50, last: 0,
        detail: { description: 'The SSH server offers host key algorithms that are considered weak.', solution: 'Disable the weak host key algorithms.', evidence: [`${TREE_BOX_IP}:10022`] } }),
      issue('xi-8', 'xt-14', null, { engine: 'openvas', key: '1.3.6.1.4.1.25623.1.0.80091', title: 'TCP timestamps information disclosure', severity: 'low', state: 'handled', resolution: 'not_relevant', resolved_by: ADMIN, resolved_at: daysAgo(20), note: 'Uptime of the firewall is not sensitive here.', first: 50, last: 0,
        detail: { description: 'The host answers with TCP timestamps, from which its uptime can be estimated.', solution: 'Turn off TCP timestamps.', evidence: [`${TREE_BOX_IP} general/tcp`] } }),
      issue('xi-9', 'xt-14', 'xs-14-6', { engine: 'surface', key: 'admin_page', title: 'FortiGate sign-in page reachable from the Internet', severity: 'high', first: 60, last: 0,
        detail: { description: 'The administration page of a FortiGate answered on the box\'s public address.', solution: 'Allow administration only from the internal network or a VPN.', evidence: [`https://${TREE_BOX_IP}:11443/`] } }),
    ],
    scans: [
      scan('run-x11-2', 'xt-11', { queuedDaysAgo: 1, minutes: 42, counts: { hosts: 5, services: 3, new_services: 0, closed_services: 0, issues: 2, new_issues: 1 }, web_steps: scheduledWeb(2, 3) }),
      scan('run-x11-1', 'xt-11', { queuedDaysAgo: 12, minutes: 39, counts: { hosts: 5, services: 3, new_services: 0, closed_services: 1, issues: 1, new_issues: 0 } }),
      scan('run-x12-1', 'xt-12', { queuedDaysAgo: 1, minutes: 18, mode: 'surface', counts: { hosts: 0, services: 2, new_services: 0, closed_services: 0, issues: 2, new_issues: 0 } }),
      scan('run-x14-2', 'xt-14', { queuedDaysAgo: 0.2, minutes: 95, status: 'partial', trigger: 'manual', requested_by: ADMIN, error: 'OpenVAS did not finish within 90 minutes; the other steps are kept.', counts: { hosts: 0, services: 6, new_services: 1, closed_services: 0, issues: 2, new_issues: 0 } }),
      scan('run-x14-1', 'xt-14', { queuedDaysAgo: 8, minutes: 0, status: 'failed', error: 'The box no longer reached the Internet through this address when the scan started.', counts: null }),
    ],
  }
}
