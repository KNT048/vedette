// API contract of module exposure (D-18, S-EXP-1). UI types are inferred from here (types.ts).
// Hard rule (LEGAL §3): POST .../scan returns 409 unless ownership is verified (IPs: not more than 30 days since the box last saw them) and the DNS TXT record is still there, and 400 `commitment_required` (D-57) until the commitment is recorded.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/)
const day = (ago: number) => {
  const d = new Date(Date.now() - ago * 864e5)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

export const TargetKind = z.enum(['domain', 'ip'])
export const VerifyMethod = z.enum(['dns_txt', 'box_egress'])

export const Counts = z.object({ subdomains: z.number().int(), ips: z.number().int(), ports: z.number().int(), admin_panels: z.number().int(), certs_expiring: z.number().int() })

export const PortRow = z.object({ ip: z.string(), port: z.number().int(), service: z.string(), product: z.string().optional() })

/** The sentence an administrator's first Scan now confirms (D-473). The backend owns the text (modules/exposure/notice.go) and sends it with the target's name in it; the page shows what it received. These two constants are the mock's copy, held equal to the backend's by a Go test. */
export const NOTICE_VERSION = '2026-11-13'
export const NOTICE_TEMPLATE = 'By choosing Scan now I confirm that my company owns {value} and that I am authorized to scan it. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.'
export const Notice = z.object({ version: z.string(), text: z.string() })
export const Commitment = z.object({
  by: z.string(), at: z.iso.datetime(),
  version: z.string().nullable().describe('Version of the sentence the administrator saw next to Scan now; null on a commitment recorded before D-473'),
  sentence: z.string().nullable().describe('The exact sentence, with the target in it, kept with who and when; null on a commitment recorded before D-473'),
})

export const Target = z.object({
  id: z.string(),
  kind: TargetKind,
  value: z.string(),
  status: z.enum(['unverified', 'verified', 'expired']).describe('expired only exists for IPs: the box has not seen this IP for more than 30 days'),
  method: VerifyMethod.nullable(),
  token: z.string().describe('Domain: the token in the TXT record vedette-verify=<token> (not secret, it is public in DNS). IP: empty string'),
  verified_at: z.iso.datetime().nullable().describe('Domain: first successful verification. IP: the last time the box saw this IP (every sighting renews it)'),
  expires_at: z.iso.datetime().nullable().describe('IP: verified_at + 30 days. Domain: null (the TXT record is re-checked right before every scan)'),
  validity: z.enum(['valid', 'expiring', 'expired']).nullable().describe('IPs only: expiring = 5 days or less left'),
  last_check: z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string() }).nullable(),
  commitment: Commitment.nullable().describe('Recorded by the first Scan now of an administrator with two-step sign-in (D-473): who, when and the exact sentence shown next to the button'),
  commitment_notice: Notice.nullable().describe('The sentence the first Scan now of an administrator confirms, with this target in it; null once the target has a commitment'),
  scannable: z.boolean(),
  blocked_reason: z.enum(['unverified', 'expired', 'txt_missing', 'no_commitment', 'ip_not_current']).nullable().describe('Why it cannot be scanned yet; null = can be scanned. ip_not_current (IPs only): the last full check that got an answer did not see the IP and no check since has, so scans are paused (until a later check sees it) while the IP stays in the list; verified_at is when the box last saw it'),
  created_at: z.iso.datetime(),
  last_scan_at: z.iso.datetime().nullable(),
  latest: Counts.nullable(),
  open_ports: z.array(PortRow).nullable().describe('The first 20 open ports of the newest scan, in its order (latest.ports is the total), so the list can say what is open; null when never scanned'),
})

export const HostRow = z.object({ name: z.string(), ip: z.string() })
export const AdminRow = z.object({ url: z.string(), product: z.string(), ip: z.string(), port: z.number().int(), risk: z.enum(['danger', 'warn']) })
export const CertRow = z.object({ host: z.string(), issuer: z.string(), expires_at: z.iso.datetime() })

// S-EXP-2 (INV-19, INV-20, D-553): what service identification (nmap -sV) read on the box's own public IP, what the scan checked and
// did not, and the exploited CVEs (CISA KEV) of the identified services, computed when the snapshot is read (not stored).
export const ServiceRow = z.object({
  ip: z.string(), port: z.number().int(),
  name: z.string().describe('nmap\'s service name: http, ssh, tcpwrapped'), product: z.string().describe('"" when nmap named none'),
  version: z.string().describe('"" when the service sent none'), cpe: z.string().describe('The CPE 2.2 URI nmap printed; "" when none'),
})
export const CheckRow = z.object({ kind: z.string().describe('ports, names, services or cve'), text: z.string(), at: z.iso.datetime() })
export const NotCheckedRow = z.object({ kind: z.string().describe('udp, ports, non_exploited, services or cve'), text: z.string() })
export const VulnBasis = z.enum(['version', 'product'])
export const VulnRow = z.object({
  ip: z.string(), port: z.number().int(), cve: z.string(), name: z.string(),
  basis: VulnBasis.describe('version: the version is inside an NVD range; product: only the product matches'),
  summary: z.string(), date_added: isoDate.nullable().describe('When CISA listed it as exploited'), ransomware: z.boolean(),
})
export const GapRow = z.object({ ip: z.string(), port: z.number().int(), software: z.string(), cves: z.array(z.string()).describe('Exploited CVEs of the product that only a version would decide') })

export const Snapshot = z.object({
  id: z.string(), date: isoDate, scanned_at: z.iso.datetime(),
  hosts: z.array(HostRow), ports: z.array(PortRow), admin_panels: z.array(AdminRow), certs: z.array(CertRow), counts: Counts,
  services: z.array(ServiceRow), checks: z.array(CheckRow), not_checked: z.array(NotCheckedRow),
  vulns: z.array(VulnRow).describe('Computed on read against today\'s CISA list, not stored'), version_gaps: z.array(GapRow),
})
export const SnapshotMeta = Snapshot.pick({ id: true, date: true, scanned_at: true, counts: true })

export const DiffKind = z.enum(['subdomain', 'port', 'admin', 'cert', 'service', 'vuln'])
export const DiffItem = z.object({ kind: DiffKind, key: z.string(), label: z.string(), detail: z.string() })
export const DiffChange = DiffItem.extend({ from: z.string(), to: z.string() })
export const Diff = z.object({ from: isoDate, to: isoDate, added: z.array(DiffItem), removed: z.array(DiffItem), changed: z.array(DiffChange) })

export const VerifyResult = z.object({ verified: z.boolean(), message: z.string(), target: Target })

/** Auto-detect of the box's public IPs (kien 2026-11-09). interval_min is 1 to 1440 (one minute to 24 hours); the server checks it (400 bad_interval). */
export const BoxIpRun = z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string().describe('What the last check saw, or why it failed') })
export const BoxIpSettings = z.object({
  auto: z.boolean().describe('On: the box detects its public IPs at first start and then every interval_min minutes. Off: only "Detect now". Default on'),
  interval_min: z.number().int().describe('Minutes between automatic checks, 1 to 1440. Default 60'),
  last_run: BoxIpRun.nullable().describe('The last automatic or manual detection; null before the first one'),
  retry_in_min: z.number().int().nullable().describe('null while attempts are left. When the 10 attempts an hour (shared by Detect now, Verify again and the DNS Check of a domain) are used up: minutes until the next one is possible, 1 or more'),
})
/** An IP the customer removed and told Vedette not to add again (D-79). The list only blocks, it never allows: restoring only lets detection add the IP again. */
export const IgnoredIp = z.object({ value: z.string().describe('A public IPv4 address'), ignored_by: z.string(), ignored_at: z.iso.datetime() })
/** D-492: the device that probably answers the open ports of the box's own public IP. Never a sure claim: NAT may forward the port to another device. */
export const Gateway = z.object({
  ip: z.string().nullable().describe('The LAN default gateway the host reports; null when the box cannot tell'),
  device_id: z.string().nullable().describe('The inventory device with that IP; null when the gateway is not in the device list'),
  name: z.string().nullable().describe('That device\'s name as the Devices page shows it (untrusted label, at most 80 characters)'),
  open_exploited: z.number().int().describe('Open findings (exploited vulnerabilities, confirmed or suspected) of that device; 0 when device_id is null'),
})
export const TargetList = z.object({ items: z.array(Target), box_ip: BoxIpSettings, ignored: z.array(IgnoredIp).describe('The Ignored list, newest first'), gateway: Gateway.nullable().describe('null unless one of the box\'s own IPs has an open port in its newest scan; then who probably answers it (D-492)') })
export const ScanPhase = z.enum(['queued', 'probing', 'saving', 'done'])
export const ScanRun = z.object({
  id: z.string(), target_id: z.string(), target_value: z.string(), by: z.string().describe('Who pressed Scan now (an e-mail)'),
  started_at: z.iso.datetime(), finished_at: z.iso.datetime().nullable(),
  status: z.enum(['running', 'done', 'failed', 'stopped']),
  phase: ScanPhase.describe('queued: accepted, about to start; probing: the Vulnerability scans module is scanning the target; saving: the result is being stored; done: the snapshot exists. A failed or stopped run keeps the phase it reached'),
  snapshot_id: z.string().nullable().describe('The new snapshot when status is done'),
  error: z.object({ code: z.string(), message: z.string() }).nullable().describe('Why the run failed, in the same codes and texts the synchronous scan used (unreachable, too_many, module_off ...); null otherwise'),
})

export const BoxIpDetectResult = z.object({ items: z.array(Target).describe('The public IPs the box saw this time, each added or renewed'), message: z.string() })

const id = z.object({ id: z.string() })
const idEx = { params: { id: 'xt-1' } }

export const endpoints = defineEndpoints([
  { method: 'get', path: '/exposure/targets', summary: 'Domains and verified public IPs with ownership status, expiry, commitment and latest result, plus the box-IP auto-detect settings', stories: ['S-EXP-1'], role: 'viewer', response: TargetList },
  { method: 'post', path: '/exposure/targets', status: 201, summary: 'Add a domain (changes scan scope). Public IPs cannot be typed in: use /exposure/box-ip/verify', stories: ['S-EXP-1'], role: 'admin', body: z.object({ value: z.string() }), response: Target },
  { method: 'post', path: '/exposure/box-ip/verify', summary: '"Detect now": the box asks three public \"what is my IP\" services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip) over several rounds of new connections, accepts an IP only when at least two of the three agree in a round, and adds or renews (30 days from now) every IP that passed, except those on the Ignored list, so several egress IPs behind a load balancer are all found. Takes no IP input; refuses private, reserved and CGNAT results (400 not_public when none is public); 502 unreachable when no round gave an IP (no service answered, or they did not agree); rate limited to 10 attempts per hour', stories: ['S-EXP-1'], role: 'admin', response: BoxIpDetectResult },
  { method: 'put', path: '/exposure/box-ip/settings', summary: 'Turn auto-detect on or off and set the check interval (1 to 1440 minutes, else 400 bad_interval). Turning it on checks at once. The IP list is kept when it is turned off. Typing an IP is not possible here either', stories: ['S-EXP-1'], role: 'admin', body: z.object({ auto: z.boolean(), interval_min: z.number().int() }), response: BoxIpSettings },
  { method: 'delete', path: '/exposure/box-ip/ignored/{ip}', summary: 'Restore an IP from the Ignored list: detection may add it again the next time the box sees it. It is not added by this call and is not scannable by itself (it still needs ownership proof and the commitment). 404 when the IP is not on the list', stories: ['S-EXP-1'], role: 'admin', params: z.object({ ip: z.string() }), response: null },
  { method: 'get', path: '/exposure/targets/{id}', summary: 'One external-exposure target', stories: ['S-EXP-1'], role: 'viewer', params: id, response: Target, example: idEx },
  { method: 'delete', path: '/exposure/targets/{id}', summary: 'Delete a target with its snapshots and commitment. For a public IP this removes it from the list; with ignore=true it also goes on the Ignored list and is never added again or scanned (ignore is only for IPs, else 400 bad_value); without it, auto-detect brings it back (as a new target) the next time the box sees it', stories: ['S-EXP-1'], role: 'admin', params: id, query: z.object({ ignore: z.enum(['true', 'false']).optional() }), response: null },
  { method: 'post', path: '/exposure/targets/{id}/verify', summary: 'Re-check ownership: domain = DNS TXT record; IP = the box must currently egress through this same IP (renews it for 30 days). Not found is a normal answer (verified:false). Rate limited', stories: ['S-EXP-1'], role: 'operator', params: id, response: VerifyResult },
  { method: 'post', path: '/exposure/targets/{id}/scan', status: 202, summary: 'Scan now. Answers at once with 202 and the run (ScanRun, status running): the scan itself goes on in the background and the page polls GET /exposure/scan. The checks below still answer synchronously. 409 when not verified, verification expired or the DNS TXT record is gone (re-checked right before the scan); 409 ip_not_current when an IP is no longer the one the box goes out through (the latest check, or a fresh full check just before the scan, must see it); 400 commitment_required when the commitment is missing and the caller is an operator (an administrator must run the first scan). For an administrator that first scan IS the confirmation (D-473, amends D-26): it needs two-step sign-in on the account (403 twofa_required otherwise) and `notice_version` of the sentence shown next to the button (400 commitment_required when left out, 409 notice_changed when it is not the current one); the commitment is then recorded with who, when and that exact sentence, and the scan goes on. A target that already has a commitment records nothing again. After those checks the Vulnerability scans module does the scan (D-229, D-57 (7)): ports are scanned only on the box\'s own verified public IPs; a domain\'s names from certificate transparency are listed and get one GET of / by name on ports 80 and 443. 409 module_off while that module is off; 409 busy while another scan runs on the box; 429 rate_limited within 10 minutes of the target\'s last scan. Failures that come while the scan runs (400 too_many when the domain has more than 300 names in the logs; 502 unreachable when the certificate-transparency search (crt.sh) does not answer or the scan does not finish within 5 minutes; module_off when the module is switched off meanwhile) end the run as status failed with that code and text, and nothing is saved. Every attempt is audited', stories: ['S-EXP-1'], role: 'operator', params: id, body: z.object({ notice_version: z.string().optional().describe('The `commitment_notice.version` the page showed next to Scan now; needed only for the first scan of a target, by an administrator') }), bodyOptional: true, response: ScanRun },
  { method: 'get', path: '/exposure/scan', summary: 'The scan that runs now, or the last one (status done, failed or stopped, with its error or snapshot_id); null when no scan has run since the box started (the run is kept in memory only)', stories: ['S-EXP-1'], role: 'viewer', response: ScanRun.nullable() },
  { method: 'post', path: '/exposure/scan/stop', summary: 'Stop the scan that runs now (status stopped, nothing is saved; audited). 409 not_running when no scan runs', stories: ['S-EXP-1'], role: 'operator', response: ScanRun },
  { method: 'get', path: '/exposure/targets/{id}/snapshots', summary: 'Scan days of a target, newest first', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(SnapshotMeta) }), example: idEx },
  { method: 'get', path: '/exposure/targets/{id}/snapshots/{date}', summary: 'Scan result of one day', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: z.object({ id: z.string(), date: isoDate }), response: Snapshot, example: { params: { id: 'xt-1', date: day(1) } } },
  { method: 'get', path: '/exposure/targets/{id}/diff', summary: 'Compare two scan days: newly exposed, gone, changed', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: id, query: z.object({ from: isoDate, to: isoDate }), response: Diff, example: { params: { id: 'xt-1' }, query: { from: day(7), to: day(1) } } },
])
