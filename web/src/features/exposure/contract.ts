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

export const PortRow = z.object({ ip: z.string(), port: z.number().int(), service: z.string(), product: z.string().optional(), last_seen: isoDate.optional().describe('Set only on a port the newest scan did not report, kept from an earlier scan: the day a scan last saw it open (INV-22)'), misses: z.number().int().optional().describe('With last_seen: how many scans in a row that checked the address missed the port (1 = missed by the last scan)'), unchecked: z.boolean().optional().describe('The newest scan did not check the address: the row is as an earlier scan left it') })

/** The sentence an administrator's first Scan now confirms (D-473). The backend owns the text (modules/exposure/notice.go) and sends it with the target's name in it; the page shows what it received. These two constants are the mock's copy, held equal to the backend's by a Go test. */
export const NOTICE_VERSION = '2026-11-14'
export const NOTICE_TEMPLATE = 'By choosing Scan now I confirm that my company owns {value} and that I am authorized to scan it, including identifying its services and versions, safe checks for known exploited vulnerabilities and a passive web scan. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.'
export const Notice = z.object({ version: z.string(), text: z.string() })
/** FULL-1 (D-566): the testing terms of a verified target, one paragraph per line, and the one extra tick (off by default). The backend
 * owns the text (modules/exposure/terms.go) and sends it with the target in it; these are the mock's copy, held equal by a Go test. */
export const TERMS_VERSION = '2026-11-14'
export const TERMS_TEMPLATE = 'I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette\'s tools may send it:\nAll ports: every TCP port, and the service and version behind each one.\nVersion and exploit-confirming checks: tests for known vulnerabilities, some of which confirm a flaw by sending the exploit request itself (for example reading a file or running a harmless command).\nAn active web scan that submits forms: a spider and an active scan that fill in and send forms and send attack payloads such as SQL injection and cross-site scripting probes. It can create records, send e-mails from forms or change data.\nAuthentication checks: whether login pages, admin interfaces and services let anyone in without a password or with weak settings. Passwords are not guessed unless the disruptive checks below are ticked.\nThe deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. An administrator can withdraw this acceptance at any time. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.'
export const TERMS_DISRUPTIVE = 'Include disruptive checks (denial of service, brute-force and default-password logins): these can crash your service or lock accounts.'
export const TermsNotice = z.object({ version: z.string(), text: z.string().describe('The terms with the target in them, one paragraph per line'), disruptive: z.string().describe('The sentence of the extra tick, off by default') })
export const Terms = z.object({
  version: z.string(), by: z.string(), at: z.iso.datetime(),
  text: z.string().describe('The exact terms the administrator accepted, with the tick\'s sentence as the last line when ticked'),
  disruptive: z.boolean().describe('The extra tick: denial of service, brute-force and default-password logins too'),
})
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
  commitment_notice: Notice.nullable().describe('The sentence the first Scan now of an administrator confirms, with this target in it; null once the target has a commitment of the current sentence; an older one is asked again once (D-559), so a target with a commitment can carry it too'),
  terms: Terms.nullable().describe('FULL-1 (D-566): the acceptance of the testing terms; null when none. An acceptance of an older version does not count (full_scan is false) until accepted again'),
  terms_notice: TermsNotice.describe('The current testing terms for this target, to accept or to read again'),
  full_scan: z.boolean().describe('Scans of this target are deep scans: the current testing terms are accepted. Otherwise the K-4 scope of the Scan now sentence'),
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
  extra: z.string().describe('nmap\'s extrainfo, e.g. (Debian); "" when none'),
})
export const CheckRow = z.object({ kind: z.string().describe('ports, names, services, templates, cve, web or greenbone'), text: z.string(), at: z.iso.datetime() })
export const NotCheckedRow = z.object({ kind: z.string().describe('udp, ports, non_exploited, services, templates, cve, web or greenbone'), text: z.string() })
export const VulnBasis = z.enum(['version', 'product', 'template', 'greenbone'])
export const VulnRow = z.object({
  ip: z.string(), port: z.number().int(), cve: z.string(), name: z.string(),
  basis: VulnBasis.describe('version: the version is inside an NVD range; product: only the product matches; template: a safe template matched (INV-23), the strongest evidence; greenbone: Greenbone named this CVE and it is on the list (INV-25), shown next to any other row of the same CVE, never instead of it'),
  summary: z.string(), date_added: isoDate.nullable().describe('When CISA listed it as exploited'), ransomware: z.boolean(),
  backport: z.string().describe('The distribution the service names (Debian, Ubuntu…), which may have backported the fix without changing the version; "" when none'),
  template: z.string().describe('Id of the safe template that ran for this CVE; "" when none ran'),
  template_result: z.enum(['', 'matched', 'no_match', 'error']).describe('What that template did: matched (basis becomes template), no_match (one check, never "not vulnerable") or error; "" when none ran'),
  qod: z.number().int().optional().describe('Basis greenbone only: Greenbone\'s quality of detection, 70 to 100'),
})
export const TemplateRow = z.object({
  ip: z.string(), port: z.number().int(), cve: z.string().describe('The CVE the template is for (one the job asked about)'),
  template: z.string(), outcome: z.enum(['matched', 'no_match', 'error']),
})
export const GapRow = z.object({ ip: z.string(), port: z.number().int(), software: z.string(), cves: z.array(z.string()).describe('Exploited CVEs of the product that only a version would decide') })

// S-EXP-2 (INV-24, D-562): what ZAP's passive web scan (spider and passive rules, no form sent) noticed on a scanned page. Not exploited CVEs.
export const WebRisk = z.enum(['high', 'medium', 'low', 'info'])
export const WebFinding = z.object({
  site: z.string().describe('The page ZAP scanned, e.g. https://203.0.113.10:18443/'), plugin_id: z.string(),
  name: z.string().describe('ZAP\'s alert name; plain text'), risk: WebRisk, confidence: z.enum(['low', 'medium', 'high', 'confirmed']),
  cwe: z.number().int().describe('CWE number, 0 when ZAP names none'), description: z.string().describe('Plain text, clipped'), solution: z.string().describe('ZAP\'s advice, plain text, clipped'),
  urls: z.array(z.string()).describe('At most 3 sample pages of the site that showed it'), count: z.number().int().describe('How many pages showed it'),
})

// S-EXP-2 (INV-25, D-563): the optional deep scan. Greenbone looked at the IP from outside without logging in; QoD >= 70 only.
export const GreenboneResult = z.object({
  ip: z.string(), port: z.string().describe('"443/tcp", "general/tcp"; "" when Greenbone gave none'),
  severity: z.number().describe('CVSS score, 0.1 to 10. Below 4.0 (Low) it is a hardening note, shown apart and never counted as an alert (D-564)'), name: z.string().describe('Name of Greenbone\'s test; plain text'),
  qod: z.number().int().describe('Quality of detection, 70 to 100'), cves: z.array(z.string()).describe('CVE ids the test names'),
  solution: z.string().describe('Greenbone\'s advice, plain text, clipped'), oid: z.string().describe('OID of the test; "" when not read'),
})

export const Snapshot = z.object({
  id: z.string(), date: isoDate, scanned_at: z.iso.datetime(),
  hosts: z.array(HostRow), ports: z.array(PortRow), admin_panels: z.array(AdminRow), certs: z.array(CertRow), counts: Counts,
  services: z.array(ServiceRow), templates: z.array(TemplateRow).describe('The safe templates that ran on the services (INV-23); the box ran no template when empty'), checks: z.array(CheckRow), not_checked: z.array(NotCheckedRow), web_findings: z.array(WebFinding),
  greenbone: z.array(GreenboneResult).describe('Results of the optional deep scan with Greenbone (INV-25); empty when it did not run (the not_checked lines of kind greenbone say why)'),
  vulns: z.array(VulnRow).describe('Computed on read against today\'s CISA list, not stored'), version_gaps: z.array(GapRow),
})
export const SnapshotMeta = Snapshot.pick({ id: true, date: true, scanned_at: true, counts: true })

/** The "to" of a service whose version the newer scan did not read (INV-20): not a change of version, and its CVEs are not gone. */
export const VERSION_NOT_READ = 'version not read this time'
/** The `to` of a changed port that the newer scan did not see (INV-22). */
export const PORT_NOT_SEEN = 'missed by the last scan'
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
export const ScanPhase = z.enum(['queued', 'probing', 'saving', 'greenbone', 'done'])
export const ScanRun = z.object({
  id: z.string(), target_id: z.string(), target_value: z.string(), by: z.string().describe('Who pressed Scan now (an e-mail)'),
  started_at: z.iso.datetime(), finished_at: z.iso.datetime().nullable(),
  status: z.enum(['running', 'done', 'failed', 'stopped']),
  phase: ScanPhase.describe('queued: accepted, about to start; probing: the Vulnerability scans module is scanning the target; saving: the result is being stored; greenbone: the snapshot of the other steps is stored and the optional Greenbone scan runs (up to 90 minutes, D-563), the box\'s one scan slot stays busy; done: the snapshot exists. A failed or stopped run keeps the phase it reached'),
  snapshot_id: z.string().nullable().describe('The new snapshot when status is done; also when a run was stopped during its Greenbone step, whose earlier results are kept'),
  error: z.object({ code: z.string(), message: z.string() }).nullable().describe('Why the run failed, in the same codes and texts the synchronous scan used (unreachable, too_many, module_off ...); null otherwise'),
})

/** D-558: what Shodan InternetDB says about one of the box's own verified public IPs, next to Vedette's own scan. It is Shodan's claim, never Vedette's finding. */
export const OutsideView = z.object({
  ip: z.string().describe('The public IP that was sent to Shodan'),
  checked_at: z.iso.datetime().describe('When the box asked Shodan (InternetDB itself gives no date; its data is updated about once a week)'),
  checked_by: z.string().describe('The administrator who asked (an e-mail)'),
  found: z.boolean().describe('false: Shodan has no record of this IP (InternetDB answered 404); the lists are then empty'),
  ports: z.array(z.number().int()).describe('Open ports Shodan saw, sorted'),
  hostnames: z.array(z.string()),
  cpes: z.array(z.string()).describe('CPE 2.2 names of the software Shodan saw'),
  tags: z.array(z.string()).describe('Shodan tags, for example self-signed, vpn, eol-product'),
  vulns: z.array(z.string()).describe('CVE IDs Shodan lists from the software versions it saw; Vedette has not confirmed them'),
  scan_ports: z.array(z.number().int()).nullable().describe('Open ports of Vedette\'s own newest scan of this IP, sorted; null when it was never scanned'),
  scan_at: z.iso.datetime().nullable().describe('When that scan ran; null when never'),
})

/** D-563: the optional deep scan with Greenbone (OpenVAS), off by default. Greenbone runs as its own containers next to Vedette. */
export const GreenboneState = z.enum(['unavailable', 'off', 'starting', 'loading', 'ready', 'error'])
export const Greenbone = z.object({
  state: GreenboneState.describe('unavailable: not set up on this box; loading: Greenbone is loading its feed (the first time takes about 2 hours) or its weekly feed update, a phase and not a hang'),
  reason: z.string().nullable().describe('Why, for unavailable and error; the feed sentence for loading; null otherwise'),
  changed_by: z.string().nullable().describe('Who last turned it on or off'), changed_at: z.iso.datetime().nullable(),
  preflight: z.object({
    memory_bytes: z.number().int().nullable().describe('MemTotal of the box; null when it could not be read'),
    disk_free_bytes: z.number().int().nullable().describe('Free space of the box data directory\'s filesystem; null when it could not be read'),
    ok: z.boolean().describe('Both meet the thresholds: 8 GB (decimal) of memory and 60 GB free'),
    reason: z.string().nullable().describe('Why it cannot be enabled, with the measured number, e.g. "This box has 7.1 GB of memory; Greenbone needs at least 8.0 GB."'),
  }),
  feed_sync: z.object({
    last_at: z.iso.datetime().nullable().describe('When the weekly feed update was last tried; null before the first'),
    ok: z.boolean().nullable().describe('Whether it worked; null before the first'),
    note: z.string().nullable().describe('What happened, e.g. "Not updated: this box has 41.3 GB of free disk space; Greenbone needs at least 60.0 GB free."'),
    next_at: z.iso.datetime().nullable().describe('When the next one is due: a week after the last that worked (or after enabling), a day after one that did not; null while Greenbone is off or unavailable'),
  }).describe('The weekly update of Greenbone\'s feed while it is enabled (D-564): never during a scan, refused below 60 GB free, audited'),
  enabled: z.boolean().describe('The stored switch; the page offers Turn off whenever it is true'),
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
  { method: 'put', path: '/exposure/targets/{id}/terms', summary: 'Accept the testing terms of a verified target (FULL-1, D-566): every scan of it is then a deep scan; disruptive adds denial-of-service, brute-force and default-password checks (off by default). Admin with two-step sign-in (403 twofa_required); 409 notice_changed when version is not the current terms_notice.version; 409 not_verified or expired. Also records the Scan now commitment when the target has none of the current sentence. Accepting what is accepted changes nothing. Audited (exposure.terms_accept, with the flag)', stories: ['S-EXP-2'], role: 'admin', params: id, body: z.object({ version: z.string().describe('terms_notice.version as the page showed it'), disruptive: z.boolean() }), response: Target },
  { method: 'delete', path: '/exposure/targets/{id}/terms', summary: 'Withdraw the testing terms of a target (FULL-1, D-566): always possible; the next scan runs in the K-4 scope again. Audited (exposure.terms_revoke) when there was an acceptance', stories: ['S-EXP-2'], role: 'admin', params: id, response: Target },
  { method: 'post', path: '/exposure/targets/{id}/scan', status: 202, summary: 'Scan now. Answers at once with 202 and the run (ScanRun, status running): the scan itself goes on in the background and the page polls GET /exposure/scan. The checks below still answer synchronously. 409 when not verified, verification expired or the DNS TXT record is gone (re-checked right before the scan); 409 ip_not_current when an IP is no longer the one the box goes out through (the latest check, or a fresh full check just before the scan, must see it); 400 commitment_required when the commitment is missing and the caller is an operator (an administrator must run the first scan). For an administrator that first scan IS the confirmation (D-473, amends D-26): it needs two-step sign-in on the account (403 twofa_required otherwise) and `notice_version` of the sentence shown next to the button (400 commitment_required when left out, 409 notice_changed when it is not the current one); the commitment is then recorded with who, when and that exact sentence, and the scan goes on. A target whose commitment is of the current sentence records nothing again; one of an older sentence (D-559) is asked again once: it counts as missing (operators get 400 commitment_required "the confirmation text changed"), a request without notice_version gets 409 notice_changed, and the administrator\'s press replaces it. After those checks the Vulnerability scans module does the scan (D-229, D-57 (7)): ports are scanned only on the box\'s own verified public IPs; a domain\'s names from certificate transparency are listed and get one GET of / by name on ports 80 and 443. 409 module_off while that module is off; 409 busy while another scan runs on the box; 429 rate_limited within 10 minutes of the target\'s last scan. Failures that come while the scan runs (400 too_many when the domain has more than 300 names in the logs; 502 unreachable when the certificate-transparency search (crt.sh) does not answer or the scan does not finish within 5 minutes; module_off when the module is switched off meanwhile) end the run as status failed with that code and text, and nothing is saved. Every attempt is audited', stories: ['S-EXP-1'], role: 'operator', params: id, body: z.object({ notice_version: z.string().optional().describe('The `commitment_notice.version` the page showed next to Scan now; needed only for the first scan of a target, by an administrator') }), bodyOptional: true, response: ScanRun },
  { method: 'get', path: '/exposure/scan', summary: 'The scan that runs now, or the last one (status done, failed or stopped, with its error or snapshot_id); null when no scan has run since the box started (the run is kept in memory only)', stories: ['S-EXP-1'], role: 'viewer', response: ScanRun.nullable() },
  { method: 'post', path: '/exposure/scan/stop', summary: 'Stop the scan that runs now (status stopped, nothing is saved; audited). 409 not_running when no scan runs', stories: ['S-EXP-1'], role: 'operator', response: ScanRun },
  { method: 'get', path: '/exposure/targets/{id}/outside', summary: 'What the Internet sees (D-558): the last answer of Shodan InternetDB about this public IP of the box, with the open ports of Vedette\'s own newest scan of it; null when nobody has asked yet. Reading sends nothing', stories: ['S-EXP-1'], role: 'viewer', params: id, response: OutsideView.nullable(), example: { params: { id: 'xt-2' } } },
  { method: 'post', path: '/exposure/targets/{id}/outside', summary: 'Ask Shodan InternetDB what it has seen on this public IP (D-558). Only an administrator\'s click sends it: no job, no polling. Only a public IP of this box that is verified and still the one the box goes out through (the same check as before a scan, INV-13) is sent: 400 bad_value for a domain, 409 not_verified, expired or ip_not_current otherwise. One HTTPS GET of https://internetdb.shodan.io/<ip>, nothing else sent; 404 there is a normal answer (found false). At most one check a minute on the box (429 rate_limited); 502 unreachable when Shodan does not answer or its answer cannot be read. The answer is kept (one per IP) and every request sent is audited', stories: ['S-EXP-1'], role: 'admin', params: id, response: OutsideView },
  { method: 'get', path: '/exposure/greenbone', summary: 'The optional deep scan with Greenbone (OpenVAS, D-563): its state and this box\'s memory and free disk against the thresholds. Reading may ask Greenbone whether it is ready; it never starts a scan', stories: ['S-EXP-2'], role: 'viewer', response: Greenbone },
  { method: 'put', path: '/exposure/greenbone', summary: 'Turn the optional deep scan with Greenbone on or off (off by default). On: refused with 409 low_memory or low_disk and the measured numbers below 8 GB of memory or 60 GB free; else Greenbone starts in the background (starting, then loading while it loads its feed, about 2 hours the first time). Off: no scan uses it, its containers stop and its data is kept (502 host_error when they could not be stopped). 501 not_implemented when Greenbone is not available on this box. A scan uses it only on a target whose testing terms are accepted (D-566). Audited', stories: ['S-EXP-2'], role: 'admin', body: z.object({ enabled: z.boolean() }), response: Greenbone },
  { method: 'get', path: '/exposure/targets/{id}/snapshots', summary: 'Scan days of a target, newest first', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(SnapshotMeta) }), example: idEx },
  { method: 'get', path: '/exposure/targets/{id}/snapshots/{date}', summary: 'Scan result of one day', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: z.object({ id: z.string(), date: isoDate }), response: Snapshot, example: { params: { id: 'xt-1', date: day(1) } } },
  { method: 'get', path: '/exposure/targets/{id}/diff', summary: 'Compare two scan days: newly exposed, gone, changed', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: id, query: z.object({ from: isoDate, to: isoDate }), response: Diff, example: { params: { id: 'xt-1' }, query: { from: day(7), to: day(1) } } },
])
