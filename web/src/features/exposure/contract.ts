// API contract of module exposure (S-EXP-1). UI types are inferred from here (types.ts).
// Hard rule (LEGAL §3): POST .../scan returns 409 unless ownership is verified and its proof passed within the last 90 days (a check since
// that did not find it is a warning, not a refusal; a proof withdrawn by removing the target that gave it refuses at once), and 400
// `commitment_required` until the commitment is recorded.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { JobProgress } from '@/lib/progress'

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/)
const day = (ago: number) => {
  const d = new Date(Date.now() - ago * 864e5)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

export const TargetKind = z.enum(['domain', 'ip'])
export const VerifyMethod = z.enum(['dns_txt', 'box_egress', 'ip_file', 'ip_ptr'])

export const Counts = z.object({ subdomains: z.number().int(), ips: z.number().int(), ports: z.number().int(), admin_panels: z.number().int(), certs_expiring: z.number().int() })

// S-EXP-1 (INV-33): the admin or VPN page a port names by what it states about itself on any port (content/adminpages, the table the
// surface scan uses too): a name of its TLS certificate (FortiGate's default certificate is issued to "FortiGate" or its serial
// number), its page title, its Server header, where its first page redirects, or the product or CPE service identification read.
// Set when the port is read, never stored.
export const ApplianceDevice = z.object({ device_id: z.string(), name: z.string(), open_exploited: z.number().int().describe('Open exploited (KEV) findings of the device') })
export const Appliance = z.object({
  name: z.string().describe('The appliance family (FortiGate, Palo Alto firewall, Check Point gateway, F5 BIG-IP, WatchGuard Firebox…), or the product for a page of no appliance family (Synology DSM, Jenkins)'),
  vendor: z.string().describe('The family\'s vendor; "" for a product of no family'),
  kind: z.enum(['admin', 'vpn', 'admin_or_vpn']).describe('admin: its management page; vpn: its VPN portal (faces the Internet by design, not counted as an admin interface); admin_or_vpn: a certificate, Server header or product the family uses for both'),
  evidence: z.enum(['certificate', 'title', 'server', 'redirect', 'product']).describe('Which statement of the port named it'),
  devices: z.array(ApplianceDevice).nullable().describe('The inventory devices of the family (its own vendor, model or OS, never a PC with the vendor\'s VPN client), at most 5, with their open exploited findings; [] when none is in the inventory; null when Vedette cannot tell or the product has no family'),
  more: z.number().int().optional().describe('Devices of the family beyond the 5 listed'),
})

export const PortRow = z.object({ ip: z.string(), port: z.number().int(), service: z.string(), product: z.string().optional(), last_seen: isoDate.optional().describe('Set only on a port the newest scan did not report, kept from an earlier scan: the day a scan last saw it open (INV-22)'), misses: z.number().int().optional().describe('With last_seen: how many scans in a row that checked the address missed the port (1 = missed by the last scan)'), unchecked: z.boolean().optional().describe('The newest scan did not check the address: the row is as an earlier scan left it'),
  ident: z.enum(['probed', 'port', 'none']).optional().describe('How service identification named the service: probed (a probe\'s answer, or the surface scan\'s GET read a product), port (only the usual service of the port number: not confirmed), none (nothing identified: service is unknown, ssl/unknown or tcpwrapped). Missing: identification did not run on the port, or an older scan'),
  cert_names: z.array(z.string()).optional().describe('The names of the port\'s TLS certificate as the deep scan read them (subject common name, then DNS alternative names), at most 5'),
  title: z.string().optional().describe('The title of the web page on the port (deep scan, http-title)'),
  server: z.string().optional().describe('The HTTP Server header on the port (deep scan, http-server-header)'),
  location: z.string().optional().describe('Where the port\'s first page redirects, when the deep scan did not follow it (http-title)'),
  appliance: Appliance.optional().describe('The network appliance the port names, with the inventory devices of that family; absent when none') })

/** The sentence an administrator's first Scan now confirms. The backend owns the text (modules/exposure/notice.go) and sends it with the target's name in it; the page shows what it received. These two constants are the mock's copy, held equal to the backend's by a Go test. */
export const NOTICE_VERSION = '2026-11-18'
export const NOTICE_TEMPLATE = 'By choosing Scan now I confirm that my company owns {value} and that I am authorized to scan it, including identifying its services and versions, safe checks for known exploited vulnerabilities and a passive web scan. Vedette is provided as is under the Apache-2.0 license; the Vedette authors are not responsible for how you use it.'
export const Notice = z.object({ version: z.string(), text: z.string() })
/** The testing terms of a verified target, one paragraph per line; one acceptance covers the deep scan and the disruptive checks. The
 * backend owns the text (modules/exposure/terms.go) and sends it with the target in it; these are the mock's copy, held equal by a Go test.
 * An acceptance of TERMS_KEPT_VERSIONS stays valid after an update, with its own stored text and disruptive flag. */
export const TERMS_VERSION = '2026-11-26'
export const TERMS_KEPT_VERSIONS: readonly [string, ...string[]] = ['2026-11-18b']
export const TERMS_TEMPLATE = 'I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette\'s tools may send it:\nAll ports: every TCP port, and the service and version behind each one.\nVulnerability checks: tests for known vulnerabilities, including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command). Some checks, OpenVAS\'s in particular, may write a harmless test file or record to confirm a flaw and then try to remove it.\nWeb scanning: a scan of the web pages that follows links and may submit forms.\nAuthentication checks: whether login pages, admin interfaces and services let anyone in without a password, through a known authentication bypass or with weak settings, including the public anonymous login a service may offer (for example anonymous FTP).\nDisruptive checks: denial of service, password guessing, sign-in attempts with default or well-known passwords, and exploit checks that send more than a harmless read, such as nuclei\'s POST exploit requests that may create or change data and nmap\'s SQL injection probes. These can crash a service, lock accounts, change data or take a device offline. They run only in a scan a person starts with Scan now, never in the scans Vedette runs by itself on the schedule.\nAccept only if {value} is yours alone: not an address shared through your Internet provider (carrier-grade NAT), a hosting provider\'s NAT or proxy, or a CDN or hosted service that serves your names. Their servers are not yours to test. Vedette also scans {value} by itself on the schedule set on its page (weekly unless changed), never with the disruptive checks, until that schedule is turned off. The deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. An administrator can withdraw this acceptance at any time. Vedette is provided as is under the Apache-2.0 license; the Vedette authors are not responsible for how you use it.'
// LEGAL-2: a domain's terms: the IP text with the "yours alone" sentence replaced by what reaches every address
// its names resolve to and who answers for a provider's permission (TERMS.md's own sentences). modules/exposure/terms.go termsTemplateDomain, held equal by a test.
export const TERMS_TEMPLATE_DOMAIN = 'I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette\'s tools may send it:\nAll ports: every TCP port, and the service and version behind each one.\nVulnerability checks: tests for known vulnerabilities, including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command). Some checks, OpenVAS\'s in particular, may write a harmless test file or record to confirm a flaw and then try to remove it.\nWeb scanning: a scan of the web pages that follows links and may submit forms.\nAuthentication checks: whether login pages, admin interfaces and services let anyone in without a password, through a known authentication bypass or with weak settings, including the public anonymous login a service may offer (for example anonymous FTP).\nDisruptive checks: denial of service, password guessing, sign-in attempts with default or well-known passwords, and exploit checks that send more than a harmless read, such as nuclei\'s POST exploit requests that may create or change data and nmap\'s SQL injection probes. These can crash a service, lock accounts, change data or take a device offline. They run only in a scan a person starts with Scan now, never in the scans Vedette runs by itself on the schedule.\nEvery name under {value} that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN. If a provider serves a name, its testing policy applies to you (for example, Cloudflare and AWS forbid denial-of-service tests). The disruptive checks run only on an address of {value} that is a proven public IP of this box; every other address (a hosting provider, a CDN, a proxy, or the address of a name that points outside {value}) gets the deep scan without them. Vedette\'s tools reach each address a name under {value} resolves to, including a third-party hosting provider, CDN or proxy in front of your names: the scan of all ports, OpenVAS, nuclei and the web scan (ZAP). Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. With shared or cloud hosting, a CDN or a proxy, that address can also serve other people\'s systems: you are responsible for having the provider\'s permission. Vedette does not check who owns those addresses. A name that points (CNAME) to a name outside {value} is scanned at whatever address the owner of that other name sets. Vedette also scans {value} by itself on the schedule set on its page (weekly unless changed), never with the disruptive checks, until that schedule is turned off. The deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. An administrator can withdraw this acceptance at any time. Vedette is provided as is under the Apache-2.0 license; the Vedette authors are not responsible for how you use it.'
export const TermsNotice = z.object({ version: z.string(), text: z.string().describe('The terms with the target in them, one paragraph per line; the disruptive checks are one of the paragraphs') })
export const Terms = z.object({
  version: z.string(), by: z.string(), at: z.iso.datetime(),
  text: z.string().describe('The exact terms the administrator accepted (an acceptance of 2026-11-18b with its tick on has the tick\'s sentence as the last line)'),
  disruptive: z.boolean().describe('The disruptive checks are included (denial of service, password guessing, default-password sign-ins and exploit checks that send more than a harmless read): always true for the current terms; false only for an acceptance of 2026-11-18b made without its tick, which keeps the deep scan only until the terms are accepted again'),
})
export const Commitment = z.object({
  by: z.string(), at: z.iso.datetime(),
  version: z.string().nullable().describe('Version of the sentence the administrator saw next to Scan now; null on a commitment recorded by an older version'),
  sentence: z.string().nullable().describe('The exact sentence, with the target in it, kept with who and when; null on a commitment recorded by an older version'),
})

// Where a domain's ownership record goes. The target's own record at "@" of its zone (the registered
// domain, Public Suffix List, both sections: never across co.uk or ddns.net) proves it, as on its own name or on _vedette-verify.<name>;
// a box domain's record on its own name covers every name under it. Never through a CNAME or a wildcard.
export const ProofHint = z.object({
  zone: z.string().describe('The registered domain: the DNS zone the record is added in ("example.com")'),
  host: z.string().describe('The Name (host) to type in that zone: "@", the zone apex, for every target (the target\'s own record there proves it, and an apex takes a record whatever the subdomain is)'),
  alt_host: z.string().nullable().describe('The alternative Name: "_vedette-verify" or "_vedette-verify.git", which proves the target only (never the name itself when it is a CNAME: no TXT may sit beside a CNAME); null when _vedette-verify.<name> would pass 253 characters (no such name can exist)'),
  covered_by: z.string().nullable().describe('A verified domain of this box that covers this name already (its parent or the zone): a Check is enough, no second record; null when none'),
})

// Where the proof of a typed public IP goes: a token file served on the IP, or a reverse DNS name under a domain this box proves.
export const IpProofHint = z.object({
  path: z.string().describe('/.well-known/vedette-verify.txt'),
  content: z.string().describe('The token: the whole content of the file'),
  urls: z.array(z.string()).describe('The two addresses the box asks, http and https, on the IP'),
  ptr_domains: z.array(z.string()).describe('Domains of this box that are proved as far as the last check knows: a reverse DNS (PTR) name of the IP under one of them, resolving back to the IP, proves it'),
})

export const Target = z.object({
  id: z.string(),
  kind: TargetKind,
  value: z.string(),
  status: z.enum(['unverified', 'verified', 'expired']).describe('expired: the proof has not passed for more than 90 days (an IP the box has not seen, a record or file not found since)'),
  method: VerifyMethod.nullable(),
  token: z.string().describe('Domain: the token in the TXT record vedette-verify=<token> (not secret, it is public in DNS). Typed IP: the token the proof file carries (ip_proof). IP the box found: empty string'),
  verified_at: z.iso.datetime().nullable().describe('The last time the proof passed (every pass renews it): a domain\'s record found, the box seeing its IP, a typed IP\'s file or name found'),
  expires_at: z.iso.datetime().nullable().describe('When the proof runs out: 90 days after its last pass (the later of verified_at and a passing last_check). A check that did not find it does not move it'),
  validity: z.enum(['valid', 'expiring', 'expired']).nullable().describe('IPs only: expiring = 5 days or less left'),
  last_check: z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string() }).nullable(),
  commitment: Commitment.nullable().describe('Recorded by the first Scan now of an administrator with two-step sign-in: who, when and the exact sentence shown next to the button'),
  commitment_notice: Notice.nullable().describe('The sentence the first Scan now of an administrator confirms, with this target in it; null once the target has a commitment of the current sentence; an older one is asked again once, so a target with a commitment can carry it too'),
  terms: Terms.nullable().describe('the acceptance of the testing terms; null when none. An acceptance of 2026-11-18b stays valid with its own text and disruptive flag; one of an older version does not count (full_scan is false) until accepted again'),
  terms_notice: TermsNotice.describe('The current testing terms for this target, to accept or to read again'),
  terms_warning: z.string().nullable().optional().describe('GET of one IP target only: the box reaches the Internet through carrier-grade NAT (its gateway is in 100.64.0.0/10), so the address is probably shared; the testing terms are refused (409 shared_address) while it shows'),
  full_scan: z.boolean().describe('Scans of this target are deep scans: the current testing terms are accepted. Otherwise the scope of the Scan now sentence'),
  scannable: z.boolean(),
  blocked_reason: z.enum(['unverified', 'expired', 'txt_missing', 'proof_missing', 'no_commitment', 'ip_not_current']).nullable().describe('Why it cannot be scanned yet; null = can be scanned. A proof holds 90 days from its last pass: a check since that did not find it (a record or file gone, a lookup that failed, an IP the box does not go out through now) is a warning in last_check, so txt_missing, proof_missing and ip_not_current are no longer given (kept for older clients)'),
  created_at: z.iso.datetime(),
  last_scan_at: z.iso.datetime().nullable().describe('When the newest scan started: every page names a scan by its start'),
  last_scan_finished_at: z.iso.datetime().nullable().optional().describe('When the newest scan ended (its OpenVAS step is its last); null while OpenVAS still runs, when never scanned, or when not known'),
  latest: Counts.nullable(),
  open_ports: z.array(PortRow).nullable().describe('The first 20 open ports of the newest scan, in its order (latest.ports is the total), so the list can say what is open; null when never scanned'),
  proof: ProofHint.nullable().describe('Domains: where the TXT record goes and which verified domain covers this one already; null for an IP'),
  origin: z.enum(['person', 'box']).describe('Who added the target: person (a domain or a public IP typed in) or box (a public IP the box found as its own egress address, neutral until its testing terms are accepted)'),
  ip_proof: IpProofHint.nullable().describe('Typed IP: where the proof file goes and which domains of this box can carry a reverse DNS name that proves it; null for a domain and for an IP the box found'),
  next_check_at: z.iso.datetime().nullable().describe('Typed IP or domain with a proof: when the box checks the proof again by itself (7 days before it expires, then every 6 hours while it is not found); null otherwise'),
  scan_state: z.enum(['unproved', 'expired', 'paused', 'needs_terms', 'ready', 'queued', 'scanning']).describe('Where the target stands for scanning: scanning (a scan of it runs now), queued (a scan of it waits for the box\'s one scan slot), ready, or why not: unproved (never proved, or the proof was withdrawn), expired (the proof has not passed for 90 days), needs_terms (the scan confirmation or testing terms are not accepted yet)'),
  open_exposures: z.number().int().describe('Open ports of the newest scan (0 when never scanned): the number the target row shows'),
})

// INV-27 (S-EXP-1): the surface of a verified domain. Every (name, address) has one kind; what serves a name (a CDN or not)
// does not matter. With the domain's testing terms accepted, each public IPv4 address gets the deep scan (at most 3 a run).
export const HostClass = z.enum(['box', 'public', 'private'])
export const HostIp = z.object({
  ip: z.string(), family: z.enum(['ipv4', 'ipv6']).describe('IPv6 is listed, not scanned yet'),
  class: HostClass.describe('box: this box\'s verified, current IP; public: any other public address; private: not a public address (or an IPv6 special-purpose range), never dialed'),
  contacted: z.boolean().optional().describe('The check by name (one GET / on ports 80 and 443) went to this address: the name\'s first public IPv4. Missing or false: not contacted'),
  deep: z.enum(['scanned', 'waiting', 'fence', 'refused', 'incomplete']).optional().describe('what this run\'s deep scan did with the address (domain terms accepted): scanned (service identification ran), waiting (left by the cap, next_in_line), fence (not this box\'s, and the box has no domain fence: by-name checks only), refused (the re-check right before it refused: nothing sent), incomplete (the re-check passed but service identification did not finish: its ports are not known this run). Missing: no deep scan (terms not accepted, IPv6 or private)'),
  last_deep: z.iso.datetime().optional().describe('when a run last deep-scanned this address (rotation: the least recently scanned go first)'),
  last_tried: z.iso.datetime().optional().describe('when a run last took this address in turn (scanned, incomplete or refused); the rotation goes by the later of last_deep and last_tried'),
  next_in_line: z.number().int().min(1).optional().describe('its place among the addresses the cap left for the next runs'),
})
export const HostRow = z.object({
  name: z.string(), ip: z.string().describe('The first IPv4 address; "" when the name has none (IPv6 only, or a CNAME that leads nowhere)'),
  source: z.enum(['ct', 'dns', 'mx', 'ns', 'wordlist']).optional().describe('Where the name was found: a certificate-transparency log, the domain itself, its MX or NS records, or the list of common names. Missing on a snapshot taken by an older version: its classes are unknown'),
  cname: z.string().optional().describe('The final CNAME target'),
  ips: z.array(HostIp).optional().describe('Every address of the name with its kind (at most 16)'),
  lookup_failed: z.boolean().optional().describe('The name\'s address lookup got no answer this time: the row is the previous scan\'s, carried forward (not gone)'),
})
export const AdminRow = z.object({ url: z.string(), product: z.string(), ip: z.string(), port: z.number().int(), risk: z.enum(['danger', 'warn']),
  appliance: Appliance.optional().describe('The network appliance the page belongs to, with the inventory devices of that family; absent when none') })
export const CertRow = z.object({ host: z.string(), issuer: z.string(), expires_at: z.iso.datetime() })

// S-EXP-2 (INV-19, INV-20): what service identification (nmap -sV) read on the box's own public IP, what the scan checked and
// did not, and the exploited CVEs (CISA KEV) of the identified services, computed when the snapshot is read (not stored).
export const ServiceRow = z.object({
  ip: z.string(), port: z.number().int(),
  name: z.string().describe('nmap\'s service name: http, ssh, tcpwrapped'), product: z.string().describe('"" when nmap named none'),
  version: z.string().describe('"" when the service sent none'), cpe: z.string().describe('The CPE 2.2 URI nmap printed; "" when none'),
  extra: z.string().describe('nmap\'s extrainfo, e.g. (Debian); "" when none'),
  method: z.enum(['probed', 'table']).optional().describe('How nmap named the service: probed (a probe\'s answer matched) or table (only the usual service of the port number, not confirmed). Missing: an older scan'),
  conf: z.number().int().min(1).max(10).optional().describe('nmap\'s confidence in the name, 1 to 10 (a table name is 3)'),
})
export const CheckRow = z.object({ kind: z.string().describe('ports, names, services, templates, cve, web or greenbone'), text: z.string(), at: z.iso.datetime() })
export const NotCheckedRow = z.object({ kind: z.string().describe('udp, ports, non_exploited, services, templates, cve, web, greenbone; a domain\'s surface (INV-27): wordlist (common names not tried: wildcard DNS), by_name (names on other public addresses: checked by name only), address_family (IPv6 not scanned), lookup (names whose address lookup got no answer: left as the last scan found them); deep (the deep scan of the names\' addresses: the cap, needs the domain fence, private addresses, a refused re-check)'), text: z.string() })
export const VulnBasis = z.enum(['version', 'product', 'template', 'greenbone', 'js_library'])
export const VulnRow = z.object({
  ip: z.string(), port: z.number().int(), cve: z.string(), name: z.string(),
  basis: VulnBasis.describe('version: the version is inside an NVD range (from nmap, or from a Server or X-Powered-By header ZAP read); product: only the product matches; template: a safe template matched (INV-23), the strongest evidence; greenbone: Greenbone named this CVE and it is on the list (INV-25), shown next to any other row of the same CVE, never instead of it; js_library: Retire.js names this CVE for a JavaScript library version ZAP saw on a page'),
  summary: z.string(), date_added: isoDate.nullable().describe('When CISA listed it as exploited'), ransomware: z.boolean(),
  backport: z.string().describe('The distribution the service names (Debian, Ubuntu…), which may have backported the fix without changing the version; "" when none'),
  template: z.string().describe('Id of the safe template that ran for this CVE; "" when none ran'),
  template_result: z.enum(['', 'matched', 'no_match', 'error']).describe('What that template did: matched (basis becomes template), no_match (one check, never "not vulnerable") or error; "" when none ran'),
  qod: z.number().int().optional().describe('Basis greenbone only: Greenbone\'s quality of detection: 70 to 100 for a vulnerability, any value for a configuration fact'),
})
export const DeepSeverity = z.enum(['info', 'low', 'medium', 'high', 'critical', 'unknown'])
export const TemplateRow = z.object({
  ip: z.string(), port: z.number().int(), cve: z.string().describe('The CVE the template is for (one the job asked about); "" on a deep row about no CVE (an exposed .git, an admin panel)'),
  template: z.string(), outcome: z.enum(['matched', 'no_match', 'error']),
  name: z.string().optional().describe('deep scan, testing terms accepted: the template\'s name from the pack index, one plain line; absent on a row of a scan without the terms'),
  severity: DeepSeverity.optional().describe('the template\'s severity from the pack index; absent on a row of a scan without the terms. A deep row is kept only when it matched'),
})
export const GapRow = z.object({ ip: z.string(), port: z.number().int(), software: z.string(), cves: z.array(z.string()).describe('Exploited CVEs of the product that only a version would decide') })

// S-EXP-2 (INV-24): what ZAP's passive web scan (spider and passive rules, no form sent) noticed on a scanned page. Not exploited CVEs.
export const WebRisk = z.enum(['high', 'medium', 'low', 'info'])
export const WebSoftware = z.object({
  product: z.string(), version: z.string(),
  cves: z.array(z.string()).describe('The CVEs Retire.js lists for that library version; [] for a header'),
  distro: z.string().describe('The distribution a header names (it may backport fixes); "" when none'),
})
export const WebFinding = z.object({
  site: z.string().describe('The page ZAP scanned, e.g. https://203.0.113.10:18443/'), plugin_id: z.string(),
  name: z.string().describe('ZAP\'s alert name; plain text'), risk: WebRisk, confidence: z.enum(['low', 'medium', 'high', 'confirmed']),
  cwe: z.number().int().describe('CWE number, 0 when ZAP names none'), description: z.string().describe('Plain text, clipped'), solution: z.string().describe('ZAP\'s advice, plain text, clipped'),
  urls: z.array(z.string()).describe('At most 3 sample pages of the site that showed it'), count: z.number().int().describe('How many pages showed it'),
  group: z.enum(['fix', 'hardening']).describe('content/zap/vedette-baseline.conf: fix = a FAIL rule, shown first as "Fix this"; hardening = a WARN rule or one the list does not name'),
  software: z.array(WebSoftware).describe('versions ZAP read (10003 JavaScript library, 10036 Server header, 10037 X-Powered-By); [] for other rules'),
})

// S-EXP-2 (INV-25): the optional deep scan. Greenbone looked at the IP from outside without logging in; QoD >= 70, plus a few configuration facts at any QoD.
export const GreenboneResult = z.object({
  ip: z.string(), port: z.string().describe('"443/tcp", "general/tcp"; "" when Greenbone gave none'),
  severity: z.number().describe('CVSS score, 0.1 to 10. Below 4.0 (Low) it is a hardening note, shown apart and never counted as an alert'), name: z.string().describe('Name of Greenbone\'s test; plain text'),
  qod: z.number().int().describe('Quality of detection: 70 to 100 for a vulnerability, any value for a configuration fact'), cves: z.array(z.string()).describe('CVE ids the test names'),
  solution: z.string().describe('Greenbone\'s advice, plain text, clipped'), oid: z.string().describe('OID of the test; "" when not read'),
})

// The one state of the snapshot's OpenVAS step, which its heading follows, and when it started (shown in the viewer's
// time zone like every other time of the page).
/** Why an OpenVAS step was stopped: person (someone pressed Stop; by is who), shutdown (Vedette shut down: an update, a restart or a
 *  stop of the service), restart (Vedette started again and found it still running: it stopped before the step could store how it ended), module_off (the
 *  External exposure module was switched off), terms (the testing terms were withdrawn or lowered; by is who). */
export const GreenboneStop = z.object({
  reason: z.enum(['person', 'shutdown', 'restart', 'module_off', 'terms']),
  by: z.string().nullable().describe('The e-mail of who stopped it (person, terms); null when the box did'),
})
export const GreenboneRunState = z.enum(['running', 'done', 'partial', 'not_run', 'failed', 'stopped', 'ended'])
export const GreenboneRun = z.object({
  state: GreenboneRunState.describe('running: OpenVAS scans now (the other results are saved); done: it finished; partial: the 90-minute cap stopped it and its rows are what it had found by then; not_run: it did not scan (the not_checked line of kind greenbone says why; also a task that stayed queued for 90 minutes); failed: it failed or its answer could not be read; stopped: a Stop, the module or a restart of the box ended it (a domain keeps the rows of the addresses that finished); ended: it scanned and ended before it finished without a stop from Vedette (OpenVAS reports it stopped or interrupted, or the domain fence stopped it), with the rows it had found if any; a task OpenVAS ended before it was seen scanning is not_run'),
  started_at: z.iso.datetime().nullable().describe('When the OpenVAS step started; null when it did not'),
  addresses: z.array(z.object({ ip: z.string(), state: GreenboneRunState })).describe('A domain\'s run: the OpenVAS state of each deep-scanned address; [] for an IP'),
  ended_at: z.iso.datetime().nullable().optional().describe('When the step ended, in any final state; for a step a restart cut, when the box started again. Missing while it runs, when it did not run, and on a scan stored before it was kept'),
  stop: GreenboneStop.nullable().optional().describe('Why a stopped step was stopped; missing in any other state and on a scan stored before it was kept'),
  again: z.boolean().optional().describe('The step ran again on its own after the scan (POST /exposure/targets/{id}/openvas), on the open ports that scan found'),
})

export const Snapshot = z.object({
  id: z.string(), date: isoDate, scanned_at: z.iso.datetime().describe('When the results of the steps before OpenVAS were stored'),
  started_at: z.iso.datetime().describe('When the scan started: the time every page names it by (header, pickers, compare, history)'),
  finished_at: z.iso.datetime().nullable().describe('When its last step ended; null while OpenVAS still runs, or on a scan stored before it was kept whose end is not known'),
  hosts: z.array(HostRow), ports: z.array(PortRow), admin_panels: z.array(AdminRow), certs: z.array(CertRow), counts: Counts,
  services: z.array(ServiceRow), templates: z.array(TemplateRow).describe('The safe templates that ran on the services (INV-23); the box ran no template when empty'), checks: z.array(CheckRow), not_checked: z.array(NotCheckedRow), web_findings: z.array(WebFinding),
  greenbone: z.array(GreenboneResult).describe('Results of the optional deep scan with Greenbone (INV-25); empty when it did not run (the not_checked lines of kind greenbone say why)'),
  greenbone_run: GreenboneRun,
  vulns: z.array(VulnRow).describe('Computed on read against today\'s CISA list, not stored'), version_gaps: z.array(GapRow),
})
export const SnapshotMeta = Snapshot.pick({ id: true, date: true, scanned_at: true, started_at: true, finished_at: true, counts: true })

/** The "to" of a service whose version the newer scan did not read (INV-20): not a change of version, and its CVEs are not gone. */
export const VERSION_NOT_READ = 'version not read this time'
/** The `to` of a changed port that the newer scan did not see (INV-22). */
export const PORT_NOT_SEEN = 'missed by the last scan'
export const DiffKind = z.enum(['subdomain', 'port', 'admin', 'cert', 'service', 'vuln'])
export const DiffItem = z.object({ kind: DiffKind, key: z.string(), label: z.string(), detail: z.string() })
export const DiffChange = DiffItem.extend({ from: z.string(), to: z.string() })
export const Diff = z.object({ from: isoDate, to: isoDate, added: z.array(DiffItem), removed: z.array(DiffItem), changed: z.array(DiffChange) })

export const VerifyResult = z.object({ verified: z.boolean(), message: z.string(), target: Target })

/** Auto-detect of the box's public IPs. interval_min is 5 to 1440 (five minutes to 24 hours); the server checks it (400 bad_interval). It is the schedule exposure.public_ip, which the schedule editor changes too. */
export const BoxIpRun = z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string().describe('What the last check saw, or why it failed') })
export const BoxIpSettings = z.object({
  auto: z.boolean().describe('On: the box detects its public IPs at first start and then every interval_min minutes. Off: only "Detect now". Default on'),
  interval_min: z.number().int().describe('Minutes between automatic checks, 5 to 1440. Default 60'),
  last_run: BoxIpRun.nullable().describe('The last automatic or manual detection; null before the first one'),
  retry_in_min: z.number().int().nullable().describe('null while attempts are left. When the 10 attempts an hour (shared by Detect now and the Verify again of an IP; the DNS Check of a domain has its own limit of one per 30 seconds per target) are used up: minutes until the next one is possible, 1 or more'),
})
/** An IP the customer removed and told Vedette not to add again. The list only blocks, it never allows: restoring only lets detection add the IP again. */
export const IgnoredIp = z.object({ value: z.string().describe('A public IPv4 address'), ignored_by: z.string(), ignored_at: z.iso.datetime() })
/** The device that probably answers the open ports of the box's own public IP. Never a sure claim: NAT may forward the port to another device. */
export const Gateway = z.object({
  ip: z.string().nullable().describe('The LAN default gateway the host reports; null when the box cannot tell'),
  device_id: z.string().nullable().describe('The inventory device with that IP; null when the gateway is not in the device list'),
  name: z.string().nullable().describe('That device\'s name as the Devices page shows it (untrusted label, at most 80 characters)'),
  open_exploited: z.number().int().describe('Open findings (exploited vulnerabilities, confirmed or suspected) of that device; 0 when device_id is null'),
})
export const TargetList = z.object({ items: z.array(Target), box_ip: BoxIpSettings, ignored: z.array(IgnoredIp).describe('The Ignored list, newest first'), gateway: Gateway.nullable().describe('null unless one of the box\'s own IPs has an open port in its newest scan; then who probably answers it') })
export const ScanPhase = z.enum(['queued', 'probing', 'saving', 'greenbone', 'done'])
// INV-36: the box runs one external scan at a time; the others wait in one queue, in the order they came.
export const QueuedScan = z.object({
  target_id: z.string(), target_value: z.string(),
  by: z.string().describe('Who pressed Scan now (an e-mail), or system for a scheduled scan'),
  queued_at: z.iso.datetime(), scheduled: z.boolean(),
  starting: z.boolean().describe('Its checks run now (the TXT record, the proof, the box\'s IP): it is the next to run and can no longer be removed'),
})
export const ScanRun = z.object({
  id: z.string(), target_id: z.string(), target_value: z.string(), by: z.string().describe('Who pressed Scan now (an e-mail)'),
  started_at: z.iso.datetime(), finished_at: z.iso.datetime().nullable(),
  status: z.enum(['queued', 'running', 'done', 'failed', 'stopped']).describe('queued: a scan that waits for the box\'s one scan slot: the 202 answer of a Scan now behind another scan, and GET /exposure/scan when nothing ran since the box started and scans wait (the first of them; started_at is then when it was queued)'),
  phase: ScanPhase.describe('queued: accepted, about to start; probing: the scan module\'s runner is scanning the target; saving: the result is being stored; greenbone: the snapshot of the other steps is stored and the optional Greenbone scan runs (up to 90 minutes), the box\'s one scan slot stays busy; done: the snapshot exists. A failed or stopped run keeps the phase it reached'),
  snapshot_id: z.string().nullable().describe('The new snapshot when status is done; also when a run was stopped during its Greenbone step, whose earlier results are kept'),
  error: z.object({ code: z.string(), message: z.string() }).nullable().describe('Why the run failed, in the same codes and texts the synchronous scan used (unreachable, too_many, module_off ...); null otherwise'),
  stop_reason: z.string().nullable().optional().describe('Why the box stopped this run when it was not a person\'s Stop, e.g. "the testing terms of this target were withdrawn", "Vedette shut down"'),
  openvas_only: z.boolean().optional().describe('The run is OpenVAS again for the newest scan of the target (POST /exposure/targets/{id}/openvas), not a scan: its phase is greenbone from the start'),
  scheduled: z.boolean().optional().describe('The run is a scheduled scan of the target, started by the box'),
  queue: z.array(QueuedScan).optional().describe('The scans that wait after this one, in order; left out when none waits'),
  progress: JobProgress.nullable().describe('How far the step that runs now is (#830): the port scan, service detection and vulnerability checks as the scan worker reports them, the passive web checks, and OpenVAS\'s own percent during the greenbone phase. Set while status is running; null otherwise'),
})

/** What Shodan InternetDB says about one of the box's own verified public IPs, next to Vedette's own scan. It is Shodan's claim, never Vedette's finding. */
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

/** The optional deep scan with Greenbone (OpenVAS), off by default. Greenbone runs as its own containers next to Vedette. */
export const GreenboneState = z.enum(['unavailable', 'off', 'starting', 'loading', 'ready', 'error'])
export const Greenbone = z.object({
  state: GreenboneState.describe('unavailable: not set up on this box; loading: Greenbone is loading its feed (the first time takes 1 to 3 hours) or its weekly feed update, a phase and not a hang'),
  reason: z.string().nullable().describe('Why, for unavailable and error; the feed sentence for loading; null otherwise'),
  changed_by: z.string().nullable().describe('Who last turned it on or off'), changed_at: z.iso.datetime().nullable(),
  preflight: z.object({
    memory_bytes: z.number().int().nullable().describe('MemTotal of the box; null when it could not be read'),
    disk_free_bytes: z.number().int().nullable().describe('Free space of the box data directory\'s filesystem; null when it could not be read'),
    ok: z.boolean().describe('Both meet the thresholds: 6 GB (decimal) of memory (under 8 GB, also 2 GB of swap) and 60 GB free'),
    reason: z.string().nullable().describe('Why it cannot be enabled, with the measured number, e.g. "This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB."'),
  }),
  feed_sync: z.object({
    last_at: z.iso.datetime().nullable().describe('When the weekly feed update was last tried; null before the first'),
    ok: z.boolean().nullable().describe('Whether it worked; null before the first'),
    note: z.string().nullable().describe('What happened, e.g. "Not updated: this box has 41.3 GB of free disk space; OpenVAS needs at least 60.0 GB free."'),
    next_at: z.iso.datetime().nullable().describe('When the next one is due: a week after the last that worked (or after enabling), a day after one that did not; null while Greenbone is off or unavailable'),
  }).describe('The weekly update of Greenbone\'s feed while it is enabled: never during a scan, refused below 60 GB free, audited'),
  feed: z.object({
    nvt_version: z.string().nullable().describe('Version of the vulnerability tests (NVT feed) OpenVAS reports in GMP get_feeds, e.g. "202611140611"; null when it gave none or one Vedette does not show'),
    nvt_date: z.iso.datetime().nullable().describe('When that feed was built (UTC), read from its version; null when the version is not of the form YYYYMMDDhhmm'),
    checked_at: z.iso.datetime().describe('When Vedette last read it from OpenVAS'),
  }).nullable().describe('The feed OpenVAS itself has loaded (T10): there from the first feed load at enable on; null while it is off or unavailable, and until Vedette has read it since the box started'),
  enabled: z.boolean().describe('The stored switch; the page offers Turn off whenever it is true'),
})

export const BoxIpDetectResult = z.object({ items: z.array(Target).describe('The public IPs the box saw this time, each added or renewed'), message: z.string() })

// ---------------------------------------------------------------------------------------------------------------------
// Target tree. A target is a node: a name under a domain target sits under it and keeps its own options and schedule, an
// ancestor's ownership proof covers its descendants, scan results are rows with first and last seen, and every scan is a
// run. The endpoints under /exposure/tree and /exposure/issues replace /exposure/targets*, /exposure/scan* and the
// snapshots; /exposure/box-ip/*, /exposure/greenbone and /exposure/targets/{id}/outside keep their shape.
// The schedule of a node is the shared schedule under the key exposure.target:<id>; a run's steps and log are the shared run.

export const ScopeMode = z.enum(['self', 'all', 'selected'])
export const NodeOrigin = z.enum(['person', 'box', 'discovered'])
export const TargetRef = z.object({ id: z.string(), value: z.string() })

export const ProofState = z.enum(['proven', 'covered', 'missing', 'expired', 'not_current'])
export const ProofCheck = z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string() })
export const DnsProof = z.object({
  zone: z.string().describe('The registered domain: the DNS zone the record is added in'),
  host: z.string().describe('The name to type in that zone: "@" for the zone apex'),
  alt_host: z.string().nullable().describe('The alternative name that proves this target only, "_vedette-verify" or "_vedette-verify.<label>"; null when it would pass 253 characters'),
  value: z.string().describe('The whole TXT value: vedette-verify=<token>'),
})
export const FileProof = z.object({
  urls: z.array(z.string()).describe('The two addresses the box asks, http and https, on the IP'),
  content: z.string().describe('The token: the whole content of /.well-known/vedette-verify.txt'),
  ptr_domains: z.array(z.string()).describe('Proven domains of this box: a reverse DNS name of the IP under one of them, resolving back to the IP, proves it too'),
})
export const Replaced = z.object({
  by: z.string().describe("The box's current egress address"),
  at: z.iso.datetime().describe('When the box was first seen going out through it'),
})
export const Proof = z.object({
  state: ProofState.describe('proven: this node\'s own proof holds; covered: the proof of an ancestor covers it (covered_by); missing: never proved, or the proof was withdrawn (the target whose record proved it was removed); expired: the proof has not passed for 90 days; not_current: an IP the box found that the box does not go out through now (still scannable until it expires). A check that did not find the proof is shown in last_check and changes the state only once the 90 days have passed'),
  method: VerifyMethod.nullable().describe('How this node proves itself; null when covered by an ancestor or not proven yet'),
  covered_by: TargetRef.nullable().describe('The ancestor whose proof covers this node; null unless state is covered'),
  verified_at: z.iso.datetime().nullable().describe('When this node\'s own proof was last found'),
  expires_at: z.iso.datetime().nullable().describe('90 days after the proof last passed; null while unproved or covered by an ancestor'),
  next_check_at: z.iso.datetime().nullable().describe('When the box checks the proof again by itself; null when it does not'),
  last_check: ProofCheck.nullable(),
  dns: DnsProof.nullable().describe('Domain not covered by an ancestor: where its TXT record goes; null otherwise'),
  file: FileProof.nullable().describe('IP typed in by a person: where its proof file goes; null otherwise'),
  replaced: Replaced.nullable().describe("An IP the box found that was replaced: it was last seen before the box's current egress address was first seen, so the two never overlapped (a dynamic address the provider took back) and it is no longer scanned unless the box goes out through it again; null otherwise"),
})

export const Consent = z.object({
  version: z.string(), text: z.string().describe('The exact text accepted, with the target in it'),
  by: z.string(), at: z.iso.datetime(),
  disruptive: z.boolean().describe('Testing terms only: the disruptive checks are included (always for the current terms; false for an acceptance of 2026-11-18b made without its tick: accept the terms again to include them); false for the scan confirmation'),
})

// Moves to web/src/lib/statusCodes.ts when the findings and exposure models meet (same values).
export const RunStatus = z.enum(['queued', 'waiting', 'running', 'stopping', 'done', 'partial', 'failed', 'stopped'])
export const RunTrigger = z.enum(['manual', 'schedule', 'event'])
export const ScanMode = z.enum(['surface', 'deep'])
export const ScanCounts = z.object({
  hosts: z.number().int(), services: z.number().int().describe('Open services after the scan'),
  new_services: z.number().int(), closed_services: z.number().int(),
  issues: z.number().int().describe('Open issues after the scan'), new_issues: z.number().int(),
})
export const Scan = z.object({
  run_id: z.string().describe('The shared run: its steps, items and log are read there, and it is stopped there'),
  target_id: z.string(),
  status: RunStatus, trigger: RunTrigger,
  requested_by: z.string().describe('Who asked (an e-mail), or system for a scheduled scan'),
  mode: ScanMode.describe('deep when the current testing terms of the target are accepted; surface otherwise'),
  queued_at: z.iso.datetime(), started_at: z.iso.datetime().nullable(), ended_at: z.iso.datetime().nullable(),
  waiting_for: z.string().nullable().describe('Set only while status is waiting, e.g. "the scan window (opens 23:00)"'),
  stop_reason: z.string().nullable(), error: z.string().nullable(),
  counts: ScanCounts.nullable().describe('What the scan left; null until it ends done or partial'),
})

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])
/** The deep-scan settings of a target: they only narrow what the testing terms and the scan's own rules allow (a scheduled scan, a
 * typed IP, an address that is not the box's own, carrier-grade NAT never get the disruptive groups, whatever is set here). */
export const MAX_SKIP_PORTS = 64
export const MAX_SKIP_PATHS = 20
export const DeepSpeed = z.enum(['normal', 'gentle'])
const deepGroups = {
  dos: z.boolean().describe('Denial-of-service and crash checks (off by default): the disruptive checks that can exhaust or crash a service'),
  logins: z.boolean().describe('Password guessing and sign-ins with default or well-known passwords'),
  web_active: z.boolean().describe('The active web scan (ZAP): its spider and attack rules; its disruptive rules also need dos and data_change'),
  data_change: z.boolean().describe('Exploit checks that send more than a harmless read and may create or change data'),
  openvas: z.boolean().describe('OpenVAS on this target; it still needs the box-wide OpenVAS switch on'),
  speed: DeepSpeed.describe('gentle: the engines that can run slower do (OpenVAS runs fewer checks at once)'),
  skip_ports: z.array(z.number().int().min(1).max(65535)).max(MAX_SKIP_PORTS).describe('TCP ports no engine is sent to; their stored services are left as they are (never closed by a scan that skipped them)'),
  skip_paths: z.array(z.string()).max(MAX_SKIP_PATHS).describe('URL path prefixes the web scans leave out, matched as written (not a pattern): ZAP, and nuclei, which runs a template only when every request it can send is known and outside them; nmap and OpenVAS keep off a path only by skipping its port'),
}
export const DeepSettings = z.object({
  ...deepGroups,
  updated_at: z.iso.datetime().nullable().describe('When the settings were saved; null while the target has the defaults'),
  updated_by: z.string().nullable().describe('Who saved them; null while the target has the defaults'),
  problem: z.string().nullable().describe('Why the stored settings cannot be read (the scan of the target refuses to run until they are saved again); null when they read fine'),
})
export const NodeBlock = z.enum(['disabled', 'proof', 'no_commitment'])
export const TargetNode = z.object({
  id: z.string(),
  parent_id: z.string().nullable().describe('The domain target this node sits under; null at the top of the tree'),
  schedule_key: z.string().describe('The key of its schedule in the shared schedules: exposure.target:<id>'),
  kind: TargetKind, value: z.string(), origin: NodeOrigin,
  scope_mode: ScopeMode.nullable().describe('Domains: self scans only this name; all this name and every name found under it; selected this name and the names chosen (Host.selected). null for an IP'),
  enabled: z.boolean().describe('The node is scanned, by Scan now and by its schedule'),
  created_at: z.iso.datetime(),
  proof: Proof,
  commitment: Consent.nullable().describe('The scan confirmation recorded by the first Scan now of an administrator; null when none'),
  terms: Consent.nullable().describe('The accepted testing terms; null when none'),
  commitment_notice: Notice.nullable().describe('The sentence the next Scan now of an administrator confirms; null once the node has a commitment of the current sentence'),
  terms_notice: TermsNotice.describe('The current testing terms for this node, to accept or read again'),
  terms_warning: z.string().nullable().describe('IP behind carrier-grade NAT: the address is probably shared, so the testing terms are refused; a typed IP: its own warning (the terms can be accepted)'),
  deep: z.boolean().describe('Scans of this node are deep scans: the current testing terms are accepted'),
  deep_settings: DeepSettings.describe('How hard the deep scan may hit this node: the groups it may run, its speed, and the ports and web paths it leaves out'),
  blocked: NodeBlock.nullable().describe('Why Scan now is refused: disabled (the node is off), proof (proof.state is neither proven nor covered), no_commitment (no scan confirmation of the current sentence: an administrator\'s Scan now records it, an operator\'s is refused); null when it can be scanned'),
  last_scan: Scan.nullable().describe('The newest run of this node, live or ended; null when never scanned'),
  counts: z.object({
    hosts: z.number().int().describe('Names found under the node'), services: z.number().int().describe('Open services'),
    web: z.number().int().describe('Open services that answered HTTP'), issues: z.number().int().describe('Open issues'),
    worst: Severity.nullable().describe('The highest severity among open issues; null when none'),
  }),
})
export const TargetTree = z.object({
  items: z.array(TargetNode).describe('Every target in tree order: each node right after its parent, siblings by value'),
  box_ip: BoxIpSettings, ignored: z.array(IgnoredIp).describe('The Ignored list, newest first'),
  gateway: Gateway.nullable().describe('null unless one of the box\'s own IPs has an open service; then who probably answers it'),
})

export const HostSource = z.enum(['ct', 'dns', 'mx', 'ns', 'wordlist', 'person'])
export const Host = z.object({
  id: z.string(), name: z.string(),
  source: HostSource.describe('Where the name was found: a certificate-transparency log, the domain\'s own records, its MX or NS records, the list of common names, or typed by a person'),
  selected: z.boolean().describe('Chosen for scanning; read only when the node\'s scope_mode is selected'),
  child: TargetRef.nullable().describe('The name is its own target: that target scans it and this node skips it'),
  cname: z.string().nullable().describe('The final CNAME target; null when none'),
  first_seen: z.iso.datetime(), last_seen: z.iso.datetime(),
})
export const Address = z.object({
  host_id: z.string().nullable().describe('The name it belongs to; null for the address of an IP target'),
  ip: z.string(), family: z.enum(['ipv4', 'ipv6']),
  class: HostClass.describe('box: this box\'s own current IP; public: any other public address; private: never dialed'),
  first_seen: z.iso.datetime(), last_seen: z.iso.datetime(),
})
export const ServiceIdent = z.enum(['probed', 'table', 'none'])
export const Service = z.object({
  id: z.string(), ip: z.string(), port: z.number().int(), proto: z.enum(['tcp', 'udp']),
  name: z.string().describe('The service name: http, ssh, sip; "" when not identified'),
  product: z.string(), version: z.string(), cpe: z.string().describe('"" when none'),
  title: z.string().describe('The page title of a web service; "" when none'),
  cert: z.object({ names: z.array(z.string()), issuer: z.string(), expires_at: z.iso.datetime() }).nullable().describe('The TLS certificate the service showed; null when none'),
  is_web: z.boolean().describe('The service answered HTTP (directly or inside TLS), on any port'),
  ident: ServiceIdent.describe('probed: a probe\'s answer named it; table: only the usual service of the port number; none: not identified'),
  state: z.enum(['open', 'closed']).describe('closed: a later scan of the address no longer found it open'),
  first_seen: z.iso.datetime(), last_seen: z.iso.datetime(),
  not_reached_since: z.iso.datetime().nullable().describe('On an open service whose newest scans could not reach the port from the box (no answer from the address, it stopped answering, or the probe step did not finish): when the first of those scans started. The service is kept until a scan reaches the port again, and is no longer listed 30 days after it was last seen. null when the newest scan that checked the port reached it, or none did'),
})

export const IssueEngine = z.enum(['surface', 'nuclei', 'zap', 'openvas', 'match'])
export const IssueState = z.enum(['open', 'gone', 'handled'])
// The handled vocabulary of findings (same values and order as FINDING_RESOLUTIONS): an issue is handled the way a finding
// is. Moves to web/src/lib/statusCodes.ts when the findings and exposure models meet.
export const Resolution = z.enum(['patched', 'mitigated', 'accepted', 'not_relevant', 'false_positive'])
// The CVSS score of a CVE as the findings contract gives it, so the shared CVE list shows a severity per CVE.
export const SeverityBand = z.enum(['critical', 'high', 'medium', 'low', 'none'])
export const CveSeverity = z.object({
  band: SeverityBand, score: z.number().min(0).max(10), version: z.enum(['4.0', '3.1', '3.0', '2.0']), vector: z.string().min(1).max(200),
}).describe('The CVSS base score the catalogue picks for the CVE and its band; null = "Not scored yet", never 0')
export const IssueCve = z.object({ cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/), severity: CveSeverity.nullable() })
export const IssueZap = z.object({
  risk: z.enum(['high', 'medium', 'low', 'info']).describe('ZAP\'s risk of the alert'),
  confidence: z.enum(['confirmed', 'high', 'medium', 'low']).describe('How sure ZAP is of it'),
  pass: z.enum(['passive', 'active']).describe('passive: the baseline read it in the pages; active: an attack request of the active scan showed it'),
  disruptive: z.boolean().optional().describe('Active only: a rule that runs only with the disruptive checks (the box\'s own public IP) found it, so only a later active scan with them closes it; missing when not'),
})
export const Issue = z.object({
  id: z.string(), target_id: z.string(),
  service_id: z.string().nullable().describe('The service it was found on; null when it is about the target as a whole'),
  engine: IssueEngine, key: z.string().describe('The engine\'s own id: plugin, template, rule or CVE'),
  title: z.string(), severity: Severity,
  cves: z.array(IssueCve).describe('The CVEs the engine names, the most severe first'),
  detail: z.object({
    description: z.string(), solution: z.string(),
    evidence: z.array(z.string()).describe('Where it was seen: URLs or lines of the engine\'s output'),
    zap: IssueZap.optional().describe('engine zap: ZAP\'s own rating of the alert and the pass that raised it; missing on other engines and on alerts stored before it was kept'),
  }),
  state: IssueState.describe('open; gone: the last scan no longer reported it; handled: a person decided (resolution)'),
  resolution: Resolution.nullable().describe('Set only when state is handled'),
  resolved_by: z.string().nullable(), resolved_at: z.iso.datetime().nullable(), note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('resolution accepted only: the last day; the issue reopens after it'),
  first_seen: z.iso.datetime(), last_seen: z.iso.datetime(),
})
export const MAX_ISSUE_IDS = 500
// One scan reads at most 300 names, the target's own included, so a target with scope selected chooses at most 299 of its names.
// More are refused before any handler runs (400 invalid) with this sentence; the box and the mock say the same.
export const MAX_SELECTED = 299
export const SELECTED_LIMIT_WHY = 'Choose at most 299 names: one scan reads at most 300 names, this one included. For more, add a subdomain as its own target.'
const issueIds = z.array(z.string()).min(1).max(MAX_ISSUE_IDS)
const HandleResult = z.object({ handled: z.number().int().min(0), skipped: z.number().int().min(0).describe('Issues not open, left as they were') })
const ReopenResult = z.object({ reopened: z.number().int().min(0), skipped: z.number().int().min(0).describe('Issues not handled, left as they were') })

const id = z.object({ id: z.string() })
const idEx = { params: { id: 'xt-1' } }
const nodeEx = { params: { id: 'xt-11' } }

export const endpoints = defineEndpoints([
  { method: 'get', path: '/exposure/targets', summary: 'Domains and verified public IPs with ownership status, expiry, commitment and latest result, plus the box-IP auto-detect settings', stories: ['S-EXP-1'], role: 'viewer', response: TargetList },
  { method: 'post', path: '/exposure/targets', status: 201, summary: 'Add a target (changes scan scope): a domain, or a public IPv4 address typed in. kind is domain or ip; left out, an IPv4 address is an IP and anything else a domain. A typed IP is accepted into the list at once and is never scanned, nor sent to Shodan, until it is proved: a token file at /.well-known/vedette-verify.txt on the IP (http or https, no redirect off the IP, the ACME HTTP-01 model), or forward-confirmed reverse DNS (its PTR is a name under a domain this box has proved, and that name resolves back to the IP). An A record of a proved domain pointing at the IP is not proof. The proof lasts 90 days from its last pass and the box checks it again by itself (expires_at, next_check_at). 400 ip_not_allowed for a private, reserved or IPv6 address, 400 bad_value for an address on the Ignored list. The IP the box finds as its own egress address is added by detection, not here', stories: ['S-EXP-1'], role: 'admin', body: z.object({ value: z.string(), kind: TargetKind.optional() }), response: Target },
  { method: 'post', path: '/exposure/box-ip/verify', summary: '"Detect now": the box asks three public \"what is my IP\" services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip) over several rounds of new connections, accepts an IP only when at least two of the three agree in a round, and adds or renews (90 days from now) every IP that passed, except those on the Ignored list, so several egress IPs behind a load balancer are all found. Takes no IP input; refuses private, reserved and CGNAT results (400 not_public when none is public); 502 unreachable when no round gave an IP (no service answered, or they did not agree); rate limited to 10 attempts per hour', stories: ['S-EXP-1'], role: 'admin', response: BoxIpDetectResult },
  { method: 'put', path: '/exposure/box-ip/settings', summary: 'Turn auto-detect on or off and set the check interval (5 to 1440 minutes, else 400 bad_interval). Turning it on checks at once. The IP list is kept when it is turned off. Typing an IP is not possible here either', stories: ['S-EXP-1'], role: 'admin', body: z.object({ auto: z.boolean(), interval_min: z.number().int() }), response: BoxIpSettings },
  { method: 'delete', path: '/exposure/box-ip/ignored/{ip}', summary: 'Restore an IP from the Ignored list: detection may add it again the next time the box sees it. It is not added by this call and is not scannable by itself (it still needs ownership proof and the commitment). 404 when the IP is not on the list', stories: ['S-EXP-1'], role: 'admin', params: z.object({ ip: z.string() }), response: null },
  { method: 'get', path: '/exposure/targets/{id}', summary: 'One external-exposure target', stories: ['S-EXP-1'], role: 'viewer', params: id, response: Target, example: idEx },
  { method: 'delete', path: '/exposure/targets/{id}', summary: 'Delete a target with its snapshots and commitment. For a public IP this removes it from the list; with ignore=true it also goes on the Ignored list and is never added again or scanned (ignore is only for IPs, else 400 bad_value); without it, auto-detect brings it back (as a new target) the next time the box sees it', stories: ['S-EXP-1'], role: 'admin', params: id, query: z.object({ ignore: z.enum(['true', 'false']).optional() }), response: null },
  { method: 'post', path: '/exposure/targets/{id}/verify', summary: 'Re-check ownership: domain = DNS TXT record; typed IP = its token file, then reverse DNS (a pass renews it for 90 days; once every 30 seconds per target, and inside the box-wide bound of domain checks); IP the box found = the box must currently egress through this same IP (renews it for 90 days). A domain\'s record found renews it for 90 days too. Not found is a normal answer (verified:false) and, inside the 90 days of the last pass, a warning only. Rate limited: a domain once every 30 seconds per target, and a box-wide burst of 20 domain checks then one more every 10 seconds, the check of a name just added included (429 rate_limited says in how many seconds the next check is allowed), an IP within the 10 attempts an hour of the box. A domain already covered by the proof of another target of the box (a TXT record on its registered domain covers that name and the names under it) is verified with the message "Ownership already proven by the TXT record at example.com (checked 18 Nov 2026, 10:00)"', stories: ['S-EXP-1'], role: 'operator', params: id, response: VerifyResult },
  { method: 'put', path: '/exposure/targets/{id}/terms', summary: 'Accept the testing terms of a verified target, one acceptance: every scan of it is then a deep scan, and a scan a person starts also runs the disruptive checks (denial of service, password guessing, default-password checks and exploit checks that send more than a harmless read); scheduled scans never do. Admin with two-step sign-in (403 twofa_required); 409 notice_changed when version is not the current terms_notice.version; 409 not_verified or expired (the box\'s own IP it does not go out through now can accept them while its 90-day proof holds); 409 shared_address for the box\'s IP behind carrier-grade NAT (terms_warning). Every refusal is logged (WARN, code and target id). Also records the Scan now commitment when the target has none of the current sentence. Accepting what is accepted changes nothing; over an older acceptance it replaces it. Audited (exposure.terms_accept, with the flag)', stories: ['S-EXP-2'], role: 'admin', params: id, body: z.object({ version: z.string().describe('terms_notice.version as the page showed it'), disruptive: z.boolean().optional().describe('Ignored (sent by older pages): every acceptance includes the disruptive checks') }), response: Target },
  { method: 'delete', path: '/exposure/targets/{id}/terms', summary: 'Withdraw the testing terms of a target: always possible; the next scan runs in the scope of the Scan now sentence again, and a deep scan of this target that runs now is stopped (ScanRun.stop_reason). Audited (exposure.terms_revoke) when there was an acceptance', stories: ['S-EXP-2'], role: 'admin', params: id, response: Target },
  { method: 'post', path: '/exposure/targets/{id}/scan', status: 202, summary: 'Scan now. Answers at once with 202 and the run (ScanRun, status running): the scan itself goes on in the background and the page polls GET /exposure/scan. The checks below still answer synchronously. 409 not_verified when never proved or the proof was withdrawn, 409 expired when the proof has not passed for 90 days. Right before the scan the proof is looked for again (a domain\'s TXT record, a typed IP\'s file or name, a fresh full check that the box goes out through its own IP): found renews it for 90 days; not found is recorded in last_check as a warning and the scan goes on while the proof is inside its 90 days; 400 commitment_required when the commitment is missing and the caller is an operator (an administrator must run the first scan). For an administrator that first scan IS the confirmation: it needs two-step sign-in on the account (403 twofa_required otherwise) and `notice_version` of the sentence shown next to the button (400 commitment_required when left out, 409 notice_changed when it is not the current one); the commitment is then recorded with who, when and that exact sentence, and the scan goes on. A target whose commitment is of the current sentence records nothing again; one of an older sentence is asked again once: it counts as missing (operators get 400 commitment_required "the confirmation text changed"), a request without notice_version gets 409 notice_changed, and the administrator\'s press replaces it. After those checks the scan module\'s runner does the scan (it follows this module\'s switch, so the Vulnerability scans module may be off): ports and pages are scanned on the box\'s own verified public IPs and on a typed public IP while its proof is found (looked for again right before, one live result reused for 5 minutes); a domain\'s names from certificate transparency, its MX and NS records and a list of common names (looked up through the box\'s DNS resolver) are listed with the kind of each address (INV-27) and get one GET of / by name on ports 80 and 443; the deep steps beyond that go to the box\'s own address, and to a typed IP or an address of a domain through the executors\' own fence. 409 module_off while the External exposure module is off. While another scan runs on the box (or others wait) the scan waits in the box\'s queue: 202 with status queued and the queue, the checks above run again right before it starts, and GET /exposure/scan lists it until then (409 busy only for the target whose scan runs now). 429 rate_limited within 10 minutes of the target\'s last scan. Failures that come while the scan runs (400 too_many when the domain has more than 300 names in the logs; 502 unreachable when the certificate-transparency search (crt.sh) does not answer, the scan does not finish within 5 minutes, or nothing of the target answered while the box could not reach the public IP services either (the box\'s own network failed: the run is incomplete and the target keeps the results of its last complete scan); module_off when the module is switched off meanwhile) end the run as status failed with that code and text, and nothing is saved. Every attempt is audited', stories: ['S-EXP-1'], role: 'operator', params: id, body: z.object({ notice_version: z.string().optional().describe('The `commitment_notice.version` the page showed next to Scan now; needed only for the first scan of a target, by an administrator') }), bodyOptional: true, response: ScanRun },
  { method: 'post', path: '/exposure/targets/{id}/openvas', status: 202, summary: 'Run OpenVAS again, on its own, for the newest scan of a public IP of this box, started less than 24 hours ago, whose OpenVAS step started and did not finish (stopped, cut by a restart, failed, or ended by OpenVAS before it found anything: findings it had are kept until a new deep scan). It checks the open TCP ports that scan found, and its outcome replaces that step in the same snapshot; the other results are kept. Answers at once with 202 and the run (openvas_only, phase greenbone); the page polls GET /exposure/scan and can stop it. The same refusals as Scan now come first (409 not_verified, expired; 400 commitment_required when the target has no current commitment; 400 out_of_scope; 409 busy, also while OpenVAS runs; 429 rate_limited), then 400 bad_value for a domain (run its deep scan again), 409 nothing_to_rerun when the newest scan has no such step or started more than 24 hours ago, 503 scanner_unavailable when OpenVAS cannot scan now (off, starting, loading its feed, testing terms not accepted). Every attempt is audited as exposure.scan', stories: ['S-EXP-2'], role: 'operator', params: id, response: ScanRun },
  { method: 'get', path: '/exposure/scan', summary: 'The scan that runs now, or the last one (status done, failed or stopped, with its error or snapshot_id), with the scans that wait (queue); null when no scan has run since the box started (the run and the queue are kept in memory only)', stories: ['S-EXP-1'], role: 'viewer', response: ScanRun.nullable() },
  { method: 'delete', path: '/exposure/targets/{id}/queue', summary: 'Take the scan of this target that waits in the queue out of it (a Scan now or a scheduled scan). 409 not_queued when none waits, or its checks have started (stop it once it runs). Audited as exposure.scan', stories: ['S-EXP-1'], role: 'operator', params: id, response: null },
  { method: 'post', path: '/exposure/scan/stop', summary: 'Stop the scan that runs now (status stopped, nothing is saved; audited). 409 not_running when no scan runs', stories: ['S-EXP-1'], role: 'operator', response: ScanRun },
  { method: 'get', path: '/exposure/targets/{id}/outside', summary: 'What the Internet sees: the last answer of Shodan InternetDB about this public IP of the box, with the open ports of Vedette\'s own newest scan of it; null when nobody has asked yet. Reading sends nothing', stories: ['S-EXP-1'], role: 'viewer', params: id, response: OutsideView.nullable(), example: { params: { id: 'xt-2' } } },
  { method: 'post', path: '/exposure/targets/{id}/outside', summary: 'Ask Shodan InternetDB what it has seen on this public IP. Only an administrator\'s click sends it: no job, no polling. Only a public IP of this box that is verified and still the one the box goes out through (the same check as before a scan, INV-13) is sent: 400 bad_value for a domain, 409 not_verified, expired or ip_not_current otherwise. One HTTPS GET of https://internetdb.shodan.io/<ip>, nothing else sent; 404 there is a normal answer (found false). At most one check a minute on the box (429 rate_limited); 502 unreachable when Shodan does not answer or its answer cannot be read. The answer is kept (one per IP) and every request sent is audited', stories: ['S-EXP-1'], role: 'admin', params: id, response: OutsideView },
  { method: 'get', path: '/exposure/greenbone', summary: 'The optional deep scan with OpenVAS (Greenbone Community Edition): its state and this box\'s memory and free disk against the thresholds. Reading may ask OpenVAS whether it is ready; it never starts a scan', stories: ['S-EXP-2'], role: 'viewer', response: Greenbone },
  { method: 'put', path: '/exposure/greenbone', summary: 'Turn the optional deep scan with OpenVAS on or off (off by default). On: refused with 409 low_memory or low_disk and the measured numbers below 6 GB of memory or 60 GB free; else OpenVAS starts in the background (starting, then loading while it loads its feed, 1 to 3 hours the first time). Off: no scan uses it, its containers stop and its data is kept (502 host_error when they could not be stopped). 501 not_implemented when OpenVAS is not available on this box. A scan uses it only on a target whose testing terms are accepted. Audited', stories: ['S-EXP-2'], role: 'admin', body: z.object({ enabled: z.boolean() }), response: Greenbone },
  { method: 'get', path: '/exposure/targets/{id}/snapshots', summary: 'Scan days of a target, newest first', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(SnapshotMeta) }), example: idEx },
  { method: 'get', path: '/exposure/targets/{id}/snapshots/{date}', summary: 'Scan result of one day', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: z.object({ id: z.string(), date: isoDate }), response: Snapshot, example: { params: { id: 'xt-1', date: day(1) } } },
  { method: 'get', path: '/exposure/targets/{id}/diff', summary: 'Compare two scan days: newly exposed, gone, changed', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: id, query: z.object({ from: isoDate, to: isoDate }), response: Diff, example: { params: { id: 'xt-1' }, query: { from: day(7), to: day(1) } } },
  { method: 'get', path: '/exposure/tree', summary: 'Every target as a tree, with its proof (own or covered by an ancestor), consent, newest scan and counts, plus the box-IP settings, the Ignored list and the gateway', stories: ['S-EXP-1'], role: 'viewer', response: TargetTree },
  { method: 'post', path: '/exposure/tree', status: 201, summary: 'Add a target: a domain, or a public IPv4 address typed in (kind left out: an IPv4 address is an IP, anything else a domain). A domain goes under the nearest domain target it is a name of, and targets that are names of it move under it in the same write; a name the parent already found becomes its own target there (Host.child). scope_mode is for domains only (default all; 400 bad_value for an IP). A typed IP is never scanned until proven. 409 duplicate, 400 bad_value, 400 ip_not_allowed for a private, reserved or IPv6 address', stories: ['S-EXP-1'], role: 'admin', body: z.object({ value: z.string(), kind: TargetKind.optional(), scope_mode: ScopeMode.optional() }), response: TargetNode },
  { method: 'get', path: '/exposure/tree/{id}', summary: 'One target node', stories: ['S-EXP-1'], role: 'viewer', params: id, response: TargetNode, example: nodeEx },
  { method: 'patch', path: '/exposure/tree/{id}', summary: 'Edit a target: scope_mode (domains only), enabled, and selected, the ids of the names to scan when the scope is selected (replaces the choice; 400 bad_value for an id of another node or with another scope). Audited', stories: ['S-EXP-1'], role: 'admin', params: id, body: z.object({ scope_mode: ScopeMode.optional(), enabled: z.boolean().optional(), selected: z.array(z.string()).max(MAX_SELECTED).optional().describe(`The ids of the names to scan, at most ${MAX_SELECTED}: ${SELECTED_LIMIT_WHY}`) }), response: TargetNode },
  { method: 'delete', path: '/exposure/tree/{id}', summary: 'Delete a target with its rows, consent and runs. Its children move up to its parent (or the top) and keep their own options; a child that was covered by its proof needs its own. ignore=true (IPs only, else 400 bad_value) also puts the IP on the Ignored list. Audited', stories: ['S-EXP-1'], role: 'admin', params: id, query: z.object({ ignore: z.enum(['true', 'false']).optional() }), response: null },
  { method: 'post', path: '/exposure/tree/{id}/verify', summary: 'Check ownership now: a domain\'s TXT record, a typed IP\'s file or reverse DNS name, or that the box still goes out through its own IP. A node covered by a proven ancestor is verified by that proof. Not found is a normal answer (verified false). 429 rate_limited as before', stories: ['S-EXP-1'], role: 'operator', params: id, response: z.object({ verified: z.boolean(), message: z.string(), node: TargetNode }) },
  { method: 'put', path: '/exposure/tree/{id}/terms', summary: 'Accept the testing terms of a node whose proof holds (proven, covered, or the box\'s own IP it does not go out through now), one acceptance: its scans are then deep scans, and a scan a person starts also runs the disruptive checks; scheduled scans never do. Admin with two-step sign-in (403 twofa_required); 409 notice_changed when version is not terms_notice.version; 409 not_verified or expired; 409 shared_address for the box\'s IP behind carrier-grade NAT. Every refusal is logged (WARN, code and node id). Records the scan confirmation too when the node has none of the current sentence. Audited', stories: ['S-EXP-2'], role: 'admin', params: id, body: z.object({ version: z.string(), disruptive: z.boolean().optional().describe('Ignored (sent by older pages): every acceptance includes the disruptive checks') }), response: TargetNode },
  { method: 'delete', path: '/exposure/tree/{id}/terms', summary: 'Withdraw the testing terms: the next scan is a surface scan, and a deep scan of this node that runs now is stopped. Audited', stories: ['S-EXP-2'], role: 'admin', params: id, response: TargetNode },
  { method: 'put', path: '/exposure/tree/{id}/deep-settings', summary: `Save the deep-scan settings of a node, whole. They only narrow: a group turned on here still runs only where the testing terms and the scan's rules allow it. Turning dos on needs two-step sign-in (403 twofa_required); 400 invalid_settings for a port outside 1-65535, more than ${MAX_SKIP_PORTS} ports, a path that does not start with /, holds a pattern, a query or a space, is over 200 characters, or more than ${MAX_SKIP_PATHS} paths. A scan that runs now takes a group turned off at its next step and never a group turned on; the ports and web paths to skip and the speed apply from the next scan. Audited (exposure.deep_settings, before and after)`, stories: ['S-EXP-2'], role: 'admin', params: id, body: z.object(deepGroups), response: TargetNode },
  { method: 'post', path: '/exposure/tree/{id}/scan', status: 202, summary: 'Scan now: queues a run for this node (202 with the scan, status queued or running). Refused when blocked: 409 disabled, 409 not_verified (the proof is re-checked right before), 400 commitment_required for an operator; an administrator\'s first Scan now records the confirmation and needs two-step sign-in (403 twofa_required) and notice_version (409 notice_changed when not current). 409 busy when a run of this node is queued or running. Stop it through the shared run', stories: ['S-EXP-1'], role: 'operator', params: id, body: z.object({ notice_version: z.string().optional() }), bodyOptional: true, response: Scan },
  { method: 'get', path: '/exposure/tree/{id}/scans', summary: 'The runs of this node, newest first (at most 100)', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(Scan) }), example: nodeEx },
  { method: 'get', path: '/exposure/tree/{id}/hosts', summary: 'Names found under this domain node, with source, first and last seen, the choice for scope selected and the child target that owns a name; empty for an IP', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(Host) }), example: nodeEx },
  { method: 'get', path: '/exposure/tree/{id}/addresses', summary: 'Addresses of this node and of its names, with kind and first and last seen', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(Address) }), example: nodeEx },
  { method: 'get', path: '/exposure/tree/{id}/services', summary: 'Services found on this node\'s public addresses, open and closed, with first and last seen and whether they answered HTTP', stories: ['S-EXP-1', 'S-EXP-2'], role: 'viewer', params: id, response: z.object({ items: z.array(Service) }), example: nodeEx },
  { method: 'get', path: '/exposure/tree/{id}/issues', summary: 'Issues every engine reported on this node, open, gone and handled, most severe first', stories: ['S-EXP-2'], role: 'viewer', params: id, response: z.object({ items: z.array(Issue) }), example: nodeEx },
  { method: 'post', path: '/exposure/issues/handle', summary: 'Handle open issues (at most 500) with one resolution and note: patched, mitigated, accepted (with accepted_until, from tomorrow to 365 days ahead, else 400 bad_until), false_positive or not_relevant. The note is required (at least 3 characters, else 400 note_required) for false_positive, not_relevant and accepted. One audit row per issue; issues not open are skipped', stories: ['S-EXP-2'], role: 'operator', body: z.object({ ids: issueIds, resolution: Resolution, note: z.string().max(500).describe('Required (at least 3 characters) for false_positive, not_relevant and accepted'), accepted_until: z.iso.date().optional().describe('accepted only: the last day, from tomorrow to 365 days ahead (else 400 bad_until)') }), response: HandleResult },
  { method: 'post', path: '/exposure/issues/reopen', summary: 'Reopen handled issues (at most 500); the others are skipped. Audited', stories: ['S-EXP-2'], role: 'operator', body: z.object({ ids: issueIds }), response: ReopenResult },
])
