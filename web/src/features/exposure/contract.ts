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

export const Commitment = z.object({ by: z.string(), at: z.iso.datetime() })

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
  commitment: Commitment.nullable().describe('Who ticked "my company owns it and I am authorized to scan it", and when'),
  scannable: z.boolean(),
  blocked_reason: z.enum(['unverified', 'expired', 'txt_missing', 'no_commitment']).nullable().describe('Why it cannot be scanned yet; null = can be scanned'),
  created_at: z.iso.datetime(),
  last_scan_at: z.iso.datetime().nullable(),
  latest: Counts.nullable(),
})

export const HostRow = z.object({ name: z.string(), ip: z.string() })
export const PortRow = z.object({ ip: z.string(), port: z.number().int(), service: z.string(), product: z.string().optional() })
export const AdminRow = z.object({ url: z.string(), product: z.string(), ip: z.string(), port: z.number().int(), risk: z.enum(['danger', 'warn']) })
export const CertRow = z.object({ host: z.string(), issuer: z.string(), expires_at: z.iso.datetime() })

export const Snapshot = z.object({
  id: z.string(), date: isoDate, scanned_at: z.iso.datetime(),
  hosts: z.array(HostRow), ports: z.array(PortRow), admin_panels: z.array(AdminRow), certs: z.array(CertRow), counts: Counts,
})
export const SnapshotMeta = Snapshot.pick({ id: true, date: true, scanned_at: true, counts: true })

export const DiffKind = z.enum(['subdomain', 'port', 'admin', 'cert'])
export const DiffItem = z.object({ kind: DiffKind, key: z.string(), label: z.string(), detail: z.string() })
export const DiffChange = DiffItem.extend({ from: z.string(), to: z.string() })
export const Diff = z.object({ from: isoDate, to: isoDate, added: z.array(DiffItem), removed: z.array(DiffItem), changed: z.array(DiffChange) })

export const VerifyResult = z.object({ verified: z.boolean(), message: z.string(), target: Target })

/** Auto-detect of the box's public IPs (kien 2026-11-09). interval_min is 15 to 1440; the server checks it (400 bad_interval). */
export const BoxIpRun = z.object({ at: z.iso.datetime(), ok: z.boolean(), message: z.string().describe('What the last check saw, or why it failed') })
export const BoxIpSettings = z.object({
  auto: z.boolean().describe('On: the box detects its public IPs at first start and then every interval_min minutes. Off: only "Detect now". Default on'),
  interval_min: z.number().int().describe('Minutes between automatic checks, 15 to 1440. Default 60'),
  last_run: BoxIpRun.nullable().describe('The last automatic or manual detection; null before the first one'),
})
export const TargetList = z.object({ items: z.array(Target), box_ip: BoxIpSettings })
export const BoxIpDetectResult = z.object({ items: z.array(Target).describe('The public IPs the box saw this time, each added or renewed'), message: z.string() })

const id = z.object({ id: z.string() })
const idEx = { params: { id: 'xt-1' } }

export const endpoints = defineEndpoints([
  { method: 'get', path: '/exposure/targets', summary: 'Domains and verified public IPs with ownership status, expiry, commitment and latest result, plus the box-IP auto-detect settings', stories: ['S-EXP-1'], role: 'viewer', response: TargetList },
  { method: 'post', path: '/exposure/targets', status: 201, summary: 'Add a domain (changes scan scope). Public IPs cannot be typed in: use /exposure/box-ip/verify', stories: ['S-EXP-1'], role: 'admin', body: z.object({ value: z.string() }), response: Target },
  { method: 'post', path: '/exposure/box-ip/verify', summary: '"Detect now": the box probes the fixed project endpoint three times over separate HTTPS connections and adds or renews (30 days from now) every distinct public IP it sees, so several egress IPs behind a load balancer are all found. Takes no IP input; refuses private, reserved and CGNAT results (400 not_public when none is public); 502 unreachable when no probe answered; rate limited to 10 attempts per hour', stories: ['S-EXP-1'], role: 'admin', response: BoxIpDetectResult },
  { method: 'put', path: '/exposure/box-ip/settings', summary: 'Turn auto-detect on or off and set the check interval (15 to 1440 minutes, else 400 bad_interval). Turning it on checks at once. The IP list is kept when it is turned off. Typing an IP is not possible here either', stories: ['S-EXP-1'], role: 'admin', body: z.object({ auto: z.boolean(), interval_min: z.number().int() }), response: BoxIpSettings },
  { method: 'get', path: '/exposure/targets/{id}', summary: 'One external-exposure target', stories: ['S-EXP-1'], role: 'viewer', params: id, response: Target, example: idEx },
  { method: 'delete', path: '/exposure/targets/{id}', summary: 'Delete a target with its snapshots and commitment. For a public IP this removes it from the list; with auto-detect on it comes back (as a new target) the next time the box sees it', stories: ['S-EXP-1'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/exposure/targets/{id}/verify', summary: 'Re-check ownership: domain = DNS TXT record; IP = the box must currently egress through this same IP (renews it for 30 days). Not found is a normal answer (verified:false). Rate limited', stories: ['S-EXP-1'], role: 'operator', params: id, response: VerifyResult },
  { method: 'post', path: '/exposure/targets/{id}/commitment', summary: 'Record the commitment: my company owns this domain/IP and I am authorized to scan it (who and when are audited). Only for verified targets', stories: ['S-EXP-1'], role: 'admin', params: id, body: z.object({ confirm: z.literal(true) }), response: Target },
  { method: 'post', path: '/exposure/targets/{id}/scan', summary: 'Scan now. 409 when not verified, verification expired or the DNS TXT record is gone (re-checked right before the scan); 400 commitment_required when the commitment is missing', stories: ['S-EXP-1'], role: 'operator', params: id, response: Snapshot },
  { method: 'get', path: '/exposure/targets/{id}/snapshots', summary: 'Scan days of a target, newest first', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(SnapshotMeta) }), example: idEx },
  { method: 'get', path: '/exposure/targets/{id}/snapshots/{date}', summary: 'Scan result of one day', stories: ['S-EXP-1'], role: 'viewer', params: z.object({ id: z.string(), date: isoDate }), response: Snapshot, example: { params: { id: 'xt-1', date: day(1) } } },
  { method: 'get', path: '/exposure/targets/{id}/diff', summary: 'Compare two scan days: newly exposed, gone, changed', stories: ['S-EXP-1'], role: 'viewer', params: id, query: z.object({ from: isoDate, to: isoDate }), response: Diff, example: { params: { id: 'xt-1' }, query: { from: day(7), to: day(1) } } },
])
