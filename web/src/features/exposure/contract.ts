// API contract of module exposure (D-18, S-EXP-1). UI types are inferred from here (types.ts).
// Hard rule (LEGAL §3): POST .../scan returns 409 unless ownership is verified (IPs: within 90 days) and the DNS TXT record is still there, and 400 `commitment_required` (D-57) until the commitment is recorded.
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
  status: z.enum(['unverified', 'verified', 'expired']).describe('expired only exists for IPs: more than 90 days since the last verification'),
  method: VerifyMethod.nullable(),
  token: z.string().describe('Domain: the token in the TXT record vedette-verify=<token> (not secret, it is public in DNS). IP: empty string'),
  verified_at: z.iso.datetime().nullable().describe('Last successful verification'),
  expires_at: z.iso.datetime().nullable().describe('IP: verified_at + 90 days. Domain: null (the TXT record is re-checked right before every scan)'),
  validity: z.enum(['valid', 'expiring', 'expired']).nullable().describe('IPs only: expiring = 14 days or less left'),
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

const id = z.object({ id: z.string() })
const idEx = { params: { id: 'xt-1' } }

export const endpoints = defineEndpoints([
  { method: 'get', path: '/exposure/targets', summary: 'Domains and verified public IPs with ownership status, expiry, commitment and latest result', stories: ['S-EXP-1'], role: 'viewer', response: z.object({ items: z.array(Target) }) },
  { method: 'post', path: '/exposure/targets', status: 201, summary: 'Add a domain (changes scan scope). Public IPs cannot be typed in: use /exposure/box-ip/verify', stories: ['S-EXP-1'], role: 'admin', body: z.object({ value: z.string() }), response: Target },
  { method: 'post', path: '/exposure/box-ip/verify', summary: 'The box detects the public IP it uses to reach the Internet (TLS to a fixed endpoint) and verifies it for 90 days. Takes no IP input; refuses private, reserved and CGNAT results; rate limited to 10 attempts per hour. 201 when the IP is new in the list, 200 when it was already there (the generated file documents 200)', stories: ['S-EXP-1'], role: 'admin', response: Target },
  { method: 'get', path: '/exposure/targets/{id}', summary: 'One external-exposure target', stories: ['S-EXP-1'], role: 'viewer', params: id, response: Target, example: idEx },
  { method: 'delete', path: '/exposure/targets/{id}', summary: 'Delete a target with its snapshots and commitment', stories: ['S-EXP-1'], role: 'admin', params: id, response: null },
  { method: 'post', path: '/exposure/targets/{id}/verify', summary: 'Re-check ownership: domain = DNS TXT record; IP = the box must currently egress through this same IP (renews 90 days). Not found is a normal answer (verified:false). Rate limited', stories: ['S-EXP-1'], role: 'operator', params: id, response: VerifyResult },
  { method: 'post', path: '/exposure/targets/{id}/commitment', summary: 'Record the commitment: my company owns this domain/IP and I am authorized to scan it (who and when are audited). Only for verified targets', stories: ['S-EXP-1'], role: 'admin', params: id, body: z.object({ confirm: z.literal(true) }), response: Target },
  { method: 'post', path: '/exposure/targets/{id}/scan', summary: 'Scan now. 409 when not verified, verification expired or the DNS TXT record is gone (re-checked right before the scan); 400 commitment_required when the commitment is missing', stories: ['S-EXP-1'], role: 'operator', params: id, response: Snapshot },
  { method: 'get', path: '/exposure/targets/{id}/snapshots', summary: 'Scan days of a target, newest first', stories: ['S-EXP-1'], role: 'viewer', params: id, response: z.object({ items: z.array(SnapshotMeta) }), example: idEx },
  { method: 'get', path: '/exposure/targets/{id}/snapshots/{date}', summary: 'Scan result of one day', stories: ['S-EXP-1'], role: 'viewer', params: z.object({ id: z.string(), date: isoDate }), response: Snapshot, example: { params: { id: 'xt-1', date: day(1) } } },
  { method: 'get', path: '/exposure/targets/{id}/diff', summary: 'Compare two scan days: newly exposed, gone, changed', stories: ['S-EXP-1'], role: 'viewer', params: id, query: z.object({ from: isoDate, to: isoDate }), response: Diff, example: { params: { id: 'xt-1' }, query: { from: day(7), to: day(1) } } },
])
