// Mock API of module exposure (S-EXP-1). Tables: exp_targets, exp_snapshots, exp_commitments, exp_attempts.
// Hard rule (LEGAL §3), enforced in the API and not only on the button: no scan unless ownership is verified (IPs: within 90 days),
// the domain's DNS TXT record is still present (re-checked right before each scan) and the commitment is recorded.
// Domain ownership = a DNS TXT record, as other providers do (Google Workspace: host @, up to 72 hours, keep the record).
// IP ownership = only the public IP the box itself uses to reach the Internet. The endpoint takes no IP input.
// DNS simulation: the first TXT check of a new domain says "not found" (DNS not updated yet), from the second check it is found.
// Box egress simulation: localStorage key "vedette-mock-egress" holds the IP the box currently egresses through (default BOX_EGRESS_IP).
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, DOMAIN_RE, fail, guard, IPV4_RE } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { BOX_EGRESS_IP, EXPIRING_DAYS, makeSnapshot, randomToken, scanContent, seedSnapshots, seedTargets, VERIFY_DAYS, type StoredTarget } from './data'
import type { Commitment, Diff, DiffChange, DiffItem, Snapshot, Target } from './types'

const targets = collection<StoredTarget[]>('exp_targets', seedTargets, () => [])
const snapshots = collection<Record<string, Snapshot[]>>('exp_snapshots', seedSnapshots, () => ({}))
const commitments = collection<Record<string, Commitment>>('exp_commitments', () => {
  const at = (d: number) => new Date(Date.now() - d * 864e5).toISOString()
  return {
    'xt-1': { by: 'admin@acme.example', at: at(20) },
    'xt-2': { by: 'admin@acme.example', at: at(77) },
    'xt-4': { by: 'admin@acme.example', at: at(99) },
    'xt-5': { by: 'admin@acme.example', at: at(39) },
  }
}, () => ({}))
/** Timestamps of verification attempts in the last hour (rate limit, anti-abuse). */
const attempts = collection<string[]>('exp_attempts', () => [], () => [])

const MAX_TARGETS = 20
const MAX_ATTEMPTS_PER_HOUR = 10

function egressIp() {
  try { return localStorage.getItem('vedette-mock-egress')?.trim() || BOX_EGRESS_IP } catch { return BOX_EGRESS_IP }
}

// Private, loopback, link-local, CGNAT (100.64.0.0/10), multicast and reserved. 203.0.113.0/24 (documentation range) is allowed because the sample data uses it.
function isPublicIp(ip: string) {
  const [a = 0, b = 0] = ip.split('.').map(Number)
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  return true
}

/** Counts one verification attempt; returns the 429 response when more than 10 happened in the last hour. */
function rateLimit() {
  const hourAgo = Date.now() - 3_600_000
  const recent = attempts.get().filter((x) => Date.parse(x) > hourAgo)
  if (recent.length >= MAX_ATTEMPTS_PER_HOUR) {
    attempts.set(recent)
    const wait = Math.max(1, Math.ceil((Date.parse(recent[0]!) + 3_600_000 - Date.now()) / 60_000))
    return fail(429, 'rate_limited', `Too many verification attempts (limit ${MAX_ATTEMPTS_PER_HOUR} per hour). Try again in about ${wait} minute${wait === 1 ? '' : 's'}.`)
  }
  attempts.set([...recent, nowIso()])
  return null
}

const dayLeft = (iso: string) => Math.ceil((Date.parse(iso) - Date.now()) / 864e5)

function view(t: StoredTarget): Target {
  const commitment = commitments.get()[t.id] ?? null
  const verified = t.verified_at !== null
  const ip = t.kind === 'ip'
  const expired = ip && verified && !!t.expires_at && Date.parse(t.expires_at) < Date.now()
  const validity = !ip || !verified || !t.expires_at ? null : expired ? 'expired' : dayLeft(t.expires_at) <= EXPIRING_DAYS ? 'expiring' : 'valid'
  const blocked: Target['blocked_reason'] = !verified ? 'unverified' : expired ? 'expired' : !ip && !t.txt_ok ? 'txt_missing' : !commitment ? 'no_commitment' : null
  const snaps = (snapshots.get()[t.id] ?? []).slice().sort((a, b) => a.date.localeCompare(b.date))
  const last = snaps[snaps.length - 1]
  return {
    id: t.id, kind: t.kind, value: t.value, status: !verified ? 'unverified' : expired ? 'expired' : 'verified', method: t.method, token: t.token,
    verified_at: t.verified_at, expires_at: t.expires_at, validity, last_check: t.last_check, commitment,
    scannable: blocked === null, blocked_reason: blocked, created_at: t.created_at, last_scan_at: t.last_scan_at, latest: last ? last.counts : null,
  }
}

const find = (id: unknown) => targets.get().find((t) => t.id === id)
const notFound = () => fail(404, 'not_found', 'No such target. It may have been deleted.')
const plus = (iso: string, d: number) => new Date(Date.parse(iso) + d * 864e5).toISOString()
const fmt = (iso: string) => new Date(iso).toISOString().slice(0, 10)

// ---------- diff ----------
function items(s: Snapshot): Map<string, DiffItem & { exp?: string }> {
  const m = new Map<string, DiffItem & { exp?: string }>()
  for (const h of s.hosts) m.set(`h:${h.name}`, { kind: 'subdomain', key: `h:${h.name}`, label: h.name, detail: h.ip })
  for (const p of s.ports) m.set(`p:${p.ip}:${p.port}`, { kind: 'port', key: `p:${p.ip}:${p.port}`, label: `${p.ip}:${p.port}`, detail: [p.service, p.product].filter(Boolean).join(', ') })
  for (const a of s.admin_panels) m.set(`a:${a.url}`, { kind: 'admin', key: `a:${a.url}`, label: a.url, detail: a.product })
  for (const c of s.certs) m.set(`c:${c.host}`, { kind: 'cert', key: `c:${c.host}`, label: c.host, detail: c.issuer, exp: c.expires_at })
  return m
}
function diff(a: Snapshot, b: Snapshot): Diff {
  const A = items(a), B = items(b)
  const added: DiffItem[] = [], removed: DiffItem[] = [], changed: DiffChange[] = []
  for (const [k, v] of B) {
    const o = A.get(k)
    if (!o) added.push({ kind: v.kind, key: k, label: v.label, detail: v.detail })
    else if (v.kind === 'cert' && o.exp !== v.exp) changed.push({ kind: 'cert', key: k, label: v.label, detail: v.detail, from: o.exp!, to: v.exp! })
  }
  for (const [k, v] of A) if (!B.has(k)) removed.push({ kind: v.kind, key: k, label: v.label, detail: v.detail })
  return { from: a.date, to: b.date, added, removed, changed }
}

export const handlers = [
  http.get(`${API}/exposure/targets`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: targets.get().map(view) })
  }),

  // Adding a target changes the scan scope, so admin. Domains only: a public IP is never typed in.
  http.post(`${API}/exposure/targets`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ value: string }>(request)
    const value = String(b.value ?? '').trim().toLowerCase()
    if (!value) return fail(400, 'empty', 'Enter a domain, for example example.com.')
    if (/[/:@\s]/.test(value)) return fail(400, 'bad_value', 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.')
    if (IPV4_RE.test(value)) return fail(400, 'ip_not_allowed', 'Public IPs are not typed in. Select "Verify this box\'s public IP": the box detects the IP it uses to reach the Internet and verifies that one.')
    if (!DOMAIN_RE.test(value)) return fail(400, 'bad_value', 'Not a valid domain. Example: example.com.')
    if (targets.get().some((t) => t.value === value)) return fail(409, 'duplicate', `${value} is already in the list.`)
    if (targets.get().length >= MAX_TARGETS) return fail(400, 'too_many', `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`)
    const t: StoredTarget = { id: newId('xt'), kind: 'domain', value, token: randomToken(), method: 'dns_txt', verified_at: null, expires_at: null, txt_ok: false, checks: 0, last_check: null, created_at: nowIso(), last_scan_at: null }
    targets.update((l) => [...l, t])
    audit('exposure.target_add', value)
    return HttpResponse.json(view(t), { status: 201 })
  }),

  // "Verify this box's public IP": the box finds the IP it uses to reach the Internet (TLS to a fixed endpoint, e.g. Cloudflare /cdn-cgi/trace).
  // No IP input. Refuses private/reserved/CGNAT. Adds the IP as verified for 90 days, or renews it.
  http.post(`${API}/exposure/box-ip/verify`, () => {
    const denied = guard('admin'); if (denied) return denied
    const limited = rateLimit(); if (limited) return limited
    const ip = egressIp()
    if (!IPV4_RE.test(ip) || !isPublicIp(ip)) {
      audit('exposure.verify_fail', ip, 'box_egress: not a public address')
      return fail(400, 'not_public', `The box reaches the Internet via ${ip}, which is a private, reserved or shared carrier (CGNAT) address. Scanning it could hit other people's devices, so Vedette will not verify it. Ask your admin to give the box a public IP that belongs to your company, then try again.`)
    }
    const at = nowIso()
    const message = `The box reaches the Internet via ${ip}. Verified until ${fmt(plus(at, VERIFY_DAYS))}.`
    const existing = targets.get().find((x) => x.kind === 'ip' && x.value === ip)
    const next: StoredTarget = existing
      ? { ...existing, verified_at: at, expires_at: plus(at, VERIFY_DAYS), last_check: { at, ok: true, message } }
      : { id: newId('xt'), kind: 'ip', value: ip, token: '', method: 'box_egress', verified_at: at, expires_at: plus(at, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: { at, ok: true, message }, created_at: at, last_scan_at: null }
    if (!existing && targets.get().length >= MAX_TARGETS) return fail(400, 'too_many', `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`)
    targets.update((l) => (existing ? l.map((x) => (x.id === next.id ? next : x)) : [...l, next]))
    audit(existing ? 'exposure.verify_renew' : 'exposure.verify_ok', ip, 'box_egress')
    return HttpResponse.json(view(next), { status: existing ? 200 : 201 })
  }),

  http.get(`${API}/exposure/targets/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const t = find(params.id)
    return t ? HttpResponse.json(view(t)) : notFound()
  }),

  http.delete(`${API}/exposure/targets/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    targets.update((l) => l.filter((x) => x.id !== t.id))
    snapshots.update((m) => { const { [t.id]: _gone, ...rest } = m; void _gone; return rest })
    commitments.update((m) => { const { [t.id]: _gone, ...rest } = m; void _gone; return rest })
    audit('exposure.target_delete', t.value)
    return new HttpResponse(null, { status: 204 })
  }),

  // Re-check ownership. "Not found" is a normal answer (200, verified:false), not an error.
  http.post(`${API}/exposure/targets/:id/verify`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const limited = rateLimit(); if (limited) return limited
    const at = nowIso()
    const checks = t.checks + 1
    let ok: boolean
    let message: string
    let next: StoredTarget
    if (t.kind === 'domain') {
      ok = t.txt_ok || checks >= 2
      message = ok
        ? `Found the TXT record vedette-verify=${t.token} on ${t.value}.`
        : `The TXT record vedette-verify=${t.token} was not found on ${t.value}. DNS usually updates within minutes and can take up to 72 hours. Check again later, and make sure the value was pasted without extra quotes and that the Name field is just @ (some providers append the domain automatically).`
      next = { ...t, checks, txt_ok: ok, last_check: { at, ok, message }, verified_at: ok ? (t.verified_at ?? at) : t.verified_at }
    } else {
      const ip = egressIp()
      ok = ip === t.value && isPublicIp(ip)
      message = ok
        ? `The box reaches the Internet via ${t.value}. Verified until ${fmt(plus(at, VERIFY_DAYS))}.`
        : `This box currently reaches the Internet via ${ip}, not ${t.value}. Ask your admin to route the box through ${t.value} (for example switch WAN), then verify again.`
      next = { ...t, checks, last_check: { at, ok, message }, verified_at: ok ? at : t.verified_at, expires_at: ok ? plus(at, VERIFY_DAYS) : t.expires_at }
    }
    targets.update((l) => l.map((x) => (x.id === t.id ? next : x)))
    audit(ok ? 'exposure.verify_ok' : 'exposure.verify_fail', t.value, t.kind === 'domain' ? 'dns_txt' : 'box_egress')
    return HttpResponse.json({ verified: ok, message, target: view(next) })
  }),

  // The commitment (replaces signed consent documents): who ticked "I own this and I am authorized to scan it", and when. Verified targets only.
  http.post(`${API}/exposure/targets/:id/commitment`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', 'Verify ownership first; only then can you confirm the commitment for this target.')
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} has expired. Verify it again first.`)
    const b = await body<{ confirm: boolean }>(request)
    if (b.confirm !== true) return fail(400, 'not_confirmed', 'Tick the box to confirm that your company owns this and you are authorized to scan it.')
    const c: Commitment = { by: currentUser()?.email ?? 'system', at: nowIso() }
    commitments.update((m) => ({ ...m, [t.id]: c }))
    audit('exposure.commitment', t.value, 'confirmed: company owns it and user is authorized to scan it')
    return HttpResponse.json(view(t))
  }),

  http.post(`${API}/exposure/targets/:id/scan`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', `${t.value} has no ownership proof, so it cannot be scanned. Finish verification first.`)
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} expired on ${fmt(t.expires_at!)}, so it cannot be scanned. Verify it again first.`)
    // Re-check the TXT record right before the scan; a missing record blocks it.
    if (t.kind === 'domain' && !t.txt_ok) {
      targets.update((l) => l.map((x) => (x.id === t.id ? { ...x, last_check: { at: nowIso(), ok: false, message: `The TXT record vedette-verify=${t.token} was not found on ${t.value}.` } } : x)))
      return fail(409, 'txt_missing', `The DNS TXT record vedette-verify=${t.token} is no longer on ${t.value}, so it cannot be scanned. Add the record back, then check again.`)
    }
    if (!v.commitment) return fail(400, 'commitment_required', `You have not confirmed that your company owns ${t.value} and you are authorized to scan it. Confirm it first.`)
    const at = nowIso()
    const content = scanContent(t)
    const snap = makeSnapshot(newId('sn'), at, content, t.kind === 'ip' ? t.value : undefined)
    snapshots.update((m) => ({ ...m, [t.id]: [...(m[t.id] ?? []).filter((s) => s.date !== snap.date), snap] }))
    targets.update((l) => l.map((x) => (x.id === t.id ? { ...x, last_scan_at: at } : x)))
    audit('exposure.scan', t.value, `${snap.counts.subdomains} subdomains, ${snap.counts.ports} ports`)
    return HttpResponse.json(snap)
  }),

  http.get(`${API}/exposure/targets/:id/snapshots`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!find(params.id)) return notFound()
    const l = (snapshots.get()[String(params.id)] ?? []).slice().sort((a, b) => b.date.localeCompare(a.date))
    return HttpResponse.json({ items: l.map((s) => ({ id: s.id, date: s.date, scanned_at: s.scanned_at, counts: s.counts })) })
  }),

  http.get(`${API}/exposure/targets/:id/snapshots/:date`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const s = (snapshots.get()[String(params.id)] ?? []).find((x) => x.date === params.date)
    return s ? HttpResponse.json(s) : fail(404, 'not_found', 'No snapshot for this day.')
  }),

  http.get(`${API}/exposure/targets/:id/diff`, ({ params, request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const q = new URL(request.url).searchParams
    const list = snapshots.get()[String(params.id)] ?? []
    const a = list.find((s) => s.date === q.get('from')), b = list.find((s) => s.date === q.get('to'))
    if (!a || !b) return fail(404, 'not_found', 'There is no snapshot for one of the two selected days.')
    if (a.date === b.date) return fail(400, 'same_date', 'Pick two different days to compare.')
    return HttpResponse.json(a.date < b.date ? diff(a, b) : diff(b, a))
  }),
]

// Shared inside the mock layer (supervisor): the scan module only scans external targets that are verified (IPs: within 90 days).
export { targets as exposureTargetsStore, snapshots as exposureSnapshotsStore, commitments as exposureCommitmentsStore }
