// Mock API of module exposure (S-EXP-1). Tables: exp_targets, exp_snapshots, exp_commitments, exp_attempts, exp_settings.
// Hard rule (LEGAL §3), enforced in the API and not only on the button: no scan unless ownership is verified (IPs: seen by the box within 30 days),
// the domain's DNS TXT record is still present (re-checked right before each scan) and the commitment is recorded.
// Domain ownership = a DNS TXT record, as other providers do (Google Workspace: host @, up to 72 hours, keep the record).
// IP ownership = only the public IPs the box itself uses to reach the Internet. No endpoint takes an IP as input.
// Auto-detect (kien 2026-11-09, D-81): on by default; the box asks three public "what is my IP" services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip),
// accepts an IP only when at least two agree in a round, over several rounds of new connections, at first start and then
// every interval_min minutes (default 60, 1 to 1440), and adds or renews (30 days from the sighting) every distinct public IP that passed, except those on the Ignored list. The mock runs
// the check when GET /exposure/targets finds it due. Removing an IP is DELETE; the person decides whether it goes on the Ignored list (D-79, ?ignore=true: never added again, never scanned;
// Restore lets detection add it again); otherwise, while auto-detect is on, an IP the box still uses comes back. Scan-time check (D-79, INV-13): an IP is scanned only while the box still goes out through it (the mock reads the same
// localStorage egress as a fresh full check would see; a check or full check of the last 5 minutes is reused, a "not seen" included); else 409 ip_not_current, and the IP stays in the list.
// DNS simulation: the first TXT check of a new domain says "not found" (DNS not updated yet), from the second check it is found.
// Box egress simulation: localStorage key "vedette-mock-egress" holds the public IPs the box currently egresses through, comma separated
// (default: the two sample IPs, i.e. a load balancer), "offline" when no public IP service answers, or "disagree" when they never agree.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, DOMAIN_RE, fail, guard, IPV4_RE } from '@/mocks/http'
import { auditStore } from '@/mocks/stores'
import { canonHash, GENESIS } from '@/lib/chain'
import { collection, newId, nowIso, type Collection } from '@/mocks/db'
import { BOX_EGRESS_IP, BOX_EGRESS_IP_2, DEFAULT_INTERVAL, EXPIRING_DAYS, makeSnapshot, MAX_INTERVAL, MIN_INTERVAL, randomToken, scanContent, seedBoxIp, seedIgnored, seedSnapshots, seedTargets, VERIFY_DAYS, type StoredTarget } from './data'
import type { BoxIpSettings, Commitment, Diff, DiffChange, DiffItem, IgnoredIp, Snapshot, Target } from './types'

const targets = collection<StoredTarget[]>('exp_targets', seedTargets, () => [])
const snapshots = collection<Record<string, Snapshot[]>>('exp_snapshots', seedSnapshots, () => ({}))
const commitments = collection<Record<string, Commitment>>('exp_commitments', () => {
  const at = (d: number) => new Date(Date.now() - d * 864e5).toISOString()
  return {
    'xt-1': { by: 'admin@acme.example', at: at(20) },
    'xt-2': { by: 'admin@acme.example', at: at(20) },
    'xt-4': { by: 'admin@acme.example', at: at(60) },
    'xt-5': { by: 'admin@acme.example', at: at(39) },
  }
}, () => ({}))
/** Timestamps of verification attempts in the last hour (rate limit, anti-abuse). */
const attempts = collection<string[]>('exp_attempts', () => [], () => [])
/** Auto-detect settings. Same defaults on a clean install; only the sample has a last check. */
const boxIp = collection<BoxIpSettings>('exp_settings', seedBoxIp, () => ({ auto: true, interval_min: DEFAULT_INTERVAL, last_run: null }))

/** The Ignored list (D-79): IPs removed with "Don't add it again if detected". It only blocks: detection never adds them, and restoring one only lets detection add it again. */
const ignored = collection<IgnoredIp[]>('exp_ignored', seedIgnored, () => [])

/** When the last full check ran. INV-13 reuses the answer of a full check for 5 minutes, a "not seen" included. */
const probe = collection<{ deep_at: string | null }>('exp_probe', () => ({ deep_at: null }), () => ({ deep_at: null }))

const MAX_TARGETS = 20
const MAX_IGNORED = 200
const MAX_ATTEMPTS_PER_HOUR = 10
/** Turning auto-detect on checks straight away, unless it checked within the last 5 minutes (no probe spam by toggling). */
const MIN_GAP_MS = 5 * 60_000
/** The public IPs the box leaves through now (each one that at least two of the three public services return in a round), "offline" when no service answers, or "disagree" when they answer but never agree. Several rounds, so a load balancer shows every IP. */
function egressIps(): string[] | 'offline' | 'disagree' {
  let raw: string | null = null
  try { raw = localStorage.getItem('vedette-mock-egress')?.trim() || null } catch { raw = null }
  if (raw === null) return [BOX_EGRESS_IP, BOX_EGRESS_IP_2]
  if (raw === 'offline' || raw === 'disagree') return raw
  return [...new Set(raw.split(',').map((x) => x.trim()).filter(Boolean))]
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

/** SYS-3 for work the box does by itself: the same hash chain as audit(), with the actor "system". */
function auditSystem(action: string, target: string, detail: string) {
  auditStore.update((l) => {
    const core = { id: newId('au'), ts: nowIso(), user: 'system', action, target, detail, prev_hash: l[0]?.hash ?? GENESIS }
    return [{ ...core, hash: canonHash(core) }, ...l].slice(0, 1000)
  })
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

// ---------- detecting the box's public IPs ----------
const OFFLINE = 'The box could not reach the public IP services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip). Check that this box can make outgoing HTTPS connections, then try again.'
const DISAGREE = "The public IP services did not agree on the box's IP (at least two of the three must return the same address), so nothing was added. Try again in a few minutes."
const list = (ips: string[]) => ips.join(', ')
function notPublicMessage(ips: string[]) {
  const one = ips.length === 1
  return `The box reaches the Internet via ${list(ips)}, which ${one ? 'is a' : 'are'} private, reserved or shared carrier (CGNAT) address${one ? '' : 'es'}. Scanning ${one ? 'it' : 'them'} could hit other people's devices, so Vedette will not verify ${one ? 'it' : 'them'}. Ask your admin to give the box a public IP that belongs to your company, then try again.`
}
const tooMany = () => `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`

type Detected = { kind: 'offline' } | { kind: 'disagree' } | { kind: 'not_public'; ips: string[] } | { kind: 'too_many' } | { kind: 'ok'; seen: StoredTarget[]; message: string }

/**
 * One detection: three probes show every public IP the box leaves through; each is added (new) or renewed (seen again, 30 days from now).
 * Private, reserved and CGNAT addresses are never stored. `who` decides how it is audited: a person's click, or the box by itself ("system").
 */
function detect(who: 'user' | 'system'): Detected {
  const at = nowIso()
  const auto = who === 'system'
  const log = (action: string, target: string, detail: string) => (auto ? auditSystem(action, target, detail) : audit(action, target, detail))
  const prev = boxIp.get().last_run
  // Every check is a full check in the mock (INV-13 reuses its answer for 5 minutes).
  const record = (ok: boolean, message: string) => { boxIp.update((s) => ({ ...s, last_run: { at, ok, message } })); probe.set({ deep_at: at }) }
  // INV-11: a person's click is always audited. A run of the box only when something changed (an IP added, an expired IP seen again, a switch between working and failing,
  // a refused address that is new), because last_run already says what the routine runs did. The first run counts as coming from "working".
  const switched = (nowOk: boolean) => !prev || prev.ok !== nowOk
  const observed = egressIps()
  if (observed === 'offline' || observed === 'disagree') {
    const down = observed === 'offline'
    const summary = down ? 'failed: the public IP services are not reachable' : 'failed: the public IP services did not agree'
    record(false, down ? OFFLINE : DISAGREE)
    if (!auto) audit('exposure.verify_fail', 'box', `box_egress: ${summary}`)
    else if (switched(false)) auditSystem('exposure.auto_detect', 'box', summary)
    return { kind: down ? 'offline' : 'disagree' }
  }
  const isPublic = (ip: string) => IPV4_RE.test(ip) && isPublicIp(ip)
  const pub = observed.filter(isPublic)
  const refused = observed.filter((ip) => !isPublic(ip))
  // A run of the box says nothing new when the last run already told about this address.
  for (const ip of refused) if (!(auto && prev?.message.includes(ip))) log('exposure.verify_fail', ip, 'box_egress: not a public address')
  if (pub.length === 0) {
    const message = notPublicMessage(refused)
    record(false, message)
    if (auto && switched(false)) auditSystem('exposure.auto_detect', 'box', `refused: ${list(refused)} (not public)`)
    return { kind: 'not_public', ips: refused }
  }
  const until = fmt(plus(at, VERIFY_DAYS))
  const seen: StoredTarget[] = []
  const skipped: string[] = []
  const added: string[] = []
  let changed = false
  const blockedIps = ignored.get().map((x) => x.value)
  const onIgnored = pub.filter((ip) => blockedIps.includes(ip))
  for (const ip of pub.filter((x) => !blockedIps.includes(x))) {
    const msg = `The box reaches the Internet via ${ip}. Verified until ${until}.`
    const existing = targets.get().find((x) => x.kind === 'ip' && x.value === ip)
    if (existing) {
      const was = view(existing).validity
      const next: StoredTarget = { ...existing, verified_at: at, expires_at: plus(at, VERIFY_DAYS), last_check: { at, ok: true, message: msg } }
      targets.update((l) => l.map((x) => (x.id === next.id ? next : x)))
      if (!auto || was === 'expired') log('exposure.verify_renew', ip, 'box_egress')
      if (was === 'expired') changed = true
      seen.push(next)
    } else if (targets.get().length >= MAX_TARGETS) {
      skipped.push(ip)
    } else {
      const next: StoredTarget = { id: newId('xt'), kind: 'ip', value: ip, token: '', method: 'box_egress', verified_at: at, expires_at: plus(at, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: { at, ok: true, message: msg }, created_at: at, last_scan_at: null }
      targets.update((l) => [...l, next])
      log('exposure.verify_ok', ip, auto ? 'box_egress, auto-detect' : 'box_egress')
      added.push(ip)
      changed = true
      seen.push(next)
    }
  }
  if (seen.length === 0 && skipped.length === 0 && onIgnored.length > 0) {
    // Every address the box uses is on the Ignored list: nothing to add, and that is a normal result.
    const message = `The box reaches the Internet via ${list(onIgnored)}, which ${onIgnored.length === 1 ? 'is' : 'are'} on your Ignored list, so nothing was added.`
    record(true, message)
    if (auto && switched(true)) auditSystem('exposure.auto_detect', 'box', `seen: ${list(onIgnored)}; not added (Ignored list)`)
    return { kind: 'ok', seen, message }
  }
  if (seen.length === 0) {
    record(false, tooMany())
    if (auto && switched(false)) auditSystem('exposure.auto_detect', 'box', `not added: ${list(skipped)} (limit of ${MAX_TARGETS} targets)`)
    return { kind: 'too_many' }
  }
  const via = seen.length === 1 ? seen[0]!.value : `${seen.length} public IPs: ${list(seen.map((x) => x.value))}`
  const message = `The box reaches the Internet via ${via}. ${seen.length === 1 ? 'Verified' : 'Each is verified'} until ${until}.`
    + (refused.length ? ` Ignored, not public: ${list(refused)}.` : '') + (skipped.length ? ` Not added, the list holds at most ${MAX_TARGETS} targets: ${list(skipped)}.` : '')
    + (onIgnored.length ? ` Not added, on your Ignored list: ${list(onIgnored)}.` : '')
  record(skipped.length === 0, message)
  if (auto && (changed || switched(skipped.length === 0))) auditSystem('exposure.auto_detect', 'box', `seen: ${list(seen.map((x) => x.value))}${added.length ? `; added: ${list(added)}` : ''}${skipped.length ? `; not added: ${list(skipped)}` : ''}`)
  return { kind: 'ok', seen, message }
}

const CURRENT_MS = 5 * 60_000
/**
 * Scan-time check of an IP (INV-13, D-79 (2)): may it be scanned now, i.e. does the box go out through it now? Yes when the latest check, or the latest full check, ran in the
 * last 5 minutes and saw it. Otherwise one full check runs now, by the caller, and at most once in 5 minutes: inside that window the answer of the last full check is reused,
 * a "not seen" included. A check that cannot tell (services down, no agreement) means "no": fail closed. The scan module calls this too (the mock's CheckScannable).
 */
function exposureIpCurrent(id: string): boolean {
  const now = Date.now()
  const fresh = (iso: string | null | undefined): iso is string => !!iso && Date.parse(iso) <= now + CURRENT_MS && now - Date.parse(iso) <= CURRENT_MS
  const sawIt = (iso: string | null | undefined) => fresh(iso) && Date.parse(find(id)?.verified_at ?? '') >= Date.parse(iso)
  const lastRun = boxIp.get().last_run?.at, deep = probe.get().deep_at
  if (sawIt(lastRun) || sawIt(deep)) return true
  if (fresh(deep)) return false
  const r = detect('user')
  return r.kind === 'ok' && r.seen.some((x) => x.id === id)
}

/** The 409 ip_not_current answer when the box is not going out through the IP now (INV-13); null when it is. Shared by exposure's scan and the scan module. */
export function ipPaused(t: { id: string; value: string }) {
  if (exposureIpCurrent(t.id)) return null
  const seenAt = find(t.id)?.verified_at
  return fail(409, 'ip_not_current', `This box no longer reaches the Internet through ${t.value}; it was last seen ${seenAt ? new Date(seenAt).toISOString().slice(0, 16).replace('T', ' ') : 'never'} UTC. Scans of it are paused until the box uses it again.`)
}

/** The check the box runs by itself: due when auto-detect is on and the last check is older than the interval (or there was none: first start). */
function autoDetectIfDue() {
  const s = boxIp.get()
  if (s.auto && (!s.last_run || Date.now() >= Date.parse(s.last_run.at) + s.interval_min * 60_000)) detect('system')
}

export const handlers = [
  http.get(`${API}/exposure/targets`, () => {
    const denied = guard('viewer'); if (denied) return denied
    autoDetectIfDue()
    return HttpResponse.json({ items: targets.get().map(view), box_ip: boxIp.get(), ignored: ignored.get().slice().sort((a, b) => b.ignored_at.localeCompare(a.ignored_at)) })
  }),

  // Auto-detect on or off and the interval. Turning it on checks at once (not when it checked in the last 5 minutes). Never takes an IP.
  http.put(`${API}/exposure/box-ip/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ auto: boolean; interval_min: number }>(request)
    if (typeof b.auto !== 'boolean') return fail(400, 'invalid_setting', 'Say whether auto-detect is on or off.')
    const n = b.interval_min
    if (typeof n !== 'number' || !Number.isInteger(n) || n < MIN_INTERVAL || n > MAX_INTERVAL) return fail(400, 'bad_interval', `Choose how often to check: every minute up to every 24 hours (${MAX_INTERVAL} minutes).`)
    const before = boxIp.get()
    boxIp.set({ ...before, auto: b.auto, interval_min: n })
    audit('exposure.box_ip_settings', 'box', `auto-detect ${b.auto ? 'on' : 'off'}, every ${n} minutes`)
    if (b.auto && !before.auto && (!before.last_run || Date.now() - Date.parse(before.last_run.at) >= MIN_GAP_MS)) detect('user')
    return HttpResponse.json(boxIp.get())
  }),

  // Adding a target changes the scan scope, so admin. Domains only: a public IP is never typed in.
  http.post(`${API}/exposure/targets`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ value: string }>(request)
    const value = String(b.value ?? '').trim().toLowerCase()
    if (!value) return fail(400, 'empty', 'Enter a domain, for example example.com.')
    if (/[/:@\s]/.test(value)) return fail(400, 'bad_value', 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.')
    if (IPV4_RE.test(value)) return fail(400, 'ip_not_allowed', 'Public IPs are not typed in. The box finds its own public IPs: turn on auto-detect or select "Detect now" under Public IPs of this box.')
    if (!DOMAIN_RE.test(value)) return fail(400, 'bad_value', 'Not a valid domain. Example: example.com.')
    if (targets.get().some((t) => t.value === value)) return fail(409, 'duplicate', `${value} is already in the list.`)
    if (targets.get().length >= MAX_TARGETS) return fail(400, 'too_many', `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`)
    const t: StoredTarget = { id: newId('xt'), kind: 'domain', value, token: randomToken(), method: 'dns_txt', verified_at: null, expires_at: null, txt_ok: false, checks: 0, last_check: null, created_at: nowIso(), last_scan_at: null }
    targets.update((l) => [...l, t])
    audit('exposure.target_add', value)
    return HttpResponse.json(view(t), { status: 201 })
  }),

  // "Detect now": the same check the box runs by itself (several rounds over the three public IP services, an IP counts when two agree).
  // No IP input. Refuses private/reserved/CGNAT. Adds every public IP it sees as verified for 30 days, or renews it. Counts as one attempt.
  http.post(`${API}/exposure/box-ip/verify`, () => {
    const denied = guard('admin'); if (denied) return denied
    const limited = rateLimit(); if (limited) return limited
    const r = detect('user')
    if (r.kind === 'offline') return fail(502, 'unreachable', OFFLINE)
    if (r.kind === 'disagree') return fail(502, 'unreachable', DISAGREE)
    if (r.kind === 'not_public') return fail(400, 'not_public', notPublicMessage(r.ips))
    if (r.kind === 'too_many') return fail(400, 'too_many', tooMany())
    return HttpResponse.json({ items: r.seen.map(view), message: r.message })
  }),

  // Restore: only lets detection add the IP again. The list blocks and never allows (D-25): nothing is added here and the IP is not scannable by itself.
  http.delete(`${API}/exposure/box-ip/ignored/:ip`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const ip = String(params.ip)
    if (!IPV4_RE.test(ip)) return fail(400, 'bad_value', 'Not a valid IPv4 address.')
    if (!ignored.get().some((x) => x.value === ip)) return fail(404, 'not_found', 'This IP is not on the Ignored list.')
    ignored.update((l) => l.filter((x) => x.value !== ip))
    audit('exposure.ip_restore', ip, 'detection may add it again')
    return new HttpResponse(null, { status: 204 })
  }),

  http.get(`${API}/exposure/targets/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const t = find(params.id)
    return t ? HttpResponse.json(view(t)) : notFound()
  }),

  // Removing a target. For an IP, ?ignore=true also puts it on the Ignored list (D-79): detection never adds it again and it is never scanned.
  http.delete(`${API}/exposure/targets/:id`, ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const ignore = new URL(request.url).searchParams.get('ignore') === 'true'
    if (ignore && t.kind !== 'ip') return fail(400, 'bad_value', 'Only a public IP can go on the Ignored list.')
    if (ignore && ignored.get().length >= MAX_IGNORED) return fail(400, 'too_many', `At most ${MAX_IGNORED} ignored IPs. Restore the ones you no longer need to block.`)
    targets.update((l) => l.filter((x) => x.id !== t.id))
    snapshots.update((m) => { const { [t.id]: _gone, ...rest } = m; void _gone; return rest })
    commitments.update((m) => { const { [t.id]: _gone, ...rest } = m; void _gone; return rest })
    audit('exposure.target_delete', t.value)
    if (ignore) {
      ignored.update((l) => [{ value: t.value, ignored_by: currentUser()?.email ?? 'system', ignored_at: nowIso() }, ...l.filter((x) => x.value !== t.value)])
      audit('exposure.ip_ignore', t.value, 'removed; detection will not add it again and it will not be scanned')
    }
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
      // One check = three probes: the IP is verified when the box leaves through it now (any of several IPs behind a load balancer). It renews for 30 days.
      const observed = egressIps()
      ok = Array.isArray(observed) && observed.includes(t.value) && isPublicIp(t.value)
      message = ok
        ? `The box reaches the Internet via ${t.value}. Verified until ${fmt(plus(at, VERIFY_DAYS))}.`
        : !Array.isArray(observed)
          ? (observed === 'offline' ? OFFLINE : DISAGREE)
          : `This box currently reaches the Internet via ${list(observed)}, not ${t.value}. Ask your admin to route the box through ${t.value} (for example switch WAN), then verify again.`
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
    // An IP is scanned only while the box still goes out through it (a fresh full check just before the scan sees it). Not seen, or no answer = paused, fail closed; the IP stays in the list.
    if (t.kind === 'ip') {
      const paused = ipPaused(t)
      if (paused) return paused
    }
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

// Shared inside the mock layer (supervisor): the scan module only scans external targets that are verified (IPs: seen by the box within 30 days).
// Reading the targets also runs the automatic check when it is due, as the box's job would have by now, so the scan page of a clean install lists the IPs the box found.
export const exposureTargetsStore: Collection<StoredTarget[]> = { get: () => { autoDetectIfDue(); return targets.get() }, set: (v) => targets.set(v), update: (fn) => targets.update(fn) }
export { snapshots as exposureSnapshotsStore, commitments as exposureCommitmentsStore }
// The scan module asks the same question before it scans an external IP (CheckScannable, INV-13).
export { ipPaused as exposureIpPaused }
