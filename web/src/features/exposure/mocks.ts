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
import { auditStore, isOn } from '@/mocks/stores'
import { canonHash, GENESIS } from '@/lib/chain'
import { collection, newId, nowIso, type Collection } from '@/mocks/db'
import { BOX_EGRESS_IP, BOX_EGRESS_IP_2, boxGreenbone, DEFAULT_INTERVAL, outsideAnswer, seedOutside, EXPIRING_DAYS, makeSnapshot, MAX_INTERVAL, MIN_INTERVAL, randomToken, scanContent, seedBoxIp, seedIgnored, seedSnapshots, seedTargets, VERIFY_DAYS, type Content, type StoredTarget } from './data'
import { NOTICE_TEMPLATE, NOTICE_VERSION, PORT_NOT_SEEN, TERMS_DISRUPTIVE, TERMS_TEMPLATE, TERMS_VERSION, VERSION_NOT_READ } from './contract'
import { dateText, dateTimeText } from './dates'
import type { BoxIpSettings, Commitment, Terms, Diff, DiffChange, DiffItem, Greenbone, IgnoredIp, OutsideView, ScanRun, Snapshot, Target } from './types'

const targets = collection<StoredTarget[]>('exp_targets', seedTargets, () => [])
const snapshots = collection<Record<string, Snapshot[]>>('exp_snapshots', seedSnapshots, () => ({}))
/** FULL-1 (D-566): the testing terms each target was given; the box's own IP has them (without the disruptive tick), the rest none. */
const termsStore = collection<Record<string, Terms>>('exp_terms', () => ({
  'xt-2': { version: TERMS_VERSION, by: 'admin@acme.example', at: new Date(Date.now() - 20 * 864e5).toISOString(), text: TERMS_TEMPLATE.replaceAll('{value}', BOX_EGRESS_IP), disruptive: false },
}), () => ({}))
const commitments = collection<Record<string, Commitment>>('exp_commitments', () => {
  const at = (d: number) => new Date(Date.now() - d * 864e5).toISOString()
  return {
    'xt-1': { by: 'admin@acme.example', at: at(20), version: NOTICE_VERSION, sentence: NOTICE_TEMPLATE.replace('{value}', 'acme.example') },
    'xt-2': { by: 'admin@acme.example', at: at(20), version: NOTICE_VERSION, sentence: NOTICE_TEMPLATE.replace('{value}', BOX_EGRESS_IP) },
    // Confirmed under an older sentence: the first Scan now after the upgrade asks again (D-559).
    'xt-6': { by: 'admin@acme.example', at: at(20), version: '2026-11-13', sentence: 'By choosing Scan now I confirm that my company owns ' + BOX_EGRESS_IP_2 + ' and that I am authorized to scan it. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.' },
    'xt-4': { by: 'admin@acme.example', at: at(60), version: null, sentence: null },
    'xt-5': { by: 'admin@acme.example', at: at(39), version: null, sentence: null },
  }
}, () => ({}))
/** Timestamps of verification attempts in the last hour (rate limit, anti-abuse). */
const attempts = collection<string[]>('exp_attempts', () => [], () => [])
/** Auto-detect settings. Same defaults on a clean install; only the sample has a last check. */
const boxIp = collection<Omit<BoxIpSettings, 'retry_in_min'>>('exp_settings', seedBoxIp, () => ({ auto: true, interval_min: DEFAULT_INTERVAL, last_run: null }))

/** The Ignored list (D-79): IPs removed with "Don't add it again if detected". It only blocks: detection never adds them, and restoring one only lets detection add it again. */
const ignored = collection<IgnoredIp[]>('exp_ignored', seedIgnored, () => [])

/** deep_at: when the last full check ran (INV-13 reuses its answer for 5 minutes, a "not seen" included). full_ok_at: the last one that got an answer (the services agreed): an IP it did not see, and nothing since, shows as paused until a later check sees it. */
const probe = collection<{ deep_at: string | null; full_ok_at?: string | null }>('exp_probe', () => ({ deep_at: null, full_ok_at: null }), () => ({ deep_at: null, full_ok_at: null }))

/** D-558: Shodan's last answer per target (without our scan's ports, which are read from the newest snapshot on each GET). */
const outside = collection<Record<string, Omit<OutsideView, 'scan_ports' | 'scan_at'>>>('exp_outside', seedOutside, () => ({}))
/** When the box last asked Shodan: at most once a minute on the box (in memory, as on the box). */
let outsideAskedMs = 0
/** D-563: the optional deep scan with Greenbone, off by default. The mock box has 16 GB of memory and 180 GB free; localStorage keys
 * "vedette-mock-box-memory" and "vedette-mock-box-disk" (bytes) play a smaller box. After Enable it is "starting" for 3 seconds, then "loading"
 * its feed until 15 seconds (about 2 hours on a real box), then ready. D-566: it scans only a target whose testing terms are accepted. */
const greenbone = collection<{ enabled: boolean; changed_by: string | null; changed_at: string | null }>('exp_greenbone', () => ({ enabled: false, changed_by: null, changed_at: null }), () => ({ enabled: false, changed_by: null, changed_at: null }))
const measured = (key: string, fallback: number) => { const v = Number(localStorage.getItem(key)); return Number.isFinite(v) && v > 0 ? v : fallback }
const gbText = (n: number) => `${(n / 1e9).toFixed(1)} GB`
const GREENBONE_NO_TERMS = 'OpenVAS did not scan: accept the testing terms for this target to run OpenVAS (Ownership tab).'
const WEEK_MS = 7 * 24 * 3600 * 1000
function greenboneView(): Greenbone {
  const g = greenbone.get()
  const mem = measured('vedette-mock-box-memory', 16e9), disk = measured('vedette-mock-box-disk', 180e9)
  const reason = mem < 6e9 ? `This box has ${gbText(mem)} of memory; OpenVAS needs at least 6.0 GB.` : disk < 60e9 ? `This box has ${gbText(disk)} of free disk space; OpenVAS needs at least 60.0 GB free.` : null
  const since = g.changed_at ? Date.now() - Date.parse(g.changed_at) : 0
  const state = !g.enabled ? 'off' : since < 3000 ? 'starting' : since < 15000 ? 'loading' : 'ready'
  // D-564 G6: the first weekly feed update is due a week after Enable (the mock never runs it)
  const next = g.enabled && g.changed_at ? new Date(Date.parse(g.changed_at) + WEEK_MS).toISOString() : null
  return { state, reason: state === 'loading' ? 'OpenVAS is loading its feed (first time takes about 2 hours)' : null, changed_by: g.changed_by, changed_at: g.changed_at,
    preflight: { memory_bytes: mem, disk_free_bytes: disk, ok: reason === null, reason }, feed_sync: { last_at: null, ok: null, note: null, next_at: next }, enabled: g.enabled }
}
/** What a scan of an IP gets from Greenbone in the mock: its results on the box's own IP when ready, else the line that says why not. */
function greenboneFor(ip: string, fullScan: boolean): Pick<Content, 'greenbone' | 'greenboneNote'> {
  const v = greenboneView()
  if (v.state !== 'off' && !fullScan) return { greenboneNote: GREENBONE_NO_TERMS }
  if (v.state === 'ready') return { greenbone: ip === BOX_EGRESS_IP ? boxGreenbone() : [] }
  if (v.state === 'off') return {}
  return { greenboneNote: v.state === 'loading' ? 'OpenVAS did not scan: it is loading its feed (the first time takes about 2 hours).' : 'OpenVAS did not scan: it is still starting.' }
}

/** Shodan's answer beside the open ports of our own newest scan of that IP (null when never scanned). */
function outsideView(id: string): OutsideView | null {
  const o = outside.get()[id]
  if (!o) return null
  const last = (snapshots.get()[id] ?? []).slice().sort((a, b) => b.date.localeCompare(a.date))[0]
  const scan_ports = last ? [...new Set(last.ports.filter((p) => p.ip === o.ip).map((p) => p.port))].sort((a, b) => a - b) : null
  return { ...o, scan_ports, scan_at: last?.scanned_at ?? null }
}

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

/** Minutes until the next of the 10 attempts an hour is possible; null while attempts are left (Detect now, Verify again and the DNS Check share them). */
function retryInMin(): number | null {
  const hourAgo = Date.now() - 3_600_000
  const recent = attempts.get().filter((x) => Date.parse(x) > hourAgo)
  return recent.length >= MAX_ATTEMPTS_PER_HOUR ? Math.max(1, Math.ceil((Date.parse(recent[0]!) + 3_600_000 - Date.now()) / 60_000)) : null
}
/** The settings as the API shows them, with the wait when the attempts are used up. */
const boxView = (): BoxIpSettings => ({ ...boxIp.get(), retry_in_min: retryInMin() })

/** Counts one verification attempt; returns the 429 response when more than 10 happened in the last hour. */
function rateLimit() {
  const hourAgo = Date.now() - 3_600_000
  const recent = attempts.get().filter((x) => Date.parse(x) > hourAgo)
  if (recent.length >= MAX_ATTEMPTS_PER_HOUR) {
    attempts.set(recent)
    const wait = retryInMin() ?? 1
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

/** The mock's scan run: the phase follows the time since the press (queued, probing, saving, then done). The snapshot, last_scan_at and the audit row come when it is done, as on the box; a stop saves nothing. */
interface MockRun { run: ScanRun; startedMs: number; snap: Snapshot }
const mockRunStore = collection<MockRun | null>('exp_scan_run', () => null, () => null)
const PHASE_AT_MS = { probing: 300, saving: 1500, done: 2000 }
function settledRun(): ScanRun | null {
  const m = mockRunStore.get()
  if (!m) return null
  const r = m.run
  if (r.status !== 'running') return r
  const ms = Date.now() - m.startedMs
  if (ms < PHASE_AT_MS.done) {
    const next: ScanRun = { ...r, phase: ms >= PHASE_AT_MS.saving ? 'saving' : ms >= PHASE_AT_MS.probing ? 'probing' : 'queued' }
    mockRunStore.set({ ...m, run: next })
    return next
  }
  const snap = m.snap
  snapshots.update((all) => ({ ...all, [r.target_id]: [...(all[r.target_id] ?? []).filter((x) => x.date !== snap.date), snap] }))
  targets.update((l) => l.map((x) => (x.id === r.target_id ? { ...x, last_scan_at: snap.scanned_at } : x)))
  audit('exposure.scan', r.target_value, `${snap.counts.subdomains} subdomains, ${snap.counts.ports} ports`)
  const next: ScanRun = { ...r, status: 'done', phase: 'done', finished_at: nowIso(), snapshot_id: snap.id }
  mockRunStore.set({ ...m, run: next })
  return next
}

function view(t: StoredTarget): Target {
  const commitment = commitments.get()[t.id] ?? null
  const terms = termsStore.get()[t.id] ?? null
  const current = commitment?.version === NOTICE_VERSION // an older sentence counts as not confirmed (D-559)
  const verified = t.verified_at !== null
  const ip = t.kind === 'ip'
  const expired = ip && verified && !!t.expires_at && Date.parse(t.expires_at) < Date.now()
  const validity = !ip || !verified || !t.expires_at ? null : expired ? 'expired' : dayLeft(t.expires_at) <= EXPIRING_DAYS ? 'expiring' : 'valid'
  const blocked: Target['blocked_reason'] = !verified ? 'unverified' : expired ? 'expired' : !ip && !t.txt_ok ? 'txt_missing' : !current ? 'no_commitment' : ip && ipNotSeenNow(t) ? 'ip_not_current' : null
  const snaps = (snapshots.get()[t.id] ?? []).slice().sort((a, b) => a.date.localeCompare(b.date))
  const last = snaps[snaps.length - 1]
  return {
    id: t.id, kind: t.kind, value: t.value, status: !verified ? 'unverified' : expired ? 'expired' : 'verified', method: t.method, token: t.token,
    verified_at: t.verified_at, expires_at: t.expires_at, validity, last_check: t.last_check, commitment,
    commitment_notice: current ? null : { version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', t.value) },
    terms, terms_notice: { version: TERMS_VERSION, text: TERMS_TEMPLATE.replaceAll('{value}', t.value), disruptive: TERMS_DISRUPTIVE }, full_scan: terms?.version === TERMS_VERSION,
    scannable: blocked === null, blocked_reason: blocked, created_at: t.created_at, last_scan_at: t.last_scan_at, latest: last ? last.counts : null, open_ports: last ? last.ports.slice(0, 20) : null,
  }
}

const find = (id: unknown) => targets.get().find((t) => t.id === id)
const notFound = () => fail(404, 'not_found', 'No such target. It may have been deleted.')
const plus = (iso: string, d: number) => new Date(Date.parse(iso) + d * 864e5).toISOString()
const fmt = dateText

// ---------- diff ----------
type Entry = DiffItem & { exp?: string; product?: string; version?: string; lastSeen?: string; missed?: boolean }
// INV-20: the same product with a version before and none now: the version was not read, nothing changed and no CVE is gone.
const versionUnread = (o?: Entry, v?: Entry) => !!o?.product && o.product === v?.product && !!o.version && !v.version
function items(s: Snapshot): Map<string, Entry> {
  const m = new Map<string, Entry>()
  for (const h of s.hosts) m.set(`h:${h.name}`, { kind: 'subdomain', key: `h:${h.name}`, label: h.name, detail: h.ip })
  for (const p of s.ports) m.set(`p:${p.ip}:${p.port}`, { kind: 'port', key: `p:${p.ip}:${p.port}`, label: `${p.ip}:${p.port}`, detail: [p.service, p.product].filter(Boolean).join(', '), lastSeen: p.last_seen, missed: (p.misses ?? 0) > 0 })
  for (const a of s.admin_panels) m.set(`a:${a.url}`, { kind: 'admin', key: `a:${a.url}`, label: a.url, detail: a.product })
  for (const c of s.certs) m.set(`c:${c.host}`, { kind: 'cert', key: `c:${c.host}`, label: c.host, detail: c.issuer, exp: c.expires_at })
  for (const x of s.services) m.set(`s:${x.ip}:${x.port}`, { kind: 'service', key: `s:${x.ip}:${x.port}`, label: `${x.ip}:${x.port}`, detail: x.product ? `${x.product} ${x.version}`.trim() : x.name, product: x.product, version: x.version })
  for (const v of s.vulns.filter((x) => x.basis !== 'greenbone')) m.set(`v:${v.ip}:${v.port}:${v.cve}`, { kind: 'vuln', key: `v:${v.ip}:${v.port}:${v.cve}`, label: `${v.cve} on ${v.ip}:${v.port}`, detail: v.name })
  return m
}
function diff(a: Snapshot, b: Snapshot): Diff {
  const A = items(a), B = items(b)
  const added: DiffItem[] = [], removed: DiffItem[] = [], changed: DiffChange[] = []
  for (const [k, v] of B) {
    const o = A.get(k)
    if (!o) added.push({ kind: v.kind, key: k, label: v.label, detail: v.detail })
    else if (v.kind === 'port' && !o.missed && v.missed) changed.push({ kind: 'port', key: k, label: v.label, detail: v.detail, from: o.detail, to: PORT_NOT_SEEN })
    else if (v.kind === 'cert' && o.exp !== v.exp) changed.push({ kind: 'cert', key: k, label: v.label, detail: v.detail, from: o.exp!, to: v.exp! })
    else if (v.kind === 'service' && versionUnread(o, v)) changed.push({ kind: 'service', key: k, label: v.label, detail: v.detail, from: o.detail, to: VERSION_NOT_READ })
    else if (v.kind === 'service' && o.product === v.product && !o.version) { /* a version read now that was not before: no change */ }
    else if (v.kind === 'service' && o.detail !== v.detail) changed.push({ kind: 'service', key: k, label: v.label, detail: v.detail, from: o.detail, to: v.detail })
  }
  for (const [k, v] of A) {
    if (B.has(k)) continue
    const at = v.kind === 'vuln' ? k.split(':').slice(1, 3).join(':') : ''
    if (at && versionUnread(A.get(`s:${at}`), B.get(`s:${at}`))) continue
    removed.push({ kind: v.kind, key: k, label: v.label, detail: v.kind === 'port' && v.missed ? `${v.detail} (closed: missed by two scans in a row, last seen ${v.lastSeen})` : v.detail })
  }
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
const IP_NOT_TYPED = 'Public IPs are not typed in. The box finds its own public IPs: turn on auto-detect or select "Detect now" under Public IPs of this box.'
/** IPv6 in any common spelling ("2001:db8::1", "[::1]", "::ffff:1.2.3.4"): hex digits, at least two colons, optional brackets. Never a domain. */
function isIPv6Text(v: string) {
  const s = v.startsWith('[') && v.endsWith(']') ? v.slice(1, -1) : v
  return (s.match(/:/g)?.length ?? 0) >= 2 && /^[0-9a-f:.]+$/i.test(s)
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
  const record = (ok: boolean, message: string, answered = true) => { boxIp.update((s) => ({ ...s, last_run: { at, ok, message } })); probe.update((p) => ({ deep_at: at, full_ok_at: answered ? at : (p.full_ok_at ?? null) })) }
  // INV-11: a person's click is always audited. A run of the box only when something changed (an IP added, an expired IP seen again, a switch between working and failing,
  // a refused address that is new), because last_run already says what the routine runs did. The first run counts as coming from "working".
  const switched = (nowOk: boolean) => !prev || prev.ok !== nowOk
  const observed = egressIps()
  if (observed === 'offline' || observed === 'disagree') {
    const down = observed === 'offline'
    const summary = down ? 'failed: the public IP services are not reachable' : 'failed: the public IP services did not agree'
    record(false, down ? OFFLINE : DISAGREE, false) // no answer: nothing is paused or cleared
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
  const seen = sightings(find(id)?.verified_at)
  if (seen.sawIt) return true
  if (seen.freshDeep) return false
  const r = detect('user')
  return r.kind === 'ok' && r.seen.some((x) => x.id === id)
}

/** What the checks of the last 5 minutes say about an IP, without probing anything: the state the gate would act on (INV-13). */
function sightings(verifiedAt: string | null | undefined) {
  const now = Date.now()
  const fresh = (iso: string | null | undefined): iso is string => !!iso && Date.parse(iso) <= now + CURRENT_MS && now - Date.parse(iso) <= CURRENT_MS
  const sawIt = (iso: string | null | undefined) => fresh(iso) && Date.parse(verifiedAt ?? '') >= Date.parse(iso)
  const lastRun = boxIp.get().last_run?.at, deep = probe.get().deep_at
  return { sawIt: sawIt(lastRun) || sawIt(deep), freshDeep: fresh(deep) }
}

/** Shown on GET (blocked_reason ip_not_current): the last full check that got an answer did not see this IP and nothing has seen it since. It rests on what is stored, not on a window: it stays until a later check sees the IP; a failed check changes nothing (INV-13). Reading probes nothing. */
function ipNotSeenNow(t: StoredTarget): boolean {
  const fullOk = probe.get().full_ok_at
  return !!fullOk && Date.parse(fullOk) <= Date.now() + CURRENT_MS && Date.parse(t.verified_at ?? '') < Date.parse(fullOk)
}

/** The 409 ip_not_current answer when the box is not going out through the IP now (INV-13); null when it is. Shared by exposure's scan and the scan module. */
export function ipPaused(t: { id: string; value: string }) {
  if (exposureIpCurrent(t.id)) return null
  const seenAt = find(t.id)?.verified_at
  return fail(409, 'ip_not_current', `This box no longer reaches the Internet through ${t.value}; it was last seen ${seenAt ? dateTimeText(seenAt) : 'never'}. Scans of it are paused until the box uses it again.`)
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
    const items = targets.get().map(view)
    // D-492: the sample gateway is an unnamed FortiGate with two exploited findings; the box answers "who answers" only for its own IPs.
    const gateway = items.some((x) => x.kind === 'ip' && (x.open_ports?.length ?? 0) > 0) ? { ip: '192.168.1.1', device_id: 'dev-gateway', name: 'fortigate-hq', open_exploited: 2 } : null
    return HttpResponse.json({ items, box_ip: boxView(), ignored: ignored.get().slice().sort((a, b) => b.ignored_at.localeCompare(a.ignored_at)), gateway })
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
    return HttpResponse.json(boxView())
  }),

  // Adding a target changes the scan scope, so admin. Domains only: a public IP is never typed in.
  http.post(`${API}/exposure/targets`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ value: string }>(request)
    const value = String(b.value ?? '').trim().toLowerCase()
    if (!value) return fail(400, 'empty', 'Enter a domain, for example example.com.')
    if (isIPv6Text(value)) return fail(400, 'ip_not_allowed', IP_NOT_TYPED)
    if (/[/:@\s]/.test(value)) return fail(400, 'bad_value', 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.')
    if (IPV4_RE.test(value)) return fail(400, 'ip_not_allowed', IP_NOT_TYPED)
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
    outside.update((m) => { const { [t.id]: _gone, ...rest } = m; void _gone; return rest })
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

  // FULL-1 (D-566): accept the testing terms of a verified target (admin with two-step), with or without the disruptive tick. They
  // include the ownership sentence, so the Scan now commitment is recorded too when missing.
  http.put(`${API}/exposure/targets/:id/terms`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const me = currentUser()!
    if (!me.twofa && !me.sso) return fail(403, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then run the first scan again. The first scan records your confirmation that your company owns the target and that you are authorized to scan it.')
    const b = await body<{ version?: string; disruptive?: boolean }>(request)
    if (b.version !== TERMS_VERSION) return fail(409, 'notice_changed', 'The testing terms changed since this page loaded. Read them again, then accept them again.')
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', 'Verify ownership first; only then can the testing terms be accepted.')
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} has expired. Verify it again first.`)
    const disruptive = b.disruptive === true
    if (v.full_scan && v.terms?.disruptive === disruptive) return HttpResponse.json(v)
    if (v.commitment?.version !== NOTICE_VERSION) {
      const sentence = NOTICE_TEMPLATE.replace('{value}', t.value)
      commitments.update((m) => ({ ...m, [t.id]: { by: me.email, at: nowIso(), version: NOTICE_VERSION, sentence } }))
      audit('exposure.commitment', t.value, `confirmed by accepting the testing terms (notice ${NOTICE_VERSION}): ${sentence}`)
    }
    const text = v.terms_notice.text + (disruptive ? `\n${TERMS_DISRUPTIVE}` : '')
    termsStore.update((m) => ({ ...m, [t.id]: { version: TERMS_VERSION, by: me.email, at: nowIso(), text, disruptive } }))
    audit('exposure.terms_accept', t.value, `${v.terms ? `accepted again (replaces terms ${v.terms.version}, accepted by ${v.terms.by} at ${v.terms.at}, disruptive checks: ${v.terms.disruptive ? 'yes' : 'no'})` : 'accepted'} (disruptive checks: ${disruptive ? 'yes' : 'no'}, terms ${TERMS_VERSION}): ${text}`)
    return HttpResponse.json(view(t))
  }),

  // FULL-1: withdraw the terms; always possible, the next scan is in the K-4 scope again.
  http.delete(`${API}/exposure/targets/:id/terms`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const was = termsStore.get()[t.id]
    if (was) {
      termsStore.update((m) => { const n = { ...m }; delete n[t.id]; return n })
      audit('exposure.terms_revoke', t.value, `withdrawn (terms ${was.version}, disruptive checks: ${was.disruptive ? 'yes' : 'no'}, accepted by ${was.by} at ${was.at})`)
    }
    return HttpResponse.json(view(t))
  }),

  http.post(`${API}/exposure/targets/:id/scan`, async ({ params, request }) => {
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
    if (v.commitment?.version !== NOTICE_VERSION) {
      // D-473: an administrator's first Scan now is the confirmation (D-26); an operator cannot scan an unconfirmed target.
      const me = currentUser()
      if (me?.role !== 'admin' && v.commitment) return fail(400, 'commitment_required', `The confirmation text changed, so ${t.value} must be confirmed again. An administrator confirms once with the next Scan now.`)
      if (me?.role !== 'admin') return fail(400, 'commitment_required', `${t.value} has not been confirmed yet. An administrator must run the first scan: it records that your company owns ${t.value} and that the scan is authorized.`)
      if (!me.twofa && !me.sso) return fail(403, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then run the first scan again. The first scan records your confirmation that your company owns the target and that you are authorized to scan it.')
      const sent = await body<{ notice_version?: string }>(request)
      if (!sent.notice_version && v.commitment) return fail(409, 'notice_changed', 'The confirmation text changed since this page loaded. Read it again, then press Scan now again.')
      if (!sent.notice_version) return fail(400, 'commitment_required', `The first scan of ${t.value} records a confirmation, so the request must carry notice_version of the sentence shown next to Scan now.`)
      if (sent.notice_version !== NOTICE_VERSION) return fail(409, 'notice_changed', 'The confirmation text changed since this page loaded. Read it again, then press Scan now again.')
      const sentence = NOTICE_TEMPLATE.replace('{value}', t.value)
      commitments.update((m) => ({ ...m, [t.id]: { by: me.email, at: nowIso(), version: NOTICE_VERSION, sentence } }))
      audit('exposure.commitment', t.value, `${v.commitment ? `re-confirmed under the new sentence (replaces notice ${v.commitment.version ?? 'recorded before versions'}, confirmed by ${v.commitment.by} at ${v.commitment.at})` : 'confirmed by the first Scan now'} (notice ${NOTICE_VERSION}): ${sentence}`)
    }
    // An IP is scanned only while the box still goes out through it (a fresh full check just before the scan sees it). Not seen, or no answer = paused, fail closed; the IP stays in the list.
    if (t.kind === 'ip') {
      const paused = ipPaused(t)
      if (paused) return paused
    }
    // The scan is done by the Vulnerability scans module (D-229): off, nothing is scanned and nothing is saved.
    if (!isOn('scan')) return fail(409, 'module_off', 'The Vulnerability scans module is off, so the box cannot scan. An admin can turn it on in Settings, Modules.')
    // Like the box: 202 with the run at once, and the phases move on while the page polls GET /exposure/scan. The mock has no one-at-a-time or 10-minute limit
    // (its tests scan an IP several times in a row). The result is stored when the run is done.
    const at = nowIso()
    const snap = makeSnapshot(newId('sn'), at, t.kind === 'ip' ? { ...scanContent(t), ...greenboneFor(t.value, v.full_scan) } : scanContent(t), t.kind === 'ip' ? t.value : undefined)
    const run: ScanRun = { id: newId('sr'), target_id: t.id, target_value: t.value, by: currentUser()?.email ?? '', started_at: at, finished_at: null, status: 'running', phase: 'queued', snapshot_id: null, error: null }
    mockRunStore.set({ run, startedMs: Date.now(), snap })
    return HttpResponse.json(run, { status: 202 })
  }),

  // The run that runs now or the last one; null before the first. In the mock it lives in memory only, as on the box.
  http.get(`${API}/exposure/scan`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(settledRun())
  }),

  http.post(`${API}/exposure/scan/stop`, () => {
    const denied = guard('operator'); if (denied) return denied
    const r = settledRun()
    const m = mockRunStore.get()
    if (!m || !r || r.status !== 'running') return fail(409, 'not_running', 'No scan is running now.')
    const stopped: ScanRun = { ...r, status: 'stopped', finished_at: nowIso() }
    mockRunStore.set({ ...m, run: stopped })
    audit('exposure.scan', r.target_value, `stopped by ${currentUser()?.email ?? ''}`)
    return HttpResponse.json(stopped)
  }),

  // What the Internet sees (D-558): reading sends nothing.
  http.get(`${API}/exposure/targets/:id/outside`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!find(params.id)) return notFound()
    return HttpResponse.json(outsideView(String(params.id)))
  }),

  // An administrator's click sends this IP of the box to Shodan InternetDB. Only the box's own verified IP that it still goes out through.
  http.post(`${API}/exposure/targets/:id/outside`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    if (t.kind !== 'ip') return fail(400, 'bad_value', 'Only a public IP of this box can be checked with Shodan, not a domain.')
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', `${t.value} has no ownership proof, so it cannot be checked with Shodan. Finish verification first.`)
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} expired on ${fmt(t.expires_at!)}, so it cannot be checked with Shodan. Verify it again first.`)
    if (ipPaused(t)) return fail(409, 'ip_not_current', `This box no longer reaches the Internet through ${t.value}; it was last seen ${t.verified_at ? dateTimeText(t.verified_at) : 'never'}. It is not sent to Shodan until the box uses it again.`)
    if (Date.now() - outsideAskedMs < 60_000) return fail(429, 'rate_limited', 'The box asked Shodan less than a minute ago. Try again in a minute: it asks at most once a minute.')
    outsideAskedMs = Date.now()
    const a = outsideAnswer(t.value)
    outside.update((m) => ({ ...m, [t.id]: { ip: t.value, checked_at: nowIso(), checked_by: currentUser()?.email ?? '', ...a } }))
    audit('exposure.outside_view', t.value, a.found ? `sent to internetdb.shodan.io; Shodan lists ${a.ports.length} ports and ${a.vulns.length} CVEs` : 'sent to internetdb.shodan.io; Shodan has no record of it')
    return HttpResponse.json(outsideView(t.id))
  }),

  http.get(`${API}/exposure/greenbone`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json(greenboneView())
  }),

  // Admin only. On: the preflight refuses with the measured numbers (409 low_memory, low_disk). Off: its containers stop, its data is kept.
  http.put(`${API}/exposure/greenbone`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'bad_body', 'enabled must be true or false.')
    const before = greenboneView()
    if (b.enabled === before.enabled) return HttpResponse.json(before)
    if (b.enabled && !before.preflight.ok) return fail(409, before.preflight.memory_bytes! < 6e9 ? 'low_memory' : 'low_disk', before.preflight.reason!)
    greenbone.set({ enabled: b.enabled, changed_by: currentUser()?.email ?? null, changed_at: nowIso() })
    audit('exposure.greenbone', 'OpenVAS', b.enabled ? `enabled (memory ${gbText(before.preflight.memory_bytes!)}, free disk ${gbText(before.preflight.disk_free_bytes!)})` : 'disabled (data kept)')
    return HttpResponse.json(greenboneView())
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
