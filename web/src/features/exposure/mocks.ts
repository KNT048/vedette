// Mock API of module exposure (S-EXP-1). Tables: exp_targets, exp_snapshots, exp_commitments, exp_attempts, exp_settings.
// Hard rule (LEGAL §3), enforced in the API and not only on the button: no scan unless ownership is verified (IPs: seen by the box within 30 days),
// the domain's DNS TXT record is still present (re-checked right before each scan) and the commitment is recorded.
// Domain ownership = a DNS TXT record, as other providers do (Google Workspace: host @, up to 72 hours, keep the record).
// IP ownership = only the public IPs the box itself uses to reach the Internet. No endpoint takes an IP as input.
// Auto-detect: on by default; the box asks three public "what is my IP" services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip),
// accepts an IP only when at least two agree in a round, over several rounds of new connections, at first start and then
// every interval_min minutes (default 60, 1 to 1440), and adds or renews (30 days from the sighting) every distinct public IP that passed, except those on the Ignored list. The mock runs
// the check when GET /exposure/targets finds it due. Removing an IP is DELETE; the person decides whether it goes on the Ignored list (?ignore=true: never added again, never scanned;
// Restore lets detection add it again); otherwise, while auto-detect is on, an IP the box still uses comes back. Scan-time check (INV-13): an IP is scanned only while the box still goes out through it (the mock reads the same
// localStorage egress as a fresh full check would see; a check or full check of the last 5 minutes is reused, a "not seen" included); else 409 ip_not_current, and the IP stays in the list.
// DNS simulation: the first TXT check of a new domain says "not found" (DNS not updated yet), from the second check it is found.
// Box egress simulation: localStorage key "vedette-mock-egress" holds the public IPs the box currently egresses through, comma separated
// (default: the two sample IPs, i.e. a load balancer), "offline" when no public IP service answers, or "disagree" when they never agree.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, DOMAIN_RE, fail, guard, IPV4_RE } from '@/mocks/http'
import { auditStore } from '@/mocks/stores'
import { canonHash, GENESIS } from '@/lib/chain'
import { collection, newId, nowIso, type Collection } from '@/mocks/db'
import { BOX_EGRESS_IP, BOX_EGRESS_IP_2, boxGreenbone, DEFAULT_INTERVAL, outsideAnswer, seedOutside, EXPIRING_DAYS, makeSnapshot, MAX_INTERVAL, MIN_INTERVAL, randomToken, scanContent, seedBoxIp, seedIgnored, seedSnapshots, seedTargets, VERIFY_DAYS, withDeep, type Content, type StoredTarget } from './data'
import { serviceLabel } from './services'
import { seedTree, seedTreeRows, type StoredNode, type TreeRows } from './treeSeed'
import { MAX_ISSUE_IDS, MAX_SELECTED, SELECTED_LIMIT_WHY, NOTICE_TEMPLATE, Resolution as ResolutionEnum, NOTICE_VERSION, PORT_NOT_SEEN, TERMS_KEPT_VERSIONS, TERMS_TEMPLATE, TERMS_TEMPLATE_DOMAIN, TERMS_VERSION, VERSION_NOT_READ } from './contract'
import { mockDeviceProgress } from '@/lib/progress'
import { scheduleSubjects } from '@/features/core/schedulesMock'
import type { Proof, ProofState, Resolution, RunStatus, Scan, ScopeMode, Severity, TargetKind, TargetNode } from './types'
import type { BoxIpSettings, Commitment, Terms, Diff, DiffChange, DiffItem, Greenbone, IgnoredIp, OutsideView, ScanRun, Snapshot, Target } from './types'
import { fmtDate, fmtDateTime } from '@/lib/format'

const targets = collection<StoredTarget[]>('exp_targets', seedTargets, () => [])
const snapshots = collection<Record<string, Snapshot[]>>('exp_snapshots', seedSnapshots, () => ({}))
/** The testing terms each target was given; the box's own IP has an acceptance of the previous version made without its
 *  disruptive tick (still valid: the deep scan only, until the terms are accepted again), the rest none. */
const termsStore = collection<Record<string, Terms>>('exp_terms', () => ({
  'xt-2': { version: TERMS_KEPT_VERSIONS[0], by: 'admin@acme.example', at: new Date(Date.now() - 20 * 864e5).toISOString(), text: TERMS_TEMPLATE.replaceAll('{value}', BOX_EGRESS_IP), disruptive: false },
}), () => ({}))
/** An acceptance of the current terms, or of a version kept valid after an update, counts (full_scan, deep). */
const termsInForce = (version: string | undefined) => version === TERMS_VERSION || (version !== undefined && TERMS_KEPT_VERSIONS.includes(version))
const commitments = collection<Record<string, Commitment>>('exp_commitments', () => {
  const at = (d: number) => new Date(Date.now() - d * 864e5).toISOString()
  return {
    'xt-1': { by: 'admin@acme.example', at: at(20), version: NOTICE_VERSION, sentence: NOTICE_TEMPLATE.replace('{value}', 'acme.example') },
    'xt-2': { by: 'admin@acme.example', at: at(20), version: NOTICE_VERSION, sentence: NOTICE_TEMPLATE.replace('{value}', BOX_EGRESS_IP) },
    // Confirmed under an older sentence: the first Scan now after the upgrade asks again.
    'xt-6': { by: 'admin@acme.example', at: at(20), version: '2026-11-13', sentence: 'By choosing Scan now I confirm that my company owns ' + BOX_EGRESS_IP_2 + ' and that I am authorized to scan it. Vedette is provided as is under the Apache-2.0 license; the Vedette authors are not responsible for how you use it.' },
    'xt-4': { by: 'admin@acme.example', at: at(60), version: null, sentence: null },
    'xt-5': { by: 'admin@acme.example', at: at(39), version: null, sentence: null },
  }
}, () => ({}))
/** INV-36: how often each target is scanned by itself; a target with no entry is weekly (the default, also of older targets). */
/** Timestamps of verification attempts in the last hour (rate limit, anti-abuse). */
const attempts = collection<string[]>('exp_attempts', () => [], () => [])
/** Auto-detect settings. Same defaults on a clean install; only the sample has a last check. */
const boxIp = collection<Omit<BoxIpSettings, 'retry_in_min'>>('exp_settings', seedBoxIp, () => ({ auto: true, interval_min: DEFAULT_INTERVAL, last_run: null }))

/** The Ignored list: IPs removed with "Don't add it again if detected". It only blocks: detection never adds them, and restoring one only lets detection add it again. */
const ignored = collection<IgnoredIp[]>('exp_ignored', seedIgnored, () => [])

/** deep_at: when the last full check ran (INV-13 reuses its answer for 5 minutes, a "not seen" included). full_ok_at: the last one that got an answer (the services agreed): an IP it did not see, and nothing since, shows as paused until a later check sees it. */
const probe = collection<{ deep_at: string | null; full_ok_at?: string | null }>('exp_probe', () => ({ deep_at: null, full_ok_at: null }), () => ({ deep_at: null, full_ok_at: null }))

/** Shodan's last answer per target (without our scan's ports, which are read from the newest snapshot on each GET). */
const outside = collection<Record<string, Omit<OutsideView, 'scan_ports' | 'scan_at'>>>('exp_outside', seedOutside, () => ({}))
/** When the box last asked Shodan: at most once a minute on the box (in memory, as on the box). */
let outsideAskedMs = 0
/** The optional deep scan with Greenbone, off by default. The mock box has 16 GB of memory and 180 GB free; localStorage keys
 * "vedette-mock-box-memory", "vedette-mock-box-swap" (default 4 GB) and "vedette-mock-box-disk" (bytes) play a smaller box. After Enable it is "starting" for 3 seconds, then "loading"
 * its feed until 15 seconds (1 to 3 hours on a real box), then ready. It scans only a target whose testing terms are accepted. */
const greenbone = collection<{ enabled: boolean; changed_by: string | null; changed_at: string | null }>('exp_greenbone', () => ({ enabled: false, changed_by: null, changed_at: null }), () => ({ enabled: false, changed_by: null, changed_at: null }))
const measured = (key: string, fallback: number) => { const v = Number(localStorage.getItem(key)); return Number.isFinite(v) && v > 0 ? v : fallback }
const gbText = (n: number) => `${(Math.floor(n / 1e8) / 10).toFixed(1)} GB`
const GREENBONE_NO_TERMS = 'OpenVAS did not scan: accept the testing terms for this target to run OpenVAS (Ownership tab).'
const WEEK_MS = 7 * 24 * 3600 * 1000
function greenboneView(): Greenbone {
  const g = greenbone.get()
  const mem = measured('vedette-mock-box-memory', 16e9), disk = measured('vedette-mock-box-disk', 180e9)
  const swap = localStorage.getItem('vedette-mock-box-swap') === null ? 4e9 : Math.max(0, Number(localStorage.getItem('vedette-mock-box-swap')) || 0)
  const reason = mem < 6e9 ? `This box has ${gbText(mem)} of memory; OpenVAS needs at least 6.0 GB.`
    : mem < 8e9 && swap < 2e9 ? `This box has ${gbText(mem)} of memory and ${gbText(swap)} of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load.` : disk < 60e9 ? `This box has ${gbText(disk)} of free disk space; OpenVAS needs at least 60.0 GB free.` : null
  const since = g.changed_at ? Date.now() - Date.parse(g.changed_at) : 0
  const state = !g.enabled ? 'off' : since < 3000 ? 'starting' : since < 15000 ? 'loading' : 'ready'
  // The first weekly feed update is due a week after Enable (the mock never runs it)
  const next = g.enabled && g.changed_at ? new Date(Date.parse(g.changed_at) + WEEK_MS).toISOString() : null
  return { state, reason: state === 'loading' ? 'OpenVAS is loading its feed (first time takes 1 to 3 hours)' : null, changed_by: g.changed_by, changed_at: g.changed_at,
    preflight: { memory_bytes: mem, disk_free_bytes: disk, ok: reason === null, reason }, feed_sync: { last_at: null, ok: null, note: null, next_at: next },
    // T10: the feed OpenVAS reports, read once it answers (the mock's feed of 14 Nov 2026, 12:00 UTC; midday so every time zone shows 14 Nov)
    feed: state === 'loading' || state === 'ready' ? { nvt_version: '202611141200', nvt_date: '2026-11-14T12:00:00.000Z', checked_at: new Date().toISOString() } : null, enabled: g.enabled }
}
/** What a scan of an IP gets from Greenbone in the mock: its results on the box's own IP when ready, else the line that says why not. */
function greenboneFor(ip: string, fullScan: boolean): Pick<Content, 'greenbone' | 'greenboneNote'> {
  const v = greenboneView()
  if (v.state !== 'off' && !fullScan) return { greenboneNote: GREENBONE_NO_TERMS }
  if (v.state === 'ready') return { greenbone: ip === BOX_EGRESS_IP ? boxGreenbone() : [] }
  if (v.state === 'off') return {}
  return { greenboneNote: v.state === 'loading' ? 'OpenVAS did not scan: it is loading its feed (the first time takes 1 to 3 hours).' : 'OpenVAS did not scan: it is still starting.' }
}

/** Shodan's answer beside the open ports of our own newest scan of that IP (null when never scanned). */
function outsideView(id: string): OutsideView | null {
  const o = outside.get()[id]
  if (!o) return null
  const last = (snapshots.get()[id] ?? []).slice().sort((a, b) => b.date.localeCompare(a.date))[0]
  const scan_ports = last ? [...new Set(last.ports.filter((p) => p.ip === o.ip).map((p) => p.port))].sort((a, b) => a - b) : null
  return { ...o, scan_ports, scan_at: last ? last.started_at ?? last.scanned_at : null } // a scan is named by its start
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

/** Minutes until the next of the 10 attempts an hour is possible; null while attempts are left (Detect now and the Verify again of an IP share them; a domain's DNS Check is limited per target, every 30 seconds, on the box). */
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
// #830: in the browser the scan takes 15 s, so the page (read every 5 s) shows its steps move; tests keep 2 s.
const PHASE_AT_MS = import.meta.env.MODE === 'test' ? { probing: 300, saving: 1500, done: 2000 } : { probing: 300, saving: 14_000, done: 15_500 }
function settledRun(): ScanRun | null {
  const m = mockRunStore.get()
  if (!m) return null
  const r = m.run
  if (r.status !== 'running') return r
  const ms = Date.now() - m.startedMs
  if (ms < PHASE_AT_MS.done) {
    const phase = ms >= PHASE_AT_MS.saving ? 'saving' : ms >= PHASE_AT_MS.probing ? 'probing' : 'queued'
    const progress = phase === 'probing' ? mockDeviceProgress(m.startedMs + PHASE_AT_MS.probing, (ms - PHASE_AT_MS.probing) / (PHASE_AT_MS.saving - PHASE_AT_MS.probing), Date.now()) : null // #830
    const next: ScanRun = { ...r, phase, progress }
    mockRunStore.set({ ...m, run: next })
    return next
  }
  const snap = m.snap
  snapshots.update((all) => ({ ...all, [r.target_id]: [...(all[r.target_id] ?? []).filter((x) => x.date !== snap.date), snap] }))
  targets.update((l) => l.map((x) => (x.id === r.target_id ? { ...x, last_scan_at: snap.started_at } : x)))
  audit('exposure.scan', r.target_value, `${snap.counts.subdomains} subdomains, ${snap.counts.ports} ports`)
  const next: ScanRun = { ...r, status: 'done', phase: 'done', finished_at: nowIso(), snapshot_id: snap.id, progress: null }
  mockRunStore.set({ ...m, run: next })
  return next
}

/** #850, for the scan module's engine list (Settings › Scanning): the exposure scan that runs now or ran last, and OpenVAS's state and switch. */
export const exposureMockRun = () => settledRun()
export const greenboneMock = {
  view: () => greenboneView(),
  /** The same as PUT /exposure/greenbone: null when done, else the refusal's code and text. */
  set(enabled: boolean): { code: string; message: string } | null {
    const before = greenboneView()
    if (enabled === before.enabled) return null
    if (enabled && !before.preflight.ok) return { code: before.preflight.reason!.includes(' of memory') ? 'low_memory' : 'low_disk', message: before.preflight.reason! }
    greenbone.set({ enabled, changed_by: currentUser()?.email ?? null, changed_at: nowIso() })
    audit('exposure.greenbone', 'OpenVAS', enabled ? `enabled (memory ${gbText(before.preflight.memory_bytes!)}, free disk ${gbText(before.preflight.disk_free_bytes!)})` : 'disabled (data kept)')
    return null
  },
}

/** Where a domain's record goes. The mock takes the last two labels as the registered domain (the box reads the Public Suffix
 *  List, so it also knows co.uk or ddns.net). covered_by: the nearest verified domain of the list that the name is under. */
function proofOf(t: StoredTarget): Target['proof'] {
  if (t.kind !== 'domain') return null
  const zone = t.value.split('.').slice(-2).join('.')
  const sub = t.value === zone ? '' : t.value.slice(0, -(zone.length + 1))
  const covering = targets.get()
    .filter((o) => o.kind === 'domain' && o.id !== t.id && o.verified_at !== null && o.txt_ok && t.value.endsWith(`.${o.value}`) && o.value.endsWith(zone))
    .sort((a, b) => b.value.length - a.value.length)[0]
  const alt = sub === '' ? '_vedette-verify' : `_vedette-verify.${sub}`
  return { zone, host: '@', alt_host: t.value.length + '_vedette-verify.'.length <= 253 ? alt : null, covered_by: covering ? covering.value : null }
}

function view(t: StoredTarget): Target {
  const commitment = commitments.get()[t.id] ?? null
  const terms = termsStore.get()[t.id] ?? null
  const current = commitment?.version === NOTICE_VERSION // an older sentence counts as not confirmed
  const verified = t.verified_at !== null
  const ip = t.kind === 'ip'
  const expired = ip && verified && !!t.expires_at && Date.parse(t.expires_at) < Date.now()
  const validity = !ip || !verified || !t.expires_at ? null : expired ? 'expired' : dayLeft(t.expires_at) <= EXPIRING_DAYS ? 'expiring' : 'valid'
  const typed = !!t.typed
  // A proof holds VERIFY_DAYS from its last pass: a later check that did not find it (a record or file gone, a lookup that failed, an IP
  // the box does not go out through now) is a warning in last_check, never a reason (INV-4).
  const blocked: Target['blocked_reason'] = !verified ? 'unverified' : expired ? 'expired' : !current ? 'no_commitment' : null
  const snaps = (snapshots.get()[t.id] ?? []).slice().sort((a, b) => a.date.localeCompare(b.date))
  const last = snaps[snaps.length - 1]
  return {
    id: t.id, kind: t.kind, value: t.value, status: !verified ? 'unverified' : expired ? 'expired' : 'verified', method: t.method, token: t.token,
    verified_at: t.verified_at, expires_at: t.expires_at, validity, last_check: t.last_check, commitment,
    commitment_notice: current ? null : { version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', t.value) },
    terms, terms_notice: { version: TERMS_VERSION, text: (t.kind === 'domain' ? TERMS_TEMPLATE_DOMAIN : TERMS_TEMPLATE).replaceAll('{value}', t.value) }, full_scan: termsInForce(terms?.version),
    scannable: blocked === null, blocked_reason: blocked, created_at: t.created_at, last_scan_at: t.last_scan_at, last_scan_finished_at: last?.finished_at ?? null, latest: last ? last.counts : null, open_ports: last ? last.ports.slice(0, 20) : null,
    proof: proofOf(t),
    origin: ip && !typed ? 'box' : 'person', open_exposures: last?.counts.ports ?? 0,
    ip_proof: typed ? { path: '/.well-known/vedette-verify.txt', content: t.token, urls: [`http://${t.value}/.well-known/vedette-verify.txt`, `https://${t.value}/.well-known/vedette-verify.txt`], ptr_domains: targets.get().filter((o) => o.kind === 'domain' && o.verified_at !== null && o.txt_ok).map((o) => o.value) } : null,
    next_check_at: typed && verified && t.expires_at ? plus(t.expires_at, -7) : null,
    scan_state: blocked === null ? 'ready' : blocked === 'expired' ? 'expired' : blocked === 'no_commitment' ? 'needs_terms' : 'unproved',
  }
}

const find = (id: unknown) => targets.get().find((t) => t.id === id)
// The box's audit keeps a detail within 2000 characters; a domain's terms with the tick's sentence can pass it (modules/exposure/terms.go auditClip).
const CLIP_NOTE = ' … (cut here; the whole text is stored with the acceptance and pinned to its version)'
const auditClip = (d: string) => ([...d].length <= 2000 ? d : [...d].slice(0, 2000 - [...CLIP_NOTE].length).join('') + CLIP_NOTE)
const notFound = () => fail(404, 'not_found', 'No such target. It may have been deleted.')
const plus = (iso: string, d: number) => new Date(Date.parse(iso) + d * 864e5).toISOString()
const fmt = fmtDate

// ---------- diff ----------
type Entry = DiffItem & { exp?: string; product?: string; version?: string; lastSeen?: string; missed?: boolean }
// INV-20: the same product with a version before and none now: the version was not read, nothing changed and no CVE is gone.
const versionUnread = (o?: Entry, v?: Entry) => !!o?.product && o.product === v?.product && !!o.version && !v.version
function items(s: Snapshot): Map<string, Entry> {
  const m = new Map<string, Entry>()
  for (const h of s.hosts) m.set(`h:${h.name}`, { kind: 'subdomain', key: `h:${h.name}`, label: h.name, detail: h.ip })
  for (const p of s.ports) m.set(`p:${p.ip}:${p.port}`, { kind: 'port', key: `p:${p.ip}:${p.port}`, label: `${p.ip}:${p.port}`, detail: [serviceLabel(p), p.product].filter(Boolean).join(', '), lastSeen: p.last_seen, missed: (p.misses ?? 0) > 0 })
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
const IP_NOT_A_DOMAIN = 'That is an IP address, not a domain. Choose Public IP to add an address.'
const IP_NOT_PUBLIC = 'Enter a public IPv4 address, for example 203.0.113.10. Private, reserved, carrier-grade NAT and IPv6 addresses cannot be scanned from the Internet.'
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
    // The target list the pages read is the tree (exp_tree), as on the box; the older list (exp_targets) is kept in step for the
    // readers that still use it (the scan module's external targets, the scan-time check).
    const node = tree.get().find((x) => x.kind === 'ip' && x.value === ip)
    const existing = targets.get().find((x) => x.kind === 'ip' && x.value === ip)
    if (node || existing) {
      const was = node ? (ownProof(node) === 'expired' ? 'expired' : 'valid') : view(existing!).validity
      upsertBoxNode(ip, at, msg, node)
      const next: StoredTarget = existing ? { ...existing, verified_at: at, expires_at: plus(at, VERIFY_DAYS), last_check: { at, ok: true, message: msg } } : boxTarget(ip, at, msg)
      targets.update((l) => (existing ? l.map((x) => (x.id === next.id ? next : x)) : [...l, next]))
      if (!auto || was === 'expired') log('exposure.verify_renew', ip, 'box_egress')
      if (was === 'expired') changed = true
      seen.push(next)
    } else if (targets.get().length >= MAX_TARGETS || tree.get().length >= MAX_TARGETS) {
      skipped.push(ip)
    } else {
      upsertBoxNode(ip, at, msg, undefined)
      const next = boxTarget(ip, at, msg)
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

const boxTarget = (ip: string, at: string, message: string): StoredTarget =>
  ({ id: newId('xt'), kind: 'ip', value: ip, token: '', method: 'box_egress', verified_at: at, expires_at: plus(at, VERIFY_DAYS), txt_ok: false, checks: 1, last_check: { at, ok: true, message }, created_at: at, last_scan_at: null })
/** The box saw it leave through this IP: a new node of the tree (this box's IP, proven by the sighting), or the node renewed. An IP a
 *  person typed becomes the box's own IP, proven the same way. */
function upsertBoxNode(ip: string, at: string, message: string, node: StoredNode | undefined) {
  const seen = { origin: 'box' as const, method: 'box_egress' as const, verified_at: at, last_check: { at, ok: true, message } }
  if (node) { patchNode(node.id, (x) => ({ ...x, ...seen, checks: x.checks + 1 })); return }
  tree.update((l) => [...l, { id: newId('xt'), parent_id: null, kind: 'ip', value: ip, scope_mode: null, enabled: true, created_at: at, token: '', checks: 1, commitment: null, terms: null, ...seen }])
}

const CURRENT_MS = 5 * 60_000
/**
 * Scan-time check of an IP (INV-13): may it be scanned now, i.e. does the box go out through it now? Yes when the latest check, or the latest full check, ran in the
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

/** The 409 ip_not_current answer when the box is not going out through the IP now (INV-13); null when it is. The Shodan check needs it (INV-21). */
export function ipPaused(t: { id: string; value: string }) {
  if (exposureIpCurrent(t.id)) return null
  const seenAt = find(t.id)?.verified_at
  return fail(409, 'ip_not_current', `This box no longer reaches the Internet through ${t.value}; it was last seen ${seenAt ? fmtDateTime(seenAt) : 'never'}. Scans of it are paused until the box uses it again.`)
}

/** The check the box runs by itself: due when auto-detect is on and the last check is older than the interval (or there was none: first start). */
function autoDetectIfDue() {
  const s = boxIp.get()
  if (s.auto && (!s.last_run || Date.now() >= Date.parse(s.last_run.at) + s.interval_min * 60_000)) detect('system')
}

// ---------------------------------------------------------------------------------------------------------------------
// Target tree (exp_tree, exp_tree_rows): nodes with proof per node and through ancestors, rows with first and last seen,
// and scans as runs. A run of the mock ends done a few seconds after it starts; one runs at a time, the others wait.
const tree = collection<StoredNode[]>('exp_tree', seedTree, () => [])
const treeRows = collection<TreeRows>('exp_tree_rows', seedTreeRows, () => ({ hosts: {}, addresses: {}, services: {}, issues: [], scans: [] }))
const MOCK_SCAN_MS = 4000
const PROOF_DAYS_MS = VERIFY_DAYS * 864e5
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const RESOLUTIONS: readonly string[] = ResolutionEnum.options
const LIVE: readonly RunStatus[] = ['queued', 'waiting', 'running', 'stopping']

const nodeOf = (id: unknown) => tree.get().find((n) => n.id === String(id))
const noNode = () => fail(404, 'not_found', 'No such target. It may have been deleted.')
const zoneOf = (name: string) => name.split('.').slice(-2).join('.')

/** The node's own proof, without its ancestors: it holds VERIFY_DAYS from its last pass; a later check that did not find it is a warning
 *  in last_check, never a state of its own (INV-4). */
function ownProof(n: StoredNode): 'proven' | 'missing' | 'expired' {
  if (!n.method || !n.verified_at) return 'missing'
  if (Date.now() - Date.parse(n.verified_at) > PROOF_DAYS_MS) return 'expired'
  return 'proven'
}

function ancestorsOf(n: StoredNode, all: StoredNode[]): StoredNode[] {
  const out: StoredNode[] = []
  for (let p = all.find((x) => x.id === n.parent_id); p && out.length < 50; p = all.find((x) => x.id === p!.parent_id)) out.push(p)
  return out
}

/** The overlap rule of the proof the scan engines get (exposure INV-13): an IP the box found that was last seen before the box's current
 *  egress address was first seen was replaced (the two never overlapped); null while it overlaps, for the current address and for
 *  every other node. */
function replacedOf(n: StoredNode, all: StoredNode[], state: ProofState): Proof['replaced'] {
  const box = (x: StoredNode) => x.kind === 'ip' && x.origin === 'box' && x.method === 'box_egress' && !!x.verified_at
  if (!box(n) || (state !== 'proven' && state !== 'not_current')) return null
  const lines = all.filter(box)
  const latest = Math.max(...lines.map((x) => Date.parse(x.verified_at!)))
  const current = lines.filter((x) => Date.parse(x.verified_at!) === latest)
  if (current.some((x) => x.id === n.id)) return null
  const newest = current.reduce((a, b) => (Date.parse(b.created_at) > Date.parse(a.created_at) ? b : a))
  return Date.parse(n.verified_at!) > Date.parse(newest.created_at) ? null : { by: newest.value, at: newest.created_at }
}

function nodeProof(n: StoredNode, all: StoredNode[]): Proof {
  const own = ownProof(n)
  const cover = own === 'proven' ? undefined : ancestorsOf(n, all).find((a) => ownProof(a) === 'proven')
  const state: ProofState = cover ? 'covered' : own
  const zone = zoneOf(n.value), label = n.value === zone ? '' : n.value.slice(0, -zone.length - 1)
  return {
    state,
    method: cover ? null : n.method,
    covered_by: cover ? { id: cover.id, value: cover.value } : null,
    verified_at: cover ? null : n.verified_at,
    expires_at: n.verified_at && !cover ? new Date(Date.parse(n.verified_at) + PROOF_DAYS_MS).toISOString() : null,
    next_check_at: n.kind === 'ip' && n.origin === 'person' && n.verified_at ? new Date(Date.parse(n.verified_at) + PROOF_DAYS_MS - 7 * 864e5).toISOString() : null,
    last_check: cover ? null : n.last_check,
    dns: n.kind === 'domain' && !cover ? { zone, host: '@', alt_host: label ? `_vedette-verify.${label}` : '_vedette-verify', value: `vedette-verify=${n.token}` } : null,
    file: n.kind === 'ip' && n.origin === 'person' ? {
      urls: [`http://${n.value}/.well-known/vedette-verify.txt`, `https://${n.value}/.well-known/vedette-verify.txt`],
      content: n.token,
      ptr_domains: all.filter((x) => x.kind === 'domain' && ownProof(x) === 'proven').map((x) => x.value),
    } : null,
    replaced: replacedOf(n, all, state),
  }
}

/** Moves the runs on: a running one ends done after a few seconds, then the oldest waiting one starts. */
function advanceRuns() {
  const rows = treeRows.get()
  let changed = false
  const scans = rows.scans.map((s) => {
    if (s.status !== 'running' || Date.now() - Date.parse(s.started_at!) < MOCK_SCAN_MS) return s
    changed = true
    const services = (rows.services[s.target_id] ?? []).filter((x) => x.state === 'open').length
    const issues = rows.issues.filter((x) => x.target_id === s.target_id && x.state === 'open').length
    return { ...s, status: 'done' as const, ended_at: nowIso(), counts: { hosts: (rows.hosts[s.target_id] ?? []).length, services, new_services: 0, closed_services: 0, issues, new_issues: 0 } }
  })
  if (!scans.some((s) => s.status === 'running')) {
    const next = scans.filter((s) => s.status === 'queued').sort((a, b) => a.queued_at.localeCompare(b.queued_at))[0]
    if (next) { changed = true; Object.assign(next, { status: 'running', started_at: nowIso() }) }
  }
  if (changed) treeRows.set({ ...rows, scans })
}

function nodeView(n: StoredNode, all = tree.get()): TargetNode {
  const rows = treeRows.get()
  const proof = nodeProof(n, all)
  const open = (rows.services[n.id] ?? []).filter((s) => s.state === 'open')
  const issues = rows.issues.filter((i) => i.target_id === n.id && i.state === 'open')
  const worst = issues.map((i) => i.severity).sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])[0] ?? null
  const scans = rows.scans.filter((s) => s.target_id === n.id).sort((a, b) => b.queued_at.localeCompare(a.queued_at))
  const commitmentCurrent = n.commitment?.version === NOTICE_VERSION
  return {
    id: n.id, parent_id: n.parent_id, schedule_key: `exposure.target:${n.id}`, kind: n.kind, value: n.value, origin: n.origin, scope_mode: n.scope_mode, enabled: n.enabled, created_at: n.created_at,
    proof,
    commitment: n.commitment, terms: n.terms,
    commitment_notice: commitmentCurrent ? null : { version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', n.value) },
    terms_notice: { version: TERMS_VERSION, text: (n.kind === 'domain' ? TERMS_TEMPLATE_DOMAIN : TERMS_TEMPLATE).replaceAll('{value}', n.value) },
    terms_warning: null,
    deep: termsInForce(n.terms?.version),
    blocked: !n.enabled ? 'disabled' : proof.state !== 'proven' && proof.state !== 'covered' ? 'proof' : !commitmentCurrent ? 'no_commitment' : null,
    last_scan: scans[0] ?? null,
    counts: { hosts: (rows.hosts[n.id] ?? []).length, services: open.length, web: open.filter((s) => s.is_web).length, issues: issues.length, worst },
  }
}

/** Every node in tree order: each right after its parent, siblings by value. */
function treeOrder(all: StoredNode[]): StoredNode[] {
  const out: StoredNode[] = []
  const visit = (parent: string | null) => {
    for (const n of all.filter((x) => x.parent_id === parent).sort((a, b) => a.value.localeCompare(b.value))) { out.push(n); visit(n.id) }
  }
  visit(null)
  return out
}

function patchNode(id: string, fn: (n: StoredNode) => StoredNode) {
  tree.update((l) => l.map((x) => (x.id === id ? fn(x) : x)))
  return nodeOf(id)!
}

/** The name entries of a parent that are this target: the parent then skips them (Host.child). */
function linkChild(parentId: string | null, child: { id: string; value: string } | null, name: string) {
  if (!parentId) return
  treeRows.update((r) => ({ ...r, hosts: { ...r.hosts, [parentId]: (r.hosts[parentId] ?? []).map((h) => (h.name === name ? { ...h, child } : h)) } }))
}

/** Shodan's answer about a node's IP beside the open services of the node (the target tree). */
function outsideNodeView(id: string): OutsideView | null {
  const o = outside.get()[id]
  if (!o) return null
  const rows = treeRows.get()
  const open = (rows.services[id] ?? []).filter((x) => x.state === 'open' && x.ip === o.ip)
  const last = rows.scans.filter((x) => x.target_id === id && x.started_at).sort((a, b) => b.queued_at.localeCompare(a.queued_at))[0]
  return { ...o, scan_ports: last ? [...new Set(open.map((x) => x.port))].sort((a, b) => a - b) : null, scan_at: last?.started_at ?? null }
}

/** An administrator's click sends a node's proven IP to Shodan InternetDB (at most once a minute on the box). */
function outsideNodeAsk(n: StoredNode) {
  if (n.kind !== 'ip') return fail(400, 'bad_value', 'Only a public IP of this box can be checked with Shodan, not a domain.')
  if (nodeProof(n, tree.get()).state !== 'proven') return fail(409, 'not_verified', `${n.value} has no ownership proof now, so it cannot be checked with Shodan.`)
  if (Date.now() - outsideAskedMs < 60_000) return fail(429, 'rate_limited', 'The box asked Shodan less than a minute ago. Try again in a minute: it asks at most once a minute.')
  outsideAskedMs = Date.now()
  const a = outsideAnswer(n.value)
  outside.update((m) => ({ ...m, [n.id]: { ip: n.value, checked_at: nowIso(), checked_by: currentUser()?.email ?? '', ...a } }))
  audit('exposure.outside_view', n.value, a.found ? `sent to internetdb.shodan.io; Shodan lists ${a.ports.length} ports and ${a.vulns.length} CVEs` : 'sent to internetdb.shodan.io; Shodan has no record of it')
  return HttpResponse.json(outsideNodeView(n.id))
}

// The schedules mock asks here whether a target exists and whether its scan can start now, as the box's owner of exposure.target does.
scheduleSubjects['exposure.target'] = (id) => {
  const n = nodeOf(id)
  if (!n) return { gone: true }
  const b = nodeView(n).blocked
  return { gone: false, refuse: b === 'disabled' ? `${n.value} is switched off, so it is not scanned.` : b === 'proof' ? `${n.value} has no ownership proof, so it cannot be scanned. Finish verification first.`
    : b === 'no_commitment' ? `${n.value} has not been confirmed yet. An administrator must run the first scan: it records that your company owns ${n.value} and that the scan is authorized.` : undefined }
}

const treeHandlers = [
  http.get(`${API}/exposure/tree`, () => {
    const denied = guard('viewer'); if (denied) return denied
    autoDetectIfDue()
    advanceRuns()
    const all = tree.get()
    const items = treeOrder(all).map((n) => nodeView(n, all))
    const gateway = items.some((x) => x.kind === 'ip' && x.origin === 'box' && x.counts.services > 0) ? { ip: '10.0.0.1', device_id: 'dev-gateway', name: 'fortigate-hq', open_exploited: 2 } : null
    return HttpResponse.json({ items, box_ip: boxView(), ignored: ignored.get().slice().sort((a, b) => b.ignored_at.localeCompare(a.ignored_at)), gateway })
  }),

  http.post(`${API}/exposure/tree`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ value: string; kind?: TargetKind; scope_mode?: ScopeMode }>(request)
    const value = String(b.value ?? '').trim().toLowerCase().replace(/\.$/, '')
    if (!value) return fail(400, 'empty', b.kind === 'ip' ? 'Enter a public IPv4 address, for example 198.51.100.10.' : 'Enter a domain, for example example.com.')
    const kind: TargetKind = b.kind ?? (IPV4_RE.test(value) ? 'ip' : 'domain')
    const all = tree.get()
    if (all.some((t) => t.value === value)) return fail(409, 'duplicate', `${value} is already in the list.`)
    if (all.length >= MAX_TARGETS) return fail(400, 'too_many', `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`)
    if (b.scope_mode !== undefined && (kind === 'ip' || !(['self', 'all', 'selected'] as const).includes(b.scope_mode))) return fail(400, 'bad_value', 'A scope is chosen for a domain only: this name, every name found under it, or the names you choose.')
    const base = { id: newId('xt'), value, origin: 'person' as const, enabled: true, created_at: nowIso(), token: randomToken(), verified_at: null, last_check: null, checks: 0, commitment: null, terms: null }
    let n: StoredNode
    if (kind === 'ip') {
      if (isIPv6Text(value) || (IPV4_RE.test(value) && !isPublicIp(value))) return fail(400, 'ip_not_allowed', IP_NOT_PUBLIC)
      if (!IPV4_RE.test(value)) return fail(400, 'bad_value', 'Not an IP address. Example: 198.51.100.10.')
      if (ignored.get().some((x) => x.value === value)) return fail(400, 'bad_value', `${value} is on your Ignored list. Restore it first.`)
      n = { ...base, parent_id: null, kind: 'ip', scope_mode: null, method: null }
    } else {
      if (isIPv6Text(value) || IPV4_RE.test(value)) return fail(400, 'ip_not_allowed', IP_NOT_A_DOMAIN)
      if (/[/:@\s]/.test(value) || !DOMAIN_RE.test(value)) return fail(400, 'bad_value', 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.')
      // The nearest domain target this is a name of becomes its parent; targets that are names of it move under it.
      const parent = all.filter((x) => x.kind === 'domain' && value.endsWith(`.${x.value}`)).sort((a, b) => b.value.length - a.value.length)[0] ?? null
      n = { ...base, parent_id: parent?.id ?? null, kind: 'domain', scope_mode: b.scope_mode ?? 'all', method: 'dns_txt' }
      const moved = all.filter((x) => x.kind === 'domain' && x.value.endsWith(`.${value}`) && x.parent_id === n.parent_id)
      tree.update((l) => l.map((x) => (moved.some((m) => m.id === x.id) ? { ...x, parent_id: n.id } : x)))
      linkChild(n.parent_id, { id: n.id, value }, value)
    }
    tree.update((l) => [...l, n])
    audit('exposure.target_add', value, n.parent_id ? `under ${nodeOf(n.parent_id)?.value}` : kind === 'ip' ? 'public IP, typed in; not scanned until proved' : '')
    return HttpResponse.json(nodeView(n), { status: 201 })
  }),

  http.get(`${API}/exposure/tree/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    advanceRuns()
    const n = nodeOf(params.id)
    return n ? HttpResponse.json(nodeView(n)) : noNode()
  }),

  http.patch(`${API}/exposure/tree/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    const b = await body<{ scope_mode?: ScopeMode; enabled?: boolean; selected?: string[] }>(request)
    if (b.scope_mode !== undefined && (n.kind === 'ip' || !(['self', 'all', 'selected'] as const).includes(b.scope_mode))) return fail(400, 'bad_value', 'A scope is chosen for a domain only: this name, every name found under it, or the names you choose.')
    if (b.enabled !== undefined && typeof b.enabled !== 'boolean') return fail(400, 'bad_value', 'enabled is true or false.')
    const scope = b.scope_mode ?? n.scope_mode
    if (b.selected !== undefined) {
      const hosts = treeRows.get().hosts[n.id] ?? []
      if (scope !== 'selected') return fail(400, 'bad_value', 'Names are chosen only when the scope is "the names I choose".')
      if (Array.isArray(b.selected) && b.selected.length > MAX_SELECTED) return fail(400, 'invalid', SELECTED_LIMIT_WHY)
      if (!Array.isArray(b.selected) || b.selected.some((h) => !hosts.some((x) => x.id === h))) return fail(400, 'bad_value', 'One of the chosen names is not a name found under this target.')
      const pick = new Set(b.selected)
      treeRows.update((r) => ({ ...r, hosts: { ...r.hosts, [n.id]: hosts.map((h) => ({ ...h, selected: pick.has(h.id) })) } }))
    }
    const next = patchNode(n.id, (x) => ({ ...x, scope_mode: scope, enabled: b.enabled ?? x.enabled }))
    audit('exposure.target_edit', n.value, `scope: ${next.scope_mode ?? 'n/a'}, enabled: ${next.enabled ? 'yes' : 'no'}${b.selected ? `, names chosen: ${b.selected.length}` : ''}`)
    return HttpResponse.json(nodeView(next))
  }),

  http.delete(`${API}/exposure/tree/:id`, ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    const ignore = new URL(request.url).searchParams.get('ignore') === 'true'
    if (ignore && n.kind !== 'ip') return fail(400, 'bad_value', 'Only an IP can go on the Ignored list.')
    tree.update((l) => l.filter((x) => x.id !== n.id).map((x) => (x.parent_id === n.id ? { ...x, parent_id: n.parent_id } : x)))
    linkChild(n.parent_id, null, n.value)
    treeRows.update((r) => {
      const drop = <T,>(m: Record<string, T>) => { const c = { ...m }; delete c[n.id]; return c }
      return { hosts: drop(r.hosts), addresses: drop(r.addresses), services: drop(r.services), issues: r.issues.filter((i) => i.target_id !== n.id), scans: r.scans.filter((s) => s.target_id !== n.id) }
    })
    if (ignore) ignored.update((l) => [...l.filter((x) => x.value !== n.value), { value: n.value, ignored_by: currentUser()?.email ?? '', ignored_at: nowIso() }])
    audit('exposure.target_delete', n.value, ignore ? 'and put on the Ignored list' : '')
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${API}/exposure/tree/:id/verify`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    const proof = nodeProof(n, tree.get())
    if (proof.state === 'covered') {
      return HttpResponse.json({ verified: true, message: `Ownership already proven by the TXT record at ${proof.covered_by!.value}.`, node: nodeView(n) })
    }
    const box = n.kind === 'ip' && n.origin === 'box'
    const limited = box ? rateLimit() : null; if (limited) return limited // this box's IP: within the 10 attempts an hour Detect now uses too
    const at = nowIso(), checks = n.checks + 1
    // The mock finds a new record or file from the second check on; this box's IP is seen only while the box goes out through it.
    const observed = box ? egressIps() : null
    const found = box ? Array.isArray(observed) && observed.includes(n.value) : checks >= 2
    const message = box
      ? found ? `The box reaches the Internet via ${n.value}.`
        : !Array.isArray(observed) ? (observed === 'offline' ? OFFLINE : DISAGREE)
          : `This box currently reaches the Internet via ${list(observed)}, not ${n.value}. Ask your admin to route the box through ${n.value} (for example switch WAN), then verify again.`
      : n.kind === 'domain' ? `The TXT record vedette-verify=${n.token} was ${found ? '' : 'not '}found on ${n.value}.`
        : found ? `The proof file was found at http://${n.value}/.well-known/vedette-verify.txt.` : `No proof file at http://${n.value}/.well-known/vedette-verify.txt or https://${n.value}/.well-known/vedette-verify.txt.`
    const next = patchNode(n.id, (x) => ({ ...x, checks, last_check: { at, ok: found, message }, ...(found ? { verified_at: at, method: x.method ?? (x.kind === 'domain' ? 'dns_txt' : 'ip_file') } : {}) }))
    audit('exposure.verify', n.value, message)
    return HttpResponse.json({ verified: found, message, node: nodeView(next) })
  }),

  http.put(`${API}/exposure/tree/:id/terms`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    const me = currentUser()!
    if (!me.twofa && !me.sso) return fail(403, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then accept the testing terms.')
    const b = await body<{ version?: string; disruptive?: boolean }>(request)
    // an older page sends its tick: false asked for the deep scan without the disruptive checks, so it is asked to read the terms again
    if (b.version !== TERMS_VERSION || b.disruptive === false) return fail(409, 'notice_changed', 'The testing terms changed since this page loaded. Read them again, then accept them again.')
    const v = nodeView(n)
    if (v.proof.state !== 'proven' && v.proof.state !== 'covered' && v.proof.state !== 'not_current') return fail(409, 'not_verified', 'Prove ownership first; only then can the testing terms be accepted.')
    if (v.terms?.version === TERMS_VERSION && v.terms.disruptive) return HttpResponse.json(v)
    const at = nowIso()
    const next = patchNode(n.id, (x) => ({
      ...x,
      commitment: x.commitment?.version === NOTICE_VERSION ? x.commitment : { version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', x.value), by: me.email, at, disruptive: false },
      terms: { version: TERMS_VERSION, text: v.terms_notice.text, by: me.email, at, disruptive: true },
    }))
    audit('exposure.terms_accept', n.value, 'disruptive checks: yes')
    return HttpResponse.json(nodeView(next))
  }),

  http.delete(`${API}/exposure/tree/:id/terms`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    if (n.terms) audit('exposure.terms_revoke', n.value, `withdrawn (terms ${n.terms.version}, accepted by ${n.terms.by} at ${n.terms.at})`)
    return HttpResponse.json(nodeView(patchNode(n.id, (x) => ({ ...x, terms: null }))))
  }),

  http.post(`${API}/exposure/tree/:id/scan`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const n = nodeOf(params.id)
    if (!n) return noNode()
    advanceRuns()
    const v = nodeView(n)
    if (v.blocked === 'disabled') return fail(409, 'disabled', `${n.value} is turned off. Turn it on to scan it.`)
    if (v.blocked === 'proof') return fail(409, 'not_verified', `${n.value} has no ownership proof, so it cannot be scanned. Prove it first.`)
    const me = currentUser()!
    if (v.blocked === 'no_commitment') {
      if (me.role !== 'admin') return fail(400, 'commitment_required', `${n.value} has not been confirmed yet. An administrator must run the first scan: it records that your company owns ${n.value} and that the scan is authorized.`)
      if (!me.twofa && !me.sso) return fail(403, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then run the first scan again.')
      const sent = await body<{ notice_version?: string }>(request)
      if (!sent.notice_version) return fail(400, 'commitment_required', `The first scan of ${n.value} records a confirmation, so the request must carry notice_version of the sentence shown next to Scan now.`)
      if (sent.notice_version !== NOTICE_VERSION) return fail(409, 'notice_changed', 'The confirmation text changed since this page loaded. Read it again, then press Scan now again.')
      patchNode(n.id, (x) => ({ ...x, commitment: { version: NOTICE_VERSION, text: NOTICE_TEMPLATE.replace('{value}', x.value), by: me.email, at: nowIso(), disruptive: false } }))
      audit('exposure.commitment', n.value, 'confirmed by the first Scan now')
    }
    const rows = treeRows.get()
    if (rows.scans.some((s) => s.target_id === n.id && LIVE.includes(s.status))) return fail(409, 'busy', `A scan of ${n.value} is already queued or running.`)
    const running = rows.scans.some((s) => s.status === 'running')
    const at = nowIso()
    const s: Scan = { run_id: newId('run'), target_id: n.id, status: running ? 'queued' : 'running', trigger: 'manual', requested_by: me.email, mode: v.deep ? 'deep' : 'surface',
      queued_at: at, started_at: running ? null : at, ended_at: null, waiting_for: null, stop_reason: null, error: null, counts: null, web_steps: [] }
    treeRows.update((r) => ({ ...r, scans: [s, ...r.scans] }))
    audit('exposure.scan', n.value, `${s.mode} scan ${s.status}`)
    return HttpResponse.json(s, { status: 202 })
  }),

  http.get(`${API}/exposure/tree/:id/scans`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!nodeOf(params.id)) return noNode()
    advanceRuns()
    const items = treeRows.get().scans.filter((s) => s.target_id === params.id).sort((a, b) => b.queued_at.localeCompare(a.queued_at)).slice(0, 100)
    return HttpResponse.json({ items })
  }),

  http.get(`${API}/exposure/tree/:id/hosts`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!nodeOf(params.id)) return noNode()
    return HttpResponse.json({ items: (treeRows.get().hosts[String(params.id)] ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)) })
  }),

  http.get(`${API}/exposure/tree/:id/addresses`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!nodeOf(params.id)) return noNode()
    return HttpResponse.json({ items: treeRows.get().addresses[String(params.id)] ?? [] })
  }),

  http.get(`${API}/exposure/tree/:id/services`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!nodeOf(params.id)) return noNode()
    const items = (treeRows.get().services[String(params.id)] ?? []).slice().sort((a, b) => a.state.localeCompare(b.state) * -1 || a.ip.localeCompare(b.ip) || a.port - b.port)
    return HttpResponse.json({ items })
  }),

  http.get(`${API}/exposure/tree/:id/issues`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!nodeOf(params.id)) return noNode()
    const items = treeRows.get().issues.filter((i) => i.target_id === params.id).sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.title.localeCompare(b.title))
    return HttpResponse.json({ items })
  }),

  http.post(`${API}/exposure/issues/handle`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ ids: string[]; resolution: Resolution; note: string; accepted_until?: string }>(request)
    const ids = issueIdsOf(b.ids)
    if (!ids) return fail(400, 'invalid', `Choose between 1 and ${MAX_ISSUE_IDS} issues.`)
    if (!RESOLUTIONS.includes(b.resolution as Resolution)) return fail(400, 'bad_value', 'Choose how the issues were handled.')
    if (typeof b.note !== 'string' || b.note.length > 500) return fail(400, 'bad_value', 'The note is at most 500 characters.')
    if ((b.resolution === 'false_positive' || b.resolution === 'not_relevant' || b.resolution === 'accepted') && b.note.trim().length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    const until = b.accepted_until
    if (b.resolution === 'accepted') {
      const today = new Date().toISOString().slice(0, 10), last = new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10)
      if (!until || !/^\d{4}-\d{2}-\d{2}$/.test(until) || until <= today || until > last) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    } else if (until !== undefined) return fail(400, 'bad_until', 'A last day is set only when the risk is accepted.')
    const me = currentUser()!.email, at = nowIso()
    let handled = 0
    treeRows.update((r) => ({ ...r, issues: r.issues.map((i) => {
      if (!ids.has(i.id) || i.state !== 'open') return i
      handled++
      audit('exposure.issue_handle', i.title, `${b.resolution}${until ? ` until ${until}` : ''}${b.note ? `: ${b.note}` : ''}`)
      return { ...i, state: 'handled' as const, resolution: b.resolution as Resolution, resolved_by: me, resolved_at: at, note: b.note || null, accepted_until: b.resolution === 'accepted' ? until! : null }
    }) }))
    return HttpResponse.json({ handled, skipped: ids.size - handled })
  }),

  http.post(`${API}/exposure/issues/reopen`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const ids = issueIdsOf((await body<{ ids: string[] }>(request)).ids)
    if (!ids) return fail(400, 'invalid', `Choose between 1 and ${MAX_ISSUE_IDS} issues.`)
    let reopened = 0
    treeRows.update((r) => ({ ...r, issues: r.issues.map((i) => {
      if (!ids.has(i.id) || i.state !== 'handled') return i
      reopened++
      audit('exposure.issue_reopen', i.title, `was ${i.resolution}`)
      return { ...i, state: 'open' as const, resolution: null, resolved_by: null, resolved_at: null, note: null, accepted_until: null }
    }) }))
    return HttpResponse.json({ reopened, skipped: ids.size - reopened })
  }),
]

// Stopping a scan of the tree goes through the shared runs. A run id that is not a scan of the tree falls through to the
// shared runs mock (no answer here).
treeHandlers.push(http.post(`${API}/runs/:id/stop`, ({ params }) => {
  const s = treeRows.get().scans.find((x) => x.run_id === params.id)
  if (!s) return undefined
  const denied = guard('operator'); if (denied) return denied
  if (!LIVE.includes(s.status)) return fail(409, 'not_running', 'This run has already ended, so there is nothing to stop.')
  const by = currentUser()?.email ?? 'system'
  const at = nowIso()
  const stopped: Scan = { ...s, status: 'stopped', stop_reason: `Stopped by ${by}`, waiting_for: null, ended_at: at }
  treeRows.update((r) => ({ ...r, scans: r.scans.map((x) => (x.run_id === s.run_id ? stopped : x)) }))
  audit('scanning.run_stop', nodeOf(s.target_id)?.value ?? s.target_id, stopped.stop_reason ?? '')
  return HttpResponse.json({ id: s.run_id, module: 'exposure', kind: 'exposure_scan', lane: 'exposure', title: `Exposure scan of ${nodeOf(s.target_id)?.value ?? s.target_id}`,
    trigger: s.trigger, trigger_note: null, requested_by: s.requested_by, schedule_id: null, subject: null, parent_id: null, status: 'stopped', waiting_for: null,
    stop_reason: stopped.stop_reason, error: null, total: 0, done: 0, queued_at: s.queued_at, started_at: s.started_at, ended_at: at, updated_at: at, can_stop: false, can_resume: false })
}))

function issueIdsOf(v: unknown): Set<string> | null {
  if (!Array.isArray(v) || v.length < 1 || v.length > MAX_ISSUE_IDS || v.some((x) => typeof x !== 'string')) return null
  return new Set(v as string[])
}

export const handlers = [
  http.get(`${API}/exposure/targets`, () => {
    const denied = guard('viewer'); if (denied) return denied
    autoDetectIfDue()
    const items = targets.get().map(view)
    // The sample gateway is an unnamed FortiGate with two exploited findings; the box answers "who answers" only for its own IPs.
    const gateway = items.some((x) => x.kind === 'ip' && (x.open_ports?.length ?? 0) > 0) ? { ip: '192.168.1.1', device_id: 'dev-gateway', name: 'fortigate-hq', open_exploited: 2 } : null
    return HttpResponse.json({ items, box_ip: boxView(), ignored: ignored.get().slice().sort((a, b) => b.ignored_at.localeCompare(a.ignored_at)), gateway })
  }),

  // Auto-detect on or off and the interval. Turning it on checks at once (not when it checked in the last 5 minutes). Never takes an IP.
  http.put(`${API}/exposure/box-ip/settings`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ auto: boolean; interval_min: number }>(request)
    if (typeof b.auto !== 'boolean') return fail(400, 'invalid_setting', 'Say whether auto-detect is on or off.')
    const n = b.interval_min
    if (typeof n !== 'number' || !Number.isInteger(n) || n < MIN_INTERVAL || n > MAX_INTERVAL) return fail(400, 'bad_interval', `The interval is at least 5 minutes. The lookup services rate-limit; a change is found at the next check.`)
    const before = boxIp.get()
    boxIp.set({ ...before, auto: b.auto, interval_min: n })
    audit('exposure.box_ip_settings', 'box', `auto-detect ${b.auto ? 'on' : 'off'}, every ${n} minutes`)
    if (b.auto && !before.auto && (!before.last_run || Date.now() - Date.parse(before.last_run.at) >= MIN_GAP_MS)) detect('user')
    return HttpResponse.json(boxView())
  }),

  // Adding a target changes the scan scope, so admin: a domain, or a public IPv4 typed in (accepted at once, never scanned until proved).
  http.post(`${API}/exposure/targets`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const b = await body<{ value: string; kind?: 'domain' | 'ip' }>(request)
    const value = String(b.value ?? '').trim().toLowerCase()
    if (!value) return fail(400, 'empty', b.kind === 'ip' ? 'Enter a public IPv4 address, for example 203.0.113.10.' : 'Enter a domain, for example example.com.')
    const kind = b.kind ?? (IPV4_RE.test(value) ? 'ip' : 'domain')
    if (targets.get().some((t) => t.value === value)) return fail(409, 'duplicate', `${value} is already in the list.`)
    if (targets.get().length >= MAX_TARGETS) return fail(400, 'too_many', `At most ${MAX_TARGETS} targets. Delete ones you no longer use.`)
    if (kind === 'ip') {
      if (isIPv6Text(value) || (IPV4_RE.test(value) && !isPublicIp(value))) return fail(400, 'ip_not_allowed', IP_NOT_PUBLIC)
      if (!IPV4_RE.test(value)) return fail(400, 'bad_value', 'Not an IP address. Example: 203.0.113.10.')
      if (ignored.get().some((x) => x.value === value)) return fail(400, 'bad_value', `${value} is on your Ignored list. Restore it in Settings first.`)
    }
    let t: StoredTarget
    if (kind === 'ip') {
      t = { id: newId('xt'), kind: 'ip', typed: true, value, token: randomToken(), method: null, verified_at: null, expires_at: null, txt_ok: false, checks: 0, last_check: null, created_at: nowIso(), last_scan_at: null }
      audit('exposure.target_add', value, 'public IP, typed in; not scanned until proved')
    } else {
      if (isIPv6Text(value) || IPV4_RE.test(value)) return fail(400, 'ip_not_allowed', IP_NOT_A_DOMAIN)
      if (/[/:@\s]/.test(value)) return fail(400, 'bad_value', 'Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.')
      if (!DOMAIN_RE.test(value)) return fail(400, 'bad_value', 'Not a valid domain. Example: example.com.')
      t = { id: newId('xt'), kind: 'domain', value, token: randomToken(), method: 'dns_txt', verified_at: null, expires_at: null, txt_ok: false, checks: 0, last_check: null, created_at: nowIso(), last_scan_at: null }
      audit('exposure.target_add', value)
    }
    targets.update((l) => [...l, t])
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

  // Restore: only lets detection add the IP again. The list blocks and never allows: nothing is added here and the IP is not scannable by itself.
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

  // Removing a target. For an IP, ?ignore=true also puts it on the Ignored list: detection never adds it again and it is never scanned.
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
    const limited = t.kind === 'ip' && !t.typed ? rateLimit() : null; if (limited) return limited
    const at = nowIso()
    const checks = t.checks + 1
    let ok: boolean
    let message: string
    let next: StoredTarget
    if (t.kind === 'domain') {
      const cover = proofOf(t)?.covered_by
      ok = t.txt_ok || checks >= 2 || !!cover
      message = ok
        ? (cover ? `Found the TXT record of ${cover} on ${cover}: it proves ${cover} and every name under it, ${t.value} included.` : `Found the TXT record vedette-verify=${t.token} on ${t.value}.`)
        : `No TXT record vedette-verify=${t.token} was found. Vedette asked ${t.value}, _vedette-verify.${t.value}. ${t.value}: no TXT record. _vedette-verify.${t.value}: no TXT record. DNS usually updates within minutes and can take up to 72 hours. Check again later, and make sure the value was pasted without extra quotes and that the Name field is the host shown (some providers append the domain automatically).`
      next = { ...t, checks, txt_ok: ok, last_check: { at, ok, message }, verified_at: ok ? (t.verified_at ?? at) : t.verified_at }
    } else if (t.typed) {
      // A typed IP: the token file, then reverse DNS. The mock finds the file from the second check on (the person has to place it first).
      ok = t.txt_ok || checks >= 2
      message = ok
        ? `Found the token file at http://${t.value}/.well-known/vedette-verify.txt. Verified until ${fmt(plus(at, VERIFY_DAYS))}.`
        : `Vedette found no proof of ${t.value}. Token file: put the token ${t.token} as the only content of /.well-known/vedette-verify.txt on that address, over http or https. http://${t.value}/.well-known/vedette-verify.txt: answered 404. https://${t.value}/.well-known/vedette-verify.txt: connection refused. Reverse DNS: ${t.value} has no reverse DNS (PTR) name.`
      next = { ...t, checks, txt_ok: ok, method: ok ? 'ip_file' : t.method, last_check: { at, ok, message }, verified_at: ok ? at : t.verified_at, expires_at: ok ? plus(at, VERIFY_DAYS) : t.expires_at }
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
    audit(ok ? 'exposure.verify_ok' : 'exposure.verify_fail', t.value, t.kind === 'domain' ? 'dns_txt' : t.typed ? 'ip proof' : 'box_egress')
    return HttpResponse.json({ verified: ok, message, target: view(next) })
  }),

  // Accept the testing terms of a verified target (admin with two-step), the disruptive checks included. They
  // include the ownership sentence, so the Scan now commitment is recorded too when missing.
  http.put(`${API}/exposure/targets/:id/terms`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    const me = currentUser()!
    if (!me.twofa && !me.sso) return fail(403, 'twofa_required', 'Turn on two-step sign-in for your account first (My account), then run the first scan again. The first scan records your confirmation that your company owns the target and that you are authorized to scan it.')
    const b = await body<{ version?: string; disruptive?: boolean }>(request)
    // an older page sends its tick: false asked for the deep scan without the disruptive checks, so it is asked to read the terms again
    if (b.version !== TERMS_VERSION || b.disruptive === false) return fail(409, 'notice_changed', 'The testing terms changed since this page loaded. Read them again, then accept them again.')
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', 'Verify ownership first; only then can the testing terms be accepted.')
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} has expired. Verify it again first.`)
    if (v.terms?.version === TERMS_VERSION && v.terms.disruptive) return HttpResponse.json(v)
    if (v.commitment?.version !== NOTICE_VERSION) {
      const sentence = NOTICE_TEMPLATE.replace('{value}', t.value)
      commitments.update((m) => ({ ...m, [t.id]: { by: me.email, at: nowIso(), version: NOTICE_VERSION, sentence } }))
      audit('exposure.commitment', t.value, `confirmed by accepting the testing terms (notice ${NOTICE_VERSION}): ${sentence}`)
    }
    const text = v.terms_notice.text
    termsStore.update((m) => ({ ...m, [t.id]: { version: TERMS_VERSION, by: me.email, at: nowIso(), text, disruptive: true } }))
    audit('exposure.terms_accept', t.value, auditClip(`${v.terms ? `accepted again (replaces terms ${v.terms.version}, accepted by ${v.terms.by} at ${v.terms.at}, disruptive checks: ${v.terms.disruptive ? 'yes' : 'no'})` : 'accepted'} (disruptive checks: yes, terms ${TERMS_VERSION}): ${text}`))
    return HttpResponse.json(view(t))
  }),

  // Withdraw the terms; always possible, the next scan is in the K-4 scope again.
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
    // Re-check the TXT record right before the scan; a missing record is a warning on the target, and the scan goes on (INV-4).
    if (t.kind === 'domain' && !t.txt_ok) {
      targets.update((l) => l.map((x) => (x.id === t.id ? { ...x, last_check: { at: nowIso(), ok: false, message: `The TXT record vedette-verify=${t.token} was not found on ${t.value}. The proof found earlier stays valid for ${VERIFY_DAYS} days from its last pass, so scans go on until then.` } } : x)))
    }
    if (v.commitment?.version !== NOTICE_VERSION) {
      // An administrator's first Scan now is the confirmation; an operator cannot scan an unconfirmed target.
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
    // The box checks whether it still goes out through the IP (a sighting renews it); one it does not go out through now stays scannable
    // until its days run out (INV-13, INV-4).
    if (t.kind === 'ip' && !t.typed) exposureIpCurrent(t.id)
    // The scan module's runner does the scan behind this module's own switch: the Vulnerability scans module may be off.
    // Like the box: 202 with the run at once, and the phases move on while the page polls GET /exposure/scan. The mock has no one-at-a-time or 10-minute limit
    // (its tests scan an IP several times in a row). The result is stored when the run is done.
    const at = nowIso()
    // A domain with accepted terms gets the deep scan of its names' addresses, in turn by when each was last deep-scanned.
    const lastDeep: Record<string, string> = {}
    for (const sn of snapshots.get()[t.id] ?? []) for (const h of sn.hosts) for (const a of h.ips ?? []) if (a.last_deep && a.last_deep > (lastDeep[a.ip] ?? '')) lastDeep[a.ip] = a.last_deep
    const content = t.kind === 'ip' ? { ...scanContent(t), ...greenboneFor(t.value, v.full_scan) } : v.full_scan ? withDeep(scanContent(t), at, lastDeep) : scanContent(t)
    const snap = makeSnapshot(newId('sn'), at, content, t.kind === 'ip' ? t.value : undefined)
    const run: ScanRun = { id: newId('sr'), target_id: t.id, target_value: t.value, by: currentUser()?.email ?? '', started_at: at, finished_at: null, status: 'running', phase: 'queued', snapshot_id: null, error: null, progress: null }
    mockRunStore.set({ run, startedMs: Date.now(), snap })
    return HttpResponse.json(run, { status: 202 })
  }),

  // The mock starts every scan at once (no queue), so nothing ever waits to be taken out.
  http.delete(`${API}/exposure/targets/:id/queue`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    return fail(409, 'not_queued', `${t.value} is not waiting in the scan queue.`)
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
    const stopped: ScanRun = { ...r, status: 'stopped', finished_at: nowIso(), progress: null }
    mockRunStore.set({ ...m, run: stopped })
    audit('exposure.scan', r.target_value, `stopped by ${currentUser()?.email ?? ''}`)
    return HttpResponse.json(stopped)
  }),

  // OpenVAS again for the newest scan of a public IP whose OpenVAS step did not finish (operator). The box runs it in the background;
  // the mock finishes it at once with what a deep scan's OpenVAS finds, in the same snapshot, and keeps the other results as they are.
  http.post(`${API}/exposure/targets/:id/openvas`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const t = find(params.id)
    if (!t) return notFound()
    if (t.kind !== 'ip') return fail(400, 'bad_value', 'OpenVAS runs again on its own only on a public IP of this box. For a domain, run its deep scan again.')
    if (settledRun()?.status === 'running') return fail(409, 'busy', 'Another external scan is running on this box. Wait for it to finish, then try again.')
    const last = (snapshots.get()[t.id] ?? []).slice().sort((a, b) => b.date.localeCompare(a.date))[0]
    if (!last || !['stopped', 'failed', 'ended'].includes(last.greenbone_run.state)) return fail(409, 'nothing_to_rerun', 'The newest scan of this target has no OpenVAS step that was stopped or did not finish, so there is nothing to run again. Run a deep scan instead.')
    const fresh = makeSnapshot(last.id, last.scanned_at, { ...scanContent(t), ...greenboneFor(t.value, view(t).full_scan) }, t.value)
    if (fresh.greenbone_run.state !== 'done') return fail(503, 'scanner_unavailable', `OpenVAS cannot run now. ${fresh.not_checked.find((n) => n.kind === 'greenbone')?.text ?? ''}`.trim())
    const at = nowIso()
    const snap: Snapshot = { ...last, greenbone: fresh.greenbone, vulns: fresh.vulns, finished_at: at,
      checks: [...last.checks.filter((c) => c.kind !== 'greenbone'), ...fresh.checks.filter((c) => c.kind === 'greenbone')],
      not_checked: last.not_checked.filter((n) => n.kind !== 'greenbone'),
      greenbone_run: { state: 'done', started_at: at, ended_at: at, addresses: [], again: true } }
    snapshots.update((all) => ({ ...all, [t.id]: (all[t.id] ?? []).map((x) => (x.id === last.id ? snap : x)) }))
    audit('exposure.scan', t.value, `OpenVAS again, on the open ports the scan of ${last.date} found`)
    const run: ScanRun = { id: newId('sr'), target_id: t.id, target_value: t.value, by: currentUser()?.email ?? '', started_at: at, finished_at: at, status: 'done', phase: 'done', snapshot_id: snap.id, error: null, progress: null, openvas_only: true }
    mockRunStore.set({ run, startedMs: Date.now(), snap })
    return HttpResponse.json(run, { status: 202 })
  }),

  // What the Internet sees: reading sends nothing.
  http.get(`${API}/exposure/targets/:id/outside`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!find(params.id)) return nodeOf(params.id) ? HttpResponse.json(outsideNodeView(String(params.id))) : notFound()
    return HttpResponse.json(outsideView(String(params.id)))
  }),

  // An administrator's click sends this IP of the box to Shodan InternetDB. Only the box's own verified IP that it still goes out through.
  http.post(`${API}/exposure/targets/:id/outside`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const t = find(params.id)
    if (!t) return nodeOf(params.id) ? outsideNodeAsk(nodeOf(params.id)!) : notFound()
    if (t.kind !== 'ip') return fail(400, 'bad_value', 'Only a public IP of this box can be checked with Shodan, not a domain.')
    const v = view(t)
    if (v.status === 'unverified') return fail(409, 'not_verified', `${t.value} has no ownership proof, so it cannot be checked with Shodan. Finish verification first.`)
    if (v.status === 'expired') return fail(409, 'expired', `Verification of ${t.value} expired on ${fmt(t.expires_at!)}, so it cannot be checked with Shodan. Verify it again first.`)
    if (ipPaused(t)) return fail(409, 'ip_not_current', `This box no longer reaches the Internet through ${t.value}; it was last seen ${t.verified_at ? fmtDateTime(t.verified_at) : 'never'}. It is not sent to Shodan until the box uses it again.`)
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
    if (b.enabled && !before.preflight.ok) return fail(409, before.preflight.reason!.includes(' of memory') ? 'low_memory' : 'low_disk', before.preflight.reason!)
    greenbone.set({ enabled: b.enabled, changed_by: currentUser()?.email ?? null, changed_at: nowIso() })
    audit('exposure.greenbone', 'OpenVAS', b.enabled ? `enabled (memory ${gbText(before.preflight.memory_bytes!)}, free disk ${gbText(before.preflight.disk_free_bytes!)})` : 'disabled (data kept)')
    return HttpResponse.json(greenboneView())
  }),

  http.get(`${API}/exposure/targets/:id/snapshots`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    if (!find(params.id)) return notFound()
    const l = (snapshots.get()[String(params.id)] ?? []).slice().sort((a, b) => b.date.localeCompare(a.date))
    return HttpResponse.json({ items: l.map((s) => ({ id: s.id, date: s.date, scanned_at: s.scanned_at, started_at: s.started_at ?? s.scanned_at, finished_at: s.finished_at ?? null, counts: s.counts })) })
  }),

  http.get(`${API}/exposure/targets/:id/snapshots/:date`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const s = (snapshots.get()[String(params.id)] ?? []).find((x) => x.date === params.date)
    // a snapshot this browser stored before scans kept their start and end reads as the box reads one: its start is its store time
    return s ? HttpResponse.json({ ...s, started_at: s.started_at ?? s.scanned_at, finished_at: s.finished_at ?? null }) : fail(404, 'not_found', 'No snapshot for this day.')
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
  ...treeHandlers,
]

// Shared inside the mock layer: the scan module only scans external targets that are verified (IPs: seen by the box within 30 days).
// Reading the targets also runs the automatic check when it is due, as the box's job would have by now, so the scan page of a clean install lists the IPs the box found.
export const exposureTargetsStore: Collection<StoredTarget[]> = { get: () => { autoDetectIfDue(); return targets.get() }, set: (v) => targets.set(v), update: (fn) => targets.update(fn) }
export { snapshots as exposureSnapshotsStore, commitments as exposureCommitmentsStore }
// The scan module asks the same question before it scans an external IP (CheckScannable, INV-13).
export { ipPaused as exposureIpPaused }
