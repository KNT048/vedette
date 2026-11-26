// Mock API: schedules (core/schedule). One model for every schedule a person can set; the box computes every time (Next in Go),
// this mock only approximates it for the dev server: it follows the box's zone but not every edge of summer time. Every schedule
// follows the box's zone (Settings › General): a tz a client sends is ignored, as the box does.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { orgStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import type { z } from 'zod'
import type { Schedule, ScheduleLimits, ScheduleRule } from './contract'

type Rule = z.infer<typeof ScheduleRule>
type Limits = z.infer<typeof ScheduleLimits>
type View = z.infer<typeof Schedule>
type Freq = Rule['freq']
type WindowMode = Rule['window']

interface Owner { module: string; perSubject: boolean; limits: Partial<Limits>; adminOnly?: boolean; defaultOn: boolean; rule: Partial<Rule> }
const FREQS: Freq[] = ['interval', 'daily', 'weekly', 'monthly', 'once']
const WINDOWS: WindowMode[] = ['global', 'none', 'custom']
const base: Rule = { freq: 'daily', every_minutes: null, at_time: null, weekdays: null, month_day: null, once_at: null, tz: 'org', window: 'none', window_days: null, window_from: null, window_to: null }

/** The owners the box registers (the modules adopt core/schedule one by one; their keys and limits are these). */
const OWNERS: Record<string, Owner> = {
  'scan.vuln': { module: 'scan', perSubject: false, limits: { windows: ['global'], reason: 'Scheduled checks run only inside the scan window (Settings, Scanning, Safety).' }, adminOnly: true, defaultOn: true, rule: { freq: 'weekly', at_time: '23:00', weekdays: [7], window: 'global' } },
  'inventory.sweep': { module: 'sensor-active', perSubject: false, limits: {}, adminOnly: true, defaultOn: true, rule: { freq: 'daily', at_time: '22:00', window: 'global' } },
  'exposure.target': { module: 'exposure', perSubject: true, adminOnly: true, limits: { min_every_minutes: 360, reason: "An external scan can take hours and loads the target's services, so it runs at most every 6 hours." }, defaultOn: true, rule: { freq: 'weekly', at_time: '02:30', weekdays: [1], window: 'global' } },
  'reports.def': { module: 'reports', perSubject: true, limits: { freqs: ['weekly', 'monthly'], reason: 'A report covers a week or a month.' }, defaultOn: false, rule: { freq: 'weekly', at_time: '08:00', weekdays: [1] } },
  'feeds.source': { module: 'feeds', perSubject: true, adminOnly: true, limits: { freqs: ['interval'], min_every_minutes: 60, windows: ['none'], reason: 'Sources ask clients not to poll more often.' }, defaultOn: true, rule: { freq: 'interval', every_minutes: 60 } },
  'exposure.public_ip': { module: 'exposure', perSubject: false, adminOnly: true, limits: { freqs: ['interval'], min_every_minutes: 5, max_every_minutes: 1440, reason: 'The lookup services rate-limit; a change is found at the next check.' }, defaultOn: true, rule: { freq: 'interval', every_minutes: 15 } },
  'agent-intake.wazuh': { module: 'agent-intake', perSubject: false, adminOnly: true, limits: { freqs: ['interval'], min_every_minutes: 5, reason: 'The Wazuh server answers slowly to frequent pulls.' }, defaultOn: true, rule: { freq: 'interval', every_minutes: 15 } },
}

interface Saved { enabled: boolean; paused_until: string | null; rule: Rule; last_due_at: string | null; last_run_id: string | null; last_skip_reason: string | null; last_skip_at: string | null; updated_by: string; updated_at: string }
const store = collection<Record<string, Saved>>('core_schedule', () => ({
  'exposure.target:xt-11': { enabled: true, paused_until: null, rule: { ...base, freq: 'interval', every_minutes: 3 * 1440, at_time: '02:30', window: 'custom', window_days: [1, 2, 3, 4, 5], window_from: '00:00', window_to: '00:00' }, last_due_at: null, last_run_id: 'run-m1', last_skip_reason: null, last_skip_at: null, updated_by: 'admin@acme.example', updated_at: nowIso() },
}), () => ({}))

/**
 * The subjects of the owners with one schedule per subject, as their own mocks know them (the exposure mock registers its targets): gone
 * makes the schedule 404 like the box, refuse is the reason the owner's Start gives (409 not_started on Run once now). An owner nobody
 * registered accepts any subject.
 */
export const scheduleSubjects: Record<string, (id: string) => { gone: boolean; refuse?: string }> = {}
const subjectOf = (key: string) => {
  const [name, id] = key.split(':', 2) as [string, string | undefined]
  const check = id === undefined ? undefined : scheduleSubjects[name]
  return check ? check(id!) : { gone: false }
}

const KEY_RE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+(:[A-Za-z0-9._-]{1,96})?$/
/** A subject whose schedule has narrower limits than its owner's (core/schedule Owner.LimitsOf): a source that asks for fewer requests. */
const SUBJECT_LIMITS: Record<string, Partial<Limits>> = {
  'feeds.source:spamhaus-drop': { min_every_minutes: 1440, reason: 'Spamhaus DROP asks for at most one download every 24 hours.' },
}
function ownerOf(key: string): Owner | null {
  if (!KEY_RE.test(key)) return null
  const [name, subject] = key.split(':', 2) as [string, string | undefined]
  const o = OWNERS[name]
  if (!o || o.perSubject !== (subject !== undefined)) return null
  return SUBJECT_LIMITS[key] ? { ...o, limits: { ...o.limits, ...SUBJECT_LIMITS[key] } } : o
}
const limitsOf = (o: Owner): Limits => ({ freqs: o.limits.freqs ?? FREQS, min_every_minutes: o.limits.min_every_minutes ?? 1, max_every_minutes: o.limits.max_every_minutes ?? 527040, windows: o.limits.windows ?? WINDOWS, reason: o.limits.reason ?? '' })

// ---- time in a zone (approximate: the offset at the instant) ----
const orgZone = () => orgStore.get().timezone || 'Asia/Ho_Chi_Minh'
function wall(t: number, tz: string) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short' })
    .formatToParts(new Date(t)).map((x) => [x.type, x.value]))
  const wd = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(p.weekday!) + 1
  return { y: +p.year!, m: +p.month!, d: +p.day!, min: +p.hour! * 60 + +p.minute!, wd }
}
function localAt(y: number, m: number, d: number, min: number, tz: string) {
  const naive = Date.UTC(y, m - 1, d, Math.floor(min / 60), min % 60)
  const off = (t: number) => { const w = wall(t, tz); return Date.UTC(w.y, w.m - 1, w.d, Math.floor(w.min / 60), w.min % 60) - Math.floor(t / 60000) * 60000 }
  return naive - off(naive - off(naive))
}
const hm = (s: string | null) => (s ? +s.slice(0, 2) * 60 + +s.slice(3) : 0)
function day(t: number, tz: string, plus: number) { const w = wall(t, tz); const u = new Date(Date.UTC(w.y, w.m - 1, w.d + plus)); return { y: u.getUTCFullYear(), m: u.getUTCMonth() + 1, d: u.getUTCDate(), wd: ((u.getUTCDay() + 6) % 7) + 1 } }

function windowOpen(r: Rule, t: number, tz: string): number {
  if (r.window !== 'custom' || !r.window_days || !r.window_from || !r.window_to) return t
  const from = hm(r.window_from), to = hm(r.window_to)
  for (let i = -1; i <= 8; i++) {
    const dd = day(t, tz, i)
    if (!r.window_days.includes(dd.wd)) continue
    const s = localAt(dd.y, dd.m, dd.d, from, tz)
    const e = to > from ? localAt(dd.y, dd.m, dd.d, to, tz) : localAt(dd.y, dd.m, dd.d + 1, to, tz)
    if (t >= s && t < e) return t
    if (s > t) return s
  }
  return t
}

/** When a rule next comes due after `after` (ms); null when never. */
function next(r: Rule, after: number): number | null {
  const tz = orgZone()
  const at = hm(r.at_time)
  let t: number | null = null
  const firstDay = (ok: (wd: number) => boolean) => {
    for (let i = 0; i <= 8; i++) { const dd = day(after, tz, i); if (!ok(dd.wd)) continue; const c = localAt(dd.y, dd.m, dd.d, at, tz); if (c > after) return c }
    return null
  }
  switch (r.freq) {
    case 'interval':
      // every N days at a time: the first such time at least N-1 days on (every 1 day is daily)
      if (r.at_time && r.every_minutes && r.every_minutes % 1440 === 0) { const n = r.every_minutes / 1440 - 1 + (at <= wall(after, tz).min ? 1 : 0); const dd = day(after, tz, n); t = localAt(dd.y, dd.m, dd.d, at, tz) } else t = after + (r.every_minutes ?? 60) * 60000
      break
    case 'daily': t = firstDay(() => true); break
    case 'weekly': t = firstDay((wd) => (r.weekdays ?? []).includes(wd)); break
    case 'monthly':
      for (let i = 0; i <= 2 && t === null; i++) {
        const w = wall(after, tz); const first = new Date(Date.UTC(w.y, w.m - 1 + i, 1)); const last = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 0)).getUTCDate()
        const dd = !r.month_day || r.month_day > last ? last : r.month_day
        const c = localAt(first.getUTCFullYear(), first.getUTCMonth() + 1, dd, at, tz); if (c > after) t = c
      }
      break
    case 'once': t = r.once_at && Date.parse(r.once_at) > after ? Date.parse(r.once_at) : null
  }
  if (t === null) return null
  const open = windowOpen(r, t, tz)
  if (open === t || (r.freq === 'interval' && !r.at_time)) return open
  // moved to the window's opening: a regular time in that opening runs instead, so one opening never starts the work twice
  const regular = next({ ...r, window: 'none' }, open - 1)
  return regular !== null && windowOpen(r, regular, tz) === regular && regular - open < 24 * 36e5 ? regular : open
}

/** The scan window of Settings › Scanning › Safety, in the organization's zone. */
function scanWindowOpen(t: number): number {
  const a = inventorySettingsStore.get().active
  return windowOpen({ ...base, window: 'custom', window_days: a.days, window_from: a.from, window_to: a.to }, t, orgZone())
}

function upcoming(r: Rule, first: number | null, now: number): string[] {
  const out: string[] = []
  for (let d = first; d !== null && out.length < 3;) {
    let start = Math.max(d, now)
    if (r.window === 'global') start = scanWindowOpen(start)
    out.push(new Date(start).toISOString())
    d = next(r, start - d > 120000 ? start : d)
  }
  return out
}

const ref = (s: Pick<Saved, 'last_due_at' | 'updated_at' | 'paused_until'>) => Math.max(...[s.last_due_at, s.updated_at, s.paused_until].filter((x): x is string => !!x).map(Date.parse))

function view(key: string, o: Owner): View {
  const saved = store.get()[key]
  const now = Date.now()
  const s: Saved = saved ?? { enabled: o.defaultOn, paused_until: null, rule: { ...base, ...o.rule }, last_due_at: null, last_run_id: null, last_skip_reason: null, last_skip_at: null, updated_by: '', updated_at: new Date(now).toISOString() }
  const due = s.enabled ? next(s.rule, ref(s)) : null
  const up = due === null ? [] : upcoming(s.rule, due, now)
  return {
    owner_key: key, module: o.module, saved: !!saved, enabled: s.enabled, paused_until: s.paused_until, rule: { ...s.rule, tz: 'org' }, zone: orgZone(),
    next_due_at: due === null ? null : new Date(due).toISOString(), upcoming: up,
    waiting_for: due !== null && due <= now && s.rule.window === 'global' && up[0] && Date.parse(up[0]) > now ? 'The scan window to open' : null,
    last_due_at: s.last_due_at, last_run_id: s.last_run_id, last_skip_reason: s.last_skip_reason, last_skip_at: s.last_skip_at,
    updated_by: saved ? s.updated_by : null, updated_at: saved ? s.updated_at : null, limits: limitsOf(o), edit_role: o.adminOnly ? 'admin' : 'operator',
  }
}

const HHMM = /^([01][0-9]|2[0-3]):[0-5][0-9]$/
const invalid = (field: string, message: string) => fail(400, 'invalid', message, { field })
/** The rule normalized, or the 400 the box answers. */
function check(raw: Partial<Rule> | undefined, o: Owner | null): Rule | Response {
  if (!raw || !FREQS.includes(raw.freq as Freq)) return invalid('freq', 'Choose how often: every N minutes, hours or days, daily, weekly, monthly or once.')
  const r: Rule = { ...base, freq: raw.freq!, tz: 'org', window: raw.window || 'none' }
  const needAt = r.freq === 'daily' || r.freq === 'weekly' || r.freq === 'monthly' || (r.freq === 'interval' && raw.at_time)
  if (needAt) {
    if (!raw.at_time) return invalid('at_time', 'Choose the time of day.')
    if (!HHMM.test(raw.at_time)) return invalid('at_time', 'The time of day is HH:MM, from 00:00 to 23:59.')
    r.at_time = raw.at_time
  }
  if (r.freq === 'interval') {
    const n = raw.every_minutes
    if (!Number.isInteger(n) || n! < 1 || n! > 527040) return invalid('every_minutes', 'The interval is 1 minute to 366 days.')
    if (raw.at_time && n! % 1440 !== 0) return invalid('at_time', 'A time of day goes with an interval of whole days only.')
    r.every_minutes = n!
  }
  if (r.freq === 'weekly') {
    const ds = [...new Set(raw.weekdays ?? [])].sort()
    if (!ds.length) return invalid('weekdays', 'Choose at least one day of the week.')
    r.weekdays = ds
  }
  if (r.freq === 'monthly') {
    if (!Number.isInteger(raw.month_day) || raw.month_day! < 0 || raw.month_day! > 31) return invalid('month_day', 'The day of the month is 1 to 31, or the last day.')
    r.month_day = raw.month_day!
  }
  if (r.freq === 'once') {
    if (!raw.once_at || Number.isNaN(Date.parse(raw.once_at))) return invalid('once_at', 'Choose the date and time.')
    if (Date.parse(raw.once_at) <= Date.now()) return invalid('once_at', 'Choose a date and time in the future.')
    r.once_at = new Date(raw.once_at).toISOString()
  }
  if (!WINDOWS.includes(r.window)) return invalid('window', 'The window is the scan window, none, or its own days and hours.')
  if (r.window === 'custom') {
    const ds = [...new Set(raw.window_days ?? [])].sort()
    if (!ds.length) return invalid('window_days', 'Choose at least one day of the week.')
    if (!raw.window_from || !HHMM.test(raw.window_from)) return invalid('window_from', 'The window opens at HH:MM, from 00:00 to 23:59.')
    if (!raw.window_to || !HHMM.test(raw.window_to)) return invalid('window_to', 'The window closes at HH:MM, from 00:00 to 23:59.')
    Object.assign(r, { window_days: ds, window_from: raw.window_from, window_to: raw.window_to })
  }
  if (o) {
    const l = limitsOf(o)
    const why = l.reason ? ` ${l.reason}` : ''
    if (!l.freqs.includes(r.freq)) return invalid('freq', `This schedule can only be ${l.freqs.join(' or ')}.${why}`)
    if (r.freq === 'interval' && r.every_minutes! < l.min_every_minutes) return invalid('every_minutes', `The interval is at least ${span(l.min_every_minutes)}.${why}`)
    if (r.freq === 'interval' && r.every_minutes! > l.max_every_minutes) return invalid('every_minutes', `The interval is at most ${span(l.max_every_minutes)}.${why}`)
    if (!l.windows.includes(r.window)) return invalid('window', `This schedule cannot use that window.${why}`)
  }
  return r
}
const span = (m: number) => { const u = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`; return m % 1440 === 0 ? u(m / 1440, 'day') : m % 60 === 0 ? u(m / 60, 'hour') : u(m, 'minute') }
const editDenied = (o: Owner) => (o.adminOnly && currentUser()?.role !== 'admin' ? fail(403, 'forbidden', 'Your account is not allowed to do this.') : null)
const keyOf = (p: Readonly<Record<string, string | readonly string[] | undefined>>) => decodeURIComponent(String(p.owner_key))
const notFound = () => fail(404, 'not_found', 'This item no longer exists.')

export const schedulesHandlers = [
  http.post(`${API}/schedules/preview`, async ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const b = await body<{ owner_key: string; rule: Rule; paused_until: string | null }>(request)
    const o = b.owner_key ? ownerOf(b.owner_key) : null
    if (b.owner_key && !o) return notFound()
    const r = check(b.rule, o); if (r instanceof Response) return r
    const now = Date.now()
    const first = next(r, Math.max(now, b.paused_until ? Date.parse(b.paused_until) : 0))
    return HttpResponse.json({ zone: orgZone(), upcoming: first === null ? [] : upcoming(r, first, now) })
  }),
  http.get(`${API}/schedules/:owner_key`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const key = keyOf(params); const o = ownerOf(key)
    return o && !subjectOf(key).gone ? HttpResponse.json(view(key, o)) : notFound()
  }),
  http.put(`${API}/schedules/:owner_key`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const key = keyOf(params); const o = ownerOf(key); if (!o || subjectOf(key).gone) return notFound()
    const forbidden = editDenied(o); if (forbidden) return forbidden
    const b = await body<{ enabled: boolean; paused_until: string | null; rule: Rule }>(request)
    const r = check(b.rule, o); if (r instanceof Response) return r
    const old = store.get()[key]
    const paused = b.paused_until && Date.parse(b.paused_until) > Date.now() ? new Date(b.paused_until).toISOString() : null
    store.update((all) => ({ ...all, [key]: { last_due_at: null, last_run_id: null, last_skip_reason: null, last_skip_at: null, ...old, enabled: !!b.enabled, paused_until: paused, rule: r, updated_by: currentUser()?.email ?? 'admin@acme.example', updated_at: nowIso() } }))
    audit('schedule.save', key, b.enabled ? r.freq : 'off')
    return HttpResponse.json(view(key, o))
  }),
  http.post(`${API}/schedules/:owner_key/run`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const key = keyOf(params); const o = ownerOf(key); if (!o || subjectOf(key).gone) return notFound()
    const forbidden = editDenied(o); if (forbidden) return forbidden
    const refuse = subjectOf(key).refuse
    if (refuse) return fail(409, 'not_started', refuse)
    const runId = o.module === 'feeds' || key === 'exposure.public_ip' || key === 'agent-intake.wazuh' ? null : 'run-m1'
    if (store.get()[key] && runId) store.update((all) => ({ ...all, [key]: { ...all[key]!, last_run_id: runId } }))
    audit('schedule.run_now', key, runId ?? '')
    return HttpResponse.json({ run_id: runId })
  }),
]
