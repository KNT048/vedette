// Pure helpers of the schedule editor: the form's values (a draft) to and from the contract's rule, the units an owner allows, a
// wall-clock time in a zone to an instant and back, and the one-line description of a rule. The box computes every due time itself
// (POST /schedules/preview); nothing here predicts one.
import type { TFunction } from 'i18next'
import type { Freq, Schedule, ScheduleLimits, ScheduleRule, ScheduleSave, WindowMode } from './types'
import { wallIn } from '@/lib/format'

export const DAYS = [1, 2, 3, 4, 5, 6, 7] as const
export type Unit = 'minutes' | 'hours' | 'days'
export const UNIT_MINUTES: Record<Unit, number> = { minutes: 1, hours: 60, days: 1440 }

/** What the form holds. Fields the frequency does not use keep their values, so switching back and forth loses nothing. */
export interface Draft {
  enabled: boolean
  freq: Freq
  every: string
  unit: Unit
  /** HH:MM; for an interval in days it may be '' (counted from the last start). */
  at: string
  weekdays: number[]
  /** 1 to 31, 0 = the last day of the month. */
  monthDay: number
  /** 'YYYY-MM-DDTHH:MM' read in the rule's zone. */
  onceAt: string
  tz: string
  window: WindowMode
  windowDays: number[]
  windowFrom: string
  windowTo: string
  /** 'YYYY-MM-DD' in the rule's zone: it starts again on that day; '' = not paused. */
  resumeOn: string
}

/** The zone a rule is read in: its own, or the organization's for "org". */
export const zoneOf = (tz: string, orgZone: string) => (tz === 'org' ? orgZone : tz)

const pad = (n: number) => String(n).padStart(2, '0')

const wall = wallIn

/** An instant as 'YYYY-MM-DDTHH:MM' on the wall clock of a zone (the value of a datetime-local input). */
export function isoToZoned(iso: string, tz: string): string {
  const w = wall(Date.parse(iso), tz)
  return `${w.y}-${pad(w.m)}-${pad(w.d)}T${pad(w.h)}:${pad(w.min)}`
}

/** 'YYYY-MM-DDTHH:MM' on the wall clock of a zone as an instant (ISO); null when it is not such a value. */
export function zonedToIso(local: string, tz: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(local)
  if (!m) return null
  const naive = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]))
  const offset = (t: number) => { const w = wall(t, tz); return Date.UTC(w.y, w.m - 1, w.d, w.h, w.min) - Math.floor(t / 60000) * 60000 }
  const t = naive - offset(naive - offset(naive))
  return Number.isNaN(t) ? null : new Date(t).toISOString()
}

/** The units an owner's interval limits leave: minutes only below an hour, days only when a day fits. */
export function unitsFor(l: ScheduleLimits): Unit[] {
  const out: Unit[] = []
  if (l.min_every_minutes < 60) out.push('minutes')
  if (l.max_every_minutes >= 60 && l.min_every_minutes < 1440) out.push('hours')
  if (l.max_every_minutes >= 1440) out.push('days')
  return out.length ? out : ['minutes']
}

/** A number of minutes in the largest unit it fills exactly, among the allowed ones. */
export function split(minutes: number, units: Unit[]): { every: number; unit: Unit } {
  for (const u of ['days', 'hours', 'minutes'] as const) if (units.includes(u) && minutes % UNIT_MINUTES[u] === 0) return { every: minutes / UNIT_MINUTES[u], unit: u }
  return { every: minutes, unit: 'minutes' }
}

export function toDraft(s: Schedule, orgZone: string, now = Date.now()): Draft {
  const r = s.rule
  const zone = zoneOf(r.tz, orgZone)
  const { every, unit } = split(r.every_minutes ?? Math.max(60, s.limits.min_every_minutes), unitsFor(s.limits))
  const tomorrow = isoToZoned(new Date(now + 864e5).toISOString(), zone).slice(0, 10)
  return {
    enabled: s.enabled, freq: r.freq, every: String(every), unit, at: r.at_time ?? (r.freq === 'interval' ? '' : '02:00'),
    weekdays: r.weekdays ?? [1], monthDay: r.month_day ?? 1,
    onceAt: r.once_at ? isoToZoned(r.once_at, zone) : `${tomorrow}T${r.at_time ?? '02:00'}`,
    tz: r.tz, window: r.window, windowDays: r.window_days ?? [1, 2, 3, 4, 5, 6, 7], windowFrom: r.window_from ?? '22:00', windowTo: r.window_to ?? '06:00',
    resumeOn: s.paused_until && Date.parse(s.paused_until) > now ? isoToZoned(s.paused_until, zone).slice(0, 10) : '',
  }
}

/** The rule the draft says, with the fields its frequency does not use set to null (as the box stores it). */
export function toRule(d: Draft, orgZone: string): ScheduleRule {
  const n = Number(d.every)
  const interval = d.freq === 'interval'
  return {
    freq: d.freq,
    every_minutes: interval ? (Number.isFinite(n) ? Math.round(n * UNIT_MINUTES[d.unit]) : 0) : null,
    at_time: interval ? (d.unit === 'days' && d.at ? d.at : null) : d.freq === 'once' ? null : d.at || null,
    weekdays: d.freq === 'weekly' ? [...d.weekdays].sort() : null,
    month_day: d.freq === 'monthly' ? d.monthDay : null,
    once_at: d.freq === 'once' ? zonedToIso(d.onceAt, zoneOf(d.tz, orgZone)) : null,
    tz: d.tz,
    window: d.window,
    window_days: d.window === 'custom' ? [...d.windowDays].sort() : null,
    window_from: d.window === 'custom' ? d.windowFrom : null,
    window_to: d.window === 'custom' ? d.windowTo : null,
  }
}

export function toSave(d: Draft, orgZone: string): ScheduleSave {
  return { enabled: d.enabled, paused_until: d.resumeOn ? zonedToIso(`${d.resumeOn}T00:00`, zoneOf(d.tz, orgZone)) : null, rule: toRule(d, orgZone) }
}

/** The days of a list in short names, a run of three or more as a range: "Mon–Fri", "Mon, Wed", "every day". */
export function daysText(days: number[], t: TFunction<'schedule'>): string {
  const ds = [...new Set(days)].sort()
  if (ds.length === 7) return t('days.every')
  const runs: number[][] = []
  for (const d of ds) { const last = runs.at(-1); if (last && last.at(-1) === d - 1) last.push(d); else runs.push([d]) }
  return runs.flatMap((r) => (r.length >= 3 ? [`${t(`days.short.${r[0]}`)}–${t(`days.short.${r.at(-1)}`)}`] : r.map((d) => t(`days.short.${d}`)))).join(', ')
}

/** One line for a rule: "Every 6 hours", "Weekly on Mon, Thu at 08:00, in the scan window". `when` writes a once rule's instant. */
export function describeRule(r: ScheduleRule, t: TFunction<'schedule'>, when: (iso: string) => string): string {
  let main: string
  switch (r.freq) {
    case 'interval': {
      const { every, unit } = split(r.every_minutes ?? 0, ['minutes', 'hours', 'days'])
      main = r.at_time ? t('describe.intervalAt', { count: every, at: r.at_time }) : t(`describe.interval.${unit}`, { count: every })
      break
    }
    case 'daily': main = t('describe.daily', { at: r.at_time }); break
    case 'weekly': main = t('describe.weekly', { days: daysText(r.weekdays ?? [], t), at: r.at_time }); break
    case 'monthly': main = r.month_day ? t('describe.monthly', { day: r.month_day, at: r.at_time }) : t('describe.monthlyLast', { at: r.at_time }); break
    case 'once': main = t('describe.once', { when: r.once_at ? when(r.once_at) : '–' })
  }
  const win = r.window === 'global' ? t('describe.window.global')
    : r.window === 'custom' ? t('describe.window.custom', { days: daysText(r.window_days ?? [], t), hours: r.window_from === r.window_to ? t('describe.allDay') : `${r.window_from}–${r.window_to}` }) : ''
  const zone = r.tz === 'org' ? '' : ` (${r.tz})`
  return `${main}${win ? `, ${win}` : ''}${zone}`
}

/** An interval the owner does not allow (0, below its minimum, above its maximum) is said in the form, in the same plain words for
 *  every value, before anything is asked of the box: the box's own answer to 0 names an API field. null when it is allowed or the
 *  rule is not an interval. */
export function intervalProblem(d: Draft, l: ScheduleLimits): { min: number } | { max: number } | null {
  if (d.freq !== 'interval') return null
  const n = Number(d.every)
  const minutes = Number.isFinite(n) ? Math.round(n * UNIT_MINUTES[d.unit]) : 0
  const min = Math.max(1, l.min_every_minutes)
  if (minutes < min) return { min }
  if (l.max_every_minutes > 0 && minutes > l.max_every_minutes) return { max: l.max_every_minutes }
  return null
}

/** "1 hour", "6 hours", "3 days". */
export function spanText(minutes: number, t: TFunction<'schedule'>): string {
  const { every, unit } = split(minutes, ['minutes', 'hours', 'days'])
  return `${every} ${t(`unit.${unit}`, { count: every })}`
}

/** The plain sentence for an interval the owner does not allow, with the owner's reason: "The interval is at least 1 hour. Sources ask
 *  clients not to poll more often." */
export function intervalText(p: { min: number } | { max: number }, l: ScheduleLimits, t: TFunction<'schedule'>): string {
  const main = 'min' in p ? t('limit.atLeast', { span: spanText(p.min, t) }) : t('limit.atMost', { span: spanText(p.max, t) })
  return l.reason ? `${main} ${l.reason}` : main
}

/** "02:30" of an instant in a zone. */
export function clockIn(iso: string, zone: string): string {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(iso))
  return `${parts.find((x) => x.type === 'hour')?.value ?? '00'}:${parts.find((x) => x.type === 'minute')?.value ?? '00'}`
}
