import { clockIn, dayOf, fmtDayMonth, fmtTime } from '@/lib/format'
import { inRanges } from './AddToScopeDialog'

/** The scan window as GET /scanning gives it (safety.window, scope and the discovery engine's next opening). */
export type FirstCheckInput = {
  /** The device's address. */
  ip: string
  /** safety.window */
  window: { days: number[]; from: string; to: string; time_zone: string }
  /** safety.scope */
  scope: { lan_ranges: string[]; confirmed_at: string | null }
  /** The discovery engine: on or off, and the next time a window opens (null: none). */
  discovery: { enabled: boolean; next_run_at: string | null } | null
  now: Date
}

export type FirstCheck =
  | { when: 'now' }
  | { when: 'tonight' | 'today' | 'tomorrow'; time: string }
  | { when: 'day'; day: string; time: string }
  | { when: 'next' }
  | { when: 'waiting'; why: 'off' | 'scope' | 'outside' }

const minutesOf = (hhmm: string) => { const [h, m] = hhmm.split(':').map(Number); return (h ?? 0) * 60 + (m ?? 0) }

/** Whether a scan window is open at `now`, read in the window's own time zone (as the box reads it: a window that crosses midnight
 *  belongs to the day it starts on). */
export function windowOpen(w: FirstCheckInput['window'], now: Date): boolean {
  const from = minutesOf(w.from), to = minutesOf(w.to)
  if (from === to) return false
  const c = clockIn(now, w.time_zone)
  if (!c) return false
  const wd = c.weekday, at = c.minutes
  const has = (d: number) => w.days.includes(((d + 6) % 7) + 1)
  if (has(wd) && at >= from && (to > from ? at < to : true)) return true
  return to < from && has(wd - 1) && at < to
}

/** What will happen to a device whose network scan is on and that no check has reached yet (INV-27 of sensor-active): its first
 *  check is the next scan window's, or runs now when the window is open. Never "not set up". */
export function firstCheck(i: FirstCheckInput): FirstCheck {
  if (i.discovery && !i.discovery.enabled) return { when: 'waiting', why: 'off' }
  if (!i.scope.confirmed_at) return { when: 'waiting', why: 'scope' }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(i.ip) && !inRanges(i.ip, i.scope.lan_ranges)) return { when: 'waiting', why: 'outside' }
  if (windowOpen(i.window, i.now)) return { when: 'now' }
  const next = i.discovery?.next_run_at
  if (!next) return { when: 'next' }
  const time = fmtTime(next)
  // calendar days in the organization's zone, never now + 24 h (a day of a clock change is 23 or 25 hours)
  const today = dayOf(i.now.toISOString()), day = dayOf(next)
  if (day === today) return { when: Number(time.slice(0, 2)) >= EVENING ? 'tonight' : 'today', time }
  const [y, m, d] = today.split('-').map(Number)
  if (day === new Date(Date.UTC(y!, m! - 1, d! + 1)).toISOString().slice(0, 10)) return { when: 'tomorrow', time }
  return { when: 'day', day: fmtDayMonth(next), time }
}

/** An opening from this hour on is "tonight"; an earlier one the same day is "today". */
const EVENING = 18
