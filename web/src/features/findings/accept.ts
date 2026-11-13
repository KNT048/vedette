// Days of "Accept risk until…" (D-498, S-MIT-1), on the person's own calendar.
import { MAX_ACCEPT_DAYS } from './contract'

/** 'YYYY-MM-DD' of the day `days` after `from`, on the person's own calendar. */
export function dayAfter(from: Date, days: number): string {
  const d = new Date(from.getFullYear(), from.getMonth(), from.getDate() + days)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

/** The first and the last day a risk can be accepted until: tomorrow and a year from today (D-498). */
export const untilBounds = (today = new Date()) => ({ min: dayAfter(today, 1), max: dayAfter(today, MAX_ACCEPT_DAYS) })

/** Whether `until` is a day the box takes (the dialog checks before sending; the API says bad_until otherwise). */
export function untilOk(until: string, today = new Date()) {
  const { min, max } = untilBounds(today)
  return /^\d{4}-\d{2}-\d{2}$/.test(until) && until >= min && until <= max
}
