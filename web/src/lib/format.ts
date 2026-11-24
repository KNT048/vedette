// One date format in the whole app: "12 Nov 2026" and "12 Nov 2026, 20:51"; 12/11/2026 reads as 11 December to half the readers.
// English only, so the format is fixed.
// One time zone too: every moment is written in the organization's time zone (Settings › General), the zone the box writes its own
// sentences, alerts and emails in, so one moment reads as the same day on every page and in every message. A calendar day sent as
// YYYY-MM-DD (a CVE's published day, a deadline, a day the box already put in that zone) is written as it is, never moved by a zone.
const loc = () => 'en-GB'
let zone: string | undefined

/** Sets the organization's time zone (RequireSession, from GET /core/general); empty or a name this browser does not know: the
 *  browser's own zone. */
export function setDisplayTimeZone(z: string | null | undefined) {
  zone = undefined
  formatters.clear()
  if (!z) return
  try {
    new Intl.DateTimeFormat(loc(), { timeZone: z })
    zone = z
  } catch {
    // an unknown name: the browser's zone
  }
}
/** The zone dates are written in now; undefined is the browser's. */
export const displayTimeZone = () => zone

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/
// A formatter is costly to build and a table formats thousands of cells: one per zone and options, dropped when the zone changes.
const formatters = new Map<string, Intl.DateTimeFormat>()
function formatter(o: Intl.DateTimeFormatOptions) {
  const key = JSON.stringify(o)
  let f = formatters.get(key)
  if (!f) formatters.set(key, (f = new Intl.DateTimeFormat(loc(), o)))
  return f
}
const inZone = (o: Intl.DateTimeFormatOptions) => (zone ? { ...o, timeZone: zone } : o)
/** A calendar day is written in UTC from its own numbers; a moment in the organization's zone (the browser's while none is set). */
function write(iso: string, o: Intl.DateTimeFormatOptions) {
  const m = iso.match(DAY)
  if (m) return formatter({ ...o, timeZone: 'UTC' }).format(new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))))
  return formatter(inZone(o)).format(new Date(iso))
}
const DATE: Intl.DateTimeFormatOptions = { day: 'numeric', month: 'short', year: 'numeric' }
const CLOCK: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' }

/** "12 Nov 2026" */
export function fmtDate(iso: string | null | undefined) {
  return iso ? write(iso, DATE) : '–'
}
/** The last day of a period that runs up to `to` without it, for fmtDate: one that ends at midnight (a calendar month, a scheduled
 *  week) ends on the day before. */
export function fmtPeriodEnd(to: string) {
  return fmtDate(new Date(Date.parse(to) - 1).toISOString())
}
/** "12 Nov 2026, 20:51" */
export function fmtDateTime(iso: string | null | undefined) {
  return iso ? write(iso, { ...DATE, ...CLOCK }) : '–'
}
/** "12 Nov 2026, 20:51 GMT+7": a moment with its zone named, for a page outside the signed-in app (an approval link), where the
 *  organization's zone is not known and the reader's browser may be in another. */
export function fmtDateTimeZone(iso: string | null | undefined) {
  return iso ? write(iso, { ...DATE, ...CLOCK, timeZoneName: 'short' }) : '–'
}
/** The time of day only, "14:03" (with seconds, "14:03:09"), for something that happened minutes ago. */
export function fmtTime(iso: string | null | undefined, seconds = false) {
  return iso ? write(iso, seconds ? { ...CLOCK, second: '2-digit' } : CLOCK) : '–'
}
/** "12 Nov", a day of a chart of the last weeks. */
export function fmtDayMonth(iso: string | null | undefined) {
  return iso ? write(iso, { day: 'numeric', month: 'short' }) : '–'
}
/** "November 2026" */
export function fmtMonthYear(iso: string | null | undefined) {
  return iso ? write(iso, { month: 'long', year: 'numeric' }) : '–'
}
/** The organization's day of a moment, "2026-11-15" (a calendar day stays as it is). */
export function dayOf(iso: string) {
  if (DAY.test(iso)) return iso
  const parts = formatter(inZone({ year: 'numeric', month: '2-digit', day: '2-digit' })).formatToParts(new Date(iso))
  const part = (t: Intl.DateTimeFormatPartTypes) => parts.find((p) => p.type === t)?.value ?? ''
  return `${part('year')}-${part('month')}-${part('day')}`
}
/** A moment as short as it can be: "10:54" on the organization's today, else "13 Nov 2026, 10:54". `now` comes from a clock that
 *  ticks past midnight. */
export function fmtWhen(iso: string | null | undefined, now = new Date()) {
  if (!iso) return '–'
  return dayOf(iso) === dayOf(now.toISOString()) ? fmtTime(iso) : fmtDateTime(iso)
}
/** The end of something that started at start: "22:43" on the same day, else "18 Nov 2026, 00:12". */
export function fmtEnd(start: string | null | undefined, end: string | null | undefined) {
  if (!end) return '–'
  return start && fmtDate(start) === fmtDate(end) ? fmtTime(end) : fmtDateTime(end)
}
/** The server sends Go's zero time (0001-01-01) for "never happened". */
export function isNever(iso: string | null | undefined) {
  return !iso || new Date(iso).getUTCFullYear() < 1971
}
export function fmtRelative(iso: string | null | undefined, now = Date.now()) {
  if (!iso) return '–'
  const diff = (new Date(iso).getTime() - now) / 1000
  const rtf = new Intl.RelativeTimeFormat(loc(), { numeric: 'auto' })
  const abs = Math.abs(diff)
  if (abs < 60) return rtf.format(Math.round(diff), 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  return rtf.format(Math.round(diff / 86400), 'day')
}
export function fmtNumber(n: number | null | undefined) {
  if (n === null || n === undefined) return '–'
  return new Intl.NumberFormat(loc()).format(n)
}
export function fmtPercent(n: number | null | undefined, digits = 1) {
  if (n === null || n === undefined) return '–'
  return new Intl.NumberFormat(loc(), { style: 'percent', maximumFractionDigits: digits }).format(n)
}
/** The small "vendor product" line under a product's display name, or null when it only repeats that name ("OpenBSD OpenSSH / OpenBSD OpenSSH"). */
export function rawProductLine(display: string, vendor: string, product: string) {
  const raw = `${vendor} ${product}`.trim()
  return raw && raw.toLowerCase() !== display.trim().toLowerCase() ? raw : null
}

/** "Sun 23 Nov 2026, 23:00": a moment on the wall clock of a given IANA zone (a schedule is read in its own zone). */
export function fmtWeekdayDateTimeIn(iso: string, timeZone: string) {
  return formatter({ timeZone, weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date(iso))
}

/** The wall clock (year, month, day, hour, minute) of an instant in a given IANA zone. */
export function wallIn(t: number, timeZone: string) {
  const p = Object.fromEntries(formatter({ timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    .formatToParts(new Date(t)).map((x) => [x.type, x.value]))
  return { y: Number(p.year), m: Number(p.month), d: Number(p.day), h: Number(p.hour), min: Number(p.minute) }
}

/** The weekday (1 = Monday … 7 = Sunday) and the minutes since midnight of a moment in a given IANA zone (a window is read in its own
 *  zone); null for a zone this browser does not know. */
export function clockIn(at: Date, timeZone: string): { weekday: number; minutes: number } | null {
  try {
    const parts = formatter({ timeZone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(at)
    const part = (t: Intl.DateTimeFormatPartTypes) => parts.find((p) => p.type === t)?.value ?? ''
    const weekday = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(part('weekday')) + 1
    return weekday === 0 ? null : { weekday, minutes: Number(part('hour')) * 60 + Number(part('minute')) }
  } catch {
    return null
  }
}
