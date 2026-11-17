// Dates of the feeds screens as "9 Nov 2026": the shared formatter (lib/format) writes 09/11/2026, which reads as 11 September
// to half the readers. The product is English only (D-28), so the format is fixed.
const day = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })
const stamp = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

/** A date as the feeds send it (YYYY-MM-DD, or a timestamp read as its UTC day). */
export const fmtDay = (iso: string | null | undefined) => (iso ? day.format(new Date(iso)) : '–')
/** A moment in the reader's time zone. */
export const fmtStamp = (iso: string | null | undefined) => (iso ? stamp.format(new Date(iso)) : '–')
const clock = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' })
/** A moment in the reader's time zone, as short as it can be: "10:54" today, else "13 Nov 2026, 10:54" (kien G11). */
export function fmtWhen(iso: string | null | undefined, now = new Date()) {
  if (!iso) return '–'
  const d = new Date(iso)
  return d.toDateString() === now.toDateString() ? clock.format(d) : stamp.format(d)
}
