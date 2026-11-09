// One unambiguous date format for the whole exposure feature: "9 Nov 2026" and "9 Nov 2026, 21:01" (QA pass 2026-11-09).
// ponytail: feature-local until @/lib/format has a shared one (the feeds feature fixes the same mix of formats); then these two become imports.
// Times are in the time zone of the browser; the box's own messages (API) use the box time zone.
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const two = (n: number) => String(n).padStart(2, '0')

/** 'YYYY-MM-DD' is a calendar day without a time: build it in local time so it never moves by a day. */
function parse(s: string) {
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/)
  return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : new Date(s)
}

/** 9 Nov 2026 */
export function dateText(iso: string | null | undefined) {
  if (!iso) return '–'
  const d = parse(iso)
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`
}

/** 9 Nov 2026, 21:01 */
export function dateTimeText(iso: string | null | undefined) {
  if (!iso) return '–'
  const d = parse(iso)
  return `${dateText(iso)}, ${two(d.getHours())}:${two(d.getMinutes())}`
}
