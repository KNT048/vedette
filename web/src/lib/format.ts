const loc = () => 'en-GB'
/** 'YYYY-MM-DD' là ngày lịch, không có giờ: dựng theo giờ địa phương để không lùi một ngày ở múi giờ âm. */
const toDate = (s: string) => { const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/); return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : new Date(s) }

export function fmtDate(iso: string | null | undefined) {
  if (!iso) return '–'
  return new Intl.DateTimeFormat(loc(), { day: 'numeric', month: 'numeric', year: 'numeric' }).format(toDate(iso))
}
export function fmtDateTime(iso: string | null | undefined) {
  if (!iso) return '–'
  return new Intl.DateTimeFormat(loc(), { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'numeric', year: 'numeric' }).format(new Date(iso))
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
