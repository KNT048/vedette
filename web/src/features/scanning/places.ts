/** Where one run opens: its own page, whatever engine runs it and wherever the link is. */
export const runHref = (id: string) => `/runs/${encodeURIComponent(id)}`

/** The Runs tab of Settings › Scanning, filtered (`runs.status`, `runs.device`: the list's keys in the URL). */
export function runsHref(filter: { status?: string; device?: string } = {}): string {
  const p = new URLSearchParams({ tab: 'runs' })
  if (filter.status) p.set('runs.status', filter.status)
  if (filter.device) p.set('runs.device', filter.device)
  return `/settings/scanning?${p}`
}

/** The link leads to the page being shown (same path and query): it is said as text there, not offered as a link. */
export function isHere(to: string, here: { pathname: string; search: string }): boolean {
  const u = new URL(to, `http://here${here.pathname}${here.search}`)
  const canon = (s: string) => [...new URLSearchParams(s)].map(([k, v]) => `${k}=${v}`).sort().join('&')
  return u.pathname === here.pathname && canon(u.search) === canon(here.search)
}
