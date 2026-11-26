/** Where one run opens: its own page, whatever engine runs it. Its breadcrumb and menu follow what the run is about (an exposure target,
 *  a device); a link from Settings › Scanning says so (`from`), and the page then leads back there. */
export const runHref = (id: string, from?: 'settings') => `/runs/${encodeURIComponent(id)}${from ? `?from=${from}` : ''}`

/** Where a run's page belongs, for its breadcrumb and the menu: the exposure target or the device it is about, or Settings › Scanning
 *  for a run opened from there (`from`), and for a run about no one subject (a LAN sweep). It reads only the run, so a link pasted
 *  elsewhere leads back to the same place. */
export type RunPlace = { kind: 'target' | 'device'; id: string; label: string } | { kind: 'settings' }
export function runPlace(subject: { kind: string; id: string; label: string } | null, from: string | null): RunPlace {
  if (from === 'settings' || !subject) return { kind: 'settings' }
  if (subject.kind === 'target' || subject.kind === 'device') return { kind: subject.kind, id: subject.id, label: subject.label }
  return { kind: 'settings' }
}

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
