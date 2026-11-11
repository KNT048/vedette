// Log categories of "Download all logs" (S-CORE-6, D-48). Kept apart from logExport.ts, which is mock code
// (msw, mock stores): DataSection imports only this, so the production bundle carries no mock layer.
export const LOG_CATEGORIES = [
  { id: 'audit', key: 'core_audit', chained: true }, { id: 'ai_activity', key: 'ai_activity', chained: true }, { id: 'response', key: 'resp_log', chained: true },
  { id: 'scan_probes', key: 'scan_probes' }, { id: 'alerts', key: 'notify_alerts' }, { id: 'device_logs', key: 'logs_events' },
  { id: 'known_bad', key: 'logs_ioc_hits' }, { id: 'honeypot', key: 'hp_hits' },
] as const
export type LogCategory = (typeof LOG_CATEGORIES)[number]['id']

/** Query string of GET /core/logs/export. `from` and `to` are the days picked in the date inputs, sent as they are (YYYY-MM-DD): the
 * box reads them as whole days of the organization's time zone (D-132), so the browser's own zone must not move them. */
export function logsExportQuery(cats: readonly string[], format: 'json' | 'csv', from: string, to: string): string {
  const q = new URLSearchParams({ categories: cats.join(','), format })
  if (from) q.set('from', from)
  if (to) q.set('to', to)
  return q.toString()
}
