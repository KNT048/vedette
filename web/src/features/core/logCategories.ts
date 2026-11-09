// Log categories of "Download all logs" (S-CORE-6, D-48). Kept apart from logExport.ts, which is mock code
// (msw, mock stores): DataSection imports only this, so the production bundle carries no mock layer.
export const LOG_CATEGORIES = [
  { id: 'audit', key: 'core_audit' }, { id: 'ai_activity', key: 'ai_activity', chained: true }, { id: 'response', key: 'resp_log' },
  { id: 'scan_probes', key: 'scan_probes' }, { id: 'alerts', key: 'notify_alerts' }, { id: 'device_logs', key: 'logs_events' },
  { id: 'known_bad', key: 'logs_ioc_hits' }, { id: 'honeypot', key: 'hp_hits' },
] as const
export type LogCategory = (typeof LOG_CATEGORIES)[number]['id']
