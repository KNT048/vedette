// English words of the progress component (#830). A flat object in the i18next shape ({{name}} placeholders, _one/_other plurals) so the
// wiring PR can move it as is to src/locales/en/progress.json and swap `say` for t(). Kept here until #824 part 2 frees the locale files.
import type { JobProgress } from '@/lib/progress'

export const PROGRESS_STRINGS_EN = {
  'phase.discovery': 'Finding the device',
  'phase.ports': 'Checking open ports',
  'phase.services': 'Identifying services',
  'phase.scripts': 'Reading service details',
  'phase.vulns': 'Checking for known vulnerabilities',
  'phase.web': 'Checking the web pages',
  'phase.openvas': 'OpenVAS deep scan',
  'phase.saving': 'Saving the results',
  starting: 'Starting',
  percent: '{{percent}}%',
  'count.checks_one': '{{done}} of {{total}} check',
  'count.checks_other': '{{done}} of {{total}} checks',
  'count.hosts_one': '{{done}} of {{total}} address',
  'count.hosts_other': '{{done}} of {{total}} addresses',
  count: '{{done}} of {{total}}',
  elapsed: '{{time}} elapsed',
  left: 'about {{time}} left in this step',
  leftSoon: 'less than a minute left in this step',
  quiet: 'Last report {{time}} ago',
  quietHelp: 'The scanner reports at most every 5 seconds, and some checks report nothing until they finish. A quiet scanner is still working; Stop ends it at any time.',
  quietTopic: 'quiet scanner',
  'time.s': '{{s}} s',
  'time.ms': '{{m}} min {{s}} s',
  'time.m': '{{m}} min',
  'time.hm': '{{h}} h {{m}} min',
} as const

export type ProgressStrings = { [K in keyof typeof PROGRESS_STRINGS_EN]: string }
export type ProgressPhase = JobProgress['phase']

const plural = new Intl.PluralRules('en')

/** Fills {{name}} placeholders; with `count`, picks key_one / key_other when the plural keys exist (i18next's rule). */
export function say(s: ProgressStrings, key: string, vars: Record<string, string | number> = {}, count?: number): string {
  const all = s as Record<string, string>
  const k = count !== undefined && all[`${key}_${plural.select(count)}`] !== undefined ? `${key}_${plural.select(count)}` : key
  return (all[k] ?? k).replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(vars[name] ?? ''))
}

/** A duration in the words of the component: "45 s", "2 min 10 s", "12 min", "1 h 5 min". Seconds are dropped from 10 minutes on. */
export function sayDuration(s: ProgressStrings, ms: number): string {
  const sec = Math.max(0, Math.floor(ms / 1000))
  if (sec < 60) return say(s, 'time.s', { s: sec })
  const m = Math.floor(sec / 60)
  if (m < 10) return sec % 60 ? say(s, 'time.ms', { m, s: sec % 60 }) : say(s, 'time.m', { m })
  if (m < 60) return say(s, 'time.m', { m })
  return say(s, 'time.hm', { h: Math.floor(m / 60), m: m % 60 })
}
