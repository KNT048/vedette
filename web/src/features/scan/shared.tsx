import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { RunResultKind, ScanRun } from './types'

export function RunStatusChip({ run }: { run: ScanRun }) {
  const { t } = useTranslation('scan')
  const tone = run.status === 'done' ? 'ok' : run.status === 'auto_stopped' ? 'warn' : run.status === 'running' || run.status === 'stopping' ? 'accent' : 'off'
  return <Chip tone={tone}>{t(`runStatus.${run.status}`)}</Chip>
}

// not_matched is neutral, not green: nuclei reports matches only, so it means "no match reported", not "safe" (D-133 (5)).
const resultTone: Record<RunResultKind, 'danger' | 'ok' | 'off' | 'warn'> = { matched: 'danger', not_matched: 'off', not_applicable: 'off', no_template: 'warn', no_response: 'warn', skipped: 'off' }
export function ResultChip({ kind }: { kind: RunResultKind }) {
  const { t } = useTranslation('scan')
  return <Chip tone={resultTone[kind]}>{t(`result.${kind}`)}</Chip>
}

const OUTCOME_ORDER: RunResultKind[] = ['matched', 'no_template', 'not_matched', 'no_response', 'not_applicable', 'skipped']
type T = (key: string, opts?: Record<string, unknown>) => string

/**
 * kien G7a: what a run found, in words, from its stored results: "Checked 3 CVEs: 1 confirmed, 2 no check exists (still
 * suspected)". Never "0 matches" when nothing could be checked; a stopped run says why first; a run that only identified devices
 * says how many were identified.
 */
export function runOutcome(r: ScanRun, t: T): string {
  if (r.status === 'running' || r.status === 'stopping') return t('outcome.running')
  const devices = new Set(r.results.map((x) => x.target_id)).size
  let body: string
  if (r.results.length) {
    const parts = OUTCOME_ORDER.map((k) => [k, r.results.filter((x) => x.result === k).length] as const).filter(([, n]) => n > 0).map(([k, n]) => t(`outcome.part.${k}`, { count: n }))
    body = `${t(devices > 1 ? 'outcome.checkedOn' : 'outcome.checked', { count: r.results.length, devices })}: ${parts.join(', ')}`
  } else if (r.identification.length) {
    body = t('outcome.identifiedOnly', { count: r.identification.length, ok: r.identification.filter((i) => !i.reason).length })
  } else body = t('outcome.nothing')
  if (r.status === 'stopped' || r.status === 'auto_stopped') return `${t('outcome.stopped', { reason: (r.stop_reason ?? t(`runStatus.${r.status}`)).replace(/\.$/, '') })} ${body}`
  return body
}
