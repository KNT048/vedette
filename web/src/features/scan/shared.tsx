import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { RunResultKind, ScanRun } from './types'

export function RunStatusChip({ run }: { run: ScanRun }) {
  const { t } = useTranslation('scan')
  const tone = run.status === 'done' ? 'ok' : run.status === 'auto_stopped' ? 'warn' : run.status === 'running' || run.status === 'stopping' ? 'accent' : 'off'
  return <Chip tone={tone}>{t(`runStatus.${run.status}`)}</Chip>
}

const resultTone: Record<RunResultKind, 'danger' | 'ok' | 'off' | 'warn'> = { matched: 'danger', not_matched: 'ok', not_applicable: 'off', no_template: 'warn', no_response: 'warn', skipped: 'off' }
export function ResultChip({ kind }: { kind: RunResultKind }) {
  const { t } = useTranslation('scan')
  return <Chip tone={resultTone[kind]}>{t(`result.${kind}`)}</Chip>
}
