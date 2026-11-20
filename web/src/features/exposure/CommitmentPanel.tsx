import { Panel } from '@/components/common/PageHeader'
import { useTranslation } from 'react-i18next'
import { InfoLine } from './InfoLine'
import type { Consent } from './types'
import { fmtDateTime } from '@/lib/format'

/** The scan confirmation record, written by an administrator's first Scan now: who, when and the exact sentence that was shown. Nothing to tick here. */
export function CommitmentPanel({ consent: c }: { consent: Consent }) {
  const { t } = useTranslation('exposure')
  return (
    <Panel className="grid gap-2 p-4 text-sm">
      <p>{t('commit.doneBody', { user: c.by, time: fmtDateTime(c.at) })}</p>
      {c.text ? <p className="text-meta text-muted"><span className="font-medium">{t('commit.sentence')}</span> {c.text}</p> : <InfoLine className="text-meta text-muted" topic={t('step.commit')} info={t('commit.olderInfo')}>{t('commit.older')}</InfoLine>}
    </Panel>
  )
}
