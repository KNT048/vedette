import { Panel } from '@/components/common/PageHeader'
import { useTranslation } from 'react-i18next'
import { dateTimeText } from './dates'
import type { Target } from './types'

/** The record of D-26, written by an administrator's first Scan now (D-473): who, when and the exact sentence that was shown. Nothing to tick here. */
export function CommitmentPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const c = target.commitment
  if (!c) return null
  return (
    <Panel className="grid gap-2 p-4 text-sm">
      <p>{t('commit.doneBody', { user: c.by, time: dateTimeText(c.at) })}</p>
      {c.sentence ? <p className="text-[13px] text-muted"><span className="font-medium">{t('commit.sentence')}</span> {c.sentence}</p> : <p className="text-[13px] text-muted">{t('commit.older')}</p>}
    </Panel>
  )
}
