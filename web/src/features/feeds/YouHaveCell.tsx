import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { YouHave } from './types'

export function YouHaveCell({ value }: { value: YouHave | null }) {
  const { t } = useTranslation('feeds')
  if (value === null) return <span className="whitespace-nowrap text-[13px] text-muted">{t('youHave.off')}</span>
  if (value === 'yes') return <Chip tone="danger">{t('youHave.yes')}</Chip>
  if (value === 'maybe') return <Chip tone="warn" title={t('youHave.maybeHint')}>{t('youHave.maybe')}</Chip>
  return <span className="whitespace-nowrap text-[13px] text-muted">{t('youHave.no')}</span>
}
