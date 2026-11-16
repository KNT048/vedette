import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import type { YouHave } from './types'

/** `noDevices`: the box knows no device but itself yet, so "No" would be a guess (first run, #825). */
export function YouHaveCell({ value, noDevices = false }: { value: YouHave | null; noDevices?: boolean }) {
  const { t } = useTranslation('feeds')
  if (value === null) return <span className="whitespace-nowrap text-meta text-muted">{t('youHave.off')}</span>
  if (value === 'yes') return <Chip tone="danger">{t('youHave.yes')}</Chip>
  // #824: the why is behind ⓘ (reachable by keyboard and touch), not a hover-only title.
  if (value === 'maybe') return <span className="flex items-center gap-1"><Chip tone="warn">{t('youHave.maybe')}</Chip><InfoTip topic={t('youHave.maybe')}>{t('youHave.maybeHint')}</InfoTip></span>
  return <span className="whitespace-nowrap text-meta text-muted">{t(noDevices ? 'youHave.noDevices' : 'youHave.no')}</span>
}
