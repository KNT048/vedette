import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { dateText, dateTimeText } from './dates'
import { InfoLine } from './InfoLine'
import type { PortRow } from './types'

/** INV-22: a port kept from an earlier scan says why it is still listed. `at` is when the newest scan ran. */
export function PortMark({ p }: { p: Pick<PortRow, 'last_seen' | 'misses' | 'unchecked'> }) {
  const { t } = useTranslation('exposure')
  if (!p.last_seen) return null
  return (p.misses ?? 0) > 0 && !p.unchecked ? <Chip tone="off">{t('open.notSeen')}</Chip> : <Chip tone="off">{t('open.notChecked', { date: dateText(p.last_seen) })}</Chip>
}

export function PortMarkNote({ p, at }: { p: Pick<PortRow, 'last_seen' | 'misses' | 'unchecked'>; at: string | null }) {
  const { t } = useTranslation('exposure')
  if (!p.last_seen) return null
  const missed = (p.misses ?? 0) > 0 && !p.unchecked
  const text = missed ? t('open.notSeenNote', { date: dateText(p.last_seen), at: at ? dateTimeText(at) : '–' }) : t('open.notCheckedNote', { date: dateText(p.last_seen) })
  return <InfoLine className="text-caption text-muted" topic={missed ? t('open.notSeen') : t('open.notChecked', { date: dateText(p.last_seen) })} info={missed ? t('open.notSeenNoteInfo') : t('open.notCheckedNoteInfo')}>{text}</InfoLine>
}
