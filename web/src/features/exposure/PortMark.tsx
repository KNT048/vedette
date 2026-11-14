import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { dateText, dateTimeText } from './dates'
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
  const text = (p.misses ?? 0) > 0 && !p.unchecked ? t('open.notSeenNote', { date: dateText(p.last_seen), at: at ? dateTimeText(at) : '–' }) : t('open.notCheckedNote', { date: dateText(p.last_seen) })
  return <span className="text-[12px] text-muted">{text}</span>
}
