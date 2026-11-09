import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import type { Target } from './types'

/** Ownership state in one chip: verified, IP expiring soon (days left), expired, or waiting. */
export function OwnerChip({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  if (target.status === 'unverified') return <Chip tone="warn">{t('status.unverified')}</Chip>
  if (target.status === 'expired') return <Chip tone="danger">{t('status.expired')}</Chip>
  if (target.validity === 'expiring' && target.expires_at) return <Chip tone="warn">{t('status.expiresIn', { count: Math.max(0, Math.ceil((Date.parse(target.expires_at) - Date.now()) / 864e5)) })}</Chip>
  return <Chip tone="ok">{t('status.verified')}</Chip>
}
