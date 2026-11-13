import { useTranslation } from 'react-i18next'
import { Chip, SeverityChip } from '@/components/common/StatusChip'
import type { Finding } from '@/lib/types'
import { unverified } from './basis'

/**
 * Mức nghiêm trọng kèm độ chắc chắn (D-484, như Qualys "potential" vàng cạnh "confirmed" đỏ): phát hiện chỉ khớp tên sản phẩm
 * hiện mức nghiêm trọng mờ kèm "unverified", không cùng khối đỏ với phát hiện đã xác nhận.
 */
export function RiskChip({ f }: { f: Pick<Finding, 'basis' | 'severity'> }) {
  const { t } = useTranslation('findings')
  if (!unverified(f)) return <SeverityChip severity={f.severity} />
  return <Chip tone="off" title={t('risk.unverifiedHint')}>{t('risk.unverifiedChip', { severity: t(`common:severity.${f.severity}`) })}</Chip>
}
