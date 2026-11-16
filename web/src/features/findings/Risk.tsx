import { useTranslation } from 'react-i18next'
import { Chip, SeverityChip } from '@/components/common/StatusChip'
import type { Finding } from '@/lib/types'
import { unverified } from './basis'
import { InfoTip } from '@/components/common/InfoTip'

/**
 * Mức nghiêm trọng kèm độ chắc chắn (D-484, như Qualys "potential" vàng cạnh "confirmed" đỏ): phát hiện chỉ khớp tên sản phẩm
 * hiện mức nghiêm trọng mờ kèm "unverified", không cùng khối đỏ với phát hiện đã xác nhận.
 */
export function RiskChip({ f }: { f: Pick<Finding, 'basis' | 'severity'> & { evidence?: Finding['evidence'] } }) {
  const { t } = useTranslation('findings')
  if (!unverified(f)) return <SeverityChip severity={f.severity} />
  // N52-2: the agent reported the installed version; Vedette could not compare it, so "add the version" does not apply.
  const label = t('risk.unverifiedChip', { severity: t(`common:severity.${f.severity}`) })
  // #824: the explanation is behind an ⓘ, not a hover-only title; the click stays off a clickable row.
  return <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}><Chip tone="off">{label}</Chip><InfoTip topic={label} className="print:hidden">{t(f.evidence?.agent_row ? 'risk.unverifiedAgentHint' : 'risk.unverifiedHint')}</InfoTip></span>
}
