import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { fmtDateTime } from '@/lib/format'
import type { Hit } from './types'

/** "Respond" opens the response module, where rules and approvals for trap hits live (D-44). Not offered for tests. */
export function RespondLink({ h }: { h: Hit }) {
  const { t } = useTranslation('honeypot')
  if (h.is_test) return <span className="text-[13px] text-muted">-</span>
  return <Link to="/response?tab=rules" className="text-[13px] text-accent underline-offset-4 hover:underline" aria-label={t('hits.respondLabel', { src: h.src_name ?? h.src_ip, time: fmtDateTime(h.ts) })}>{t('hits.respond')}</Link>
}
