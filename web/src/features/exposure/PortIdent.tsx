import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import { identOf, portHints, riskOf, serviceName, serviceText } from './services'
import type { PortRow } from './types'

/** M2-7: "Commonly attacked" for a service a probe named; "Commonly attacked if it is SIP" when only the port number says so. */
export function RiskChip({ p, purpose = false }: { p: Pick<PortRow, 'service' | 'ident'>; purpose?: boolean }) {
  const { t } = useTranslation('exposure')
  const risk = riskOf(p)
  if (!risk) return null
  const guess = identOf(p) === 'port'
  const label = guess ? t('open.attackedIf', { service: serviceName(p.service) }) : t('open.attacked')
  return (
    <span className="flex items-center gap-1">
      <Chip tone="warn">{label}</Chip>
      <InfoTip topic={label}>
        {guess ? <p>{t('open.attackedIfInfo', { service: serviceName(p.service) })}</p> : null}
        <p>{t(`risky.${risk}`)}</p>
        {purpose ? <p>{t('open.purposePlain')}</p> : null}
      </InfoTip>
    </span>
  )
}

/** M2-7: the service of a port or a service row in a table cell, with how sure the name is. */
export function ServiceCell({ service, ident, port }: { service: string; ident: 'probed' | 'port' | 'none' | undefined; port: number }) {
  const { t } = useTranslation('exposure')
  const { name, note } = serviceText(service, ident)
  if (!note && identOf({ service, ident }) !== 'none') return <>{name}</>
  const info = ident === 'port' ? t('open.byPortInfo', { port, service: serviceName(service) }) : service === 'tcpwrapped' ? t('vulns.tcpwrapped') : t('open.notIdentifiedInfo')
  return (
    <span className="grid gap-0.5">
      <span className="inline-flex items-center gap-1">{name}<InfoTip topic={name}>{info}</InfoTip></span>
      {note ? <span className="text-caption text-muted">{note}</span> : null}
    </span>
  )
}

/** M2-7: what the deep scan's scripts read on the port (certificate names, page title, Server header), or nothing. */
export function PortHints({ p, className = 'text-meta text-muted' }: { p: Pick<PortRow, 'cert_names' | 'title' | 'server' | 'product'>; className?: string }) {
  const hints = portHints(p)
  return hints.length > 0 ? <span className={className}>{hints.join(' · ')}</span> : null
}
