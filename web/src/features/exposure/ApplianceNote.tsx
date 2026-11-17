import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { InfoTip } from '@/components/common/InfoTip'
import type { Appliance } from './types'

/** S-EXP-1: the network appliance a port names (its certificate, page title, Server header or product), and the devices of that
 * family in the inventory with their open exploited vulnerabilities. Says nothing about the inventory when the server could not tell. */
export function ApplianceNote({ a, className = 'text-meta' }: { a: Appliance; className?: string }) {
  const { t } = useTranslation('exposure')
  const what = t(`appliance.kind.${a.kind}`, { name: a.name })
  return (
    <div className={`grid gap-0.5 ${className}`} data-testid="appliance-note">
      <span className="inline-flex flex-wrap items-center gap-1">
        <span className={a.kind === 'vpn' ? 'font-medium text-warn' : 'font-medium text-danger'}>{t('appliance.says', { what, from: t(`appliance.from.${a.evidence}`) })}</span>
        <InfoTip topic={what}>{t(a.kind === 'vpn' ? 'appliance.vpnInfo' : 'appliance.adminInfo', { name: a.name })}</InfoTip>
      </span>
      {a.devices === null ? null : a.devices.length === 0 ? (
        <span className="text-muted">{t('appliance.notListed', { name: a.name })}</span>
      ) : (
        <ul className="grid gap-0.5">
          {a.devices.map((d) => (
            <li key={d.device_id} className="flex flex-wrap items-center gap-x-2">
              <span>{d.open_exploited > 0 ? t('appliance.device.known', { device: d.name, name: a.name, count: d.open_exploited }) : t('appliance.device.none', { device: d.name, name: a.name })}</span>
              <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${encodeURIComponent(d.device_id)}`}>{t('appliance.device.link', { device: d.name })}</Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
