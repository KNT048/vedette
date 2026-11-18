import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { ApplianceNote } from './ApplianceNote'
import { PortHints, RiskChip } from './PortIdent'
import { PortMark, PortMarkNote } from './PortMark'
import { identOf, portLabel, serviceName } from './services'
import { useTargets } from './api'
import type { Gateway, Target } from './types'

/** The open exposures of one target: every open port of its newest scan, the commonly attacked ones called out, with "is that on purpose?" (S-EXP-1). */
export function OpenPortsPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const ports = target.open_ports ?? []
  const total = target.latest?.ports ?? ports.length
  // The gateway note is the list's (one device answers the box's own public IPs): it is asked for only when this target's ports are the box's own.
  const gateway = useTargets({ enabled: target.origin === 'box' && ports.length > 0 }).data?.gateway ?? null
  if (ports.length === 0) return <EmptyState title={target.last_scan_at ? t('openEmpty') : t('openNever')} />
  return (
    <Section id="open" title={t('open.title', { count: total })} description={t('open.description')} info={t('open.descriptionInfo')}>
      {/* The gateway answers the ports no appliance claims; a port that names one (a FortiGate certificate) is tied to it instead */}
      {gateway && (total > ports.length || ports.some((p) => !p.appliance)) ? <GatewayNote g={gateway} rest={ports.some((p) => p.appliance)} /> : null}
      <Panel className="divide-y divide-rule">
        {ports.map((p) => {
          const ident = identOf(p)
          return (
            <div key={`${p.ip}|${p.port}`} className="grid gap-1 px-4 py-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-medium">{portLabel(p)}</span>
                <span className="text-muted">{t('open.on', { ip: p.ip })}</span>
                {p.product ? <span className="text-muted">{t('open.software', { product: p.product })}</span> : null}
                {ident === 'port' ? <span className="inline-flex items-center gap-1 text-muted">{t('open.byPort')}<InfoTip topic={t('open.byPort')}>{t('open.byPortInfo', { port: p.port, service: serviceName(p.service) })}</InfoTip></span> : null}
                {ident === 'none' ? <InfoTip topic={portLabel(p)}>{p.service === 'tcpwrapped' ? t('vulns.tcpwrapped') : t('open.notIdentifiedInfo')}</InfoTip> : null}
                <PortHints p={p} className="text-muted" />
                <RiskChip p={p} />
                <PortMark p={p} />
              </div>
              {p.appliance ? <ApplianceNote a={p.appliance} /> : null}
              {p.last_seen ? <PortMarkNote p={p} at={target.last_scan_at} /> : null}
              <p className="text-meta text-muted">{t('open.purposePlain')}</p>
            </div>
          )
        })}
      </Panel>
      {total > ports.length ? <p className="mt-2 text-meta text-muted">{t('open.moreOnTarget', { count: total - ports.length })}</p> : null}
    </Section>
  )
}

/** The gateway as the note names it: "name (ip)", or the IP alone when the device is named by its IP or has no name (M2-8). */
const gatewayLabel = (name: string, ip: string) => (name && name !== ip ? `${name} (${ip})` : ip)

/** Which device probably answers the open ports, and what is exploited on it. Never says for sure (a router can forward a port to another device).
 * rest: some ports name an appliance of their own (ApplianceNote), so the note is about the other ports. */
function GatewayNote({ g, rest = false }: { g: Gateway; rest?: boolean }) {
  const { t } = useTranslation('exposure')
  const name = g.name ?? ''
  const ip = g.ip ?? ''
  const known = g.device_id !== null
  const label = gatewayLabel(name, ip) // M2-8: "192.168.18.1", not "192.168.18.1 (192.168.18.1)"
  const text = !g.ip ? t('gateway.unknown') : !known ? t(rest ? 'gateway.notListedRest' : 'gateway.notListed', { ip })
    : g.open_exploited > 0 ? t(rest ? 'gateway.knownRest' : 'gateway.known', { label, count: g.open_exploited }) : t(rest ? 'gateway.noneRest' : 'gateway.none', { label })
  const info = !g.ip ? t('gateway.unknownInfo') : !known ? t('gateway.notListedInfo') : g.open_exploited > 0 ? t('gateway.knownInfo') : t('gateway.noneInfo', { name })
  return (
    <Notice tone="accent" data-testid="gateway-note" title={text} info={info}
      actions={known && g.open_exploited > 0 ? <Link className="text-meta text-accent underline-offset-4 hover:underline" to={`/findings?tab=open&device=${encodeURIComponent(g.device_id ?? '')}`}>{t('gateway.link', { name })}</Link> : undefined} />
  )
}
