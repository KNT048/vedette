import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate } from '@/lib/format'
import { useRows } from './api'
import { InfoLine } from '@/components/common/InfoLine'
import { Seen, useTabHref } from './NodeParts'
import { riskOf, serviceText } from './services'
import type { Gateway, Issue, Service, TargetNode } from './types'

const CERT_WARN_DAYS = 30
type View = 'open' | 'closed'
const VIEWS: View[] = ['open', 'closed']
const daysLeft = (iso: string) => Math.ceil((Date.parse(iso) - Date.now()) / 864e5)

/** The services found on the target's public addresses, open and closed, each with when it was first and last seen. */
export function ServicesPanel({ node, gateway }: { node: TargetNode; gateway: Gateway | null }) {
  const q = useRows(node.id, 'services')
  const issues = useRows(node.id, 'issues')
  return <QueryState query={q}>{(d) => <ServicesTable node={node} services={d.items} issues={issues.data?.items ?? []} gateway={gateway} />}</QueryState>
}

function ServicesTable({ node, services, issues, gateway }: { node: TargetNode; services: Service[]; issues: Issue[]; gateway: Gateway | null }) {
  const { t } = useTranslation('exposure')
  const [params, setParams] = useSearchParams()
  const tabHref = useTabHref()
  const issuesOf = (id: string) => { const p = new URLSearchParams(tabHref('issues').slice(1)); p.set('service', id); return `?${p}` }
  const view: View = params.get('services') === 'closed' ? 'closed' : 'open'
  const setView = (v: View) => { const p = new URLSearchParams(params); if (v === 'open') p.delete('services'); else p.set('services', v); setParams(p, { replace: true }) }
  const rows = services.filter((s) => s.state === view)
  const open = services.filter((s) => s.state === 'open')
  const openIssues = (s: Service) => issues.filter((i) => i.service_id === s.id && i.state === 'open').length
  // A scan that found open services but none that answered HTTP had no page for the passive web scan: say so, with the ports it checked.
  const noWeb = node.last_scan && open.length > 0 && !open.some((s) => s.is_web)
  const columns: ColumnDef<Service>[] = [
    { id: 'port', header: t('services.col.port'), accessorFn: (s) => `${s.ip}:${String(s.port).padStart(5, '0')}`, cell: ({ row }) => <span className="whitespace-nowrap font-mono text-meta">{row.original.ip}:{row.original.port}/{row.original.proto}</span> },
    { id: 'service', header: t('services.col.service'), accessorFn: (s) => serviceText(s).name, cell: ({ row }) => <ServiceCell s={row.original} /> },
    { id: 'web', header: t('services.col.web'), enableSorting: false, cell: ({ row }) => <WebCell s={row.original} /> },
    { id: 'issues', header: t('services.col.issues'), accessorFn: openIssues, cell: ({ row }) => {
      const n = openIssues(row.original)
      const s = row.original
      // to the issues of this service only: each row's link has its own target and its own label
      return n > 0 ? <Link className="font-medium text-accent underline-offset-4 hover:underline" to={issuesOf(s.id)} aria-label={t('services.issuesOn', { count: n, where: `${s.ip}:${s.port}/${s.proto}` })}>{t('services.issues', { count: n })}</Link> : <span className="text-muted">0</span>
    } },
    { id: 'seen', header: t('services.col.seen'), accessorFn: (s) => s.last_seen, cell: ({ row }) => <ServiceSeen s={row.original} /> },
  ]
  return (
    <div className="grid gap-3">
      {gateway && open.length > 0 ? <GatewayNote g={gateway} /> : null}
      {noWeb ? <p className="max-w-3xl text-meta text-muted">{t('services.noWeb', { ports: [...new Set(open.map((s) => s.port))].sort((a, b) => a - b).join(', ') })}</p> : null}
      <Segmented<View> className="w-fit" label={t('services.view')} value={view} onChange={setView} options={VIEWS.map((v) => ({ value: v, label: t(`services.views.${v}`, { count: services.filter((s) => s.state === v).length }) }))} />
      <DataTable urlKey="exposure-services" resetPageOn={view} caption={t('services.caption', { value: node.value })} data={rows} columns={columns} pageSize={25}
        initialSort={[{ id: 'port', desc: false }]}
        mobileRow={(s) => (
          <div className="grid gap-1.5">
            <span className="font-mono text-meta">{s.ip}:{s.port}/{s.proto}</span>
            <ServiceCell s={s} />
            <WebCell s={s} />
            <ServiceSeen s={s} />
          </div>
        )}
        empty={<EmptyState title={t(`services.empty.${view}`)}>{view === 'open' && !node.last_scan ? t('services.emptyNever') : null}</EmptyState>} />
    </div>
  )
}

/** The service as a person names it, its product and version, and why it is commonly attacked when it is. */
function ServiceCell({ s }: { s: Service }) {
  const { t } = useTranslation('exposure')
  const text = serviceText(s)
  const risk = s.state === 'open' ? riskOf(s) : null
  const product = [s.product, s.version].filter(Boolean).join(' ')
  return (
    <span className="grid gap-0.5">
      <span className="font-medium">{text.name}</span>
      {product ? <span className="text-meta">{product}</span> : null}
      {text.byPort ? <span className="text-caption text-muted">{t('services.byPort')}</span> : null}
      {risk ? <InfoLine className="text-caption text-warn" topic={t('services.onPurpose')} info={t(`risky.${risk}`)}>{t('services.onPurpose')}</InfoLine> : null}
    </span>
  )
}

/** A service that answered HTTP: its page title; and the TLS certificate it showed, with its end when that is near. */
function WebCell({ s }: { s: Service }) {
  const { t } = useTranslation('exposure')
  const left = s.cert ? daysLeft(s.cert.expires_at) : null
  return (
    <span className="grid gap-1">
      {s.is_web ? <span className="flex flex-wrap items-center gap-1.5"><Chip tone="accent">{t('services.webChip')}</Chip>{s.title ? <span className="text-meta [overflow-wrap:anywhere]">{s.title}</span> : null}</span> : null}
      {s.cert ? (
        <span className={left !== null && left <= CERT_WARN_DAYS ? 'text-caption text-warn' : 'text-caption text-muted'} title={s.cert.issuer}>
          {left !== null && left < 0 ? t('services.certExpired', { names: s.cert.names.join(', '), date: fmtDate(s.cert.expires_at) })
            : t('services.cert', { names: s.cert.names.join(', '), date: fmtDate(s.cert.expires_at) })}
        </span>
      ) : null}
      {!s.is_web && !s.cert ? <span className="text-muted">—</span> : null}
    </span>
  )
}

/** When the service was first and last seen; on an open one the last scans could not reach, since when, and what happens to it. */
function ServiceSeen({ s }: { s: Service }) {
  const { t } = useTranslation('exposure')
  if (s.state !== 'open' || !s.not_reached_since) return <Seen i={s} />
  return (
    <div className="grid gap-0.5">
      <Seen i={s} />
      <InfoLine className="text-caption text-warn" topic={t('services.notReached', { date: fmtDate(s.not_reached_since) })} info={t('services.notReachedInfo')}>
        {t('services.notReached', { date: fmtDate(s.not_reached_since) })}
      </InfoLine>
    </div>
  )
}

/** The gateway as the note names it: "name (ip)", or the IP alone when the device is named by its IP or has no name. */
const gatewayLabel = (name: string, ip: string) => (name && name !== ip ? `${name} (${ip})` : ip)

/** Which device probably answers the open services of the box's own IP, and what is exploited on it. Never says for sure (a router can forward a port). */
function GatewayNote({ g }: { g: Gateway }) {
  const { t } = useTranslation('exposure')
  const name = g.name ?? ''
  const ip = g.ip ?? ''
  const known = g.device_id !== null
  const label = gatewayLabel(name, ip)
  const text = !g.ip ? t('gateway.unknown') : !known ? t('gateway.notListed', { ip })
    : g.open_exploited > 0 ? t('gateway.known', { label, count: g.open_exploited }) : t('gateway.none', { label })
  const info = !g.ip ? t('gateway.unknownInfo') : !known ? t('gateway.notListedInfo') : g.open_exploited > 0 ? t('gateway.knownInfo') : t('gateway.noneInfo', { name })
  return (
    <Notice tone="accent" data-testid="gateway-note" className="mb-0" title={text} info={info}
      actions={known && g.open_exploited > 0 ? <Link className="text-meta text-accent underline-offset-4 hover:underline" to={`/findings?tab=open&device=${encodeURIComponent(g.device_id ?? '')}`}>{t('gateway.link', { name })}</Link> : undefined} />
  )
}
