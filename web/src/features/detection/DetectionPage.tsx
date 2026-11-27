import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, ErrorState, Loading, QueryState } from '@/components/common/States'
import { CveList } from '@/components/common/status'
import { Segmented } from '@/components/ui/segmented'
import { Select } from '@/components/ui/input'
import { fmtDateTime, fmtNumber, fmtRelative } from '@/lib/format'
import { useInstallKind } from '@/lib/modules'
import { useAlerts, useOverview } from './api'
import { actionTarget } from './places'
import { AlertLine, DeviceLink, severityText } from './parts'
import { ALERT_WINDOWS, type Alert, type AlertSort, type AlertWindow, type Watcher } from './types'
import { ListToolbar } from '@/components/common/ListParts'

const link = 'text-accent underline-offset-4 hover:underline'

export default function DetectionPage() {
  const { t } = useTranslation('detection')
  const ov = useOverview()
  return (
    <>
      <PageHeader title={t('common:shell.detection')} meta={t('meta')} stories={['S-IDS-1', 'S-LOG-4', 'S-HP-1']} />
      {ov.error ? <ErrorState error={ov.error} onRetry={() => void ov.refetch()} /> : ov.isPending ? <Loading /> : (
        <>
          <Kinds kinds={ov.data.kinds} />
          <MirrorHits hits={ov.data.mirror_port_hits} />
          {ov.data.watchers.some((w) => w.id === 'ips_events' && w.state !== 'off') ? <Alerts /> : null}
          <Watchers watchers={ov.data.watchers} badAddresses={ov.data.kinds.find((k) => k.kind === 'bad_address')?.incidents ?? 0} />
        </>
      )}
    </>
  )
}

/** "Bad addresses": the names and addresses your devices reach, matched against the bad-address lists. Only two inputs feed it, the
 *  mirror port (DNS names, TLS and HTTP hosts) and received logs (a firewall or DNS log); the box does not read its own DNS. Its
 *  state is read from those two watchers: watching when one of them is, quiet when one stopped, else what it needs to work. */
export function badAddressRow(watchers: Watcher[], container = false): { state: 'watching' | 'quiet' | 'not_set_up'; sources: ('mirror_port' | 'logs')[]; last: string | null; to: string; dnsGap: string | null } {
  const row = badAddressState(watchers, container)
  // received logs alone see only what their senders log: the names the devices and the box itself look up (DNS) reach the lists only
  // through a mirror port or a DNS server's (or a firewall's DNS) log; the row says so with the step that closes the gap
  const mirror = watchers.find((w) => w.id === 'mirror_port')
  const dnsGap = row.state === 'not_set_up' || row.sources.includes('mirror_port') ? null
    : mirror && (mirror.state === 'watching' || mirror.state === 'quiet') ? null : '/logs?tab=sources&add=source'
  return { ...row, dnsGap }
}

function badAddressState(watchers: Watcher[], container: boolean): { state: 'watching' | 'quiet' | 'not_set_up'; sources: ('mirror_port' | 'logs')[]; last: string | null; to: string } {
  const feeds = watchers.filter((w): w is Watcher & { id: 'mirror_port' | 'logs' } => w.id === 'mirror_port' || w.id === 'logs')
  const watching = feeds.filter((w) => w.state === 'watching')
  const quiet = feeds.filter((w) => w.state === 'quiet')
  const last = feeds.map((w) => w.last_input_at).filter((x): x is string => !!x).sort().at(-1) ?? null
  const logs = feeds.find((w) => w.id === 'logs')
  // what to do when nothing feeds it: a log source is the step every install can take (a mirror port needs a switch that mirrors)
  const to = !logs || logs.state === 'off' ? '/settings/modules#module-logs' : '/logs?tab=sources&add=source'
  if (watching.length) return { state: 'watching', sources: watching.map((w) => w.id), last, to: '/logs?tab=digest' }
  if (quiet.length) return { state: 'quiet', sources: quiet.map((w) => w.id), last, to: quiet[0]!.id === 'logs' ? '/logs?tab=sources' : (actionTarget({ id: 'mirror_port', action: 'fix' }, container) ?? '/settings/network#span') }
  return { state: 'not_set_up', sources: [], last, to }
}

function Watchers({ watchers, badAddresses }: { watchers: Watcher[]; badAddresses: number }) {
  const { t } = useTranslation('detection')
  const container = useInstallKind() === 'container'
  const bad = badAddressRow(watchers, container)
  const names = bad.sources.map((x) => t(`badAddresses.source.${x}`)).join(t('badAddresses.and'))
  const logsOff = bad.to.startsWith('/settings/modules')
  return (
    <Section id="watching" title={t('watching.title')}>
      <Card flush>
        <ul className="divide-y divide-rule">
          {watchers.map((w) => {
            const to = actionTarget(w, container)
            return (
              <li key={w.id} data-testid={`watcher-${w.id}`} className="grid gap-x-4 gap-y-1 px-4 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                <div className="grid gap-0.5">
                  <p className="flex flex-wrap items-baseline gap-x-2"><span className="font-medium">{t(`watcher.${w.id}`)}</span><span className="text-meta" data-state={w.state}>{t(`state.${w.state}`)}</span></p>
                  <p className="text-meta text-muted">{w.detail}</p>
                  <p className="text-caption text-muted">
                    {w.last_input_at ? t('watching.last', { when: fmtRelative(w.last_input_at) }) : t('watching.never')}
                    {w.state === 'unavailable' ? null : ` · ${t('watching.raised', { count: w.detections_7d })}`}
                  </p>
                </div>
                {w.action && to ? (to.startsWith('#') ? <a href={to} className={`text-meta ${link}`}>{t(`action.${w.action}.${w.id}`)}</a> : <Link to={to} className={`text-meta ${link}`}>{t(`action.${w.action}.${w.id}`)}</Link>) : null}
              </li>
            )
          })}
          <li data-testid="watcher-bad-addresses" className="grid gap-x-4 gap-y-1 px-4 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
            <div className="grid gap-0.5">
              <p className="flex flex-wrap items-baseline gap-x-2"><span className="font-medium">{t('badAddresses.name')}</span><span className="text-meta" data-state={bad.state}>{t(`state.${bad.state}`)}</span></p>
              <p className="text-meta text-muted">{t(`badAddresses.${bad.state}`, { sources: names })}</p>
              {bad.dnsGap ? (
                <p className="text-meta text-warn" data-testid="bad-addresses-dns-gap">
                  {t('badAddresses.dnsGap')} <Link to={bad.dnsGap} className={link}>{t('badAddresses.dnsGapAction')}</Link>
                </p>
              ) : null}
              <p className="text-caption text-muted">
                {bad.last ? t('watching.last', { when: fmtRelative(bad.last) }) : t('watching.never')}{` · ${t('watching.raised', { count: badAddresses })}`}
              </p>
            </div>
            <Link to={bad.to} className={`text-meta ${link}`}>{t(bad.state === 'watching' ? 'badAddresses.view' : bad.state === 'quiet' ? 'badAddresses.check' : logsOff ? 'action.turn_on.logs' : 'action.set_up.logs')}</Link>
          </li>
        </ul>
      </Card>
    </Section>
  )
}

function KindTile({ label, incidents, note }: { label: string; incidents: number; note: string }) {
  return (
    <>
      <span className="text-meta text-muted">{label}</span>
      <span className="text-xl font-semibold tabular-nums">{fmtNumber(incidents)}</span>
      <span className="text-caption text-muted">{note}</span>
    </>
  )
}

function Kinds({ kinds }: { kinds: { kind: string; incidents: number; new: number }[] }) {
  const { t } = useTranslation('detection')
  return (
    <Section id="kinds" title={t('kinds.title')}>
      <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {kinds.map((k) => {
          const note = k.new > 0 ? t('kinds.new', { count: k.new }) : t('kinds.none')
          return (
          <li key={k.kind}>
            {k.incidents > 0 ? (
              <Link to="/incidents" className="grid gap-0.5 rounded-md border border-rule p-3 hover:border-accent">
                <KindTile label={t(`kind.${k.kind}`)} incidents={k.incidents} note={note} />
              </Link>
            ) : (
              <div className="grid gap-0.5 rounded-md border border-rule p-3">
                <KindTile label={t(`kind.${k.kind}`)} incidents={0} note={t('kinds.none')} />
              </div>
            )}
          </li>
          )
        })}
      </ul>
    </Section>
  )
}

function MirrorHits({ hits }: { hits: { total: number; latest: Array<{ ts: string; src_ip: string; device: { id: string; name: string } | null; dest: string; seen_via: string; feeds: string[] }> } }) {
  const { t } = useTranslation('detection')
  if (hits.total === 0) return null
  return (
    <Section id="mirror-hits" title={t('mirror.title', { count: hits.total })} actions={<Link to="/logs" className={`text-meta ${link}`}>{t('mirror.all')}</Link>}>
      <Card flush>
        <ul className="divide-y divide-rule">
          {hits.latest.map((h) => (
            <li key={`${h.ts}-${h.src_ip}-${h.dest}`} className="grid gap-0.5 px-4 py-2">
              <p><DeviceLink device={h.device} ip={h.src_ip} />{' → '}<span className="font-medium [overflow-wrap:anywhere]">{h.dest}</span></p>
              <p className="text-caption text-muted">{fmtDateTime(h.ts)} · {t(`via.${h.seen_via}`)} · {h.feeds.join(', ')}</p>
            </li>
          ))}
        </ul>
      </Card>
    </Section>
  )
}

const WINDOW_LABEL: Record<AlertWindow, string> = { '24h': 'w24h', '7d': 'w7d', '30d': 'w30d' }

function Alerts() {
  const { t } = useTranslation('detection')
  const list = useListParams('alerts')
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const win = ALERT_WINDOWS.find((w) => w === params.get('alerts.window')) ?? '7d'
  const sort: AlertSort = params.get('alerts.sort') === 'count' ? 'count' : 'last'
  const setParam = (k: 'window' | 'sort', v: string, dflt: string) => setParams((prev) => {
    const p = new URLSearchParams(prev)
    if (v === dflt) p.delete(`alerts.${k}`); else p.set(`alerts.${k}`, v)
    p.delete('alerts.page')
    return p
  }, { replace: true, preventScrollReset: true })
  const size = list.size ?? 25
  const q = useAlerts({ window: win, q: list.q, sort, offset: list.page * size, limit: size }, true)
  const columns: ColumnDef<Alert>[] = [
    { id: 'severity', header: t('alerts.col.severity'), cell: ({ row }) => <span className="font-medium">{severityText(t, row.original.severity)}</span> },
    { id: 'signature', header: t('alerts.col.signature'), cell: ({ row: { original: a } }) => (
      <div className="grid"><Link to={`/detection/alerts/${a.id}`} onClick={(e) => e.stopPropagation()} className={`font-medium [overflow-wrap:anywhere] ${link}`}>{a.signature}</Link>
        {a.cves.length ? <CveList label={t('alerts.cvesOf', { signature: a.signature })} items={a.cves.map((cve) => ({ cve }))} /> : <span className="text-caption text-muted">{t('alerts.noCve')}</span>}</div>
    ) },
    { id: 'flow', header: t('alerts.col.flow'), cell: ({ row: { original: a } }) => <AlertLine a={a} /> },
    { id: 'count', header: t('alerts.col.count'), cell: ({ row }) => <span className="tabular-nums">{fmtNumber(row.original.count)}</span> },
    { id: 'seen', header: t('alerts.col.seen'), cell: ({ row }) => <span className="whitespace-nowrap text-meta">{fmtDateTime(row.original.last_seen)}</span> },
    { id: 'handling', header: t('alerts.col.handling'), cell: ({ row: { original: a } }) => (
      <div className="grid text-meta">
        {a.incident ? <Link to={`/incidents/${a.incident.id}`} onClick={(e) => e.stopPropagation()} className={link}>{t('alerts.incident', { status: t(`incidentStatus.${a.incident.status}`) })}</Link> : <span className="text-muted">{t('alerts.noIncident')}</span>}
        {a.findings.length ? <span className="text-caption text-muted">{t('alerts.findings', { count: a.findings.length })}</span> : null}
      </div>
    ) },
  ]
  return (
    <Section id="alerts" title={t('alerts.title')}>
      <div className="grid gap-3">
        <ListToolbar search={{ value: list.q, onChange: (v) => list.set({ q: v, page: 0 }), label: t('alerts.search') }}>
          <Segmented label={t('alerts.window')} value={win} onChange={(v) => setParam('window', v, '7d')} options={ALERT_WINDOWS.map((w) => ({ value: w, label: t(`alerts.${WINDOW_LABEL[w]}`) }))} />
          <Select className="w-full sm:w-auto" aria-label={t('alerts.sortLabel')} value={sort} onChange={(e) => setParam('sort', e.target.value, 'last')}>
            <option value="last">{t('alerts.sortLast')}</option>
            <option value="count">{t('alerts.sortCount')}</option>
          </Select>
        </ListToolbar>
        <QueryState query={q}>
          {(d) => d.total === 0 && !list.q ? <EmptyState title={t('alerts.empty')} /> : (
            <DataTable caption={t('alerts.caption')} data={d.items} columns={columns} pageSize={25} urlKey="alerts" server={{ total: d.total, list }}
              filtered={!!list.q} onClearFilters={() => list.set({ q: '', page: 0 })}
              rowTone={(a) => (a.severity === 'critical' ? 'danger' : a.severity === 'high' ? 'warn' : undefined)}
              onRowClick={(a) => navigate(`/detection/alerts/${a.id}`)}
              mobileRow={(a) => (
                <div className="grid gap-1">
                  <Link to={`/detection/alerts/${a.id}`} className={`font-medium [overflow-wrap:anywhere] ${link}`}>{a.signature}</Link>
                  <span className="text-meta">{severityText(t, a.severity)}, <AlertLine a={a} /></span>
                  <span className="text-caption text-muted">{t('alerts.mobileLine', { count: a.count, time: fmtDateTime(a.last_seen) })}</span>
                </div>
              )} />
          )}
        </QueryState>
      </div>
    </Section>
  )
}
