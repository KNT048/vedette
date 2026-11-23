import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListSearch } from '@/components/common/Pager'
import { useListParams } from '@/components/common/listParams'
import { QueryState } from '@/components/common/States'
import { Select } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { RUN_STATUSES } from '@/lib/statusCodes'
import { useDevices } from '@/features/inventory/api'
import { displayName } from '@/features/inventory/nameOf'
import { runMoves, runWaits, useRunList } from './api'
import { runHref } from './places'
import { RunBar, RunStateChip, useKindLabel, useStartedBy } from './RunParts'
import type { Run } from './types'

const link = 'font-medium text-accent underline-offset-4 hover:underline [overflow-wrap:anywhere]'
const PAGE = 25
/** The kinds the engines register today (the list is open: a kind not named here is still listed, under its own name). */
const KINDS = ['lan_sweep', 'device_check', 'snmp_read', 'all_ports', 'vuln_check', 'exposure_scan']

/** The state of one run in its row: the chip, the box's line of words (what it waits for, how far it got, why it stopped) and a bar. */
function State({ r }: { r: Run }) {
  const { t } = useTranslation('scanning')
  const showBar = r.total > 0 && (runMoves(r.status) || runWaits(r.status) || r.status === 'partial' || r.status === 'stopped')
  return (
    <div className="grid min-w-0 justify-items-start gap-1 text-meta">
      <RunStateChip status={r.status} />
      <span className="text-muted [overflow-wrap:anywhere]">{r.summary}</span>
      {showBar ? <span className="grid w-full max-w-56 gap-1"><RunBar done={r.done} total={r.total} label={t('runs.progressOf', { title: r.title })} /></span> : null}
    </div>
  )
}

/**
 * Settings › Scanning › Runs: every run of every engine (LAN sweeps, device checks, SNMP reads, all-ports scans, vulnerability
 * checks, public scans and their engine steps), newest first by the time it started (the Started column), paged, searched and
 * filtered by the box (GET /runs): by kind, by state and by device. The search, the filters and the page live in the URL (`runs.*`),
 * so a refresh, a poll or a link back keeps them. Each run opens its own page.
 */
export function RunsTab() {
  const { t } = useTranslation('scanning')
  const kindLabel = useKindLabel()
  const startedBy = useStartedBy()
  const list = useListParams('runs')
  const [params, setParams] = useSearchParams()
  const kind = params.get('runs.kind') ?? ''
  const status = (RUN_STATUSES as readonly string[]).includes(params.get('runs.status') ?? '') ? params.get('runs.status')! : ''
  const device = params.get('runs.device') ?? ''
  const setFilter = (k: 'kind' | 'status' | 'device', v: string) => setParams((prev) => {
    const p = new URLSearchParams(prev)
    if (v) p.set(`runs.${k}`, v); else p.delete(`runs.${k}`)
    p.delete('runs.page')
    return p
  }, { replace: true, preventScrollReset: true })
  const size = list.size ?? PAGE
  const q = useRunList({ q: list.q, kind, status, device, offset: list.page * size, limit: size })
  const filtered = !!(list.q || kind || status || device)
  const clear = () => setParams((prev) => {
    const p = new URLSearchParams(prev)
    for (const k of ['q', 'kind', 'status', 'device', 'page']) p.delete(`runs.${k}`)
    return p
  }, { replace: true, preventScrollReset: true })
  const columns = useMemo<ColumnDef<Run>[]>(() => [
    { id: 'what', header: t('runs.col.what'), cell: ({ row: { original: r } }) => (
      <div className="grid min-w-0 text-meta">
        <Link to={runHref(r.id)} className={link}>{r.title}</Link>
        <span className="text-muted">{kindLabel(r.kind)} · {startedBy(r)}</span>
      </div>
    ) },
    { id: 'state', header: t('runs.col.state'), cell: ({ row: { original: r } }) => <State r={r} /> },
    { id: 'when', header: t('runs.col.when'), cell: ({ row: { original: r } }) => <span className="whitespace-nowrap text-meta">{fmtDateTime(r.started_at ?? r.queued_at)}</span> },
  ], [t, kindLabel, startedBy])
  const devices = useDevices()
  const deviceOptions = (devices.data?.items ?? []).map((d) => {
    const name = displayName(d)
    return { id: d.id, label: name && d.ip && name !== d.ip ? `${name} (${d.ip})` : name || d.id }
  })
  // a device the list does not hold (removed since, or not read yet) keeps the name its runs carry
  if (device && !deviceOptions.some((o) => o.id === device)) {
    deviceOptions.push({ id: device, label: q.data?.items.find((r) => r.subject?.kind === 'device' && r.subject.id === device)?.subject?.label ?? device })
  }
  deviceOptions.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }))
  return (
    <div className="grid gap-3">
      <div role="search" aria-label={t('runs.filters')} className="flex flex-wrap items-center gap-2">
        <ListSearch value={list.q} onChange={(v) => list.set({ q: v, page: 0 })} label={t('runs.search')} />
        <Select className="w-full sm:w-auto" aria-label={t('runs.kindFilter')} value={kind} onChange={(e) => setFilter('kind', e.target.value)}>
          <option value="">{t('runs.anyKind')}</option>
          {[...new Set([...KINDS, ...(kind ? [kind] : [])])].map((k) => <option key={k} value={k}>{kindLabel(k)}</option>)}
        </Select>
        <Select className="w-full sm:w-auto" aria-label={t('runs.stateFilter')} value={status} onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">{t('runs.anyState')}</option>
          {RUN_STATUSES.map((s) => <option key={s} value={s}>{t(`runs.status.${s}`)}</option>)}
        </Select>
        <Select className="w-full sm:w-auto sm:max-w-72" aria-label={t('runs.deviceFilter')} value={device} onChange={(e) => setFilter('device', e.target.value)}>
          <option value="">{t('runs.anyDevice')}</option>
          {deviceOptions.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
        </Select>
      </div>
      <QueryState query={q}>
        {(d) => (
          <DataTable urlKey="runs" caption={t('runs.caption')} data={d.items} columns={columns} pageSize={PAGE} server={{ total: d.total, list }}
            filtered={filtered} onClearFilters={clear} empty={t('runs.empty')}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <Link to={runHref(r.id)} className={link}>{r.title}</Link>
                <span className="text-meta text-muted">{fmtDateTime(r.started_at ?? r.queued_at)} · {kindLabel(r.kind)} · {startedBy(r)}</span>
                <State r={r} />
              </div>
            )} />
        )}
      </QueryState>
    </div>
  )
}
