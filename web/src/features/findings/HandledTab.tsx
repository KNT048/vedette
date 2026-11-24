// Handled: what was done about each finding, the newest first, with who and how ("Patched by Vedette: version moved 6.24 → 7.23",
// "Mitigated by ana: firewall rule"). Accepted risks are a filter here, with the day they end. The screen a person shows their
// manager; the weekly report reads the same rows (GET /findings/handled).
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListSearch } from '@/components/common/Pager'
import { useListParams } from '@/components/common/listParams'
import { QueryState } from '@/components/common/States'
import { FindingStatusLines, HandledLine, SeverityBadge, StatusBadge, useStatusLabel } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { FINDING_RESOLUTIONS } from '@/lib/statusCodes'
import { useCan } from '@/lib/session'
import { useHandledList, useReopen } from './api'
import { AskDialog } from './AskDialog'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { DeviceLine } from './parts'
import type { HandledRow, Resolution } from './types'

const PERIODS = ['7', '30', '90'] as const
/** The start of the day `days` ago, in UTC: one value all day long, so the list's cache key holds still. */
const since = (days: number) => { const n = new Date(); return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate() - days)).toISOString() }

function Reopen({ r }: { r: HandledRow }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const reopen = useReopen()
  const [open, setOpen] = useState(false)
  const on = { cve: r.cve, device: r.device.name }
  return (
    <>
      <Button size="sm" variant="ghost" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        aria-label={t('handledTab.reopenOf', on)} onClick={(e) => { e.stopPropagation(); setOpen(true) }}>{t('handledTab.reopen')}</Button>
      {open ? (
        <AskDialog title={t('handledTab.reopenTitle', on)} description={t('handledTab.reopenBody')} submit={t('handledTab.reopen')} done={t('handledTab.reopened', on)}
          fields={[{ name: 'note', label: t('handledTab.reopenNote'), required: false, max: 500, long: true }]}
          onSend={(v) => reopen.mutateAsync({ id: r.id, note: v.note ?? '' })} onClose={() => setOpen(false)} />
      ) : null}
    </>
  )
}

export function HandledTab({ device }: { device: string }) {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const label = useStatusLabel()
  const raw = useListParams('handled')
  const list = useMemo(() => ({ ...raw, size: raw.size === undefined ? undefined : Math.min(raw.size, PAGE_MAX) }), [raw])
  const size = list.size ?? PAGE_DEFAULT
  const resolution = FINDING_RESOLUTIONS.find((x) => x === params.get('resolution')) ?? ''
  const period = PERIODS.find((x) => x === params.get('period')) ?? ''
  const from = period ? since(Number(period)) : undefined
  // Vedette's corrections of its own match (hundreds of rows when a kernel's package lines fold into one) are left out by default, as
  // the report leaves them out: they were never a flaw someone handled. One link shows them.
  const corrections = params.get('corrections') === 'true'
  const q = useHandledList({ q: raw.q, resolution, device, from, corrections }, { offset: list.page * size, limit: size })
  const set = (k: string, v: string) => setParams((prev) => { const p = new URLSearchParams(prev); if (v) p.set(k, v); else p.delete(k); return p }, { replace: true, preventScrollReset: true })
  const filtered = !!(raw.q || resolution || period || device)
  const clear = () => { raw.set({ q: '', page: 0 }); setParams((prev) => { const p = new URLSearchParams(prev); for (const k of ['resolution', 'period', 'device', 'corrections']) p.delete(k); return p }, { replace: true }) }
  const columns: ColumnDef<HandledRow>[] = [
    { id: 'cve', header: t('handledTab.col.cve'), cell: ({ row: { original: r } }) => (
      <span className="grid gap-1">
        <Link to={`/findings/${encodeURIComponent(r.id)}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link>
        <SeverityBadge severity={r.severity} compact />
      </span>
    ) },
    { id: 'device', header: t('handledTab.col.device'), cell: ({ row: { original: r } }) => (
      <span className="grid gap-0.5">
        <DeviceLine device={r.device} badge={false} />
        {r.software ? <span className="text-meta text-muted">{r.software.name}</span> : null}
      </span>
    ) },
    { id: 'status', header: t('handledTab.col.status'), cell: ({ row: { original: r } }) => (
      <span className="grid gap-1">
        <FindingStatusLines value={{ status: r.status, handled: r.handled, software: r.software?.name }} />
      </span>
    ) },
    { id: 'actions', header: t('handledTab.col.actions'), cell: ({ row: { original: r } }) => <Reopen r={r} /> },
  ]
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="max-w-full overflow-x-auto">
          <Segmented<Resolution | ''> label={t('handledTab.resolution')} value={resolution} onChange={(v) => set('resolution', v)}
            options={[{ value: '', label: t('handledTab.all') }, ...FINDING_RESOLUTIONS.map((r) => ({ value: r, label: label(r) }))]} />
        </div>
        <Select className="w-full sm:w-auto" aria-label={t('handledTab.period')} value={period} onChange={(e) => set('period', e.target.value)}>
          <option value="">{t('handledTab.anyTime')}</option>
          {PERIODS.map((p) => <option key={p} value={p}>{t('handledTab.lastDays', { count: Number(p) })}</option>)}
        </Select>
        <ListSearch value={raw.q} onChange={(v) => raw.set({ q: v, page: 0 })} label={t('handledTab.search')} />
      </div>
      <QueryState query={q}>
        {(d) => (
          <>
          {d.corrections > 0 ? (
            <p className="text-meta text-muted" data-count="corrections">
              {corrections ? t('handledTab.correctionsShown', { count: d.corrections }) : t('handledTab.correctionsHidden', { count: d.corrections })}{' '}
              <Button variant="link" size="sm" onClick={() => set('corrections', corrections ? '' : 'true')}>
                {corrections ? t('handledTab.hideCorrections') : t('handledTab.showCorrections', { count: d.corrections })}
              </Button>
            </p>
          ) : null}
          <DataTable urlKey="handled" caption={t('handledTab.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
            server={{ total: d.total, list, max: PAGE_MAX }} filtered={filtered} onClearFilters={clear} resetPageOn={`${resolution}|${period}|${device}|${corrections}`} empty={t('handledTab.empty')}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Link to={`/findings/${encodeURIComponent(r.id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link>
                  <StatusBadge code={r.status} until={r.handled.accepted_until} />
                </div>
                <DeviceLine device={r.device} badge={false} />
                <HandledLine underBadge handled={r.handled} software={r.software?.name} />
                <span className="w-fit"><Reopen r={r} /></span>
              </div>
            )} />
          </>
        )}
      </QueryState>
    </div>
  )
}
