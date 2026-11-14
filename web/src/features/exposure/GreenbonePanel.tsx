import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { KeyValue, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { dateTimeText } from './dates'
import { useGreenbone, useSetGreenbone } from './api'
import type { Greenbone, GreenboneResult, Snapshot } from './types'

const STATE_TONE: Record<Greenbone['state'], Tone> = { unavailable: 'off', off: 'off', starting: 'accent', loading: 'accent', ready: 'ok', error: 'danger' }
/** Decimal GB with one decimal, as the box measures it (8 GB = 8e9 bytes, D-563). */
const gb = (n: number | null) => (n === null ? null : `${(n / 1e9).toFixed(1)} GB`)

/**
 * S-EXP-2 (INV-25, D-563): the optional deep scan with Greenbone (OpenVAS), off by default, admin only. The box measures its memory and
 * free disk first and refuses with the numbers; the first start loads Greenbone's feed for about 2 hours, shown as a phase.
 */
export function GreenboneSetting() {
  const { t } = useTranslation('exposure')
  const q = useGreenbone()
  return (
    <Section id="greenbone" title={t('greenbone.title')} description={t('greenbone.description')}>
      <QueryState query={q}>{(g) => <GreenboneBody g={g} />}</QueryState>
    </Section>
  )
}

function GreenboneBody({ g }: { g: Greenbone }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const set = useSetGreenbone()
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : undefined
  const on = g.state !== 'off' && g.state !== 'unavailable'
  const change = (enabled: boolean) => set.mutate(enabled, {
    onSuccess: () => toast.success(enabled ? t('greenbone.toastOn') : t('greenbone.toastOff')),
    onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
  })
  const p = g.preflight
  return (
    <Panel className="grid max-w-3xl gap-4 p-4">
      <p className="flex flex-wrap items-center gap-2 text-sm font-medium" role="status">
        <Chip tone={STATE_TONE[g.state]}>{t(`greenbone.state.${g.state}`)}</Chip>
        {g.state === 'loading' ? t('greenbone.loading') : g.state === 'error' || g.state === 'unavailable' ? g.reason : t(`greenbone.stateText.${g.state}`)}
      </p>
      {g.state === 'unavailable' ? null : (
        <>
          <ul className="grid list-disc gap-1.5 pl-5 text-[13px] text-muted">
            <li>{t('greenbone.what')}</li><li>{t('greenbone.apart')}</li><li>{t('greenbone.offKeeps')}</li>
          </ul>
          <KeyValue items={[
            { label: t('greenbone.memory'), value: gb(p.memory_bytes) ?? t('common:unknown') },
            { label: t('greenbone.disk'), value: gb(p.disk_free_bytes) ?? t('common:unknown') },
          ]} />
          {!on ? <p className="text-[13px]">{t('greenbone.needs')}</p> : null}
          {!on && !p.ok ? <p role="alert" className="text-sm text-warn">{p.reason}</p> : null}
          <div className="flex flex-wrap items-center gap-3">
            {on ? (
              <Button onClick={() => change(false)} disabled={!can || set.isPending} title={locked}>{t('greenbone.disable')}</Button>
            ) : (
              <Button variant="primary" onClick={() => change(true)} disabled={!can || !p.ok || set.isPending} title={locked ?? (p.ok ? undefined : p.reason ?? undefined)}>{t('greenbone.enable')}</Button>
            )}
            {g.changed_by && g.changed_at ? <span className="text-[12px] text-muted">{t(on ? 'greenbone.changedOn' : 'greenbone.changedOff', { by: g.changed_by, time: dateTimeText(g.changed_at) })}</span> : null}
          </div>
          {locked ? <p className="text-[13px] text-muted">{locked}</p> : null}
        </>
      )}
    </Panel>
  )
}

/** S-EXP-2 (INV-25): what Greenbone reported on this IP. Apart from the exploited CVEs, and never "nothing found = not affected". */
export function GreenboneSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const rows = s.greenbone ?? [] // a snapshot read from an older box has no list
  const ran = s.checks.some((c) => c.kind === 'greenbone')
  const why = s.not_checked.find((n) => n.kind === 'greenbone')
  const cols: ColumnDef<GreenboneResult>[] = [
    { id: 'severity', header: t('greenbone.col.severity'), accessorFn: (r) => r.severity, cell: ({ row }) => {
      const v = row.original.severity
      return <Chip tone={v >= 7 ? 'danger' : v >= 4 ? 'warn' : 'off'}>{t(v >= 7 ? 'greenbone.sev.high' : v >= 4 ? 'greenbone.sev.medium' : 'greenbone.sev.low', { score: v.toFixed(1) })}</Chip>
    } },
    { id: 'name', header: t('greenbone.col.name'), accessorFn: (r) => r.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'port', header: t('greenbone.col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{row.original.port || t('common:unknown')}</span> },
    { id: 'qod', header: t('greenbone.col.qod'), accessorFn: (r) => r.qod, cell: ({ row }) => <span className="tabular-nums">{row.original.qod}%</span> },
    { id: 'cves', header: t('greenbone.col.cves'), enableSorting: false, accessorFn: (r) => r.cves.join(' '), cell: ({ row }) => (
      row.original.cves.length > 0 ? <span className="grid gap-0.5 text-[12px]">{row.original.cves.map((c) => <span key={c}>{c}</span>)}</span> : <span className="text-[12px] text-muted">{t('greenbone.noCve')}</span>
    ) },
    { id: 'solution', header: t('greenbone.col.solution'), enableSorting: false, accessorFn: (r) => r.solution, cell: ({ row }) => <span className="text-[13px]">{row.original.solution}</span> },
  ]
  return (
    <Section id="greenbone-results" title={t('greenbone.results.title')} description={t('greenbone.results.header')}>
      {rows.length > 0 ? (
        <DataTable caption={t('greenbone.results.caption')} data={rows} columns={cols} pageSize={20} initialSort={[{ id: 'severity', desc: true }]} rowTone={(r) => (r.severity >= 7 ? 'warn' : undefined)} />
      ) : ran ? (
        <EmptyState title={t('greenbone.results.noneTitle')}>{t('greenbone.results.noneBody')}</EmptyState>
      ) : (
        <EmptyState title={t('greenbone.results.notRunTitle')}>{why?.text ?? t('greenbone.results.notRunBody')}</EmptyState>
      )}
    </Section>
  )
}
