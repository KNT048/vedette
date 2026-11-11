import { Link } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useEvents, useSaveConfig } from './api'
import { errMsg } from './errors'
import type { RescanEvent } from './types'

// clear is only "no match reported" (D-133 (5)): neutral, never green; pick_only and stopped are neutral too (D-145 (7))
const tone = { matched: 'danger', clear: 'off', skipped_off: 'off', no_match: 'off', pick_only: 'off', stopped: 'off', expired_no_template: 'off', expired_scanner: 'off', expired_zone: 'off' } as const
const linkClass = 'font-medium text-accent underline underline-offset-4'

// The result of a rescan. pick_only says how many devices need a hand pick and links to Scan now (the device column names
// them; Scan now never ticks them for you, D-126 (2)); stopped links to the run, whose results show what was not checked.
function ResultCell({ r }: { r: RescanEvent }) {
  const { t } = useTranslation('scan')
  if (r.result === 'pick_only') {
    return <Chip tone={tone.pick_only}><Trans t={t} i18nKey="auto.result.pick_only" count={r.devices.length} components={{ nav: <Link to="/scans?tab=runs" className={linkClass} /> }} /></Chip>
  }
  if (r.result === 'stopped') {
    const link = r.run_id ? <Link to={`/scans?tab=runs&run=${encodeURIComponent(r.run_id)}`} className={linkClass} /> : <span />
    return <Chip tone={tone.stopped}><Trans t={t} i18nKey="auto.result.stopped" components={{ nav: link }} /></Chip>
  }
  return <Chip tone={tone[r.result]}>{t(`auto.result.${r.result}`)}</Chip>
}

export function AutoTab() {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const save = useSaveConfig()
  const q = useEvents()
  const columns: ColumnDef<RescanEvent>[] = [
    { id: 'ts', header: t('auto.col.when'), accessorFn: (r) => r.ts, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.ts)}</span> },
    { id: 'cve', header: t('auto.col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <Link to={`/cve/${r.cve}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link> },
    { id: 'product', header: t('auto.col.product'), accessorFn: (r) => r.product, cell: ({ row: { original: r } }) => <span>{r.product}</span> },
    { id: 'devices', header: t('auto.col.devices'), accessorFn: (r) => r.devices.join(', '), cell: ({ row: { original: r } }) => (r.devices.length ? <span>{r.devices.join(', ')}</span> : r.result.startsWith('expired') ? <span className="text-muted">–</span> : <span className="text-muted">{t('auto.noDevices')}</span>) },
    { id: 'latency', header: t('auto.col.latency'), accessorFn: (r) => r.latency_min ?? -1, cell: ({ row: { original: r } }) => (r.latency_min === null ? <span className="text-muted">–</span> : <span>{t('auto.minutes', { count: r.latency_min })}</span>) },
    { id: 'result', header: t('auto.col.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <ResultCell r={r} /> },
  ]
  return (
    <Section id="auto" title={t('auto.title')} description={t('auto.description')} stories={['S-SCAN-2']}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid gap-4">
            <div className="flex flex-wrap items-center gap-3">
              <Switch id="auto-on" checked={d.auto_rescan} disabled={!can || save.isPending}
                onCheckedChange={(v) => save.mutate({ auto_rescan: v }, { onSuccess: () => toast.success(v ? t('auto.onToast') : t('auto.offToast')), onError: (e) => toast.error(errMsg(e)) })} />
              <Label htmlFor="auto-on">{t('auto.switch')}</Label>
              {!can ? <span className="text-[13px] text-muted">{t('common:needRole', { role: t('common:role.admin') })}</span> : null}
            </div>
            {!d.auto_rescan ? <p className="rounded-md border border-dashed border-warn bg-warn-soft/60 px-3 py-2 text-sm">{t('auto.offNote')}</p> : null}
            <DataTable caption={t('auto.caption')} data={d.items} columns={columns} pageSize={10} empty={<EmptyState title={t('auto.empty')}>{t('auto.emptyHelp')}</EmptyState>} />
          </div>
        )}
      </QueryState>
    </Section>
  )
}
