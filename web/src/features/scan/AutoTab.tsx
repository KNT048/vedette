import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
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

const tone = { matched: 'danger', clear: 'ok', skipped_off: 'off', no_match: 'off' } as const

export function AutoTab() {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const save = useSaveConfig()
  const q = useEvents()
  const columns: ColumnDef<RescanEvent>[] = [
    { id: 'ts', header: t('auto.col.when'), accessorFn: (r) => r.ts, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.ts)}</span> },
    { id: 'cve', header: t('auto.col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <Link to={`/cve/${r.cve}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{r.cve}</Link> },
    { id: 'product', header: t('auto.col.product'), accessorFn: (r) => r.product, cell: ({ row: { original: r } }) => <span>{r.product}</span> },
    { id: 'devices', header: t('auto.col.devices'), accessorFn: (r) => r.devices.join(', '), cell: ({ row: { original: r } }) => (r.devices.length ? <span>{r.devices.join(', ')}</span> : <span className="text-muted">{t('auto.noDevices')}</span>) },
    { id: 'latency', header: t('auto.col.latency'), accessorFn: (r) => r.latency_min ?? -1, cell: ({ row: { original: r } }) => (r.latency_min === null ? <span className="text-muted">–</span> : <span>{t('auto.minutes', { count: r.latency_min })}</span>) },
    { id: 'result', header: t('auto.col.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <Chip tone={tone[r.result]}>{t(`auto.result.${r.result}`)}</Chip> },
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
