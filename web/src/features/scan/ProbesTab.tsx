import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { download } from '@/lib/api'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useProbes } from './api'
import { errMsg } from './errors'
import type { ProbeEntry } from './types'

const tone = { matched: 'danger', not_matched: 'ok', no_response: 'warn', banner: 'off' } as const

export function ProbesTab() {
  const { t } = useTranslation('scan')
  const q = useProbes()
  const columns: ColumnDef<ProbeEntry>[] = [
    { id: 'ts', header: t('probes.col.when'), accessorFn: (r) => r.ts, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.ts)}</span> },
    { id: 'target', header: t('probes.col.target'), accessorFn: (r) => r.ip, cell: ({ row: { original: r } }) => <div className="grid"><span className="font-medium">{r.label}</span><span className="text-[12px] text-muted">{r.ip}</span></div> },
    { id: 'template', header: t('probes.col.template'), accessorFn: (r) => r.template, cell: ({ row: { original: r } }) => <span className="text-[13px]">{r.template}</span> },
    { id: 'request', header: t('probes.col.request'), accessorFn: (r) => r.request, cell: ({ row: { original: r } }) => <code className="font-mono text-[12px]">{r.request}</code> },
    { id: 'result', header: t('probes.col.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <Chip tone={tone[r.result]}>{t(`probes.result.${r.result}`)}</Chip> },
  ]
  return (
    <Section id="probes" title={t('probes.title')} description={t('probes.description')} stories={['S-SCAN-4']}
      actions={<Button size="sm" onClick={() => void download('/scans/probes.csv', 'vedette-probe-log.csv').catch((e: unknown) => toast.error(errMsg(e)))}><Download />{t('probes.download')}</Button>}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid gap-3">
            <p className="text-[13px] text-muted">{t('probes.retention', { days: d.retention_days, count: d.items.length, oldest: fmtDate(d.items.at(-1)?.ts) })}</p>
            <DataTable caption={t('probes.caption')} data={d.items} columns={columns} filterPlaceholder={t('probes.filter')} pageSize={15}
              empty={<EmptyState title={t('probes.empty')}>{t('probes.emptyHelp')}</EmptyState>} initialSort={[{ id: 'ts', desc: true }]} />
          </div>
        )}
      </QueryState>
    </Section>
  )
}
