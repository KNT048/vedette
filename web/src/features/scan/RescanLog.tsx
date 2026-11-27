import { Link } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { Notice, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { fmtDateTime } from '@/lib/format'
import { useEvents } from './api'
import { runHref } from '@/features/scanning/places'
import type { RescanEvent } from './types'
import { RowTitle } from '@/components/common/ListParts'

// clear is only "no match reported": neutral, never green; pick_only and stopped are neutral too
const tone = { matched: 'danger', clear: 'off', skipped_off: 'off', no_match: 'off', pick_only: 'off', stopped: 'off', expired_no_template: 'off', expired_scanner: 'off', expired_zone: 'off' } as const
const linkClass = 'font-medium text-accent underline underline-offset-4'

// The result of a rescan. pick_only says how many devices need a hand pick and links to Scan now (the device column names
// them; Scan now never ticks them for you); stopped links to the run, whose results show what was not checked.
function ResultCell({ r }: { r: RescanEvent }) {
  const { t } = useTranslation('scan')
  if (r.result === 'pick_only') {
    return <Chip tone={tone.pick_only}><Trans t={t} i18nKey="auto.result.pick_only" count={r.devices.length} components={{ nav: <Link to="/devices" className={linkClass} /> }} /></Chip>
  }
  if (r.result === 'stopped') {
    const link = r.run_id ? <Link to={runHref(r.run_id, 'settings')} className={linkClass} /> : <span />
    return <Chip tone={tone.stopped}><Trans t={t} i18nKey="auto.result.stopped" components={{ nav: link }} /></Chip>
  }
  return <Chip tone={tone[r.result]}>{t(`auto.result.${r.result}`)}</Chip>
}

/** S-SCAN-2: the log of automatic rescans when a new KEV entry has a template. Its switch is on the Nuclei engine card (#850). */
export function RescanLog() {
  const { t } = useTranslation('scan')
  const q = useEvents()
  const columns: ColumnDef<RescanEvent>[] = [
    { id: 'ts', header: t('auto.col.when'), accessorFn: (r) => r.ts, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.ts)}</span> },
    { id: 'cve', header: t('auto.col.cve'), accessorFn: (r) => r.cve, cell: ({ row: { original: r } }) => <RowTitle to={`/cve/${r.cve}`} className="whitespace-nowrap">{r.cve}</RowTitle> },
    { id: 'product', header: t('auto.col.product'), accessorFn: (r) => r.product, cell: ({ row: { original: r } }) => <span>{r.product}</span> },
    { id: 'devices', header: t('auto.col.devices'), accessorFn: (r) => r.devices.join(', '), cell: ({ row: { original: r } }) => (r.devices.length ? <span>{r.devices.join(', ')}</span> : r.result.startsWith('expired') ? <span className="text-muted">–</span> : <span className="text-muted">{t('auto.noDevices')}</span>) },
    { id: 'latency', header: t('auto.col.latency'), accessorFn: (r) => r.latency_min ?? -1, cell: ({ row: { original: r } }) => (r.latency_min === null ? <span className="text-muted">–</span> : <span>{t('auto.minutes', { count: r.latency_min })}</span>) },
    { id: 'result', header: t('auto.col.result'), accessorFn: (r) => r.result, cell: ({ row: { original: r } }) => <ResultCell r={r} /> },
  ]
  return (
    <Section id="auto" title={t('auto.title')} description={t('auto.description')} info={t('auto.descriptionInfo')} stories={['S-SCAN-2']}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid gap-4">
            {!d.auto_rescan ? <Notice tone="warn" className="mb-0" title={t('auto.offNote')} info={t('auto.offNoteInfo')} /> : null}
            <DataTable urlKey="rescan-log" caption={t('auto.caption')} data={d.items} columns={columns} pageSize={10} empty={<EmptyState title={t('auto.empty')}>{t('auto.emptyHelp')}</EmptyState>} />
          </div>
        )}
      </QueryState>
    </Section>
  )
}
