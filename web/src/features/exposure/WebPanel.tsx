import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import type { Snapshot, WebFinding } from './types'

const ORDER = { high: 0, medium: 1, low: 2, info: 3 } as const

/** S-EXP-2 (INV-24, D-562): what ZAP's passive web scan noticed. Apart from the exploited CVEs: these are hints, never "exploited". */
export function WebSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const rows = [...s.web_findings].sort((a, b) => ORDER[a.risk] - ORDER[b.risk])
  const scanned = s.checks.some((c) => c.kind === 'web')
  const why = s.not_checked.find((n) => n.kind === 'web')
  const cols: ColumnDef<WebFinding>[] = [
    { id: 'risk', header: t('web.col.risk'), accessorFn: (r) => ORDER[r.risk], cell: ({ row }) => <Chip tone={row.original.risk === 'high' || row.original.risk === 'medium' ? 'warn' : 'off'}>{t(`web.risk.${row.original.risk}`)}</Chip> },
    { id: 'alert', header: t('web.col.alert'), accessorFn: (r) => r.name, cell: ({ row }) => (
      <span className="grid gap-1">
        <span className="font-medium">{row.original.name}</span>
        <span className="text-[12px] text-muted">{row.original.description}</span>
        {row.original.cwe > 0 ? (
          <a className="w-fit text-[12px] text-accent underline underline-offset-4" href={`https://cwe.mitre.org/data/definitions/${row.original.cwe}.html`} target="_blank" rel="noopener noreferrer" aria-label={t('web.cweLink', { id: row.original.cwe })}>{t('web.cwe', { id: row.original.cwe })}</a>
        ) : null}
      </span>
    ) },
    { id: 'confidence', header: t('web.col.confidence'), accessorFn: (r) => r.confidence, cell: ({ row }) => t(`web.confidence.${row.original.confidence}`) },
    { id: 'pages', header: t('web.col.pages'), enableSorting: false, accessorFn: (r) => r.urls.join(' '), cell: ({ row }) => (
      <span className="grid gap-0.5 text-[12px]">
        {row.original.urls.map((u) => <span key={u} className="break-all">{u}</span>)}
        {row.original.count > row.original.urls.length ? <span className="text-muted">{t('web.pagesMore', { count: row.original.count })}</span> : null}
      </span>
    ) },
    { id: 'fix', header: t('web.col.fix'), enableSorting: false, accessorFn: (r) => r.solution, cell: ({ row }) => <span className="text-[13px]">{row.original.solution}</span> },
  ]
  return (
    <Section id="web" title={t('web.title')} description={rows.length > 0 || scanned ? t('web.description') : undefined}>
      {rows.length > 0 ? (
        <DataTable caption={t('web.caption')} data={rows} columns={cols} pageSize={20} rowTone={(r) => (r.risk === 'high' ? 'warn' : undefined)} />
      ) : scanned ? (
        <EmptyState title={t('web.noneTitle')}>{t('web.noneBody')}</EmptyState>
      ) : (
        <EmptyState title={t('web.notScannedTitle')}>{why?.text ?? t('web.notScannedBody')}</EmptyState>
      )}
    </Section>
  )
}
