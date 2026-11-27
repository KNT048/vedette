import { useTranslation } from 'react-i18next'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { useCoverage } from './api'
import { coverageRows, share, type CoverageRow as Row } from './coverage'
import type { Coverage } from './types'

/** Settings → Diagnostics (admin): what the last match pass decided, by source, and why the rest is undecided, by reason (S-MIT-1). */
export default function CoverageSection() {
  const { t } = useTranslation('findings')
  const q = useCoverage()
  return (
    <>
      <PageHeader title={t('common:shell.diagnostics')} meta={t('coverage.meta')} info={t('coverage.info')} stories={['S-MIT-1']} />
      <QueryState query={q}>{(c) => (c.at === null ? <EmptyState title={t('common:shell.diagnostics')}>{t('coverage.none')}</EmptyState> : <CoverageTable c={c} />)}</QueryState>
    </>
  )
}

function CoverageTable({ c }: { c: Coverage }) {
  const { t } = useTranslation('findings')
  const fmt = (n: number | null) => (n === null ? '' : fmtNumber(n))
  const decided = c.decided.reduce((n, d) => n + d.affected + d.not_affected, 0)
  const undecided = c.possible.reduce((n, p) => n + p.count, 0)
  const other = c.possible.reduce((n, p) => n + (p.cause.startsWith('other') ? p.count : 0), 0) // every class nobody is told the reason of
  const label = (r: Row) => (r.outcome === 'decided' ? t(`coverage.by.${r.name}`, { defaultValue: r.name }) : t(`coverage.cause.${r.name}`, { defaultValue: r.name }))
  const columns: ColumnDef<Row>[] = [
    { id: 'outcome', header: t('coverage.col.outcome'), enableSorting: false, accessorFn: (r) => r.outcome, cell: ({ row }) => t(`coverage.outcome.${row.original.outcome}`) },
    { id: 'source', header: t('coverage.col.source'), enableSorting: false, accessorFn: (r) => label(r), cell: ({ row }) => <span title={row.original.name}>{label(row.original)}</span> },
    { id: 'detail', header: t('coverage.col.detail'), enableSorting: false, accessorFn: (r) => r.details.map((d) => d.detail).join(' '),
      cell: ({ row }) => <span className="text-meta text-muted">{row.original.details.map((d) => `${t(`coverage.cause.${d.detail}`, { defaultValue: d.detail })} ${fmt(d.count)}`).join(' · ')}</span> },
    { id: 'affected', header: t('coverage.col.affected'), enableSorting: false, accessorFn: (r) => r.affected, cell: ({ row }) => <span className="tabular-nums">{fmt(row.original.affected)}</span> },
    { id: 'notAffected', header: t('coverage.col.notAffected'), enableSorting: false, accessorFn: (r) => r.notAffected, cell: ({ row }) => <span className="tabular-nums">{fmt(row.original.notAffected)}</span> },
    { id: 'pairs', header: t('coverage.col.pairs'), enableSorting: false, accessorFn: (r) => r.pairs, cell: ({ row }) => <span className="tabular-nums">{fmt(row.original.pairs)}</span> },
    { id: 'share', header: t('coverage.col.share'), enableSorting: false, accessorFn: (r) => r.pairs, cell: ({ row }) => <span className="tabular-nums">{share(row.original.pairs, c.pairs)}</span> },
  ]
  const identity = c.identity.map((m) => t(`coverage.method.${m.method}`, { n: fmt(m.lines) })).join(', ')
  return (
    <Section id="coverage" label={t('coverage.caption')}
      description={<>
        <span className="block">{t('coverage.at', { at: fmtDateTime(c.at), devices: fmt(c.devices), lines: fmt(c.lines), pairs: fmt(c.pairs) })}</span>
        <span className="block font-medium text-ink">{t('coverage.decidedShare', { share: share(decided, c.pairs) })} · {t('coverage.undecidedShare', { share: share(undecided, c.pairs) })} · {t('coverage.otherShare', { share: share(other, c.pairs) })}</span>
        <span className="block">{t('coverage.identity', { list: identity })}</span>
      </>}>
      <DataTable urlKey="coverage" data={coverageRows(c)} columns={columns} caption={t('coverage.caption')} pageSize={50} />
    </Section>
  )
}
