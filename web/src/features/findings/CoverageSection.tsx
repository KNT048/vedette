import { useTranslation } from 'react-i18next'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { fmtDateTime } from '@/lib/format'
import { useCoverage } from './api'
import type { Coverage } from './types'

/** One row of the coverage table: a source that decided pairs, or a reason pairs stay undecided. */
type Row = { key: string; outcome: 'decided' | 'undecided'; name: string; affected: number | null; notAffected: number | null; pairs: number }

/** The rows of the table: decided by source, then undecided by cause, each the most first (the box's order). */
export function coverageRows(c: Coverage): Row[] {
  return [
    ...c.decided.map((d): Row => ({ key: `d-${d.by}`, outcome: 'decided', name: d.by, affected: d.affected, notAffected: d.not_affected, pairs: d.affected + d.not_affected })),
    ...c.possible.map((p): Row => ({ key: `u-${p.cause}`, outcome: 'undecided', name: p.cause, affected: null, notAffected: null, pairs: p.count })),
  ]
}

/** A share of a whole as a percentage with one decimal ("1.9 %"); 0 % of nothing. */
export function share(n: number, of: number): string {
  return `${(of > 0 ? (100 * n) / of : 0).toFixed(1)} %`
}

/** Settings → Diagnostics (admin): what the last match pass decided, by source, and why the rest is undecided, by reason (S-MIT-1). */
export default function CoverageSection() {
  const { t } = useTranslation('findings')
  const q = useCoverage()
  return (
    <>
      <PageHeader title={t('coverage.title')} meta={t('coverage.meta')} info={t('coverage.info')} stories={['S-MIT-1']} />
      <QueryState query={q}>{(c) => (c.at === null ? <EmptyState title={t('coverage.title')}>{t('coverage.none')}</EmptyState> : <CoverageTable c={c} />)}</QueryState>
    </>
  )
}

function CoverageTable({ c }: { c: Coverage }) {
  const { t } = useTranslation('findings')
  const fmt = (n: number | null) => (n === null ? '' : n.toLocaleString('en'))
  const decided = c.decided.reduce((n, d) => n + d.affected + d.not_affected, 0)
  const undecided = c.possible.reduce((n, p) => n + p.count, 0)
  const other = c.possible.reduce((n, p) => n + (p.cause.startsWith('other') ? p.count : 0), 0) // every class nobody is told the reason of
  const label = (r: Row) => (r.outcome === 'decided' ? t(`coverage.by.${r.name}`, { defaultValue: r.name }) : t(`coverage.cause.${r.name}`, { defaultValue: r.name }))
  const columns: ColumnDef<Row>[] = [
    { id: 'outcome', header: t('coverage.col.outcome'), enableSorting: false, accessorFn: (r) => r.outcome, cell: ({ row }) => t(`coverage.outcome.${row.original.outcome}`) },
    { id: 'source', header: t('coverage.col.source'), enableSorting: false, accessorFn: (r) => label(r), cell: ({ row }) => <span title={row.original.name}>{label(row.original)}</span> },
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
      <DataTable urlKey="coverage" data={coverageRows(c)} columns={columns} caption={t('coverage.caption')} search={false} pageSize={50} />
    </Section>
  )
}
