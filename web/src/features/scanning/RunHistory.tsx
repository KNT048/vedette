import { useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { fmtDateTime } from '@/lib/format'
import { useScanningHistory } from './api'
import type { HistoryRun } from './types'

const tone = { ok: 'ok', partial: 'warn', failed: 'danger', stopped: 'warn', running: 'accent' } as const

/**
 * kien G7a: Settings › Scanning › History lists every run, not only the vulnerability checks: discovery sweeps, the identification
 * of a device ("Check this device now", the first step of Scan now, the window's queue), SNMP reads and the scans of public
 * targets, each with what it found in words. Served by core (GET /scanning/history), so it answers while the scan module is off.
 */
export function RunHistory() {
  const { t } = useTranslation('scanning')
  const q = useScanningHistory()
  const columns = useMemo<ColumnDef<HistoryRun>[]>(() => [
    { id: 'started', header: t('history.col.started'), accessorFn: (r) => r.started_at, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.started_at)}</span> },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.label, cell: ({ row: { original: r } }) => (
      <div className="grid text-meta">
        {r.kind === 'external' && r.target_id ? <Link to={`/exposure/${encodeURIComponent(r.target_id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.label}</Link> : <span className="font-medium">{r.label}</span>}
        <span className="text-muted">{t(`history.kind.${r.kind}`)}, {t(`history.trigger.${r.trigger}`)}</span>
      </div>
    ) },
    { id: 'outcome', header: t('history.col.outcome'), accessorFn: (r) => r.outcome, cell: ({ row: { original: r } }) => (
      <div className="grid justify-items-start gap-1 text-meta"><Chip tone={tone[r.outcome]}>{t(`history.outcome.${r.outcome}`)}</Chip><span>{r.text}</span></div>
    ) },
  ], [t])
  return (
    <Section id="run-history" title={t('history.title')} description={t('history.description')} info={t('history.descriptionInfo')} stories={['S-SCAN-4', 'S-INV-1']}>
      <QueryState query={q}>
        {(d) => (
          <DataTable caption={t('history.caption')} data={d.items} columns={columns} pageSize={20} empty={t('history.empty')}
            mobileRow={(r) => (
              <div className="grid gap-1.5">
                <div className="flex items-start justify-between gap-3">
                  <span className="font-medium">{r.label}</span>
                  <Chip tone={tone[r.outcome]}>{t(`history.outcome.${r.outcome}`)}</Chip>
                </div>
                <span className="text-meta text-muted">{fmtDateTime(r.started_at)} · {t(`history.kind.${r.kind}`)}, {t(`history.trigger.${r.trigger}`)}</span>
                <span className="text-meta">{r.text}</span>
              </div>
            )} />
        )}
      </QueryState>
    </Section>
  )
}
