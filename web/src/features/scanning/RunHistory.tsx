import { useEffect, useMemo, useRef } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { fmtDateTime } from '@/lib/format'
import { useScanningHistory } from './api'
import type { HistoryRun } from './types'

const tone = { ok: 'ok', partial: 'warn', failed: 'danger', stopped: 'warn', running: 'accent' } as const

/** A run's outcome as History says it: the chip and the sentence the box wrote from what the run stored. The device
 *  page's Last checks shows the same. */
export function HistoryOutcome({ r }: { r: HistoryRun }) {
  const { t } = useTranslation('scanning')
  return <div className="grid justify-items-start gap-1 text-meta"><Chip tone={tone[r.outcome]}>{t(`history.outcome.${r.outcome}`)}</Chip><span>{r.text}</span></div>
}

/** One run, as the phone list shows it (and the run a link opened). */
function RunCard({ r }: { r: HistoryRun }) {
  const { t } = useTranslation('scanning')
  return (
    <div className="grid gap-1.5">
      <div className="flex items-start justify-between gap-3">
        <span className="font-medium">{r.label}</span>
        <Chip tone={tone[r.outcome]}>{t(`history.outcome.${r.outcome}`)}</Chip>
      </div>
      <span className="text-meta text-muted">{fmtDateTime(r.started_at)} · {t(`history.kind.${r.kind}`)}, {t(`history.trigger.${r.trigger}`)}</span>
      <span className="text-meta">{r.text}</span>
    </div>
  )
}

/** The run a link from a device page opened (?job=), above the table so it is seen whatever page of the table it is on. */
function Opened({ r }: { r: HistoryRun | undefined }) {
  const { t } = useTranslation('scanning')
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { ref.current?.scrollIntoView?.({ block: 'center' }) }, [r?.id])
  return (
    <div ref={ref} role="region" aria-label={t('history.opened')} className="mb-4 grid gap-2 rounded-md border border-accent/40 bg-accent-soft p-4">
      <h3 className="text-sm font-semibold">{t('history.opened')}</h3>
      {r ? <RunCard r={r} /> : <p className="text-meta text-muted">{t('history.openedGone')}</p>}
    </div>
  )
}

/**
 * Settings › Scanning › History lists every run, not only the vulnerability checks: discovery sweeps, the identification
 * of a device ("Check this device now", the first step of Scan now, the window's queue), SNMP reads and the scans of public
 * targets, each with what it found in words. Served by core (GET /scanning/history), so it answers while the scan module is off.
 * From a device page's Last checks, ?asset= lists only that device's runs and ?job= shows the run it opened on top.
 */
export function RunHistory() {
  const { t } = useTranslation('scanning')
  const [params] = useSearchParams()
  const asset = params.get('asset')
  const job = params.get('job')
  const q = useScanningHistory(asset)
  const columns = useMemo<ColumnDef<HistoryRun>[]>(() => [
    { id: 'started', header: t('history.col.started'), accessorFn: (r) => r.started_at, cell: ({ row: { original: r } }) => <span className="whitespace-nowrap">{fmtDateTime(r.started_at)}</span> },
    { id: 'what', header: t('history.col.what'), accessorFn: (r) => r.label, cell: ({ row: { original: r } }) => (
      <div className="grid text-meta">
        {r.kind === 'external' && r.target_id ? <Link to={`/exposure/${encodeURIComponent(r.target_id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.label}</Link> : <span className="font-medium">{r.label}</span>}
        <span className="text-muted">{t(`history.kind.${r.kind}`)}, {t(`history.trigger.${r.trigger}`)}</span>
      </div>
    ) },
    { id: 'outcome', header: t('history.col.outcome'), accessorFn: (r) => r.outcome, cell: ({ row: { original: r } }) => <HistoryOutcome r={r} /> },
  ], [t])
  return (
    <Section id="run-history" title={t('history.title')} description={t('history.description')} info={t('history.descriptionInfo')} stories={['S-SCAN-4', 'S-INV-1']}>
      {asset ? (
        <p className="mb-3 flex flex-wrap gap-x-3 gap-y-1 text-meta">
          <span>{t('history.oneDevice')}</span>
          <Link to={`/devices/${encodeURIComponent(asset)}`} className="text-accent underline-offset-4 hover:underline">{t('history.seeDevice')}</Link>
          <Link to="/settings/scanning?tab=history" className="text-accent underline-offset-4 hover:underline">{t('history.showAll')}</Link>
        </p>
      ) : null}
      <QueryState query={q}>
        {(d) => (
          <>
            {job ? <Opened r={d.items.find((r) => r.id === job)} /> : null}
            <DataTable caption={t('history.caption')} data={d.items} columns={columns} pageSize={20} empty={t(asset ? 'history.emptyDevice' : 'history.empty')}
              mobileRow={(r) => <RunCard r={r} />} />
          </>
        )}
      </QueryState>
    </Section>
  )
}
