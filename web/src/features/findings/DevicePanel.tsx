// The findings of one device, on its page: the badge and the counts per status (Overview's summary line and the Findings tab's
// count) and the Findings tab itself, which is this device's By device card: the same component and the same answer as the
// Findings screen (fix blocks, the most urgent first, each CVE one click from its finding, Mark as handled… in place), then the
// device's possible findings (CVEs Vedette cannot decide), what a check settled not affected, and the answers given.
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { useKeepListParams } from '@/components/common/listParams'
import { ListToolbar } from '@/components/common/ListParts'
import { QueryState } from '@/components/common/States'
import { StatusBadge } from '@/components/common/status'
import { useModuleEnabled } from '@/lib/modules'
import { OPEN_FINDING_STATUSES, type OpenFindingStatus } from '@/lib/statusCodes'
import type { DeviceBadgeValue } from '@/features/inventory/RiskMarker'
import { useDeviceCards, useHandledList, usePossibleCounts } from './api'
import { DeviceCardView, type Handling } from './ByDevice'
import { HandleDialog } from './HandleDialog'
import { DevicePossible, usePossibleCheckWatch } from './Possible'
import { StatusFilter, statusesOf } from './StatusFilter'
import type { DeviceCard } from './types'

const ONE = { offset: 0, limit: 1 }
/** The address key of the Findings tab's search text. */
const SEARCH_KEY = 'device-findings.q'

/** What the device page says about the device's findings: the badge, the open count and, from the model, the counts per status. */
export type DeviceFindingsSummary = {
  badge: DeviceBadgeValue
  open: number
  /** Open findings per status. */
  counts: Record<OpenFindingStatus, number> | null
  /** Possible CVEs of this device (0 when not known): counted apart from the open findings. */
  possible: number
}

/** The device's findings summary; undefined while loading or when the findings module is off. */
export function useDeviceFindingsSummary(assetId: string): DeviceFindingsSummary | undefined {
  const on = useModuleEnabled('findings') === true
  const cards = useDeviceCards({ device: assetId }, ONE, on)
  const counts = usePossibleCounts(assetId, on && cards.isSuccess)
  if (!on) return undefined
  if (!cards.data) return undefined
  const card = cards.data.items.find((c) => c.device.id === assetId) ?? null
  const possible = counts.data?.possible ?? 0
  return {
    badge: card?.status ?? (possible ? { code: 'possible', count: possible } : null),
    open: card?.findings ?? 0,
    counts: card?.counts ?? Object.fromEntries(OPEN_FINDING_STATUSES.map((s) => [s, 0])) as Record<OpenFindingStatus, number>,
    possible,
  }
}

/** Overview's line: the open findings by status and "View findings". */
export function DeviceFindingsLine({ summary }: { summary: DeviceFindingsSummary }) {
  const { t } = useTranslation('findings')
  const keep = useKeepListParams() // the page's lists keep their pages
  const statuses = summary.counts ? OPEN_FINDING_STATUSES.filter((s) => summary.counts![s] > 0) : []
  return (
    <div className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-2" data-testid="device-findings-line">
      <span className="text-sm font-medium">{summary.open ? t('device.open', { count: summary.open }) : t('device.noOpen')}</span>
      {/* the counts per status; the title's badge already leads to the most urgent ones, View findings to all */}
      {statuses.map((s) => <StatusBadge key={s} code={s} count={summary.counts![s]} />)}
      {summary.open ? <Link to={keep('?tab=findings')} className="text-sm font-medium text-accent underline-offset-4 hover:underline">{t('device.view')}</Link> : null}
      {summary.possible ? <Link to={`${keep('?tab=findings')}#possible`} className="text-sm text-accent underline-offset-4 hover:underline">{t('possible.countLink', { count: summary.possible })}</Link> : null}
    </div>
  )
}

/** The Findings tab: the device's card (filtered by the status toggles above it), Mark as handled… in place, the device's possible
 *  findings, and the way to what was handled. */
export function DeviceFindings({ assetId, summary }: { assetId: string; summary: DeviceFindingsSummary | undefined }) {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const status = statusesOf(params.get('status')).join(',')
  // searched like every other list (the CVE id, the software's name); one card, so no pages: only the text is in the address
  const q = params.get(SEARCH_KEY) ?? ''
  const setQ = (v: string) => setParams((prev) => {
    const p = new URLSearchParams(prev)
    if (v) p.set(SEARCH_KEY, v); else p.delete(SEARCH_KEY)
    return p
  }, { replace: true, preventScrollReset: true })
  const cards = useDeviceCards({ device: assetId, status, q }, ONE)
  const handled = useHandledList({ device: assetId }, ONE, cards.isSuccess)
  const [handling, setHandling] = useState<Handling | null>(null)
  const id = encodeURIComponent(assetId)
  const done = handled.data?.total ?? 0
  usePossibleCheckWatch() // a check of this device's possible findings runs in the background: its end is said here
  return (
    <section id="device-findings" aria-label={t('device.title')}>
      <div className="grid gap-3">
        {/* the toggles help only when the device has findings of two statuses or more (or a link brought one pressed) */}
        <ListToolbar search={summary?.open || q ? { value: q, onChange: setQ, label: t('device.search') } : undefined}>
          {summary?.counts && (status || OPEN_FINDING_STATUSES.filter((s) => summary.counts![s] > 0).length > 1) ? <StatusFilter counts={summary.counts} /> : null}
        </ListToolbar>
        <QueryState query={cards}>
          {(d) => {
            const card: DeviceCard | undefined = d.items.find((c) => c.device.id === assetId)
            if (!card) return <p className="text-sm text-muted">{q ? t('device.noneMatch', { q }) : status ? t('device.noneWithStatus') : t('device.none')}</p>
            return <Card><DeviceCardView own card={card} narrowed={!!status || !!q} onHandle={setHandling} /></Card>
          }}
        </QueryState>
        <DevicePossible assetId={assetId} />
        {done ? (
          <p className="text-sm">
            <Link to={`/findings?tab=handled&device=${id}`} className="text-accent underline-offset-4 hover:underline">{t('device.handled', { count: done })}</Link>
          </p>
        ) : null}
      </div>
      {handling ? <HandleDialog {...handling} onClose={() => setHandling(null)} /> : null}
    </section>
  )
}
