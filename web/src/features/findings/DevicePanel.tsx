// The findings of one device, on its page: the badge and the counts per status (Overview's summary line and the Findings tab's
// count) and the Findings tab itself, which is this device's By device card: the same component and the same answer as the
// Findings screen (fix blocks, the most urgent first, each CVE one click from its finding, Mark as handled… in place).
//
// The device page reads the findings model (GET /findings/devices?device=). While the box answers that read 501 not_implemented
// (a backend from before the model), the tab shows the earlier list of the device's findings instead: `LegacyDeviceFindings`
// below, the one place to delete once every backend serves the model.
import { useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { useKeepListParams } from '@/components/common/listParams'
import { Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { StatusBadge, SeverityBadge } from '@/components/common/status'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { OPEN_FINDING_STATUSES, type OpenFindingStatus } from '@/lib/statusCodes'
import { badgeOfRisk, type DeviceBadgeValue } from '@/features/inventory/RiskMarker'
import type { DeviceRisk, SoftwareLine } from '@/features/inventory/types'
import { useDeviceCards, useFindings, useHandledList, useInputList, useToFix } from './api'
import { DeviceCardView, type Handling } from './ByDevice'
import { HandleDialog } from './HandleDialog'
import { StatusFilter, statusesOf } from './StatusFilter'
import { FindingStatus, legacySeverity } from './legacyStatus'
import { isOpen, riskRank } from './basis'
import { IUpdated, type UpdatedSoftware } from './Updated'
import { useDeviceSoftware } from './rematch'
import { DeviceCard as ToFixCard, WithBox, actionable, listed as hasWork, typedSoftware } from './ToFix'
import { NotRelevantToggle, withoutNotRelevant } from './notRelevant'
import { RowActions } from './Handle'
import type { DeviceCard, FindingRow, ToFixDevice } from './types'

const ONE = { offset: 0, limit: 1 }
const modelMissing = (e: unknown) => e instanceof ApiError && e.status === 501
/** Whether the box answered the model's read 501, remembered for as long as the component lives: a refetch clears the error while it
 *  runs, and the earlier list (with a dialog open in it) must not unmount and come back meanwhile. */
function useBeforeModel(error: unknown): boolean {
  const [seen, setSeen] = useState(false)
  const now = modelMissing(error)
  if (now && !seen) setSeen(true) // kept from this render on (React's state derived during render)
  return seen || now
}

/** What the device page says about the device's findings: the badge, the open count and, from the model, the counts per status. */
export type DeviceFindingsSummary = {
  badge: DeviceBadgeValue
  open: number
  /** Open findings per status; null on a backend from before the findings model. */
  counts: Record<OpenFindingStatus, number> | null
  /** Items of Needs your input for this device (0 when not known). */
  input: number
}

/** The device's findings summary; undefined while loading or when the findings module is off. `risk` is the device's older
 *  marker, the badge on a backend from before the findings model. */
export function useDeviceFindingsSummary(assetId: string, risk: DeviceRisk | null | undefined): DeviceFindingsSummary | undefined {
  const on = useModuleEnabled('findings') === true
  const cards = useDeviceCards({ device: assetId }, ONE, on)
  const legacy = useBeforeModel(cards.error)
  const input = useInputList({ device: assetId }, ONE, on && !legacy && cards.isSuccess)
  const old = useFindings(assetId, on && legacy)
  if (!on) return undefined
  if (legacy) return old.data ? { badge: badgeOfRisk(risk), open: old.data.items.filter((f) => isOpen(f.status)).length, counts: null, input: 0 } : undefined
  if (!cards.data) return undefined
  const card = cards.data.items.find((c) => c.device.id === assetId) ?? null
  const waiting = input.data?.total ?? 0
  return {
    badge: card?.status ?? (waiting ? { code: 'needs_input', count: waiting } : null),
    open: card?.findings ?? 0,
    counts: card?.counts ?? Object.fromEntries(OPEN_FINDING_STATUSES.map((s) => [s, 0])) as Record<OpenFindingStatus, number>,
    input: waiting,
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
    </div>
  )
}

/** The Findings tab: the device's card (filtered by the status toggles above it), Mark as handled… in place, and the way to what
 *  waits for an answer and to what was handled. */
export function DeviceFindings({ assetId, summary }: { assetId: string; summary: DeviceFindingsSummary | undefined }) {
  const { t } = useTranslation('findings')
  const [params] = useSearchParams()
  const status = statusesOf(params.get('status')).join(',')
  const cards = useDeviceCards({ device: assetId, status }, ONE)
  const handled = useHandledList({ device: assetId }, ONE, cards.isSuccess)
  const [handling, setHandling] = useState<Handling | null>(null)
  const beforeModel = useBeforeModel(cards.error)
  if (beforeModel) return <Section id="device-findings" title={t('device.title')}><LegacyDeviceFindings assetId={assetId} /></Section>
  const id = encodeURIComponent(assetId)
  const input = summary?.input ?? 0
  const done = handled.data?.total ?? 0
  return (
    <Section id="device-findings" title={t('device.title')} stories={['S-MIT-1']}>
      <div className="grid gap-3">
        {/* the toggles help only when the device has findings of two statuses or more (or a link brought one pressed) */}
        {summary?.counts && (status || OPEN_FINDING_STATUSES.filter((s) => summary.counts![s] > 0).length > 1) ? <StatusFilter counts={summary.counts} /> : null}
        <QueryState query={cards}>
          {(d) => {
            const card: DeviceCard | undefined = d.items.find((c) => c.device.id === assetId)
            if (!card) return <p className="text-sm text-muted">{status ? t('device.noneWithStatus') : t('device.none')}</p>
            return <Card><DeviceCardView own card={card} narrowed={!!status} onHandle={setHandling} /></Card>
          }}
        </QueryState>
        {input || done ? (
          <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {input ? <Link to={`/findings?tab=input&device=${id}`} className="font-medium text-accent underline-offset-4 hover:underline">{t('device.input', { count: input })}</Link> : null}
            {done ? <Link to={`/findings?tab=handled&device=${id}`} className="text-accent underline-offset-4 hover:underline">{t('device.handled', { count: done })}</Link> : null}
          </p>
        ) : null}
      </div>
      {handling ? <HandleDialog {...handling} onClose={() => setHandling(null)} /> : null}
    </Section>
  )
}

/** The device's findings from the endpoints before the findings model: its To fix card and every finding of the device, one row each. */
function LegacyDeviceFindings({ assetId }: { assetId: string }) {
  const { t } = useTranslation('findings')
  const q = useFindings(assetId)
  const toFix = useToFix(assetId)
  const sw = useDeviceSoftware(assetId)
  const [showNotRelevant, setShowNotRelevant] = useState(false)
  const found = toFix.data?.devices.find((x) => x.asset.id === assetId)
  const card = found && hasWork(found) ? found : undefined
  return (
    <>
      {card ? (actionable(card).some((a) => a.kind === 'distro')
        ? <WithBox>{(boxId) => <ul aria-label={t('device.todo')} className="mb-3 grid"><ToFixCard d={card} box={boxId === assetId} showName={false} typed={false} /></ul>}</WithBox>
        : <ul aria-label={t('device.todo')} className="mb-3 grid"><ToFixCard d={card} box={false} showName={false} typed={false} /></ul>) : null}
      <Updated card={card} items={q.data?.items} software={sw.data?.asset.software} />
      <QueryState query={q}>
        {(d) => {
          if (d.items.length === 0) return card ? null : <p className="text-sm text-muted">{t('device.none')}</p>
          const listed = withoutNotRelevant(d.items, showNotRelevant)
          const toggle = <NotRelevantToggle count={listed.total} shown={showNotRelevant} onChange={setShowNotRelevant} />
          if (listed.rows.length === 0) return <div className="grid gap-1"><p className="text-sm text-muted">{t('device.onlyNotRelevant', { count: listed.total })}</p>{toggle}</div>
          return (
            <div className="grid gap-2">
              <Card flush><ul aria-label={t('device.all')} className="divide-y divide-rule">
                {[...listed.rows].sort((a, b) => riskRank(b) - riskRank(a)).map((f) => (
                  <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                    <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
                    <span className="text-sm text-muted">{f.kev?.display ?? ''}</span>
                    <FindingStatus f={f} />
                    <SeverityBadge severity={legacySeverity(f)} />
                    <span className="ml-auto text-caption text-muted" title={`${fmtDateTime(f.last_seen)}. ${t('matchedInfo')}`}>{t('matched', { time: fmtRelative(f.last_seen) })}</span>
                    <RowActions f={f} />
                  </li>
                ))}
              </ul></Card>
              {toggle}
            </div>
          )
        }}
      </QueryState>
    </>
  )
}

/** "I updated <software>" for each hand-added software of the device, one button per software however many rows name it. A software
 *  shown once stays mounted for the visit, so its dialog can say what the re-match closed after the row is gone. */
function Updated({ card, items = [], software }: { card: ToFixDevice | undefined; items?: FindingRow[]; software: SoftwareLine[] | undefined }) {
  const kept = useRef(new Map<string, UpdatedSoftware>())
  const seen = useRef<FindingRow['asset'] | undefined>(undefined)
  const asset = (seen.current = card?.asset ?? items.find((f) => f.asset)?.asset ?? seen.current)
  const rows = card ? typedSoftware(card) : new Map<string, { software: UpdatedSoftware }>()
  for (const [id, r] of rows) {
    const s = software?.find((x) => x.id === id)
    kept.current.set(id, s ? { ...s, kev_cves: [...new Set([...s.kev_cves, ...r.software.kev_cves])] } : r.software)
  }
  for (const s of software ?? []) {
    if (s.source === 'manual' && !rows.has(s.id) && items.some((f) => s.kev_cves.includes(f.cve))) kept.current.set(s.id, s)
  }
  if (!asset || kept.current.size === 0) return null
  const active = (s: UpdatedSoftware) => rows.has(s.id) || items.some((f) => isOpen(f.status) && s.kev_cves.includes(f.cve))
  return <div className="mb-3 flex flex-wrap gap-2 empty:hidden">{[...kept.current.values()].map((s) => <IUpdated key={s.id} size="sm" asset={asset} software={s} active={active(s)} />)}</div>
}
