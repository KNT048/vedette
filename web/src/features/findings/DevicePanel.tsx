import { useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { ModuleOff, QueryState } from '@/components/common/States'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { FindingStatusChip } from './AcceptRisk'
import { useFindings, usePlan, useToFix } from './api'
import type { SoftwareView } from '@/features/inventory/types'
import type { FindingRow, ToFixDevice } from './types'
import { isOpen, riskRank } from './basis'
import { RiskChip } from './Risk'
import { IUpdated, type UpdatedSoftware } from './Updated'
import { useDeviceSoftware } from './rematch'
import { PlanDataState } from './Plan'
import { DeviceCard, WithBox, actionable, listed as hasWork, typedSoftware } from './ToFix'
import { NotRelevantToggle, withoutNotRelevant } from './notRelevant'
import { RowActions } from './Handle'

/** Slot device.panels (trang chi tiết thiết bị của module inventory): phát hiện của đúng thiết bị này. */
export function DevicePanel(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const { t } = useTranslation('findings')
  const on = useModuleEnabled('findings')
  const q = useFindings(assetId)
  const toFix = useToFix(assetId, on === true)
  const sw = useDeviceSoftware(assetId)
  const [showNotRelevant, setShowNotRelevant] = useState(false)
  const found = toFix.data?.devices.find((x) => x.asset.id === assetId)
  const card = found && hasWork(found) ? found : undefined
  if (on === false) return <Section title={t('device.title')}><ModuleOff module="findings" /></Section>
  return (
    <>
    <Section id="device-findings" title={t('device.title')} description={t('device.description')} stories={['S-MIT-1']}>
      {/* The device's To fix card whenever it has any action, recommended updates only included */}
      {card ? (actionable(card).some((a) => a.kind === 'distro')
        ? <WithBox>{(boxId) => <ul aria-label={t('device.todo')} className="mb-3 grid"><DeviceCard d={card} box={boxId === assetId} showName={false} typed={false} /></ul>}</WithBox>
        : <ul aria-label={t('device.todo')} className="mb-3 grid"><DeviceCard d={card} box={false} showName={false} typed={false} /></ul>) : null}
      {/* "I updated <software>" once per typed software, right after the card's rows */}
      <Updated card={card} items={q.data?.items} software={sw.data?.asset.software} />
      <QueryState query={q}>
        {(d) => d.items.length === 0 ? (
          card ? null : <p className="text-sm text-muted">{t('device.none')}</p>
        ) : (() => {
          // Not relevant is hidden until asked for. What to do is the device's To fix card, the
          // same answer and component as Findings (one grouping on the page); below it every finding of the device, one row each.
          const listed = withoutNotRelevant(d.items, showNotRelevant)
          const rest = listed.rows
          const toggle = <NotRelevantToggle count={listed.total} shown={showNotRelevant} onChange={setShowNotRelevant} />
          if (listed.rows.length === 0) return <div className="grid gap-1"><p className="text-sm text-muted">{t('device.onlyNotRelevant', { count: listed.total })}</p>{toggle}</div>
          return (
          <div className="grid gap-2">
          {/* each finding is handled on its own line (Confirm or Mark as handled…, the rest under More actions); the device page has
              its own Add device and Ignore */}
          {rest.length ? <Card flush><ul aria-label={t('device.all')} className="divide-y divide-rule">
            {[...rest].sort((a, b) => riskRank(b) - riskRank(a)).map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
                <span className="text-sm text-muted">{f.kev?.display ?? ''}</span>
                <FindingStatusChip f={f} />
                <RiskChip f={f} />
                <span className="ml-auto text-caption text-muted" title={`${fmtDateTime(f.last_seen)}. ${t('matchedInfo')}`}>{t('matched', { time: fmtRelative(f.last_seen) })}</span>
                <RowActions f={f} />
              </li>
            ))}
          </ul></Card> : null}
          {toggle}
          </div>
          )
        })()}
      </QueryState>
    </Section>
    <DevicePlan assetId={assetId} />
    </>
  )
}

/** S-TIER-1: the updates to plan of this device, below its findings; never findings, never alerts. */
function DevicePlan({ assetId }: { assetId: string }) {
  const { t } = useTranslation('findings')
  const q = usePlan('all', assetId)
  if (!q.data?.compared) return null // review r1 #4 of #803: nothing to show on every device page until this version compares
  return (
    <Section id="device-plan" title={t('plan.device.title')} description={t('plan.device.description')} info={t('plan.device.descriptionInfo')} stories={['S-TIER-1', 'S-TIER-2']}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid gap-2">
            <PlanDataState plan={d} compact />
            {/* The updates themselves are on the device's To fix card above (one grouping on the page) */}
            {d.compared && d.items.length === 0 && (d.data.epss === 'ready' || d.data.recent === 'ready') ? <p className="text-sm text-muted">{t('plan.device.none')}</p> : null}
            {/* The way to every update to plan only when this device has some (no link to an empty list) */}
            {d.items.length > 0 ? <Link to="/plan" className="w-fit text-meta text-accent underline underline-offset-4">{t('plan.device.all')}</Link> : null}
          </div>
        )}
      </QueryState>
    </Section>
  )
}

/** "I updated <software>" for each hand-added software of the device, one button per software however many rows name it (the
 *  card's update rows, exploited and recommended, and its findings); a scanned or agent-read one is on the card (DeviceUpdated).
 *  A software shown once stays mounted for the visit, so its dialog can say what the re-match closed after the row is gone; the button
 *  shows only while a row of the card or an open finding names it. */
function Updated({ card, items = [], software }: { card: ToFixDevice | undefined; items?: FindingRow[]; software: SoftwareView[] | undefined }) {
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
