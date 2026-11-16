import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { ModuleOff, QueryState } from '@/components/common/States'
import { fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { FindingStatusChip } from './AcceptRisk'
import { useFindings, usePlan } from './api'
import type { SoftwareView } from '@/features/inventory/types'
import type { FindingRow } from './types'
import { isOpen, riskRank } from './basis'
import { RiskChip } from './Risk'
import { IUpdated } from './Updated'
import { useDeviceSoftware } from './rematch'
import { FixGroupList } from './FixGroups'
import { fixGroups } from './fix'
import { PlanDataState, PlanItems } from './Plan'

/** Slot device.panels (trang chi tiết thiết bị của module inventory): phát hiện của đúng thiết bị này. */
export function DevicePanel(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const { t } = useTranslation('findings')
  const on = useModuleEnabled('findings')
  const q = useFindings(assetId)
  const sw = useDeviceSoftware(assetId)
  if (on === false) return <Section title={t('device.title')}><ModuleOff module="findings" /></Section>
  return (
    <>
    <Section id="device-findings" title={t('device.title')} description={t('device.description')} stories={['S-MIT-1']}>
      <QueryState query={q}>
        {(d) => d.items.length === 0 ? (
          <p className="text-sm text-muted">{t('device.none')}</p>
        ) : (() => {
          // D-545: the findings one update fixes are one item; the rest are listed one by one.
          const { groups, rest } = fixGroups(d.items)
          return (
          <div className="grid gap-2">
          {d.items.some((f) => isOpen(f.status)) ? (
            <Link to={`/findings?device=${encodeURIComponent(assetId)}`} className="w-fit text-[13px] text-accent underline underline-offset-4">{t('device.handleAll')}</Link>
          ) : null}
          <Updated items={d.items} software={sw.data?.asset.software} />
          <FixGroupList groups={groups} showDevice={false} />
          {rest.length ? <ul className="divide-y divide-rule rounded-md border border-rule bg-surface">
            {[...rest].sort((a, b) => riskRank(b) - riskRank(a)).map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
                <span className="text-sm text-muted">{f.kev?.display ?? ''}</span>
                <FindingStatusChip f={f} />
                <RiskChip f={f} />
                <span className="ml-auto text-[12px] text-muted">{t('device.lastSeen', { time: fmtRelative(f.last_seen) })}</span>
              </li>
            ))}
          </ul> : null}
          </div>
          )
        })()}
      </QueryState>
    </Section>
    <DevicePlan assetId={assetId} />
    </>
  )
}

/** D-613 (S-TIER-1): the updates to plan of this device, below its findings; never findings, never alerts. */
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
            {d.compared && d.items.length > 0 ? <PlanItems items={d.items} showDevice={false} /> : null}
            {d.compared && d.items.length === 0 && (d.data.epss === 'ready' || d.data.recent === 'ready') ? <p className="text-sm text-muted">{t('plan.device.none')}</p> : null}
            <Link to="/plan" className="w-fit text-[13px] text-accent underline underline-offset-4">{t('plan.device.all')}</Link>
          </div>
        )}
      </QueryState>
    </Section>
  )
}

/** D-499: "I updated <software>" for each hand-added software with findings; a scanned one is checked by a scan. */
function Updated({ items, software }: { items: FindingRow[]; software: SoftwareView[] | undefined }) {
  const asset = items.find((f) => f.asset)?.asset
  // Any finding, not only open ones: the button stays while its dialog says what the re-match closed.
  const manual = (software ?? []).filter((s) => s.source === 'manual' && items.some((f) => s.kev_cves.includes(f.cve)))
  if (!asset || manual.length === 0) return null
  return <div className="flex flex-wrap gap-2">{manual.map((s) => <IUpdated key={s.id} size="sm" asset={asset} software={s} />)}</div>
}
