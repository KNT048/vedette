// Updates to plan (S-TIER-1, S-TIER-2; D-613, D-615, D-616, D-623): route /plan, Monitor group after Findings, module findings.
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { Segmented } from '@/components/ui/segmented'
import { fmtDay } from '@/features/feeds/dates'
import { usePlan } from './api'
import { PlanDataState, PlanItems } from './Plan'
import type { PlanFilter } from './types'

const FILTERS: PlanFilter[] = ['likely', 'recent', 'all']

function Page() {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const asked = FILTERS.find((f) => f === params.get('tier'))
  // D-623: until a person picks a filter, the page opens on "Likely to be exploited" whenever some update fixes such a CVE: it asks
  // for that tier first and for "All" only when it is empty (review r1 #5 of #808: never the heaviest answer just to choose)
  const likely = usePlan('likely', undefined, !asked)
  const tier: PlanFilter = asked ?? (likely.data && likely.data.items.length === 0 ? 'all' : 'likely')
  const q = usePlan(tier)
  const p = q.data
  const setTier = (v: PlanFilter) => { params.set('tier', v); setParams(params, { replace: true }) }
  const dataLine = p && (p.data.epss_date || p.data.recent_since) ? [
    p.data.epss_date ? t('plan.dataEpss', { date: fmtDay(p.data.epss_date) }) : null,
    p.data.recent_since ? t('plan.dataRecent', { date: fmtDay(p.data.recent_since) }) : null,
  ].filter(Boolean).join(' · ') : null
  return (
    <>
      <PageHeader
        title={!p || !p.compared || p.items.length === 0 ? t('plan.title') : t('plan.titleCount', { count: p.items.length })}
        stories={['S-TIER-1', 'S-TIER-2']}
        meta={dataLine}
        info={<><p>{t('plan.intro')}</p><p>{t('plan.introInfo')}</p></>}
        actions={<SampleDataNote />}
      />
      <p className="mb-4 text-sm">{t('plan.introLine')} <Link to="/findings" className="text-accent underline underline-offset-4">{t('plan.toFindings')}</Link></p>
      <div className="mb-4 flex max-w-full items-center gap-1 overflow-x-auto">
        <Segmented<PlanFilter> label={t('plan.filterLabel')} value={tier} onChange={setTier} options={FILTERS.map((v) => ({ value: v, label: t(`plan.filter.${v}`) }))} />
        <InfoTip topic={t('plan.filterLabel')}>{FILTERS.map((v) => <p key={v}><span className="font-medium">{t(`plan.filter.${v}`)}</span>{': '}{t(`plan.filterHint.${v}`)}</p>)}</InfoTip>
      </div>
      <QueryState query={q}>
        {(d) => (
          <>
            <PlanDataState plan={d} />
            {d.compared && d.old_evidence > 0 ? <p className="mb-3 text-[13px] text-muted">{t('plan.oldEvidence', { count: d.old_evidence })}</p> : null}
            {d.compared && d.items.length > 0 ? <PlanItems items={d.items} showDevice likelyOnly={tier === 'likely'} /> : null}
            {d.compared && d.items.length === 0 && (d.data.epss === 'ready' || d.data.recent === 'ready') && d.data.epss !== 'module_off' ? (
              <EmptyState title={tier === 'all' ? t('plan.empty') : t(`plan.emptyFilter.${tier}`)} info={t('plan.emptyBodyInfo')}>
                {t('plan.emptyBody', { compared: d.compared_devices, count: d.unchecked_devices })}{' '}
                {d.unchecked_devices > 0 ? <Link to="/devices" className="text-accent underline underline-offset-4">{t('plan.emptyDevices')}</Link> : null}
              </EmptyState>
            ) : null}
            {d.compared && d.items.length > 0 && d.unchecked_devices > 0 ? (
              <Notice tone="off" className="mt-4" title={t('plan.unchecked', { count: d.unchecked_devices })} info={t('plan.uncheckedBodyInfo')}>
                <p>{t('plan.uncheckedBody')} <Link to="/devices" className="text-accent underline underline-offset-4">{t('plan.emptyDevices')}</Link></p>
              </Notice>
            ) : null}
          </>
        )}
      </QueryState>
    </>
  )
}

export default function PlanPage() {
  return <RequireModule module="findings"><Page /></RequireModule>
}
