// S-TIER-1: the CVE page of a CVE on no exploited list, from the tier data (EPSS of FIRST, NVD's record of the
// last 12 months). Its devices are the items of Updates to plan that list it: never findings, never alerts.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { KeyValue, PageHeader, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SeverityBadge, StatusBadge } from '@/components/common/status'
import { fmtDate, fmtPercent } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { usePlan } from '@/features/findings/api'
import { EvidenceChip, PlanDataState } from '@/features/findings/Plan'
import { usePlanAction } from '@/features/findings/fix'
import type { TierCve } from './types'
import { RiskMarker } from '@/features/inventory/RiskMarker'

export function TierCvePage({ v }: { v: TierCve }) {
  const { t } = useTranslation('feeds')
  return (
    <>
      <PageHeader title={v.cve} stories={['S-TIER-1']} info={t(v.tier ? 'tierCve.intro' : 'tierCve.introOld')}
        meta={<span className="flex flex-wrap items-center gap-2">
          {v.tier ? <Chip tone={v.tier === 'likely' ? 'warn' : 'off'}>{t(`tierCve.tier.${v.tier}`)}</Chip> : <Chip tone="off">{t('tierCve.tier.old')}</Chip>}
          <StatusBadge code="update_recommended" />
        </span>} />
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div>
          <Section title={t('cve.facts')}>
            <Card>
              <KeyValue items={[
                { label: t('tierCve.products'), value: v.products.length ? v.products.join(', ') : <span className="text-muted">{t('tierCve.productsNone')}</span> },
                { label: t('cve.published'), value: v.published ? fmtDate(v.published) : <span className="text-muted">{t('tierCve.publishedNone')}</span> },
                { label: t('tierCve.severity'), value: <SeverityBadge severity={v.severity ? { band: v.severity, score: v.score } : null} /> },
                { label: t('cve.epss'), value: v.epss === null ? <span className="text-muted">{t('tierCve.epssNone')}</span> : <>{fmtPercent(v.epss)} <span className="text-caption text-muted">{t('tierCve.epssHint', { date: fmtDate(v.epss_date) })}</span></> },
                { label: t('tierCve.status'), value: v.nvd_status ? <>{v.nvd_status}{v.last_modified ? <span className="text-caption text-muted"> {t('tierCve.changed', { date: fmtDate(v.last_modified) })}</span> : null}</> : '–' },
                { label: t('tierCve.ranges'), value: v.published ? t(v.ranges ? 'tierCve.rangesYes' : 'tierCve.rangesNo') : '–' },
              ]} />
            </Card>
          </Section>
          <Section title={t('cve.links')}>
            <ul className="grid gap-1 text-sm">
              {[`https://nvd.nist.gov/vuln/detail/${v.cve}`, `https://www.cve.org/CVERecord?id=${v.cve}`].map((l) => (
                <li key={l} className="break-all"><a href={l} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{l}</a></li>
              ))}
            </ul>
          </Section>
        </div>
        <aside aria-label={t('cve.matched')}>
          <Section title={t('cve.matched')} stories={['S-TIER-1']}><TierDevices cve={v.cve} /></Section>
        </aside>
      </div>
    </>
  )
}

/** The devices whose updates to plan fix this CVE, with the update and the evidence. */
export function TierDevices({ cve }: { cve: string }) {
  const { t } = useTranslation('feeds')
  const on = useModuleEnabled('findings')
  const q = usePlan()
  const action = usePlanAction()
  if (on === false) return <ModuleOff module="findings" />
  return (
    <QueryState query={q}>
      {(p) => {
        const hits = p.items.flatMap((i) => i.cves.filter((c) => c.cve === cve).map((c) => ({ i, c })))
        if (!p.compared || (p.data.epss !== 'ready' && p.data.recent !== 'ready')) return <PlanDataState plan={p} compact />
        if (hits.length === 0) return <p className="text-sm text-muted">{t('tierCve.noDevice')}</p>
        return (
          <>
            <Card flush><ul className="grid divide-y divide-rule">
              {hits.map(({ i, c }) => (
                <li key={i.group} className="grid gap-1 px-4 py-2.5 text-sm">
                  <span className="flex flex-wrap items-center gap-2"><Link to={`/devices/${i.asset.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{i.asset.name}</Link><RiskMarker id={i.asset.id} risk={i.risk} /></span>
                  <span className="text-meta">{action(i)}</span>
                  <EvidenceChip basis={c.basis} gone={i.agent_gone} />
                </li>
              ))}
            </ul></Card>
            <Link to="/plan" className="mt-3 inline-block text-sm text-accent underline-offset-4 hover:underline">{t('tierCve.toPlan')}</Link>
          </>
        )
      }}
    </QueryState>
  )
}
