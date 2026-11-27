// S-TIER-1: the CVE page of a CVE on no exploited list, from the tier data (EPSS of FIRST, NVD's record of the
// last 12 months). Its devices are the open findings of the CVE (GET /findings/devices searched for it).
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { KeyValue, PageHeader, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SeverityBadge, StatusBadge, VerificationLine } from '@/components/common/status'
import { fmtDate, fmtPercent } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCveFindings } from '@/features/findings/api'
import { useFixTitle } from '@/features/findings/parts'
import { RowTitle } from '@/components/common/ListParts'
import type { TierCve } from './types'

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

/** The devices that have this CVE as an open finding, each with the fix that closes it and how the finding is known. */
export function TierDevices({ cve }: { cve: string }) {
  const { t } = useTranslation('feeds')
  const on = useModuleEnabled('findings')
  const { query, hits } = useCveFindings(cve, on === true)
  const title = useFixTitle()
  if (on === false) return <ModuleOff module="findings" />
  return (
    <QueryState query={query}>
      {() => hits.length === 0 ? <p className="text-sm text-muted">{t('tierCve.noDevice')}</p> : (
        <>
          <Card flush><ul className="grid divide-y divide-rule">
            {hits.map(({ device, block, finding }) => (
              <li key={finding.id} className="grid gap-1 px-4 py-2.5 text-sm">
                <span className="flex flex-wrap items-center gap-2">
                  <RowTitle to={`/devices/${encodeURIComponent(device.id)}`}>{device.name}</RowTitle>
                  <StatusBadge code={finding.status} to={`/findings/${encodeURIComponent(finding.id)}`} />
                </span>
                <span className="text-meta">{title(block.fix, block.software)}</span>
                <VerificationLine verified={finding.verified} />
              </li>
            ))}
          </ul></Card>
          <Link to={`/findings?cve=${encodeURIComponent(cve)}`} className="mt-3 inline-block text-sm text-accent underline-offset-4 hover:underline">{t('tierCve.toFindings', { count: hits.length })}</Link>
        </>
      )}
    </QueryState>
  )
}
