// The CVE page: everything the box knows about one CVE, from its brief (GET /feeds/cve/{id}), for any CVE the catalogue holds.
// The layout follows GitHub's advisories: the affected and fixed versions first, then what to do, the description and the
// sources; the facts (severity with who scored it, weakness, EPSS, dates) and your devices on the side.
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { EmptyState, ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { ReasonsLine, SeverityBadge, StatusBadge } from '@/components/common/status'
import { Slot } from '@/components/common/Slot'
import { fmtDate } from '@/lib/format'
import { CVE_ID, useCve, useTierCve } from './api'
import { ApiError } from '@/lib/api'
import { TierCvePage, TierDevices } from './TierCvePage'
import { YouHaveCell } from './YouHaveCell'
import { useModuleEnabled } from '@/lib/modules'
import { useCveOpenCount } from '@/features/findings/api'
import { briefReasons, briefSentence, briefSources, briefStatus, fixLink, fixRows } from './brief'
import { AffectedAll, BriefFacts, BriefRemedy, BriefSources, FixTable } from './BriefParts'
import type { CveDetail } from './types'

const yearAgo = () => new Date(Date.now() - 365 * 86_400_000).toISOString().slice(0, 10)
const link = 'text-accent underline-offset-4 hover:underline'

export default function CvePage() {
  const { t } = useTranslation('feeds')
  const { id: raw = '' } = useParams()
  const id = raw.trim().toUpperCase() // the API only knows CVE ids in capitals; the mock used to forgive a lower-case address
  const cve = useCve(id)
  // S-TIER-1: a CVE the catalogue does not hold may still have EPSS data: the tier page answers instead of a dead end
  const missing = cve.error instanceof ApiError && cve.error.code === 'not_in_data'
  const tier = useTierCve(id, missing)
  // docs/UI.md §3: a CVE page's parent is Lookup (where any CVE is looked up), shown in every state of the page. Breadcrumbs show where
  // the page sits, not the path taken (Primer, Atlassian page header): Home and Findings link here too, the browser's Back returns there.
  const crumbs = <Breadcrumbs items={[{ label: t('common:shell.lookup'), to: '/lookup' }]} />
  if (missing && !(tier.error instanceof ApiError && tier.error.code === 'not_in_data')) {
    return (
      <>
        {crumbs}
        <QueryState query={tier}>{(v) => <TierCvePage v={v} />}</QueryState>
      </>
    )
  }
  return (
    <>
      {crumbs}
      {!CVE_ID.test(id) ? <EmptyState title={t('cve.notAnId', { id: raw.trim().slice(0, 80) })}>{t('cve.notAnIdBody')}<p className="mt-2"><Link to={`/lookup?q=${encodeURIComponent(raw.trim().slice(0, 200))}`} className={link}>{t('cve.tryLookup')}</Link></p></EmptyState> : null}
      {CVE_ID.test(id) ? <QueryState query={cve}>{(b) => <Brief b={b} />}</QueryState> : null}
      {CVE_ID.test(id) && cve.error ? <p className="mt-4 text-sm"><Link to={`/lookup?q=${encodeURIComponent(id)}`} className={link}>{t('cve.tryLookup')}</Link></p> : null}
    </>
  )
}

function Brief({ b }: { b: CveDetail }) {
  const { t } = useTranslation('feeds')
  const k = b.lists[0]
  const advisory = fixLink(b)
  const status = briefStatus(b)
  // an old CVE: a device that matches by name only is listed but is no finding; said beside the list, only when it lists devices
  const old = !!k && !!b.matched?.length && !!b.published && b.published < yearAgo()
  const product = b.display ?? b.products[0] ?? t('brief.theProduct')
  return (
    <>
      <PageHeader title={b.cve} stories={['S-FEED-1', 'S-FEED-3']}
        meta={<span className="flex flex-wrap items-center gap-2">
          {status ? <StatusBadge code={status} /> : null}
          <SeverityBadge severity={b.cvss ? { band: b.cvss.severity, score: b.cvss.score, version: b.cvss.version, vector: b.cvss.vector } : null} />
          {k?.ransomware ? <Chip tone="danger">{t('cve.ransomware')}</Chip> : null}
          {k ? <span className="text-meta text-muted">{t('cve.inKev', { date: fmtDate(k.date_added) })}</span> : null}
        </span>} />
      <div className="mb-6 grid max-w-[72ch] gap-1.5">
        <p className="text-base leading-relaxed" data-testid="cve-sentence">{briefSentence(t, b)}</p>
        <ReasonsLine urgency={{ reasons: briefReasons(b), internet: null }} />
      </div>
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div>
          <Section id="affected" title={t('brief.affected.title')}>
            <div className="grid gap-3">
              {fixRows(b).length ? <FixTable b={b} /> : (
                <p className="text-sm">{t('brief.affected.noFix')}</p>
              )}
              <AffectedAll b={b} />
            </div>
          </Section>
          <Section id="todo" title={t('brief.todo.title')}>
            <ol className="grid max-w-[72ch] list-decimal gap-1.5 pl-5 text-sm">
              <li>{advisory ? <>{t('brief.todo.fix')} <a href={advisory} target="_blank" rel="noopener noreferrer" className={link}>{t('brief.advisory')}</a></> : t('brief.todo.search', { product, cve: b.cve })}</li>
              <BriefRemedy b={b} />
              {b.lists.map((l) => (
                <li key={l.source}><span className="font-medium">{t('brief.todo.required', { source: l.source_name })}</span> <span lang="en">{l.required_action}</span>{l.due_date ? ` ${t('brief.todo.due', { date: fmtDate(l.due_date) })}` : ''}</li>
              ))}
            </ol>
          </Section>
          {b.description || k ? (
            <Section id="description" title={t('cve.description')}>
              {b.title ? <p lang="en" className="mb-2 max-w-[72ch] text-sm font-medium">{b.title}</p> : null}
              <p lang="en" className="max-w-[72ch] text-base leading-relaxed">{b.description || k?.description}</p>
            </Section>
          ) : null}
          {briefSources(b).length ? (
            <Section id="sources" title={t('brief.sources')}>
              <BriefSources b={b} />
            </Section>
          ) : null}
          <Slot name="cve.panels" props={{ cve: b.cve }} />
        </div>
        <aside aria-label={t('cve.matched')} className="grid content-start gap-2">
          <Section title={t('cve.matched')} stories={['S-FEED-1', 'S-TIER-4']}
            info={old ? <><p>{t('cve.oldNote', { date: fmtDate(b.published) })}</p><p>{t('cve.oldNoteInfo')}</p></> : undefined}>
            {k ? <Devices b={b} /> : <TierDevices cve={b.cve} />}
          </Section>
          <Section title={t('cve.facts')}>
            <Card><BriefFacts b={b} product /></Card>
          </Section>
        </aside>
      </div>
    </>
  )
}

/** The devices whose product matches the exploited-list entry, and the way to their open findings. */
function Devices({ b }: { b: CveDetail }) {
  const { t } = useTranslation('feeds')
  // "See findings" only when this CVE has open findings (a matched device may not be a finding, or all are closed)
  const findingsOn = useModuleEnabled('findings') === true
  const openFindings = useCveOpenCount(b.cve, findingsOn) ?? 0
  return (
    <>
      {b.matched === null ? <ModuleOff module="inventory" /> : b.matched.length === 0 && b.not_affected ? (
        <p className="text-sm text-muted">{t('cve.notAffected', { count: b.not_affected })}</p>
      ) : b.matched.length === 0 ? (
        <EmptyState title={t('cve.matchedNone')}>{t('cve.matchedNoneBody')}</EmptyState>
      ) : (
        <Card flush><ul className="grid divide-y divide-rule">
          {b.matched.map((m) => (
            <li key={m.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <Link to={`/devices/${m.id}`} className="grid text-sm hover:underline">
                <span className="font-medium">{m.hostname ?? m.display}</span>
                <span className="text-caption text-muted">{m.ip}</span>
              </Link>
              <YouHaveCell value={m.how} />
            </li>
          ))}
        </ul></Card>
      )}
      {b.matched?.length && b.not_affected ? <p className="mt-2 text-meta text-muted">{t('cve.notAffected', { count: b.not_affected })}</p> : null}
      {openFindings > 0 ? <Link to={`/findings?cve=${b.cve}`} className={`mt-3 inline-block text-sm ${link}`}>{t('cve.toFindings', { count: openFindings })}</Link> : null}
    </>
  )
}
