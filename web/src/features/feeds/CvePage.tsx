import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice, PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { EmptyState, ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Slot } from '@/components/common/Slot'
import { fmtDate, fmtPercent } from '@/lib/format'
import { CVE_ID, useCve, useTierCve } from './api'
import { ApiError } from '@/lib/api'
import { TierCvePage } from './TierCvePage'
import { YouHaveCell } from './YouHaveCell'
import { useModuleEnabled } from '@/lib/modules'
import { useFindings } from '@/features/findings/api'
import { isOpen } from '@/features/findings/basis'

const yearAgo = () => new Date(Date.now() - 365 * 86_400_000).toISOString().slice(0, 10)

export default function CvePage() {
  const { t } = useTranslation('feeds')
  const { id: raw = '' } = useParams()
  const id = raw.trim().toUpperCase() // the API only knows CVE ids in capitals; the mock used to forgive a lower-case address
  const cve = useCve(id)
  // S-TIER-1: a CVE on no exploited list (its brief names no list entry, or the catalogue does not hold it) answers from the tier
  // data instead of a dead end
  const notInKev = (cve.error instanceof ApiError && cve.error.code === 'not_in_data') || cve.data?.lists.length === 0
  const tier = useTierCve(id, notInKev)
  // "See findings" only when this CVE has open findings (a matched device may not be a finding, or all are closed)
  const findingsOn = useModuleEnabled('findings') === true
  const openFindings = useFindings(undefined, findingsOn && CVE_ID.test(id)).data?.items.filter((f) => f.cve === id && isOpen(f.status)).length ?? 0
  // docs/UI.md §3: a CVE page's parent is Lookup (where any CVE is looked up), shown in every state of the page. Breadcrumbs show where
  // the page sits, not the path taken (Primer, Atlassian page header): Home and Findings link here too, the browser's Back returns there.
  const crumbs = <Breadcrumbs items={[{ label: t('nav.lookup'), to: '/lookup' }]} />
  if (notInKev && !(tier.error instanceof ApiError && tier.error.code === 'not_in_data')) {
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
      {!CVE_ID.test(id) ? <EmptyState title={t('cve.notAnId', { id: raw.trim().slice(0, 80) })}>{t('cve.notAnIdBody')}<p className="mt-2"><Link to={`/lookup?q=${encodeURIComponent(raw.trim().slice(0, 200))}`} className="text-accent underline-offset-4 hover:underline">{t('cve.tryLookup')}</Link></p></EmptyState> : null}
      {CVE_ID.test(id) ? <QueryState query={cve}>
        {(b) => {
          const k = b.lists[0]
          if (!k) return <EmptyState title={t('cve.notListed', { cve: b.cve })}>{t('cve.notListedBody')}</EmptyState>
          const v = { ...k, cve: b.cve, published: b.published, epss: b.epss?.score ?? null, has_template: b.signals.some((g) => g.kind === 'public_exploit' && g.source === 'nuclei-templates'), matched: b.matched, not_affected: b.not_affected }
          return (
          <>
            <PageHeader title={t('cve.title', { cve: v.cve, product: v.display })} stories={['S-FEED-1', 'S-FEED-3']}
              meta={<span className="flex flex-wrap items-center gap-2">{v.ransomware ? <Chip tone="danger">{t('cve.ransomware')}</Chip> : null}<Chip tone="danger">{t('cve.inKev', { date: fmtDate(v.date_added) })}</Chip></span>} />
            <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_380px]">
              <div>
                <Section title={t('cve.facts')}>
                  <Card>
                    <KeyValue items={[
                      { label: t('cve.name'), value: v.name },
                      { label: t('cve.product'), value: `${v.vendor} ${v.product}` },
                      { label: t('cve.published'), value: v.published ? fmtDate(v.published) : <span className="text-muted">{t('cve.publishedUnknown')}</span> },
                      { label: t('cve.kevDate'), value: fmtDate(v.date_added) },
                      { label: t('cve.dueDate'), value: v.due_date ? <>{fmtDate(v.due_date)} <span className="text-caption text-muted">{t('cve.dueHint')}</span></> : '–' },
                      { label: t('cve.epss'), value: <>{fmtPercent(v.epss)} <span className="text-caption text-muted">{t('cve.epssHint')}</span></> },
                      { label: t('cve.template'), value: v.has_template ? t('cve.templateYes') : t('cve.templateNo') },
                    ]} />
                  </Card>
                </Section>
                <Section title={t('cve.description')} description={t(v.source === 'vulncheck-kev' ? 'cve.descriptionHintVulnCheck' : 'cve.descriptionHint')}>
                  <p lang="en" className="max-w-[72ch] text-base leading-relaxed">{v.description}</p>
                  <p lang="en" className="mt-3 max-w-[72ch] text-meta text-muted">{t(v.source === 'vulncheck-kev' ? 'cve.requiredActionVulnCheck' : 'cve.requiredAction')} {v.required_action}</p>
                </Section>
                <Section title={t('cve.links')}>
                  <ul className="grid gap-1 text-sm">
                    {v.links.filter((l) => /^https?:\/\//i.test(l)).map((l) => <li key={l} className="break-all"><a href={l} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{l}</a></li>)}
                  </ul>
                </Section>
                <Slot name="cve.panels" props={{ cve: v.cve }} />
              </div>
              <aside aria-label={t('cve.matched')}>
                <Section title={t('cve.matched')} stories={['S-FEED-1', 'S-TIER-4']}>
                  {v.published && v.published < yearAgo() ? <Notice tone="off" className="mb-3" title={t('cve.oldNote', { date: fmtDate(v.published) })} info={t('cve.oldNoteInfo')} /> : null}
                  {v.matched === null ? <ModuleOff module="inventory" /> : v.matched.length === 0 && v.not_affected ? (
                    <p className="text-sm text-muted">{t('cve.notAffected', { count: v.not_affected })}</p>
                  ) : v.matched.length === 0 ? (
                    <EmptyState title={t('cve.matchedNone')}>{t('cve.matchedNoneBody')}</EmptyState>
                  ) : (
                    <Card flush><ul className="grid divide-y divide-rule">
                      {v.matched.map((m) => (
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
                  {v.matched?.length && v.not_affected ? <p className="mt-2 text-meta text-muted">{t('cve.notAffected', { count: v.not_affected })}</p> : null}
                  {openFindings > 0 ? <Link to={`/findings?cve=${v.cve}`} className="mt-3 inline-block text-sm text-accent underline-offset-4 hover:underline">{t('cve.toFindings', { count: openFindings })}</Link> : null}
                </Section>
              </aside>
            </div>
          </>
          )
        }}
      </QueryState> : null}
      {CVE_ID.test(id) && cve.error ? <p className="mt-4 text-sm"><Link to={`/lookup?q=${encodeURIComponent(id)}`} className="text-accent underline-offset-4 hover:underline">{t('cve.tryLookup')}</Link></p> : null}
    </>
  )
}
