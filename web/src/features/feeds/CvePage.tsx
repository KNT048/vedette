import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft } from 'lucide-react'
import { PageHeader, Section, KeyValue, Panel } from '@/components/common/PageHeader'
import { EmptyState, ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Slot } from '@/components/common/Slot'
import { fmtPercent } from '@/lib/format'
import { fmtDay } from './dates'
import { CVE_ID, useCve } from './api'
import { YouHaveCell } from './YouHaveCell'

export default function CvePage() {
  const { t } = useTranslation('feeds')
  const { id: raw = '' } = useParams()
  const id = raw.trim().toUpperCase() // the API only knows CVE ids in capitals; the mock used to forgive a lower-case address
  const cve = useCve(id)
  return (
    <>
      <Link to="/" className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"><ArrowLeft className="size-3.5" />{t('cve.back')}</Link>
      {!CVE_ID.test(id) ? <EmptyState title={t('cve.notAnId', { id: raw.trim().slice(0, 80) })}>{t('cve.notAnIdBody')}<p className="mt-2"><Link to={`/lookup?q=${encodeURIComponent(raw.trim().slice(0, 200))}`} className="text-accent underline-offset-4 hover:underline">{t('cve.tryLookup')}</Link></p></EmptyState> : null}
      {CVE_ID.test(id) ? <QueryState query={cve}>
        {(v) => (
          <>
            <PageHeader title={t('cve.title', { cve: v.cve, product: v.display })} stories={['S-FEED-1', 'S-FEED-3']}
              meta={<span className="flex flex-wrap items-center gap-2">{v.ransomware ? <Chip tone="danger">{t('cve.ransomware')}</Chip> : null}<Chip tone="accent">{t('cve.inKev', { date: fmtDay(v.date_added) })}</Chip></span>} />
            <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_380px]">
              <div>
                <Section title={t('cve.facts')}>
                  <Panel className="p-4">
                    <KeyValue items={[
                      { label: t('cve.name'), value: v.name },
                      { label: t('cve.product'), value: `${v.vendor} ${v.product}` },
                      { label: t('cve.kevDate'), value: fmtDay(v.date_added) },
                      { label: t('cve.dueDate'), value: v.due_date ? <>{fmtDay(v.due_date)} <span className="text-[12px] text-muted">{t('cve.dueHint')}</span></> : '–' },
                      { label: t('cve.epss'), value: <>{fmtPercent(v.epss)} <span className="text-[12px] text-muted">{t('cve.epssHint')}</span></> },
                      { label: t('cve.template'), value: v.has_template ? t('cve.templateYes') : t('cve.templateNo') },
                    ]} />
                  </Panel>
                </Section>
                <Section title={t('cve.description')} description={t(v.source === 'vulncheck-kev' ? 'cve.descriptionHintVulnCheck' : 'cve.descriptionHint')}>
                  <p lang="en" className="max-w-[72ch] text-[15px] leading-relaxed">{v.description}</p>
                  <p lang="en" className="mt-3 max-w-[72ch] text-[13px] text-muted">{t(v.source === 'vulncheck-kev' ? 'cve.requiredActionVulnCheck' : 'cve.requiredAction')} {v.required_action}</p>
                </Section>
                <Section title={t('cve.links')}>
                  <ul className="grid gap-1 text-sm">
                    {v.links.filter((l) => /^https?:\/\//i.test(l)).map((l) => <li key={l} className="break-all"><a href={l} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{l}</a></li>)}
                  </ul>
                </Section>
                <Slot name="cve.panels" props={{ cve: v.cve }} />
              </div>
              <aside aria-label={t('cve.matched')}>
                <Section title={t('cve.matched')} stories={['S-FEED-1']}>
                  {v.matched === null ? <ModuleOff module="inventory" /> : v.matched.length === 0 ? (
                    <EmptyState title={t('cve.matchedNone')}>{t('cve.matchedNoneBody')}</EmptyState>
                  ) : (
                    <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
                      {v.matched.map((m) => (
                        <li key={m.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                          <Link to={`/devices/${m.id}`} className="grid text-sm hover:underline">
                            <span className="font-medium">{m.hostname ?? m.display}</span>
                            <span className="text-[12px] text-muted">{m.ip}</span>
                          </Link>
                          <YouHaveCell value={m.how} />
                        </li>
                      ))}
                    </ul>
                  )}
                  {v.matched?.length ? <Link to={`/findings?cve=${v.cve}`} className="mt-3 inline-block text-sm text-accent underline-offset-4 hover:underline">{t('cve.toFindings')}</Link> : null}
                </Section>
              </aside>
            </div>
          </>
        )}
      </QueryState> : null}
      {CVE_ID.test(id) && cve.error ? <p className="mt-4 text-sm"><Link to={`/lookup?q=${encodeURIComponent(id)}`} className="text-accent underline-offset-4 hover:underline">{t('cve.tryLookup')}</Link></p> : null}
    </>
  )
}
