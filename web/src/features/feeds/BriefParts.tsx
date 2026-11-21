// The parts of a CVE brief that the CVE page and a finding's summary card both show: the facts, the affected and fixed versions,
// the sources. Each reads the brief only (GET /feeds/cve/{id}); the finding page adds the device's own line.
import { Fragment } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyValue } from '@/components/common/PageHeader'
import { SeverityBadge } from '@/components/common/status'
import { fmtDate, fmtPercent } from '@/lib/format'
import { cn } from '@/lib/utils'
import { affectedGroups, briefSources, fixRows } from './brief'
import type { CveBrief } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

/** Severity with who scored it, weakness, exploit likelihood, dates, NVD's status, CISA's assessment and the two records. */
export function BriefFacts({ b, product = false }: { b: CveBrief; product?: boolean }) {
  const { t } = useTranslation('feeds')
  const s = b.cvss
  const ssvc = b.ssvc.exploitation || b.ssvc.automatable || b.ssvc.technical_impact
  const items = [
    ...(product ? [{ label: t('brief.facts.product'), value: b.display ?? b.products[0] ?? '–' }] : []),
    { label: t('brief.facts.severity'), value: (
      <span className="grid gap-1">
        <SeverityBadge severity={s ? { band: s.severity, score: s.score, version: s.version, vector: s.vector } : null} detail />
        {s ? <span className="text-caption text-muted">{t('brief.scoredBy', { version: s.version, source: t(`brief.scorer.${s.source}`) })}</span> : null}
        {s?.reading ? <span className="text-meta">{s.reading.summary}</span> : null}
      </span>
    ) },
    ...(b.cwe.length ? [{ label: t('brief.facts.weakness'), value: (
      <span className="grid gap-0.5">
        {b.cwe.map((c) => <a key={c.id} className={cn('w-fit', link)} href={`https://cwe.mitre.org/data/definitions/${c.id.slice(4)}.html`} target="_blank" rel="noopener noreferrer">{c.name ? `${c.id}: ${c.name}` : c.id}</a>)}
      </span>
    ) }] : []),
    ...(b.epss ? [{ label: t('brief.facts.epss'), value: t('brief.epssValue', { score: fmtPercent(b.epss.score), percentile: fmtPercent(b.epss.percentile, 0) }) }] : []),
    ...(b.published ? [{ label: t('brief.facts.published'), value: fmtDate(b.published) }] : []),
    ...(b.modified ? [{ label: t('brief.facts.modified'), value: fmtDate(b.modified) }] : []),
    ...(b.nvd_status ? [{ label: t('brief.facts.nvd'), value: b.nvd_status }] : []),
    ...(ssvc ? [{ label: t('brief.facts.ssvc'), value: t('brief.ssvcValue', {
      exploitation: b.ssvc.exploitation ?? t('brief.notKnown'), automatable: b.ssvc.automatable ?? t('brief.notKnown'), impact: b.ssvc.technical_impact ?? t('brief.notKnown'),
    }) }] : []),
    { label: t('brief.facts.ids'), value: (
      <span className="flex flex-wrap gap-x-3">
        <a className={link} href={b.nvd_url} target="_blank" rel="noopener noreferrer">{t('brief.nvdLink')}</a>
        <a className={link} href={b.record_url} target="_blank" rel="noopener noreferrer">{t('brief.recordLink')}</a>
      </span>
    ) },
  ]
  return <KeyValue items={items} />
}

/**
 * The releases that fix the CVE, one row per product and release train (or fixed release). `mark`: the fixed release the device
 * needs (from the finding's own fix): that row says "Your device". Nothing when no range names a fixed release.
 */
export function FixTable({ b, mark }: { b: CveBrief; mark?: string | null }) {
  const { t } = useTranslation('feeds')
  const rows = fixRows(b)
  if (!rows.length) return null
  const trains = rows.some((r) => r.train)
  const th = 'py-1.5 pr-4 font-medium'
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-caption text-muted">
          <tr>
            <th scope="col" className={th}>{t('brief.affected.product')}</th>
            {trains ? <th scope="col" className={th}>{t('brief.affected.train')}</th> : null}
            <th scope="col" className={th}>{t('brief.affected.versions')}</th>
            <th scope="col" className="py-1.5 font-medium">{t('brief.affected.fixed')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-rule border-t border-rule">
          {rows.map((r) => {
            const mine = !!mark && r.names.includes(mark)
            return (
              <tr key={`${r.product}-${r.train}-${r.fixed}`} className={mine ? 'bg-accent-soft' : undefined} data-device={mine || undefined}>
                <td className="py-1.5 pr-4">{r.product}{mine ? <span className="ml-2 text-caption font-medium text-accent">{t('brief.affected.yourDevice')}</span> : null}</td>
                {trains ? <td className="py-1.5 pr-4">{r.train || '–'}</td> : null}
                <td className="py-1.5 pr-4">{r.versions || '–'}</td>
                <td className="py-1.5 font-medium">{r.fixed}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** Every affected-versions row, by who stated it and the product. */
export function AffectedAll({ b }: { b: CveBrief }) {
  const { t } = useTranslation('feeds')
  const groups = affectedGroups(b)
  if (!groups.length) return null
  return (
    <details className="text-sm">
      <summary className="w-fit cursor-pointer text-accent">{t('brief.affected.all', { count: b.ranges.length })}</summary>
      <dl className="mt-2 grid gap-2">
        {groups.map((g) => (
          <div key={`${g.origin}-${g.product}`} className="grid gap-0.5">
            <dt className="font-medium">{g.product} <span className="font-normal text-caption text-muted">{t(`brief.affected.origin.${g.origin}`)}{g.counts ? '' : ` (${t('brief.affected.notUsed')})`}</span></dt>
            <dd className="text-meta [overflow-wrap:anywhere]">{g.versions.join(', ')}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}

/** The fix as the record states it: the vendor's solution text, then the workaround, or the plain line that none is published. */
export function BriefRemedy({ b }: { b: CveBrief }) {
  const { t } = useTranslation('feeds')
  return (
    <>
      {b.solution ? <li><span className="font-medium">{t('brief.todo.vendor')}</span> <span lang="en" className="whitespace-pre-line">{b.solution}</span></li> : null}
      <li>{b.workaround ? <><span className="font-medium">{t('brief.todo.workaround')}</span> <span lang="en" className="whitespace-pre-line">{b.workaround}</span></> : t('brief.todo.noWorkaround')}</li>
    </>
  )
}

/** Every reference under its tag (Vendor advisory, Patch, Mitigation, Exploit …), as links. */
export function BriefSources({ b }: { b: CveBrief }) {
  const { t } = useTranslation('feeds')
  const groups = briefSources(b)
  if (!groups.length) return null
  return (
    <dl className="grid gap-2 text-sm">
      {groups.map((g) => (
        <Fragment key={g.group}>
          <dt className="text-caption font-medium text-muted">{t(`brief.ref.${g.group}`)}</dt>
          <dd className="grid gap-0.5">
            {g.links.map((l) => <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer" className={cn('w-fit break-all', link)}>{l.url}</a>)}
          </dd>
        </Fragment>
      ))}
    </dl>
  )
}
