import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { CveList, SeverityBadge } from '@/components/common/status'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { InfoTip } from '@/components/common/InfoTip'
import { InfoLine } from './InfoLine'
import type { Snapshot, WebFinding } from './types'

const ORDER = { high: 0, medium: 1, low: 2, info: 3 } as const

/** S-EXP-2 (INV-24): what ZAP's passive web scan noticed, in two groups by Vedette's rule list: "Fix this" first, then
 * "Hardening". Apart from the exploited CVEs: these are hints, never "exploited" (a version ZAP read is compared in the CVE section). */
export function WebSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const rows = [...s.web_findings].sort((a, b) => ORDER[a.risk] - ORDER[b.risk])
  const groups = (['fix', 'hardening'] as const).map((g) => ({ g, rows: rows.filter((r) => r.group === g) })).filter((x) => x.rows.length > 0)
  const scanned = s.checks.some((c) => c.kind === 'web')
  const why = s.not_checked.find((n) => n.kind === 'web')
  const cols: ColumnDef<WebFinding>[] = [
    { id: 'risk', header: t('web.col.risk'), accessorFn: (r) => ORDER[r.risk], cell: ({ row }) => <SeverityBadge severity={row.original.risk} /> },
    { id: 'alert', header: t('web.col.alert'), accessorFn: (r) => r.name, cell: ({ row }) => (
      <span className="grid gap-1">
        <span className="font-medium">{row.original.name}</span>
        <span className="text-caption text-muted">{row.original.description}</span>
        {row.original.software.map((w) => (
          <span key={`${w.product}/${w.version}`} className="grid gap-0.5 text-caption">{t('web.software', { product: w.product, version: w.version })}{w.cves.length > 0 ? <CveList items={w.cves.map((cve) => ({ cve }))} label={t('web.software', { product: w.product, version: w.version })} /> : null}</span>
        ))}
        {row.original.cwe > 0 ? (
          <a className="w-fit text-caption text-accent underline underline-offset-4" href={`https://cwe.mitre.org/data/definitions/${row.original.cwe}.html`} target="_blank" rel="noopener noreferrer" aria-label={t('web.cweLink', { id: row.original.cwe })}>{t('web.cwe', { id: row.original.cwe })}</a>
        ) : null}
      </span>
    ) },
    { id: 'confidence', header: t('web.col.confidence'), accessorFn: (r) => r.confidence, cell: ({ row }) => t(`web.confidence.${row.original.confidence}`) },
    { id: 'pages', header: t('web.col.pages'), enableSorting: false, accessorFn: (r) => r.urls.join(' '), cell: ({ row }) => (
      <span className="grid gap-0.5 text-caption">
        {row.original.urls.map((u) => <span key={u} className="break-all">{u}</span>)}
        {row.original.count > row.original.urls.length ? <span className="text-muted">{t('web.pagesMore', { count: row.original.count })}</span> : null}
      </span>
    ) },
    { id: 'fix', header: t('web.col.fix'), enableSorting: false, accessorFn: (r) => r.solution, cell: ({ row }) => <span className="text-meta">{row.original.solution}</span> },
  ]
  return (
    <Section id="web" title={t('web.title')} description={rows.length > 0 || scanned ? t('web.description') : undefined} info={rows.length > 0 || scanned ? t('web.descriptionInfo') : undefined}>
      {rows.length > 0 ? (
        <div className="grid gap-6">
          {groups.map(({ g, rows: data }) => (
            <section key={g} aria-labelledby={`web-${g}-title`} className="grid gap-2">
              <div className="flex items-center gap-1">
                <h3 id={`web-${g}-title`} className="text-sm font-semibold">{t(`web.group.${g}.title`)}</h3>
                <InfoTip topic={t(`web.group.${g}.title`)}>{t(`web.group.${g}.description`)}</InfoTip>
              </div>
              <DataTable urlKey={`web-${g}`} caption={t(`web.group.${g}.caption`)} data={data} columns={cols} pageSize={20} rowTone={(r) => (g === 'fix' || r.risk === 'high' ? 'warn' : undefined)} />
            </section>
          ))}
        </div>
      ) : scanned ? (
        <EmptyState title={t('web.noneTitle')}><InfoLine topic={t('web.noneTitle')} info={t('web.noneBodyInfo')}>{t('web.noneBody')}</InfoLine></EmptyState>
      ) : (
        <EmptyState title={t('web.notScannedTitle')}>{why?.text ?? t('web.notScannedBody')}</EmptyState>
      )}
    </Section>
  )
}
