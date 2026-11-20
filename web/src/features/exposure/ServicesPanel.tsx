import { useTranslation } from 'react-i18next'
import { Panel, Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { CveList, SeverityBadge, StatusBadge, VerificationLine } from '@/components/common/status'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { PortMark } from './PortMark'
import { InfoLine } from './InfoLine'
import type { ServiceRow, Snapshot, TemplateRow, VulnRow } from './types'
import { serviceIdent, serviceText } from './services'
import { PortHints, ServiceCell } from './PortIdent'
import { fmtDate, fmtDateTime } from '@/lib/format'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 } as const

/** S-EXP-2 (INV-19, INV-20): the services nmap -sV identified on the box's own public IP and their exploited CVEs (CISA KEV). */
export function VulnSection({ s, domain = false }: { s: Snapshot; domain?: boolean }) {
  const { t } = useTranslation('exposure')
  // A match on a distribution package (backport) weighs less: it is counted apart and shown in the neutral tone.
  // A JavaScript library's CVE runs in the visitors' browsers, not in the service on that port, and a Greenbone
  // row repeats a CVE, it is not one more: neither is counted on the service.
  const on = (r: ServiceRow) => s.vulns.filter((v) => v.ip === r.ip && v.port === r.port && v.basis !== 'js_library' && v.basis !== 'greenbone')
  const count = (r: ServiceRow) => on(r).filter((v) => !v.backport).length
  const maybe = (r: ServiceRow) => on(r).filter((v) => v.backport).length
  // INV-22: a service or CVE on a port kept from an earlier scan carries the port's mark
  const mark = (ip: string, port: number) => <PortMark p={s.ports.find((x) => x.ip === ip && x.port === port) ?? {}} />
  // A domain's services and CVEs are on several addresses (its deep scan): each row says which
  const ipCol = <T extends { ip: string }>(): ColumnDef<T>[] => (domain ? [{ id: 'ip', header: t('col.ip'), accessorFn: (r) => r.ip, cell: ({ row }) => <span className="font-mono text-meta">{row.original.ip}</span> }] : [])
  const portOf = (r: ServiceRow) => s.ports.find((x) => x.ip === r.ip && x.port === r.port)
  const view = (r: ServiceRow) => {
    const p = portOf(r), ident = serviceIdent(r)
    return p?.ident === 'probed' && p.product && !r.product && (ident === 'port' || ident === 'none') ? { service: p.service, ident: p.ident, product: p.product } : { service: r.name, ident, product: r.product }
  }
  const serviceCols: ColumnDef<ServiceRow>[] = [
    ...ipCol<ServiceRow>(),
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="grid gap-1"><span className="tabular-nums">{row.original.port}</span>{mark(row.original.ip, row.original.port)}</span> },
    // M2-7: a person's name for the service, "Probably SIP" when only the port number says so, "Service not identified" when nothing does.
    // Review r2 L4: a port whose page the surface scan read (its Server header) reads as the Ports table says, not as nmap's table guess.
    { id: 'service', header: t('col.service'), accessorFn: (r) => serviceText(view(r).service, view(r).ident).name, cell: ({ row }) => <ServiceCell service={view(row.original).service} ident={view(row.original).ident} port={row.original.port} /> },
    { id: 'product', header: t('col.product'), accessorFn: (r) => view(r).product, cell: ({ row }) => {
      const port = portOf(row.original)
      return view(row.original).product || <span className="grid gap-0.5"><span className="text-muted">{t('vulns.noProduct')}</span>{port ? <PortHints p={port} className="text-caption text-muted" /> : null}</span>
    } },
    // a version is "not sent" only by a service a probe named; nmap read none of an unconfirmed or unknown one
    { id: 'version', header: t('col.version'), accessorFn: (r) => r.version, cell: ({ row }) => row.original.version || <span className="text-muted">{t(view(row.original).ident === 'port' || view(row.original).ident === 'none' ? 'vulns.notRead' : 'vulns.noVersion')}</span> },
    { id: 'cves', header: t('col.exploited'), accessorFn: count, cell: ({ row }) => {
      const n = count(row.original), m = maybe(row.original)
      return n + m > 0 ? <span className="flex flex-wrap gap-1">{n > 0 ? <StatusBadge code="exploited" count={n} /> : null}{m > 0 ? <Chip tone="off">{t('vulns.countBackport', { count: m })}</Chip> : null}</span> : null
    } },
  ]
  const vulnCols: ColumnDef<VulnRow>[] = [
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row }) => <span className="grid gap-0.5"><span className="font-medium">{row.original.cve}</span><span className="text-caption text-muted">{row.original.name}</span></span> },
    ...ipCol<VulnRow>(),
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="grid gap-1"><span className="tabular-nums">{row.original.port}</span>{mark(row.original.ip, row.original.port)}</span> },
    { id: 'basis', header: t('col.basis'), accessorFn: (r) => r.basis, cell: ({ row: { original: r } }) => (
      // how the match is known: a safe template confirmed it, else the version a banner or page gave (product only: not even that)
      <span className="grid gap-0.5">
        {r.basis === 'template' ? <VerificationLine verified="scan" basis="scan" /> : <VerificationLine verified="no" basis={r.basis === 'product' ? null : 'banner_version'} />}
        <span className="text-caption text-muted">{r.basis === 'template' ? r.template : r.basis === 'greenbone' ? t('vulns.basis.greenbone', { qod: r.qod ?? 0 }) : r.backport ? t('vulns.basis.backport', { distro: r.backport }) : t(`vulns.basis.${r.basis}`)}</span>
      </span>
    ) },
    { id: 'listed', header: t('col.listed'), accessorFn: (r) => r.date_added ?? '', cell: ({ row }) => (
      <span className="grid gap-1">{row.original.date_added ? fmtDate(row.original.date_added) : t('common:unknown')}{row.original.ransomware ? <Chip tone="danger">{t('vulns.ransomware')}</Chip> : null}</span>
    ) },
    { id: 'why', header: t('col.why'), enableSorting: false, accessorFn: (r) => r.summary, cell: ({ row }) => <span className="text-meta">{row.original.summary}</span> },
  ]
  // deep scan, testing terms accepted: what nuclei's deep templates matched (an exposed .git, an admin panel, a technology).
  // A matched row of a CVE the list above already shows as "Confirmed by template" is not repeated.
  const deep = (s.templates ?? []) // a snapshot read from an older box may not carry the list
    .filter((r) => r.severity !== undefined && r.outcome === 'matched' && !(r.cve && s.vulns.some((v) => v.ip === r.ip && v.port === r.port && v.cve === r.cve)))
    .sort((a, b) => SEVERITY_ORDER[a.severity!] - SEVERITY_ORDER[b.severity!])
  const deepCols: ColumnDef<TemplateRow>[] = [
    { id: 'risk', header: t('col.risk'), accessorFn: (r) => SEVERITY_ORDER[r.severity!], cell: ({ row }) => row.original.severity === 'unknown' || row.original.severity === undefined ? <Chip tone="off">{t('common:unknown')}</Chip> : <SeverityBadge severity={row.original.severity} /> },
    { id: 'name', header: t('col.name'), accessorFn: (r) => r.name ?? r.template, cell: ({ row }) => <span className="grid gap-0.5"><span className="font-medium">{row.original.name || row.original.template}</span><span className="text-caption text-muted">{t('vulns.deepTemplate', { id: row.original.template })}</span></span> },
    ...ipCol<TemplateRow>(),
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="grid gap-1"><span className="tabular-nums">{row.original.port}</span>{mark(row.original.ip, row.original.port)}</span> },
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row }) => row.original.cve || null },
  ]
  const why = s.not_checked.find((n) => n.kind === 'services' || n.kind === 'cve')
  // TUNE-1a review M1: identification did not complete, so the title must not read as "nothing is there"
  const unidentified = why?.kind === 'services'
  const desc = domain ? (s.services.length > 0 ? 'vulns.descriptionDomainDeep' : 'vulns.descriptionDomain') : 'vulns.description'
  return (
    <Section id="vulns" title={t('vulns.title')} description={t(desc)} info={t(`${desc}Info`)}>
      {s.services.length === 0 && s.vulns.length === 0 ? (
        <EmptyState title={t(unidentified ? 'vulns.notIdentifiedTitle' : 'vulns.noneIdentifiedTitle')}>{why?.text ?? t('vulns.noneIdentifiedBody')}</EmptyState>
      ) : (
        <div className="grid gap-4">
          {s.vulns.length > 0 ? (
            <DataTable urlKey="vulns" caption={t(domain ? (s.services.length > 0 ? 'vulns.captionDomainDeep' : 'vulns.captionDomain') : 'vulns.caption')} data={s.vulns} columns={vulnCols} pageSize={20} rowTone={(r) => (r.backport ? undefined : 'warn')} />
          ) : s.not_checked.some((n) => n.kind === 'cve') ? (
            <p role="status" className="text-sm text-warn">{s.not_checked.find((n) => n.kind === 'cve')!.text}</p>
          ) : (
            // review r1 L4: not an all-clear when the deep scan's table below has rows
            <EmptyState title={t(deep.length > 0 ? 'vulns.noneTitleDeep' : 'vulns.noneTitle')}><InfoLine topic={t(deep.length > 0 ? 'vulns.noneTitleDeep' : 'vulns.noneTitle')} info={t('vulns.noneBodyInfo')}>{t(deep.length > 0 ? 'vulns.noneBodyDeep' : 'vulns.noneBody')}</InfoLine></EmptyState>
          )}
          {s.version_gaps.length > 0 ? (
            <ul aria-label={t('vulns.gapsLabel')} className="grid gap-1 text-sm">
              {s.version_gaps.map((g) => <li key={`${g.ip}:${g.port}`} className="grid gap-0.5">{t('vulns.gap', { count: g.cves.length, software: g.software, port: g.port })}<CveList items={g.cves.map((cve) => ({ cve }))} label={t('vulns.gapCves', { software: g.software, port: g.port })} /></li>)}
            </ul>
          ) : null}
          {deep.length > 0 ? (
            <div className="grid gap-2">
              <DataTable urlKey="vulns-deep" caption={t('vulns.deepCaption')} data={deep} columns={deepCols} pageSize={20} />
              <InfoLine className="text-meta text-muted" topic={t('vulns.deepCaption')} info={t('vulns.deepNoteInfo')}>{t('vulns.deepNote')}</InfoLine>
            </div>
          ) : null}
          {s.services.length > 0 ? <DataTable urlKey="vulns-services" caption={t('vulns.servicesCaption')} data={s.services} columns={serviceCols} pageSize={20} empty={t('vulns.noneIdentifiedBody')} /> : null}
        </div>
      )}
    </Section>
  )
}

/** S-EXP-2 (INV-19): what the scan checked, with counts and times, and what it did not check, with why. */
export function ChecksSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  return (
    <Section id="checked" title={t('checked.title')} description={t('checked.description')} info={t('checked.descriptionInfo')}>
      {s.checks.length === 0 && s.not_checked.length === 0 ? <p className="text-sm text-muted">{t('checked.older')}</p> : (
        <Panel className="grid gap-4 p-4 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-semibold">{t('checked.checked')}</h3>
            <ul aria-label={t('checked.checked')} className="grid gap-2 text-sm">
              {s.checks.map((c, i) => <li key={i}>{c.text} <span className="text-caption text-muted">{fmtDateTime(c.at)}</span></li>)}
            </ul>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-semibold">{t('checked.notChecked')}</h3>
            <ul aria-label={t('checked.notChecked')} className="grid gap-2 text-sm">
              {s.not_checked.map((n, i) => <li key={i}>{n.text}</li>)}
            </ul>
          </div>
        </Panel>
      )}
    </Section>
  )
}
