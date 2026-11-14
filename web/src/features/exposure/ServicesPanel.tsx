import { useTranslation } from 'react-i18next'
import { Panel, Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { dateText, dateTimeText } from './dates'
import { PortMark } from './PortMark'
import type { ServiceRow, Snapshot, VulnRow } from './types'

/** S-EXP-2 (INV-19, INV-20): the services nmap -sV identified on the box's own public IP and their exploited CVEs (CISA KEV). */
export function VulnSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  // A match on a distribution package (backport) weighs less: it is counted apart and shown in the neutral tone.
  const on = (r: ServiceRow) => s.vulns.filter((v) => v.ip === r.ip && v.port === r.port)
  const count = (r: ServiceRow) => on(r).filter((v) => !v.backport).length
  const maybe = (r: ServiceRow) => on(r).filter((v) => v.backport).length
  // INV-22: a service or CVE on a port kept from an earlier scan carries the port's mark
  const mark = (ip: string, port: number) => <PortMark p={s.ports.find((x) => x.ip === ip && x.port === port) ?? {}} />
  const serviceCols: ColumnDef<ServiceRow>[] = [
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="grid gap-1"><span className="tabular-nums">{row.original.port}</span>{mark(row.original.ip, row.original.port)}</span> },
    { id: 'service', header: t('col.service'), accessorFn: (r) => r.name, cell: ({ row }) => row.original.name === 'tcpwrapped' ? <span title={t('vulns.tcpwrapped')}>{t('vulns.tcpwrappedShort')}</span> : row.original.name },
    { id: 'product', header: t('col.product'), accessorFn: (r) => r.product, cell: ({ row }) => row.original.product || <span className="text-muted">{t('vulns.noProduct')}</span> },
    { id: 'version', header: t('col.version'), accessorFn: (r) => r.version, cell: ({ row }) => row.original.version || <span className="text-muted">{t('vulns.noVersion')}</span> },
    { id: 'cves', header: t('col.exploited'), accessorFn: count, cell: ({ row }) => {
      const n = count(row.original), m = maybe(row.original)
      return n + m > 0 ? <span className="flex flex-wrap gap-1">{n > 0 ? <Chip tone="warn">{t('vulns.count', { count: n })}</Chip> : null}{m > 0 ? <Chip tone="off">{t('vulns.countBackport', { count: m })}</Chip> : null}</span> : null
    } },
  ]
  const vulnCols: ColumnDef<VulnRow>[] = [
    { id: 'cve', header: t('col.cve'), accessorFn: (r) => r.cve, cell: ({ row }) => <span className="grid gap-0.5"><span className="font-medium">{row.original.cve}</span><span className="text-[12px] text-muted">{row.original.name}</span></span> },
    { id: 'port', header: t('col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="grid gap-1"><span className="tabular-nums">{row.original.port}</span>{mark(row.original.ip, row.original.port)}</span> },
    { id: 'basis', header: t('col.basis'), accessorFn: (r) => r.basis, cell: ({ row }) => row.original.basis === 'template' ? <Chip tone="danger">{t('vulns.basis.template', { id: row.original.template })}</Chip> : row.original.backport ? <Chip tone="off">{t('vulns.basis.backport', { distro: row.original.backport })}</Chip> : <Chip tone="warn">{t(`vulns.basis.${row.original.basis}`)}</Chip> },
    { id: 'listed', header: t('col.listed'), accessorFn: (r) => r.date_added ?? '', cell: ({ row }) => (
      <span className="grid gap-1">{row.original.date_added ? dateText(row.original.date_added) : t('common:unknown')}{row.original.ransomware ? <Chip tone="danger">{t('vulns.ransomware')}</Chip> : null}</span>
    ) },
    { id: 'why', header: t('col.why'), enableSorting: false, accessorFn: (r) => r.summary, cell: ({ row }) => <span className="text-[13px]">{row.original.summary}</span> },
  ]
  const why = s.not_checked.find((n) => n.kind === 'services' || n.kind === 'cve')
  return (
    <Section id="vulns" title={t('vulns.title')} description={t('vulns.description')}>
      {s.services.length === 0 ? (
        <EmptyState title={t('vulns.noneIdentifiedTitle')}>{why?.text ?? t('vulns.noneIdentifiedBody')}</EmptyState>
      ) : (
        <div className="grid gap-4">
          {s.vulns.length > 0 ? (
            <DataTable caption={t('vulns.caption')} data={s.vulns} columns={vulnCols} pageSize={20} rowTone={(r) => (r.backport ? undefined : 'warn')} />
          ) : s.not_checked.some((n) => n.kind === 'cve') ? (
            <p role="status" className="text-sm text-warn">{s.not_checked.find((n) => n.kind === 'cve')!.text}</p>
          ) : (
            <EmptyState title={t('vulns.noneTitle')}>{t('vulns.noneBody')}</EmptyState>
          )}
          {s.version_gaps.length > 0 ? (
            <ul aria-label={t('vulns.gapsLabel')} className="grid gap-1 text-sm">
              {s.version_gaps.map((g) => <li key={`${g.ip}:${g.port}`}>{t('vulns.gap', { count: g.cves.length, software: g.software, port: g.port, cves: g.cves.join(', ') })}</li>)}
            </ul>
          ) : null}
          <DataTable caption={t('vulns.servicesCaption')} data={s.services} columns={serviceCols} pageSize={20} empty={t('vulns.noneIdentifiedBody')} />
        </div>
      )}
    </Section>
  )
}

/** S-EXP-2 (INV-19): what the scan checked, with counts and times, and what it did not check, with why. */
export function ChecksSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  return (
    <Section id="checked" title={t('checked.title')} description={t('checked.description')}>
      {s.checks.length === 0 && s.not_checked.length === 0 ? <p className="text-sm text-muted">{t('checked.older')}</p> : (
        <Panel className="grid gap-4 p-4 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-semibold">{t('checked.checked')}</h3>
            <ul aria-label={t('checked.checked')} className="grid gap-2 text-sm">
              {s.checks.map((c, i) => <li key={i}>{c.text} <span className="text-[12px] text-muted">{dateTimeText(c.at)}</span></li>)}
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
