import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { dateTimeText } from './dates'
import type { HostIp, Snapshot } from './types'

// D-571 (S-EXP-2, FULL-5 slice 3): a domain's deep scan per address. Each public IPv4 address its names resolve to, the names that led to
// it, what this run's deep scan did with it and what it found there; the details (services, exploited CVEs, web findings, OpenVAS) are
// in the sections below, by address.
type Deep = NonNullable<HostIp['deep']>
const TONE: Record<Deep, Tone> = { scanned: 'ok', waiting: 'accent', fence: 'off', refused: 'warn', incomplete: 'warn' }

type DeepAddr = { ip: string; names: string[]; deep: Deep; last?: string; next?: number; services: number; vulns: number; web: number; openvas: number }

const hostOf = (site: string) => { try { return new URL(site).hostname } catch { return '' } }

/** One row per address with a deep state, in the order the scan took them (scanned, then next in line, then the rest). */
function deepAddrs(s: Snapshot): DeepAddr[] {
  const by = new Map<string, DeepAddr>()
  for (const h of s.hosts) {
    for (const a of h.ips ?? []) {
      if (!a.deep) continue
      const r = by.get(a.ip) ?? { ip: a.ip, names: [], deep: a.deep, last: a.last_deep, next: a.next_in_line, services: 0, vulns: 0, web: 0, openvas: 0 }
      if (!r.names.includes(h.name)) r.names.push(h.name)
      by.set(a.ip, r)
    }
  }
  const rows = [...by.values()]
  for (const r of rows) {
    r.names.sort()
    r.services = s.services.filter((x) => x.ip === r.ip).length
    r.vulns = s.vulns.filter((v) => v.ip === r.ip).length
    r.web = s.web_findings.filter((w) => r.names.includes(hostOf(w.site))).length
    r.openvas = (s.greenbone ?? []).filter((g) => g.ip === r.ip).length
  }
  const rank: Record<Deep, number> = { scanned: 0, incomplete: 1, waiting: 2, refused: 3, fence: 4 }
  return rows.sort((a, b) => rank[a.deep] - rank[b.deep] || (a.next ?? 0) - (b.next ?? 0) || a.ip.localeCompare(b.ip, undefined, { numeric: true }))
}

export function DeepSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const rows = deepAddrs(s)
  if (rows.length === 0) return null
  const cols: ColumnDef<DeepAddr>[] = [
    { id: 'ip', header: t('col.ip'), accessorFn: (r) => r.ip, cell: ({ row }) => <span className="font-mono text-[13px]">{row.original.ip}</span> },
    { id: 'names', header: t('deep.col.names'), accessorFn: (r) => r.names.join(' '), cell: ({ row }) => <span className="grid gap-0.5 break-all text-[13px]">{row.original.names.map((n) => <span key={n}>{n}</span>)}</span> },
    { id: 'deep', header: t('deep.col.state'), accessorFn: (r) => r.deep, cell: ({ row }) => {
      const r = row.original
      return (
        <span className="grid gap-1">
          <Chip tone={TONE[r.deep]}>{t(`deep.state.${r.deep}`)}</Chip>
          <span className="text-[12px] text-muted">{r.deep === 'waiting' ? t('deep.next', { n: r.next ?? 1 }) + ' ' : ''}{r.last ? t('deep.last', { time: dateTimeText(r.last) }) : t('deep.never')}</span>
        </span>
      )
    } },
    { id: 'found', header: t('deep.col.found'), enableSorting: false, cell: ({ row }) => {
      const r = row.original
      return r.deep === 'scanned' ? <span className="text-[13px]">{t('deep.found', { services: r.services, vulns: r.vulns, web: r.web, openvas: r.openvas })}</span> : <span className="text-[13px] text-muted">{t(`deep.why.${r.deep}`)}</span>
    } },
  ]
  return (
    <Section id="deep" title={t('deep.title')} description={t('deep.description')}>
      <DataTable caption={t('deep.caption')} data={rows} columns={cols} pageSize={20} rowTone={(r) => (r.vulns > 0 ? 'warn' : undefined)} />
    </Section>
  )
}
