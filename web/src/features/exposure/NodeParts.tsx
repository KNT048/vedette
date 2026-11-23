import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { SeverityBadge } from '@/components/common/status/SeverityBadge'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { isLive } from './api'
import type { Scan, TargetNode } from './types'

const link = 'font-medium text-accent underline-offset-4 hover:underline'

/** Whose proof makes the node scannable, in one chip: its own, an ancestor's (named), or why it does not hold. */
export function ProofChip({ node, linkParent = true }: { node: Pick<TargetNode, 'proof' | 'kind'>; linkParent?: boolean }) {
  const { t } = useTranslation('exposure')
  const p = node.proof
  if (p.state === 'covered' && p.covered_by) {
    return (
      <span className="grid gap-0.5">
        <Chip tone="ok">{t('proof.state.covered')}</Chip>
        <span className="text-caption text-muted">{t('proof.coveredBy')} {linkParent ? <Link className={link} to={`/exposure/${encodeURIComponent(p.covered_by.id)}`}>{p.covered_by.value}</Link> : p.covered_by.value}</span>
      </span>
    )
  }
  const tone = p.state === 'proven' ? 'ok' : p.state === 'expired' ? 'danger' : 'warn'
  return (
    <span className="grid gap-0.5">
      <Chip tone={tone}>{t(`proof.state.${p.state}`)}</Chip>
      {node.kind === 'ip' && p.state === 'proven' && p.expires_at ? <span className="text-caption text-muted">{t('proof.until', { date: fmtDate(p.expires_at) })}</span> : null}
    </span>
  )
}

/** A run's state in the eight shared words. */
export function RunState({ scan }: { scan: Scan }) {
  const { t } = useTranslation('exposure')
  const tone = scan.status === 'done' ? 'ok' : scan.status === 'failed' ? 'danger' : scan.status === 'partial' || scan.status === 'waiting' ? 'warn' : isLive(scan) ? 'accent' : 'off'
  return <Chip tone={tone}>{t(`run.status.${scan.status}`)}</Chip>
}

/** The scan line of a node: its live scan, why Scan now is refused, or when it was last scanned. */
export function ScanCell({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const s = node.last_scan
  if (s && isLive(s)) {
    return <span className="grid gap-0.5"><RunState scan={s} />{s.waiting_for ? <span className="text-caption text-muted">{t('run.waitingFor', { what: s.waiting_for })}</span> : null}</span>
  }
  // a missing proof is said once, by the ownership chip beside it
  if (node.blocked && node.blocked !== 'proof') return <span className="text-meta text-warn">{t(`blocked.short.${node.blocked}`)}</span>
  if (!s) return <span className="text-meta text-muted">{t('run.never')}</span>
  const when = s.started_at ?? s.queued_at
  return (
    <span className="grid gap-0.5">
      <span title={fmtDateTime(when)}>{fmtRelative(when)}</span>
      {s.status !== 'done' ? <span><RunState scan={s} /></span> : null}
    </span>
  )
}

/** Open issues of a node: the count with the worst severity, linked to its Issues tab. */
export function IssuesCell({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const c = node.counts
  if (c.issues === 0) return <span className="text-muted">0</span>
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Link className={link} to={`/exposure/${encodeURIComponent(node.id)}?tab=issues`} aria-label={t('tree.issuesLabel', { count: c.issues, value: node.value })}>{c.issues}</Link>
      {c.worst ? <SeverityBadge severity={c.worst} compact /> : null}
    </span>
  )
}

/** Open services of a node, with how many answered HTTP, linked to its Services tab. */
export function ServicesCell({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const c = node.counts
  if (c.services === 0) return <span className="text-muted">0</span>
  return (
    <span className="grid gap-0.5">
      <Link className={link} to={`/exposure/${encodeURIComponent(node.id)}?tab=services`} aria-label={t('tree.servicesLabel', { count: c.services, value: node.value })}>{c.services}</Link>
      {c.web > 0 ? <span className="text-caption text-muted">{t('tree.web', { count: c.web })}</span> : null}
    </span>
  )
}

/** When a row was first and last seen: "3 Oct 2026 – 19 Nov 2026", the times on hover. */
export function Seen({ i }: { i: { first_seen: string; last_seen: string } }) {
  const { t } = useTranslation('exposure')
  return <span className="whitespace-nowrap text-meta" title={`${fmtDateTime(i.first_seen)} – ${fmtDateTime(i.last_seen)}`}>{t('seen.range', { first: fmtDate(i.first_seen), last: fmtDate(i.last_seen) })}</span>
}

/** A link to another tab of this page that keeps the page's other parameters (a list's page and filters). */
export function useTabHref() {
  const [params] = useSearchParams()
  return (tab: string, hash = '') => { const p = new URLSearchParams(params); p.set('tab', tab); return `?${p}${hash}` }
}
