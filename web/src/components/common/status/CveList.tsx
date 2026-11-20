import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { FINDING_STATUSES, type FindingStatusCode } from '@/lib/statusCodes'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { asSeverity, BANDS, severityRank, type Band, type SeverityValue } from './severity'

/** One CVE of a list. `severity` undefined: the list has no severity data; null: the CVE is not scored yet. `to` defaults to the
 *  CVE page; a finding's list links to the finding. */
export type CveItem = { cve: string; id?: string; severity?: SeverityValue | Band | null; status?: FindingStatusCode; to?: string }

/** Without severities, how many CVEs show before "+N more". */
export const CVE_FIRST = 8

const urgent = (b: Band | undefined) => b === 'critical' || b === 'high'
const statusRank = (s: FindingStatusCode | undefined) => (s ? FINDING_STATUSES.indexOf(s) : FINDING_STATUSES.length)

/**
 * Every list of CVEs: most severe first, each with its own severity and a link, a count line ("2 Critical · 18 High · 5 Medium"),
 * Critical and High shown and the rest one click away ("+12 Medium/Low"). Without severity data the server's order stays and the
 * first CVE_FIRST show. `rows` puts one CVE per line (with its status when `showStatus`, and `action` after it); the default
 * is a wrapping run. `all` shows every CVE (a printed report).
 */
export function CveList({ items, label, rows = false, showStatus = false, action, all = false, className }: {
  items: CveItem[]; label: string; rows?: boolean; showStatus?: boolean; action?: (item: CveItem) => ReactNode; all?: boolean; className?: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const list = useRef<HTMLUListElement>(null)
  const scored = items.some((i) => i.severity !== undefined)
  const sorted = scored
    ? [...items].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || statusRank(a.status) - statusRank(b.status) || a.cve.localeCompare(b.cve))
    : items
  const top = scored ? sorted.filter((i) => urgent(asSeverity(i.severity)?.band)) : []
  const first = top.length ? top : sorted.slice(0, CVE_FIRST)
  const shown = all || open ? sorted : first
  const hidden = sorted.slice(first.length)
  // #808: the button goes away, so focus moves to the first CVE it revealed, not back to the top of the page
  useEffect(() => { if (open) list.current?.querySelectorAll('a')[first.length]?.focus() }, [open, first.length])
  if (!items.length) return null

  const counts = scored && items.length > 1 ? countLine(t, items) : null
  const hiddenBands = [...new Set(hidden.map((i) => asSeverity(i.severity)?.band))].filter((b): b is Band => !!b)
  return (
    <div className={cn('grid gap-1', className)}>
      {counts ? <p className="text-meta text-muted">{counts}</p> : null}
      <ul ref={list} aria-label={label} className={rows ? 'grid gap-1' : 'flex flex-wrap gap-x-3 gap-y-1'}>
        {shown.map((i) => (
          <li key={`${i.cve}-${i.id ?? ''}`} className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <Link to={i.to ?? `/cve/${encodeURIComponent(i.cve)}`} onClick={(e: MouseEvent) => e.stopPropagation()}
              className="whitespace-nowrap text-meta text-accent underline-offset-4 hover:underline">{i.cve}</Link>
            {i.severity !== undefined ? <SeverityBadge severity={i.severity} compact /> : null}
            {showStatus && i.status ? <StatusBadge code={i.status} /> : null}
            {action ? action(i) : null}
          </li>
        ))}
      </ul>
      {!all && hidden.length ? (
        <button type="button" onClick={(e) => { e.stopPropagation(); setOpen((o) => !o) }} aria-expanded={open}
          className="w-fit text-meta font-medium text-accent underline-offset-4 hover:underline">
          {open ? t('cveList.fewer')
            : hiddenBands.length ? t('cveList.more', { count: hidden.length, bands: hiddenBands.map((b) => t(`severity.${b}`)).join('/') })
            : t('cveList.moreAny', { count: hidden.length })}
        </button>
      ) : null}
    </div>
  )
}

/** "2 Critical · 18 High · 5 Medium · 1 not scored yet" */
function countLine(t: ReturnType<typeof useTranslation>['t'], items: CveItem[]) {
  const by = new Map<Band | 'unscored', number>()
  for (const i of items) {
    const b = asSeverity(i.severity)?.band ?? 'unscored'
    by.set(b, (by.get(b) ?? 0) + 1)
  }
  return [...BANDS, 'unscored' as const].filter((b) => by.has(b))
    .map((b) => (b === 'unscored' ? t('cveList.unscored', { count: by.get(b) }) : `${by.get(b)} ${t(`severity.${b}`)}`)).join(' · ')
}
