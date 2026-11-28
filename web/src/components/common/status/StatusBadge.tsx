import type { MouseEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowUpCircle, CircleCheck, CircleHelp, CircleMinus, CircleX, Clock, FileCode2, Flame, Router, ShieldCheck, Siren, type LucideIcon } from 'lucide-react'
import { fmtDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import { DEVICE_STATUSES, type DeviceStatusCode, type FindingStatusCode } from '@/lib/statusCodes'

/** A finding's status, or a device's badge (its most urgent open status, else "Needs your input"). */
export type BadgeCode = FindingStatusCode | DeviceStatusCode

/**
 * One look per status, most urgent first. Colour is never alone: each status has its own icon and words. Only "Under attack
 * here" is filled; the outline marks a status that is a rule rather than a signal (critical on an edge device) or a workaround
 * rather than a fix (mitigated).
 */
const LOOK: Record<BadgeCode, { cls: string; Icon: LucideIcon }> = {
  under_attack: { cls: 'border-danger bg-danger text-paper', Icon: Siren },
  exploited: { cls: 'border-danger/40 bg-danger-soft text-danger', Icon: Flame },
  public_exploit: { cls: 'border-warn bg-warn-soft text-warn', Icon: FileCode2 },
  critical_edge: { cls: 'border-warn bg-transparent text-warn', Icon: Router },
  update_recommended: { cls: 'border-warn/50 bg-warn-soft text-warn', Icon: ArrowUpCircle },
  patched: { cls: 'border-ok/40 bg-ok-soft text-ok', Icon: CircleCheck },
  mitigated: { cls: 'border-ok bg-transparent text-ok', Icon: ShieldCheck },
  accepted: { cls: 'border-rule bg-off-soft text-off', Icon: Clock },
  not_relevant: { cls: 'border-rule bg-off-soft text-off', Icon: CircleMinus },
  false_positive: { cls: 'border-rule bg-off-soft text-off', Icon: CircleX },
  possible: { cls: 'border-accent/40 bg-accent-soft text-accent', Icon: CircleHelp },
}

/** The words of a status: "Exploited in the wild"; with a count, a device's badge ("2 exploited"); "Risk accepted until 3 Mar 2027". */
export function useStatusLabel() {
  const { t } = useTranslation()
  return (code: BadgeCode, opts: { count?: number; until?: string | null } = {}) => {
    if (opts.count !== undefined && (DEVICE_STATUSES as readonly string[]).includes(code)) return t(`deviceStatus.${code}`, { count: opts.count })
    if (code === 'accepted' && opts.until) return t('findingStatus.acceptedUntil', { date: fmtDate(opts.until) })
    return t(`findingStatus.${code}`)
  }
}

/**
 * The one badge for a status (finding or device), everywhere: lists, the device page, Home, the finding page and reports. Its
 * meaning is the hover text; `to` makes it a link (a device's badge leads to that device's findings with that status).
 */
export function StatusBadge({ code, count, older, until, to, className }: {
  code: BadgeCode; count?: number; until?: string | null; to?: string; className?: string
  /** A possible badge: how many of `count` are reported only for an older build, said apart ("3 possible · 2 older build"). */
  older?: number
}) {
  const { t } = useTranslation()
  const words = useStatusLabel()
  const main = code === 'possible' && older && count !== undefined ? count - older : null
  const label = main === null ? words(code, { count, until })
    : main > 0 ? `${words(code, { count: main })} · ${t('olderBuildCount', { count: older })}` : t('olderBuildCount', { count: older })
  const { cls, Icon } = LOOK[code]
  const badge = (
    <span data-status={code} title={t(`findingStatus.meaning.${code}`)}
      className={cn('inline-flex h-6 w-fit shrink-0 items-center gap-1.5 whitespace-nowrap rounded-sm border px-2 text-caption font-medium leading-none', cls, !to && className)}>
      <Icon aria-hidden className="size-3.5 shrink-0" />
      {label}
    </span>
  )
  if (!to) return badge
  // a badge inside a clickable row opens its own target, not the row's
  return (
    <Link to={to} onClick={(e: MouseEvent) => e.stopPropagation()}
      className={cn('inline-flex w-fit shrink-0 rounded-sm no-underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent', className)}>
      {badge}
    </Link>
  )
}
