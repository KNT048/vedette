// A device's badge, wherever a device is named: its most urgent open status with a count ("2 exploited", "Update recommended"),
// else "Needs your input", else nothing (like Defender's device exposure level, Tenable's asset exposure and runZero's risk
// column). Words and an icon, not colour only. The badge is a link: to the device's Findings tab filtered to that status, or to
// its questions.
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { StatusBadge } from '@/components/common/status'
import type { DeviceStatusCode } from '@/lib/statusCodes'
import { cn } from '@/lib/utils'
import type { DeviceRisk } from './types'

/** A device's badge: the code and its count, or null for none. */
export type DeviceBadgeValue = { code: DeviceStatusCode; count: number } | null

/** Where a device's badge leads: the device's Findings tab filtered to that status; its questions for "Needs your input". */
export function deviceFindingsLink(device: string, code?: DeviceStatusCode): string {
  const d = encodeURIComponent(device)
  if (code === 'needs_input') return `/findings?tab=input&device=${d}`
  return code ? `/devices/${d}?tab=findings&status=${code}` : `/devices/${d}?tab=findings`
}

/** The badge of the older risk marker the device lists still carry: exploited with its count, else Update recommended. */
export const badgeOfRisk = (risk: DeviceRisk | null | undefined): DeviceBadgeValue =>
  !risk ? null : risk.level === 'exploited' ? { code: 'exploited', count: risk.exploited } : { code: 'update_recommended', count: risk.updates }

/** The badge of device `id`, a link to its findings with that status; nothing for a clean device. `label` is the link's name for
 *  screen readers and on hover; it starts with the words shown (WCAG 2.5.3). */
export function DeviceBadge({ id, badge, label, className, ...rest }: { id: string; badge: DeviceBadgeValue; label?: string; className?: string; 'data-risk'?: string }) {
  const here = useLocation()
  if (!badge) return null
  const to = deviceFindingsLink(id, badge.code)
  // already showing what it leads to (the device's Findings tab with that status): the badge, not a link to this page
  const at = new URL(to, 'http://x')
  if (at.pathname === here.pathname && at.searchParams.get('tab') === new URLSearchParams(here.search).get('tab') && at.searchParams.get('status') === new URLSearchParams(here.search).get('status')) {
    return <span title={label} className={cn('inline-flex', className)} {...rest}><StatusBadge code={badge.code} count={badge.count} /></span>
  }
  return (
    <Link to={to} aria-label={label} title={label} onClick={(e) => e.stopPropagation()} {...rest}
      className={cn('inline-flex w-fit shrink-0 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent', className)}>
      <StatusBadge code={badge.code} count={badge.count} />
    </Link>
  )
}

/** The badge of device `id` from its risk marker, or nothing when `risk` is null (a clean device). */
export function RiskMarker({ id, risk, className }: { id: string; risk: DeviceRisk | null | undefined; className?: string }) {
  const { t } = useTranslation('inventory')
  if (!risk) return null
  return <DeviceBadge id={id} badge={badgeOfRisk(risk)} label={`${riskWord(t, risk)}: ${riskDescription(t, risk)}`} data-risk={risk.level} className={className} />
}

type T = ReturnType<typeof useTranslation>['t']
/** The marker's short text: "2 exploited", "Update recommended"; '' when clean (for a <select> option: append it). */
export const riskWord = (t: T, risk: DeviceRisk | null | undefined) =>
  !risk ? '' : risk.level === 'exploited' ? t('common:deviceStatus.exploited', { count: risk.exploited }) : t('common:deviceStatus.update_recommended', { count: risk.updates })
/** What the marker says to a screen reader and on hover, and where it leads. */
export const riskDescription = (t: T, risk: DeviceRisk) =>
  risk.level === 'exploited' ? t('inventory:risk.exploitedAria', { count: risk.exploited }) : t('inventory:risk.updateAria', { count: risk.updates })

/** Sort key: exploited above update above clean; more exploited findings (then updates) first within a level. */
export const riskRank = (risk: DeviceRisk | null | undefined) =>
  !risk ? 0 : risk.level === 'exploited' ? 1_000_000 + risk.exploited * 1000 + risk.updates : 1000 + risk.updates
