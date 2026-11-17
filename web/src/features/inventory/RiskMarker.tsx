// Which devices carry risk, at a glance wherever a device is named in a list. One marker, two levels, like Defender's
// device "exposure level", Tenable's asset exposure and runZero's risk column, read from what Findings › To fix shows for the device
// (the server's findings.RiskOf, one rule): red = open exploited findings To fix lists (with the count), amber = none of those but a
// Recommended update fixes a CVE likely to be exploited (EPSS ≥ 10%) or of High or Critical severity; nothing when clean. Words, not
// colour only; it links to the device's To fix.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowUpCircle, ShieldAlert } from 'lucide-react'
import { Chip } from '@/components/common/StatusChip'
import { cn } from '@/lib/utils'
import type { DeviceRisk } from './types'

/** The marker of device `id`, or nothing when `risk` is null (a clean device). */
export function RiskMarker({ id, risk, className }: { id: string; risk: DeviceRisk | null | undefined; className?: string }) {
  const { t } = useTranslation('inventory')
  if (!risk) return null
  const exploited = risk.level === 'exploited'
  const aria = `${riskWord(t, risk)}: ${riskDescription(t, risk)}` // WCAG 2.5.3: the name starts with the words shown
  const to = `/findings?tab=fix&device=${encodeURIComponent(id)}` // the device's To fix: its updates to install, then the recommended ones
  return (
    <Link to={to} aria-label={aria} title={aria} data-risk={risk.level} onClick={(e) => e.stopPropagation()}
      className={cn('inline-flex shrink-0 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent', className)}>
      <Chip tone={exploited ? 'danger' : 'warn'}>
        {exploited ? <ShieldAlert aria-hidden className="size-3.5" /> : <ArrowUpCircle aria-hidden className="size-3.5" />}
        {riskWord(t, risk)}
      </Chip>
    </Link>
  )
}

type T = ReturnType<typeof useTranslation>['t']
/** The marker's short text: "2 exploited", "Update recommended"; '' when clean (for a <select> option: append it). */
export const riskWord = (t: T, risk: DeviceRisk | null | undefined) =>
  !risk ? '' : risk.level === 'exploited' ? t('inventory:risk.exploited', { count: risk.exploited }) : t('inventory:risk.update')
/** What the marker says to a screen reader and on hover, and where it leads. */
export const riskDescription = (t: T, risk: DeviceRisk) =>
  risk.level === 'exploited' ? t('inventory:risk.exploitedAria', { count: risk.exploited }) : t('inventory:risk.updateAria', { count: risk.updates })

/** Sort key: exploited above update above clean; more exploited findings (then updates) first within a level. */
export const riskRank = (risk: DeviceRisk | null | undefined) =>
  !risk ? 0 : risk.level === 'exploited' ? 1_000_000 + risk.exploited * 1000 + risk.updates : 1000 + risk.updates
