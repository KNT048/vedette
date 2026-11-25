import { cn } from '@/lib/utils'
import { OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import type { Handled, StatusCode, Urgency, Verification } from '@/features/findings/types'
import { HandledLine } from './HandledLine'
import { ReasonsLine } from './ReasonsLine'
import { StatusBadge } from './StatusBadge'
import { VerificationLine } from './VerificationLine'

/** What a finding's status lines are drawn from: the fields every findings read gives (the finding's View, a list row, a report row). */
export type FindingStatusValue = {
  status: StatusCode
  urgency?: Pick<Urgency, 'reasons' | 'internet'> | null
  verification?: Verification | null
  handled?: Handled | null
  software?: string | null
}

/**
 * A finding's status as every screen says it: the badge, then why it has that status (the reasons line: layers, sources, dates) and
 * how Vedette knows (the verification line); a handled finding says who handled it and how instead. By device, the device's Findings
 * tab, Home, the finding page and the report draw a finding's status only through this, so the same finding reads the same in all of
 * them. `badge` false draws the lines alone, under a badge the row already shows.
 */
export function FindingStatusLines({ value: v, badge = true, className }: { value: FindingStatusValue; badge?: boolean; className?: string }) {
  const open = (OPEN_FINDING_STATUSES as readonly string[]).includes(v.status)
  const reasons = open && v.urgency ? <ReasonsLine urgency={v.urgency} /> : null
  const verified = open && v.verification
    ? <VerificationLine verified={v.verification.verified} basis={v.verification.basis} by={v.verification.by} entered={v.verification.entered} at={v.verification.at} />
    : null
  const handled = !open && v.handled ? <HandledLine underBadge={badge} handled={v.handled} software={v.software} className="block" /> : null
  if (!badge && !reasons && !verified && !handled) return null
  return (
    <span data-testid="finding-status" className={cn('grid justify-items-start gap-0.5', className)}>
      {badge ? <StatusBadge code={v.status} until={v.handled?.accepted_until} /> : null}
      {reasons}
      {verified}
      {handled}
    </span>
  )
}
