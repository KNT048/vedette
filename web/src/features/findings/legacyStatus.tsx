// Findings rows of the current API shown with the status model's components (components/common/status), so every page already
// uses one look and one wording. Each screen drops these adapters when it reads the findings model (status code, verification,
// handling) from the server.
import { StatusBadge, VerificationLine, fromCvss, type SeverityValue } from '@/components/common/status'
import { OPEN_FINDING_STATUSES, type FindingStatusCode } from '@/lib/statusCodes'
import type { Finding, Severity } from '@/lib/types'
import type { Basis, Cvss, FindingRow, Verified } from './types'

type Row = { status: FindingRow['status']; urgency?: number; accepted_until?: string | null; basis?: Finding['basis']; evidence?: Finding['evidence'] | { agent?: boolean } | null; agent?: boolean }

/** An open finding's status is its urgency layer (1 under attack here .. 5 update recommended; a row that does not say reads as
 *  update recommended, never as exploited); a handled one is its resolution. */
export const legacyCode = (s: FindingRow['status'], urgency?: number): FindingStatusCode =>
  s === 'confirmed' || s === 'suspected' ? (OPEN_FINDING_STATUSES[(urgency ?? 5) - 1] ?? 'update_recommended') : s === 'risk_accepted' ? 'accepted' : s

/** How the match is known: a safe check or a person confirmed it, or the device itself (SNMP, its agent) reports the version;
 *  null for a confirmed row that does not say how (a report row). */
export function legacyVerification(f: Row): { verified: Verified; basis: Basis | null } | null {
  const ev = f.evidence as Finding['evidence'] | null | undefined
  if (f.basis === 'scan') return { verified: 'scan', basis: 'scan' }
  if (f.basis === 'person') return { verified: 'person', basis: 'person' }
  if (ev?.source || ev?.agent || f.agent) return { verified: 'device', basis: 'device_version' }
  return f.status === 'confirmed' ? null : { verified: 'no', basis: null }
}

/** The CVSS score when there is one, else the band the row carries. */
export const legacySeverity = (f: { severity: Severity; cvss?: Cvss | null }): SeverityValue => fromCvss(f.cvss) ?? { band: f.severity }

/** A finding's status badge, and under an open one how it is known. */
export function FindingStatus({ f }: { f: Row }) {
  const how = f.status === 'confirmed' || f.status === 'suspected' ? legacyVerification(f) : null
  return (
    <span className="grid justify-items-start gap-0.5">
      <StatusBadge code={legacyCode(f.status, f.urgency)} until={f.accepted_until} />
      {how ? <VerificationLine {...how} /> : null}
    </span>
  )
}
