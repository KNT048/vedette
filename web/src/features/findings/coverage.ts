// The rows and shares of Settings → Diagnostics (CoverageSection.tsx).
import { fmtPercent } from '@/lib/format'
import type { Coverage } from './types'

/** One row of the coverage table: a source that decided pairs, or a cause pairs stay undecided with the matcher's own reasons for them. */
export type CoverageRow = { key: string; outcome: 'decided' | 'undecided'; name: string; affected: number | null; notAffected: number | null; pairs: number
  details: { detail: string; count: number }[] }

/** The rows of the table: decided by source, then undecided by cause, each the most first (the box's order). */
export function coverageRows(c: Coverage): CoverageRow[] {
  return [
    ...c.decided.map((d): CoverageRow => ({ key: `d-${d.by}`, outcome: 'decided', name: d.by, affected: d.affected, notAffected: d.not_affected, pairs: d.affected + d.not_affected, details: [] })),
    ...c.possible.map((p): CoverageRow => ({ key: `u-${p.cause}`, outcome: 'undecided', name: p.cause, affected: null, notAffected: null, pairs: p.count, details: p.details })),
  ]
}

/** A share of a whole as a percentage with at most one decimal ("1.9%"); 0% of nothing. */
export function share(n: number, of: number): string {
  return fmtPercent(of > 0 ? n / of : 0)
}
