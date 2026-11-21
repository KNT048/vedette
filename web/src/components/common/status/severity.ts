// A CVE's severity: its CVSS base score and band. Separate from the status: it says how bad the flaw is in general, never how
// urgent it is here, and it never changes the status.

/** FIRST's bands, plus `info` for a scanner's informational result (it has no CVSS score). */
export type Band = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'info'
export const BANDS: readonly Band[] = ['critical', 'high', 'medium', 'low', 'none', 'info']

/** What a severity badge needs: the band, and the score with its version and vector when they are known. */
export type SeverityValue = { band: Band; score?: number | null; version?: string | null; vector?: string | null }

/**
 * FIRST's qualitative bands, the same in CVSS v3.x and v4.0: 0.0 None, 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0
 * Critical. CVSS 2.0 has NVD's own three bands: 0.0–3.9 Low, 4.0–6.9 Medium, 7.0–10.0 High (no None, no Critical).
 */
export function bandOf(score: number, version?: string | null): Exclude<Band, 'info'> {
  if (version === '2.0') return score < 4 ? 'low' : score < 7 ? 'medium' : 'high'
  if (score === 0) return 'none'
  if (score < 4) return 'low'
  if (score < 7) return 'medium'
  if (score < 9) return 'high'
  return 'critical'
}

/** A CVSS score as the contracts carry it; null stays null ("Not scored yet", never 0). */
export function fromCvss(c: { score: number; version?: string | null; vector?: string | null } | null | undefined): SeverityValue | null {
  return c ? { band: bandOf(c.score, c.version), score: c.score, version: c.version ?? null, vector: c.vector ?? null } : null
}

/** A severity that may be a bare band ("high") or a full value. */
export const asSeverity = (s: SeverityValue | Band | null | undefined): SeverityValue | null => (typeof s === 'string' ? { band: s } : s ?? null)

/** Sort key, larger is more severe: the band first, then the score; nothing known sorts last. */
export function severityRank(s: SeverityValue | Band | null | undefined): number {
  const v = asSeverity(s)
  if (!v) return -1
  return (BANDS.length - BANDS.indexOf(v.band)) * 100 + (v.score ?? 0) * 10
}
