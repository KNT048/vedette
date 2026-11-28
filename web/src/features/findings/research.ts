// What the customer's AI researched about a CVE Vedette could not decide (contract.ts: AiResearch, on PossibleCheck.reading.research):
// the pure reads every screen shares, so a row says the same thing wherever it is shown. Counts are tokens, never money.
import type { AiConfigView, AiRun } from '@/features/ai/types'
import type { PossibleCheck } from './types'

type Research = NonNullable<NonNullable<PossibleCheck['reading']>['research']>

export const researchOf = (check: PossibleCheck | null | undefined): Research | null => check?.reading?.research ?? null

/** The AI says the answer comes from a product that shares code with this one, not from a page about this product. */
export const isInferred = (check: PossibleCheck | null | undefined): boolean => researchOf(check)?.detail.basis === 'inferred'

/** Pages the research read: the pages its layers named, or what the box fetched for it, whichever is more. */
export function pagesRead(r: Research): number {
  const named = new Set(r.detail.steps.flatMap((s) => s.pages)).size
  return Math.max(named, r.detail.fetch.pages)
}

/** The box found the quote in text it read itself (the tools', the digest, or a live fetch of the page). */
export const quoteChecked = (r: Research): boolean => r.quote_check === 'tool' || r.quote_check === 'digest' || r.quote_check === 'live'

/** The model of the layer whose answer stands (else the last layer that ran). */
export function modelOf(r: Research): string | null {
  const steps = r.detail.steps
  return (steps.find((s) => s.layer === r.layer) ?? steps[steps.length - 1])?.model ?? null
}

/** The page the answer cites (else the first page that was read): where a person verifies it. */
export function evidenceUrl(check: PossibleCheck): string | null {
  const s = check.sources.find((x) => x.cited) ?? check.sources.find((x) => x.status === 'ok')
  return s?.url ?? null
}

/** Whole tokens with thousands separators ("12,400"). */
export const tokens = (n: number): string => n.toLocaleString('en-US')

/** The AI's own confidence of its answer, high first. */
export const CONFIDENCES = ['high', 'medium', 'low'] as const
export type Confidence = (typeof CONFIDENCES)[number]
export const confidenceOf = (check: PossibleCheck | null | undefined): Confidence | null => {
  const c = researchOf(check)?.detail.confidence
  return c === 'high' || c === 'medium' || c === 'low' ? c : null
}

/** Tokens one research of a CVE takes on this box in the current research mode, measured from its own runs (the box's own figure when
 *  it has one, else the research tokens of the last 30 days over the distinct CVEs researched: the same source as Settings, AI
 *  assistant). null when nothing is measured: nobody shows an invented figure. */
export function measuredTokens(cfg: AiConfigView | undefined, runs: AiRun[] | undefined): number | null {
  if (!cfg) return null
  const est = cfg.research_estimates[cfg.research_mode]
  if (est?.measured) return est.tokens
  const since = Date.now() - 30 * 86_400_000
  const mine = (runs ?? []).filter((r) => r.skill === 'research-cves' && r.status === 'ok' && new Date(r.ts).getTime() >= since)
  const cves = new Set(mine.map((r) => r.target).filter(Boolean))
  if (!mine.length || !cves.size) return null
  return Math.round(mine.reduce((n, r) => n + r.tokens_in + r.tokens_out, 0) / cves.size)
}
