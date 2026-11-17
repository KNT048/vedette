import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { useModuleEnabled } from '@/lib/modules'
import { useFindings } from './api'
import { isOpen } from './basis'
import type { FindingRow } from './types'

/**
 * kien G5: a finding closed as not relevant (by a person, or by Vedette when the device cannot have it) is noise wherever findings
 * are listed: the device page, the Findings list and Home hide it by default, and one toggle "Show not relevant (N)" brings it back.
 * Counts on those pages leave it out too, so the numbers agree.
 */
export const isNotRelevant = (f: Pick<FindingRow, 'status'>) => f.status === 'not_relevant'

/** The rows to list, and how many not-relevant ones are hidden (0 when shown). */
export function withoutNotRelevant<T extends Pick<FindingRow, 'status'>>(rows: readonly T[], show: boolean): { rows: T[]; hidden: number; total: number } {
  const total = rows.filter(isNotRelevant).length
  return show ? { rows: [...rows], hidden: 0, total } : { rows: rows.filter((r) => !isNotRelevant(r)), hidden: total, total }
}

/** "Show not relevant (N)" / "Hide not relevant (N)"; nothing at all when there is none (an action with nothing to act on is not shown). */
export function NotRelevantToggle({ count, shown, onChange }: { count: number; shown: boolean; onChange: (show: boolean) => void }) {
  const { t } = useTranslation('findings')
  if (count === 0) return null
  return (
    <Button size="sm" variant="link" className="w-fit" aria-pressed={shown} onClick={() => onChange(!shown)}>
      {t(shown ? 'notRelevant.hide' : 'notRelevant.show', { count })}
    </Button>
  )
}

/**
 * The numbers the device page shows for one device, from the same read as its findings list (one query key, no second fetch):
 * open (what needs a person) and listed (open and handled, not relevant left out). undefined while loading, off or failed.
 */
export function useDeviceFindingCounts(assetId: string): { open: number; listed: number; cves: string[] } | undefined {
  const on = useModuleEnabled('findings')
  const q = useFindings(assetId)
  if (on === false || !q.data) return undefined
  const items = q.data.items
  const open = items.filter((f) => isOpen(f.status))
  return { open: open.length, listed: items.filter((f) => !isNotRelevant(f)).length, cves: [...new Set(open.map((f) => f.cve))] }
}

/** Open findings per device, from the findings list (the same cached read as the Findings page): what a "N findings" link that
 * opens the Open list of a device must count (findings_count counts every status). undefined while loading or off. */
export function useOpenFindingsByAsset(enabled: boolean): Map<string, number> | undefined {
  const q = useFindings(undefined, enabled)
  if (!enabled || !q.data) return undefined
  const m = new Map<string, number>()
  for (const f of q.data.items) if (isOpen(f.status)) m.set(f.asset_id, (m.get(f.asset_id) ?? 0) + 1)
  return m
}
