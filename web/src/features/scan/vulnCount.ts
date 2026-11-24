import { useModuleEnabled } from '@/lib/modules'
import { useTargets } from './api'
import type { ScanTarget } from './types'

type T = (k: string, o?: Record<string, unknown>) => string

/** What a vulnerability check of some devices can do, from the box's own rule (GET /scans/targets `suspected`, `checkable`, `again`,
 *  the counts the run plans with): `checkable` of the `suspected` findings have a safe check it can confirm or rule out, `again` of the
 *  confirmed ones a check it runs again to see whether a fix holds, on the `ids` that have either (the only devices a run includes).
 *  `none`: nothing to check, so no run is offered. Not counted (the target list not read): the run is offered without a count and the
 *  box still leaves out a device with nothing to check. Every button that starts vulnerability checks reads this one count. */
export type VulnCount = { counted: boolean; suspected: number; checkable: number; again: number; ids: string[]; none: boolean }

export function vulnCount(items: ScanTarget[] | undefined, of: string[]): VulnCount {
  if (!items) return { counted: false, suspected: 0, checkable: 0, again: 0, ids: of, none: false }
  const byId = new Map(items.map((x) => [x.id, x]))
  const c = { suspected: 0, checkable: 0, again: 0 }
  const ids: string[] = []
  for (const id of of) {
    const x = byId.get(id)
    if (!x) continue
    c.suspected += x.suspected
    c.checkable += x.checkable
    c.again += x.again
    if (x.checkable + x.again > 0) ids.push(id)
  }
  return { counted: true, ...c, ids, none: ids.length === 0 }
}

/** The count of one device (its page's button and its Last checks row). `pending` while the list is read; without an id it reads nothing. */
export function useVulnCheckable(assetId: string): VulnCount & { pending: boolean } {
  const on = useModuleEnabled('scan') === true && assetId !== ''
  const targets = useTargets(on)
  const c = vulnCount(on && targets.isSuccess ? targets.data.items : undefined, assetId ? [assetId] : [])
  return { ...c, pending: on && targets.isPending }
}

/** The button's words, from the count: "Check 5 suspected findings on 3 devices", "Check 2 confirmed findings again on 1 device", "Check
 *  1 suspected and 1 confirmed findings on 2 devices" (on one
 *  device's own page without "on 1 device"); not counted: the general words. Namespace scan. */
export function vulnLabel(t: T, c: VulnCount, here = false) {
  if (!c.counted || c.none) return t('checks.button')
  const n = c.ids.length
  const what = c.checkable > 0 && c.again > 0 ? t('checks.label.both', { count: c.checkable + c.again, suspected: c.checkable, again: c.again })
    : c.checkable > 0 ? t('checks.label.confirm', { count: c.checkable }) : t('checks.label.again', { count: c.again })
  return here ? what : t('checks.label.on', { what, count: n })
}

/** Why nothing runs, from the count: no safe check exists for the findings, or there is no open finding to check. Namespace scan. */
export function vulnNothing(t: T, c: VulnCount) {
  return c.suspected > 0 ? t('checks.nothing') : t('checks.nothingOpen')
}

/** What the run will do, in words that follow the count (never "to confirm or rule them out" when no suspected finding has a safe
 *  check): the suspected findings it confirms or rules out, the confirmed ones it checks again, and, when only the latter, that the
 *  suspected ones have no check. Not counted: the general sentence. Namespace scanning. */
export function vulnWords(t: T, c: Pick<VulnCount, 'counted' | 'suspected' | 'checkable' | 'again'>) {
  const parts = !c.counted ? [t('hint.vulnUncounted')] : [
    c.checkable === 0 ? '' : c.checkable === c.suspected ? t('hint.vulnConfirmAll', { count: c.checkable }) : t('hint.vulnConfirmSome', { count: c.checkable, total: c.suspected }),
    c.again > 0 ? t('hint.vulnAgain', { count: c.again }) : '',
    c.checkable === 0 && c.suspected > 0 ? t('hint.vulnNoneOf', { count: c.suspected }) : '',
  ]
  return [...parts, t('hint.vulnTail')].filter(Boolean).join(' ')
}
