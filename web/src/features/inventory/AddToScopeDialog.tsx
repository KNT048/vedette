import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/input'
import { useSaveSettings, useSettings } from './api'
import { errMsg } from './kinds'
import { DependencyLink } from '@/components/common/DependencyLink'
import { CIDR_RE_UI, cidrRange, IPV4_RE_UI, normalizeRange, overlapping, rangeProblem } from './validate'

/** An address or range as a scope entry: one address is its /32. */
export const asRange = (v: string) => (IPV4_RE_UI.test(v) ? `${v}/32` : normalizeRange(v).value)
/** Whether `v` (an address or a range) lies inside one of `ranges`. */
export function inRanges(v: string, ranges: string[]): boolean {
  if (!IPV4_RE_UI.test(v) && !CIDR_RE_UI.test(v)) return false
  const r = cidrRange(asRange(v))
  const base = Math.floor(r.base / r.size) * r.size
  return ranges.some((s) => { const q = cidrRange(asRange(s)); const qb = Math.floor(q.base / q.size) * q.size; return base >= qb && base + r.size <= qb + q.size })
}

/** "Add 192.168.20.0/24 to the scan scope" without leaving the step that needs it (#842 "do it where you are"): the same commitment
 *  as Scope (D-28), then the saved ranges plus this one. `entry` null only confirms the ranges already saved (scope_not_confirmed).
 *  ponytail: PUT /inventory/settings sends the whole block; switch to POST /scanning/safety/ranges {range, confirm} (append-only, #850)
 *  when it merges, so two people editing at once cannot overwrite each other. */
export function AddToScopeDialog({ entry, onClose, onDone }: { entry: string | null; onClose: () => void; onDone?: () => void }) {
  const { t } = useTranslation('inventory')
  const settings = useSettings()
  const save = useSaveSettings()
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const s = settings.data
  const range = entry ? asRange(entry) : null
  // The checks of the Scope page (NetworkForm): a public range or one overlapping a saved range is said before the commitment, not after.
  const problem = range && s && !s.lan_ranges.includes(range) ? rangeProblem(range, s.lan_ranges) : null
  function submit() {
    if (!s) return
    setError(null)
    const lan = range && !s.lan_ranges.includes(range) ? [...s.lan_ranges, range] : s.lan_ranges
    save.mutate({ ...s, lan_ranges: lan, scope_confirmed: true }, { onSuccess: () => { onDone?.(); onClose() }, onError: (e) => setError(errMsg(e)) })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={range ? t('toScope.title', { range }) : t('toScope.confirmTitle')} description={t('toScope.body')} info={t('toScope.info')}>
        <div className="grid gap-4">
          {s ? <p className="text-meta text-muted">{s.lan_ranges.length ? t('toScope.now', { list: s.lan_ranges.join(', ') }) : t('toScope.none')}</p> : null}
          <div className="flex items-start gap-2">
            <Checkbox id="to-scope-confirm" className="mt-0.5" checked={confirmed} onCheckedChange={(v) => setConfirmed(v === true)} />
            <Label htmlFor="to-scope-confirm" className="font-normal">{t('scope.confirm')}</Label>
          </div>
          {problem ? <Notice tone="danger" role="alert" className="mb-0" title={t(`network.problem.${problem}`, { value: range, net: range ? cidrRange(range).network : '', other: overlapping(range ?? '', s?.lan_ranges ?? []) ?? '' })} /> : null}
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <DependencyLink reason={t('toScope.restWhy')} to="/devices/setup?tab=scope#active-enabled" label={t('toScope.rest')} />
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="primary" disabled={!confirmed || !s || !!problem || save.isPending} onClick={submit}>{range ? t('toScope.add') : t('toScope.confirm')}</Button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}
