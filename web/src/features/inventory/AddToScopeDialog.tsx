import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useAddScopeRange, useSaveSettings, useSettings } from './api'
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
 *  as Scope. A range goes through the append-only POST /scanning/safety/ranges (#860) with the ranges and confirmation shown
 *  here: if someone changed the scope meanwhile the box answers 409 scope_changed, the dialog re-reads and asks again, nothing is
 *  overwritten. `entry` null only confirms the ranges already saved (scope_not_confirmed), through the same call. */
export function AddToScopeDialog({ entry, onClose, onDone }: { entry: string | null; onClose: () => void; onDone?: () => void }) {
  const { t } = useTranslation('inventory')
  const settings = useSettings()
  const save = useSaveSettings()
  const add = useAddScopeRange()
  const [changed, setChanged] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const s = settings.data
  const range = entry ? asRange(entry) : null
  // The checks of the scope editor (Settings › Scanning › Safety): a public range or one overlapping a saved range is said before the commitment, not after.
  const problem = range && s && !s.lan_ranges.includes(range) ? rangeProblem(range, s.lan_ranges) : null
  function submit() {
    if (!s) return
    setError(null)
    setChanged(false)
    const done = () => { onDone?.(); onClose() }
    // Confirming only: append a range the scope already holds; the box confirms the ranges shown (#860) and changes nothing else.
    const target = range ?? s.lan_ranges[0]
    if (!target) { save.mutate({ ...s, scope_confirmed: true }, { onSuccess: done, onError: (e) => setError(errMsg(e)) }); return }
    add.mutate({ range: target, confirm: true, shown_ranges: s.lan_ranges, shown_confirmed_at: s.scope_confirmed_at }, {
      onSuccess: done,
      onError: (e) => {
        // the scope changed while this was open: show the new one (refetched) and ask for the tick again
        if (e instanceof ApiError && e.code === 'scope_changed') { setChanged(true); setConfirmed(false); void settings.refetch(); return }
        setError(errMsg(e))
      },
    })
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
          {changed ? <Notice tone="warn" role="alert" className="mb-0" title={t('toScope.changed')} /> : null}
          {problem ? <Notice tone="danger" role="alert" className="mb-0" title={t(`network.problem.${problem}`, { value: range, net: range ? cidrRange(range).network : '', other: overlapping(range ?? '', s?.lan_ranges ?? []) ?? '' })} /> : null}
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <DependencyLink reason={t('toScope.restWhy')} to="/settings/scanning?tab=safety#win-from" label={t('toScope.rest')} />
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="primary" disabled={!confirmed || !s || !!problem} busy={save.isPending || add.isPending} busyLabel={t(range ? 'common:busy.adding' : 'common:busy.confirming')} onClick={submit}>{range ? t('toScope.add') : t('toScope.confirm')}</Button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}
