import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label } from '@/components/ui/input'
import { Loading, ErrorState } from '@/components/common/States'
import { api, ApiError } from '@/lib/api'
import { SCANNING_KEY, useScanning } from './homeSummary'
import type { z } from 'zod'
import type { Safety, SafetySaved } from '@/features/scanning/contract'
import { fmtDateTime } from '@/lib/format'

type Scope = z.infer<typeof Safety>['scope']
type Saved = z.infer<typeof SafetySaved>

/**
 * Home's first-run "Set the network range", done where the customer is (docs/UI.md §0.1, #825, #860): one range and the scope
 * commitment (the same words as Devices › Scope), sent with `POST /scanning/safety/ranges`. The dialog shows the ranges already in
 * the scope and whether they are confirmed, and sends both back: the tick confirms exactly those and the new one. Read only when
 * opened (or by the step, for an administrator), under the step's key. The toast says when the range is scanned: the step then offers
 * "Scan the LAN now". The whole scope stays editable under Devices › Scope and sensors.
 */
export function AddRangeDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('feeds')
  const qc = useQueryClient()
  const read = useScanning(open)
  // After a 409 scope_changed the box sends the current block: the dialog shows it and asks for the tick again.
  const [fresh, setFresh] = useState<Scope | null>(null)
  const scope = fresh ?? read.data?.safety.scope
  const [range, setRange] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [error, setError] = useState<{ field: 'range' | 'confirm'; text: string } | null>(null)
  const add = useMutation({
    mutationFn: (s: Scope) => api.post<Saved>('/scanning/safety/ranges', { range: range.trim(), confirm, shown_ranges: s.lan_ranges, shown_confirmed_at: s.confirmed_at }),
    onSuccess: (saved) => {
      const added = saved.adjusted.find((a) => a.from === range.trim())?.to ?? range.trim()
      toast.success(t('range.added', { range: added }))
      // The step on Home reads the same key: it then says the range is set and offers "Scan the LAN now".
      void qc.invalidateQueries({ queryKey: SCANNING_KEY })
      void qc.invalidateQueries({ queryKey: ['inventory'] })
      void qc.invalidateQueries({ queryKey: ['findings', 'model', 'overview'] })
      onOpenChange(false)
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'scope_changed') {
        const cur = (e.details.safety as { scope?: Scope } | undefined)?.scope
        if (cur) setFresh(cur)
        setConfirm(false)
        setError({ field: 'confirm', text: t('range.changed') })
        return
      }
      const text = e instanceof ApiError ? e.message : String(e)
      setError({ field: e instanceof ApiError && e.code === 'scope_not_confirmed' ? 'confirm' : 'range', text })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!scope) return
    if (!range.trim()) { setError({ field: 'range', text: t('range.blank') }); document.getElementById('home-range')?.focus(); return }
    if (!confirm) { setError({ field: 'confirm', text: t('range.confirmNeeded') }); document.getElementById('home-range-confirm')?.focus(); return }
    setError(null)
    add.mutate(scope)
  }
  const others = scope?.lan_ranges ?? []
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('range.title')} description={t('range.description')} info={t('range.info')}>
        {read.isPending ? <Loading /> : read.isError ? <ErrorState error={read.error} onRetry={() => void read.refetch()} /> : (
          <form noValidate onSubmit={submit} className="grid gap-4">
            <Field label={t('range.label')} hint={t('range.hint')} htmlFor="home-range" error={error?.field === 'range' ? error.text : undefined}>
              <Input id="home-range" value={range} maxLength={64} placeholder="192.168.1.0/24" autoComplete="off" inputMode="decimal"
                onChange={(e) => { setRange(e.target.value); if (error?.field === 'range') setError(null) }} />
            </Field>
            {others.length ? (
              <p className="text-meta text-muted">
                {t('range.current', { count: others.length, ranges: others.join(', ') })}{' '}
                {scope?.confirmed_at ? t('range.confirmedAt', { who: scope.confirmed_by ?? '', when: fmtDateTime(scope.confirmed_at) }) : t('range.notConfirmed')}
              </p>
            ) : null}
            <div className="grid gap-1.5">
              <div className="flex items-start gap-2">
                <Checkbox id="home-range-confirm" className="mt-0.5" checked={confirm} aria-invalid={error?.field === 'confirm' ? true : undefined}
                  aria-describedby={error?.field === 'confirm' ? 'home-range-confirm-error' : 'home-range-asis'}
                  onCheckedChange={(v) => { setConfirm(v === true); if (error?.field === 'confirm') setError(null) }} />
                <Label htmlFor="home-range-confirm" className="font-normal">{t('inventory:scope.confirm')}</Label>
              </div>
              {error?.field === 'confirm' ? <p id="home-range-confirm-error" className="text-meta text-danger">{error.text}</p> : null}
              <p id="home-range-asis" className="text-meta text-muted">{t('inventory:scope.asIs')}</p>
            </div>
            <DialogFooter>
              <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
              <Button type="submit" variant="primary" busy={add.isPending} busyLabel={t('common:busy.adding')}>{t('range.submit')}</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
