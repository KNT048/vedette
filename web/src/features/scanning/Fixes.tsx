import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label } from '@/components/ui/input'
import { useToggleModule } from '@/features/core/api'
import { ApiError } from '@/lib/api'
import type { ModuleId } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useAddRange, useScanning } from './api'
import type { Safety } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** What the dialog shows next to the tick: frozen when it opens (#877 r1 M1), so a page read in the background (every 30 s, 5 s
 *  during a run) never puts ranges under a tick the admin gave for another list. Taken again only from a 409's current block. */
type Shown = { ranges: string[]; at: string | null; by: string | null }
const shownOf = (s: Safety): Shown => ({ ranges: s.scope.lan_ranges, at: s.scope.confirmed_at, by: s.scope.confirmed_by ?? null })

/**
 * "Do it where you are" (docs/UI.md §0): the LAN ranges and the commitment that they may be scanned, from any place that needs
 * them (an engine that needs setup, a switch refused for its scope, Scan now). It adds one range, or confirms the ranges shown,
 * through POST /scanning/safety/ranges (#860): one transaction on the box, so it never overwrites another edit. The tick confirms
 * exactly the ranges listed in the dialog; if an admin changed them since it opened, nothing is stored, the dialog shows the
 * current list and asks again. The ranges stay editable under Settings › Scanning › Safety and Devices › Scope and sensors.
 */
export function ScopeDialog({ open, onOpenChange, onSaved }: { open: boolean; onOpenChange: (v: boolean) => void; /** Runs after the save, e.g. to retry the switch that needed it (review r2 N1). */ onSaved?: () => void }) {
  const { t } = useTranslation(['scanning', 'inventory'])
  const q = useScanning()
  const add = useAddRange()
  const s = q.data?.safety
  const [range, setRange] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const id = useId()
  const [frozen, setFrozen] = useState<Shown | null>(null)
  if (!frozen && s) setFrozen(shownOf(s))
  const shown = frozen?.ranges ?? []
  // a new range, or (none typed) the first range shown: then the tick confirms the list as it is
  const sent = range.trim() || shown[0] || ''
  const close = (v: boolean) => { if (!v) { setRange(''); setConfirmed(false); setError(null); setFrozen(null) } onOpenChange(v) }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!frozen || !sent) return
    setError(null)
    add.mutate({ range: sent, confirm: confirmed, shown_ranges: shown, shown_confirmed_at: frozen.at }, {
      onSuccess: () => { toast.success(t('scope.saved')); close(false); onSaved?.() },
      onError: (err) => {
        const code = err instanceof ApiError ? err.code : undefined
        if (code === 'scope_changed') {
          // the list shown is the current one from the 409 (or the next read): the tick must be given again for it
          const cur = err instanceof ApiError ? (err.details.safety as Safety | undefined) : undefined
          setFrozen(cur ? shownOf(cur) : null)
          setConfirmed(false)
        }
        setError({ message: errMsg(err), code })
      },
    })
  }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent title={t('scope.dialogTitle')} description={t('scope.dialogDescription')} info={t('scope.dialogInfo')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <div className="grid gap-1">
            <p className="text-sm font-medium">{t('scope.current')}</p>
            {shown.length ? (
              <ul aria-label={t('scope.current')} className="grid gap-0.5 text-sm tabular-nums">{shown.map((r) => <li key={r}>{r}</li>)}</ul>
            ) : <p className="text-meta text-muted">{t('scope.noneYet')}</p>}
            <p className="text-meta text-muted">{frozen?.at ? t('scope.confirmedBy', { by: frozen.by ?? '' }) : t('scope.notConfirmed')}</p>
          </div>
          <Field htmlFor={`${id}-range`} label={shown.length ? t('scope.addOptional') : t('scope.add')} hint={t('scope.rangesHint')}>
            <Input id={`${id}-range`} spellCheck={false} value={range} placeholder="192.168.10.0/24" onChange={(e) => setRange(e.target.value)} />
          </Field>
          <div className="flex items-start gap-3">
            <Checkbox id={`${id}-confirm`} className="mt-0.5" checked={confirmed} onCheckedChange={(v) => setConfirmed(v === true)} />
            <Label htmlFor={`${id}-confirm`} className="font-normal">{t('inventory:scope.confirm')}</Label>
          </div>
          {error ? <Notice tone={error.code === 'scope_changed' ? 'warn' : 'danger'} role="alert" className="mb-0" title={error.code === 'scope_changed' ? t('scope.changed') : error.message} /> : null}
          <DialogFooter>
            <Button onClick={() => close(false)}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" disabled={!frozen || !confirmed || !sent} busy={add.isPending} busyLabel={t('common:busy.saving')}>{range.trim() ? t('scope.save') : t('scope.confirmOnly')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** The button that opens ScopeDialog (admin only; others get the reason as text from the caller). */
export function ScopeButton({ label, size = 'sm', onSaved }: { label?: string; size?: 'sm' | 'md'; onSaved?: () => void }) {
  const { t } = useTranslation('scanning')
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button size={size} onClick={() => setOpen(true)}>{label ?? t('scope.open')}</Button>
      {open ? <ScopeDialog open onOpenChange={setOpen} onSaved={onSaved} /> : null}
    </>
  )
}

/** Turn a module on from where it is missing (admin), asking first when others must come with it (modules.md: never silently). */
export function TurnOnModule({ module, name }: { module: ModuleId; name: string }) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const qc = useQueryClient()
  const [missing, setMissing] = useState<ModuleId[] | null>(null)
  if (!admin) return null
  const go = (withDependencies: boolean) => toggle.mutate({ id: module, enabled: true, withDependencies }, {
    onSuccess: (r) => { if (r.kind === 'missing') setMissing(r.missing); else {
      setMissing(null); toast.success(t('module.on', { name }))
      // the engine cards read GET /scanning (and exposure's own pages): their state and switch move now, not at the next poll (#877 r1 L10)
      for (const k of ['scanning', 'exposure']) void qc.invalidateQueries({ queryKey: [k] })
    } },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : errMsg(e)),
  })
  return (
    <>
      <Button size="sm" disabled={toggle.isPending} busy={toggle.isPending && !toggle.variables?.withDependencies} busyLabel={t('common:busy.turningOn')} onClick={() => go(false)}>{t('module.turnOn', { name })}</Button>
      <Dialog open={!!missing} onOpenChange={(v) => { if (!v) setMissing(null) }}>
        <DialogContent title={t('module.depsTitle', { name })} description={t('module.depsBody', { list: (missing ?? []).map((m) => t(`common:modules.${m}.name`)).join(', ') })}>
          <DialogFooter>
            <Button onClick={() => setMissing(null)}>{t('common:cancel')}</Button>
            <Button variant="primary" busy={toggle.isPending} busyLabel={t('common:busy.turningOn')} onClick={() => go(true)}>{t('module.depsConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
