import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { DependencyLink } from '@/components/common/DependencyLink'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Label, Textarea } from '@/components/ui/input'
import { useToggleModule } from '@/features/core/api'
import { ApiError } from '@/lib/api'
import type { ModuleId } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { safetyInput, useSaveSafety, useScanning } from './api'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const lines = (v: string) => v.split('\n').map((l) => l.trim()).filter(Boolean)

/**
 * "Do it where you are" (docs/UI.md §0): the LAN ranges and the commitment that they may be scanned, set in a small dialog from any
 * place that needs them (an engine that needs setup, Scan now, the Safety tab). It saves the whole shared block with
 * PUT /scanning/safety, as the Safety tab does; the ranges stay editable there and under Devices, Scope and sensors.
 */
export function ScopeDialog({ open, onOpenChange, onSaved }: { open: boolean; onOpenChange: (v: boolean) => void; /** Runs after the save, e.g. to retry the switch that needed it (review r2 N1). */ onSaved?: () => void }) {
  const { t } = useTranslation('scanning')
  const q = useScanning()
  const save = useSaveSafety()
  const s = q.data?.safety
  const [ranges, setRanges] = useState<string | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const text = ranges ?? s?.scope.lan_ranges.join('\n') ?? ''
  const id = useId()
  const close = (v: boolean) => { if (!v) { setRanges(null); setConfirmed(false); setError(null) } onOpenChange(v) }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!s) return
    setError(null)
    save.mutate(safetyInput(s, { scope: { lan_ranges: lines(text), confirmed } }), {
      onSuccess: () => { toast.success(t('scope.saved')); close(false); onSaved?.() },
      onError: (err) => setError({ message: errMsg(err), code: err instanceof ApiError ? err.code : undefined }),
    })
  }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent title={t('scope.dialogTitle')} description={t('scope.dialogDescription')} info={t('scope.dialogInfo')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <Field htmlFor={`${id}-ranges`} label={t('scope.ranges')} hint={t('scope.rangesHint')}>
            <Textarea id={`${id}-ranges`} rows={3} spellCheck={false} value={text} placeholder="192.168.10.0/24" onChange={(e) => setRanges(e.target.value)} />
          </Field>
          <div className="flex items-start gap-3">
            <Checkbox id={`${id}-confirm`} className="mt-0.5" checked={confirmed} onCheckedChange={(v) => setConfirmed(v === true)} />
            <Label htmlFor={`${id}-confirm`} className="font-normal">{t('inventory:scope.confirm')}</Label>
          </div>
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error.message} /> : null}
          {/* what the dialog cannot fix itself, with the exact field (§0) */}
          {error?.code === 'too_many_exclusions' ? <DependencyLink reason={t('scope.fixExclusions')} to="/settings/scanning?tab=safety#excl" label={t('scope.fixExclusionsLink')} /> : null}
          {error?.code === 'no_days' || error?.code === 'bad_window' ? <DependencyLink reason={t('scope.fixWindow')} to="/settings/scanning?tab=safety#win-from" label={t('scope.fixWindowLink')} /> : null}
          <DialogFooter>
            <Button onClick={() => close(false)}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" disabled={!s || save.isPending || !confirmed || lines(text).length === 0}>{t('scope.save')}</Button>
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
  const [missing, setMissing] = useState<ModuleId[] | null>(null)
  if (!admin) return null
  const go = (withDependencies: boolean) => toggle.mutate({ id: module, enabled: true, withDependencies }, {
    onSuccess: (r) => { if (r.kind === 'missing') setMissing(r.missing); else { setMissing(null); toast.success(t('module.on', { name })) } },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : errMsg(e)),
  })
  return (
    <>
      <Button size="sm" disabled={toggle.isPending} onClick={() => go(false)}>{t('module.turnOn', { name })}</Button>
      <Dialog open={!!missing} onOpenChange={(v) => { if (!v) setMissing(null) }}>
        <DialogContent title={t('module.depsTitle', { name })} description={t('module.depsBody', { list: (missing ?? []).map((m) => t(`common:modules.${m}.name`)).join(', ') })}>
          <DialogFooter>
            <Button onClick={() => setMissing(null)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={toggle.isPending} onClick={() => go(true)}>{t('module.depsConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
