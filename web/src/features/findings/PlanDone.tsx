// A recommended update a person marks as done (S-TIER-1): the plan can be wrong (the device was updated and no agent reported it yet, a
// backport the data does not know, a fix applied another way). Like "Mark as handled" on a finding: an optional note, operator role,
// audited; the item leaves the list and comes back by itself when the device reports another version or a new CVE joins it.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { usePlanDone } from './api'
import { errMsg } from './errors'
import type { PlanDone } from './types'

/** "Mark as done…" on one recommended update: a small dialog with an optional note. */
export function MarkDoneButton({ group, action, software }: { group: string; action: string; software: string }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const { mark } = usePlanDone()
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | undefined>()
  function submit() {
    setError(undefined)
    mark.mutate({ group, note: note.trim() }, { onSuccess: () => { toast.success(t('plan.done.marked')); setOpen(false); setNote('') }, onError: (e) => setError(errMsg(e)) })
  }
  return (
    <>
      <Button size="sm" variant="link" className="w-fit px-0" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        aria-label={t('plan.done.markFor', { action })} onClick={() => setOpen(true)}>{t('plan.done.mark')}</Button>
      {open ? (
        <Dialog open onOpenChange={(v) => { if (!v) setOpen(false) }}>
          <DialogContent title={t('plan.done.title')} description={t('plan.done.description', { software })}>
            <Field htmlFor={`pd-note-${group}`} label={t('plan.done.noteLabel')} error={error}>
              <Textarea id={`pd-note-${group}`} value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} />
            </Field>
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
              <Button variant="primary" busy={mark.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('plan.done.submit')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

/** Who marked an item done and when, its note, and Undo. */
export function DoneLine({ group, action, done }: { group: string; action: string; done: PlanDone }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const { undo } = usePlanDone()
  return (
    <span className="flex flex-wrap items-center gap-x-2 text-meta text-muted">
      <span>{t('plan.done.line', { by: done.by, date: fmtDate(done.at) })}{done.note ? `: ${done.note}` : ''}</span>
      <Button size="sm" variant="link" className="px-0" disabled={!can} busy={undo.isPending} busyLabel={t('common:busy.saving')} aria-label={t('plan.done.undoFor', { action })}
        title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        onClick={() => undo.mutate(group, { onSuccess: () => toast.success(t('plan.done.undone')), onError: (e) => toast.error(errMsg(e)) })}>{t('plan.done.undo')}</Button>
    </span>
  )
}
