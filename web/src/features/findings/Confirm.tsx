import { useState, type RefObject } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { useConfirmFinding, useUnconfirmFinding } from './api'
import { errMsg } from './errors'
import type { FindingRow } from './types'

type Target = Pick<FindingRow, 'id' | 'cve' | 'status' | 'basis'>

/** A suspected finding an admin can confirm on their own word; a confirmation a person made can be undone. */
export const canConfirm = (f: Pick<FindingRow, 'status'>) => f.status === 'suspected'
export const canUndo = (f: Pick<FindingRow, 'status' | 'basis'>) => f.status === 'confirmed' && f.basis === 'person'

/** The small dialog of Confirm: what the person checked, required, goes into the history next to their name. */
export function ConfirmDialog({ f, onClose, opener }: { f: Target; onClose: () => void; opener?: RefObject<HTMLElement | null> }) {
  const { t } = useTranslation('findings')
  const confirm = useConfirmFinding(f.id)
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | undefined>()
  function submit() {
    if (note.trim().length < 3) { setError(t('confirm.noteRequired')); return }
    setError(undefined)
    confirm.mutate({ note: note.trim() }, { onSuccess: () => { toast.success(t('confirm.done')); onClose() }, onError: (e) => setError(errMsg(e)) })
  }
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={t('confirm.title')} description={t('confirm.description', { cve: f.cve })} info={t('confirm.descriptionInfo')}
        onCloseAutoFocus={opener ? (e) => { e.preventDefault(); opener.current?.focus() } : undefined}>
        <Field htmlFor="cf-note" label={t('confirm.noteLabel')} error={error}>
          <Textarea id="cf-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? 'cf-note-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant="primary" busy={confirm.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('confirm.submit')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Undo of a person's confirmation: one click, back to suspected (the history keeps both lines). */
export function UndoButton({ f, size }: { f: Target; size?: 'sm' }) {
  const { t } = useTranslation('findings')
  const can = useCan('admin')
  const undo = useUnconfirmFinding(f.id)
  return (
    <Button size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })} busy={undo.isPending} busyLabel={t('confirm.undoing')}
      aria-label={size ? t('confirm.undoFor', { cve: f.cve }) : undefined}
      onClick={() => undo.mutate(undefined, { onSuccess: () => toast.success(t('confirm.undone')), onError: (e) => toast.error(errMsg(e)) })}>{t('confirm.undo')}</Button>
  )
}

/** The Confirm button: admin only, said in its title for anyone else. */
export function ConfirmButton({ f, onClick, size, buttonRef }: { f: Target; onClick: () => void; size?: 'sm'; buttonRef?: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('findings')
  const can = useCan('admin')
  return (
    <Button ref={buttonRef} size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}
      aria-label={size ? t('confirm.buttonFor', { cve: f.cve }) : undefined} onClick={onClick}>{t('confirm.button')}</Button>
  )
}
