// A short dialog that asks for a few words or values and sends them: Confirm vulnerability, the answer to a question, Reopen, the
// version of a software line. Forms of the Findings screen open here, never inside a row.
import { useId, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Textarea } from '@/components/ui/input'
import { errMsg } from './errors'

/** One value the dialog asks for. `min`: the fewest characters (a note's 3); `long`: a note (a text area). */
export type Ask = { name: string; label: string; hint?: string; placeholder?: string; min?: number; max: number; long?: boolean; required?: boolean; check?: (v: string) => string | undefined }

/** `undo`: the toast after sending offers to take it back (an answer that leaves the queue and no finding records). */
export function AskDialog({ title, description, fields, submit, busyLabel, done, undo, onSend, onClose }: {
  title: string; description?: string; fields: Ask[]; submit: string; busyLabel?: string; done: string
  undo?: { label: string; run: () => Promise<unknown>; done: string }
  onSend: (values: Record<string, string>) => Promise<unknown>; onClose: () => void
}) {
  const { t } = useTranslation('findings')
  const id = useId()
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.name, ''])))
  const [errors, setErrors] = useState<Record<string, string | undefined>>({})
  const [busy, setBusy] = useState(false)
  function send(e: FormEvent) {
    e.preventDefault()
    const errs = Object.fromEntries(fields.map((f) => {
      const v = (values[f.name] ?? '').trim()
      const err = !v && f.required !== false ? t('ask.required', { field: f.label })
        : f.min && v.length < f.min ? t('ask.tooShort', { count: f.min })
        : v ? f.check?.(v) : undefined
      return [f.name, err]
    }))
    setErrors(errs)
    if (Object.values(errs).some(Boolean)) return
    setBusy(true)
    onSend(Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.trim()])))
      .then(() => {
        toast.success(done, undo ? { action: { label: undo.label, onClick: () => { undo.run().then(() => toast.success(undo.done), (er: unknown) => toast.error(errMsg(er))) } } } : undefined)
        onClose()
      }, (er: unknown) => setErrors({ [fields.at(-1)!.name]: errMsg(er) }))
      .finally(() => setBusy(false))
  }
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={title} description={description}>
        <form onSubmit={send} noValidate className="grid gap-4">
          {fields.map((f) => (
            <Field key={f.name} htmlFor={`${id}-${f.name}`} label={f.label} hint={f.hint} error={errors[f.name]}>
              {f.long ? (
                <Textarea id={`${id}-${f.name}`} value={values[f.name]} maxLength={f.max} placeholder={f.placeholder}
                  onChange={(e) => { setValues((s) => ({ ...s, [f.name]: e.target.value })); setErrors((s) => ({ ...s, [f.name]: undefined })) }} />
              ) : (
                <Input id={`${id}-${f.name}`} value={values[f.name]} maxLength={f.max} placeholder={f.placeholder}
                  onChange={(e) => { setValues((s) => ({ ...s, [f.name]: e.target.value })); setErrors((s) => ({ ...s, [f.name]: undefined })) }} />
              )}
            </Field>
          ))}
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" busy={busy} busyLabel={busyLabel ?? t('common:busy.saving')}>{submit}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
