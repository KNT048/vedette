// Accept the risk of a device, a software line or one CVE of a line, from Needs your input: "I know it may affect this and I live with
// it until a day". It is not "Not affected": the CVEs are recorded as affected and accepted, and they come back after the day.
import { useId, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { fmtDate } from '@/lib/format'
import { dayAfter, untilOk } from './accept'
import { AcceptUntil } from './AcceptRisk'
import { useAcceptRiskQuestions } from './api'
import { errMsg } from './errors'

const DEFAULT_DAYS = 90

/** `line` is a software line, `question` one CVE row of it; neither: the whole device. `what` names the thing in the title. */
export function AcceptRiskDialog({ device, line, question, what, count, onClose }: {
  device: { id: string; name: string }; line?: { id: string } | null; question?: string; what: string; count: number; onClose: () => void
}) {
  const { t } = useTranslation('findings')
  const id = useId()
  const accept = useAcceptRiskQuestions()
  const [note, setNote] = useState('')
  const [until, setUntil] = useState(() => dayAfter(new Date(), DEFAULT_DAYS))
  const [noteError, setNoteError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  const [error, setError] = useState<string | undefined>()
  function send(e: FormEvent) {
    e.preventDefault()
    const n = note.trim()
    const badNote = n.length < 3 ? t('accept.noteRequired') : undefined
    const badUntil = untilOk(until) ? undefined : t('accept.untilRequired')
    setNoteError(badNote)
    setUntilError(badUntil)
    if (badNote || badUntil) return
    accept.mutate({ device: device.id, software: line?.id, question, note: n, until }, {
      onSuccess: (r) => { toast.success(t('queue.acceptDone', { date: fmtDate(until), count: r.findings, device: device.name })); onClose() },
      onError: (er) => setError(errMsg(er)),
    })
  }
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={t('queue.acceptTitle', { what, device: device.name })} description={t('queue.acceptBody', { count })}>
        <form onSubmit={send} noValidate className="grid gap-4">
          <Field htmlFor={`${id}-note`} label={t('queue.acceptNote')} error={noteError}>
            <Textarea id={`${id}-note`} value={note} maxLength={500} onChange={(e) => { setNote(e.target.value); setNoteError(undefined); setError(undefined) }} />
          </Field>
          <AcceptUntil id={`${id}-until`} value={until} onChange={(v) => { setUntil(v); setUntilError(undefined); setError(undefined) }} error={untilError} />
          <p className="text-meta text-muted">{t('queue.acceptNewOnes')}</p>
          {error ? <p role="alert" className="text-meta text-danger">{error}</p> : null}
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" busy={accept.isPending} busyLabel={t('common:busy.saving')}>{t('queue.acceptSubmit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
