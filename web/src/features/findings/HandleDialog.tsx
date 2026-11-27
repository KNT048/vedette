// "Mark as handled…": the one dialog of the Findings screen, for one finding, a fix block or a device of a fix. It always acts on
// findings of one device (accepting a risk on device A never touches device B) and says on how many findings and CVEs it acts.
// One request (POST /findings/handle), one note; the box writes one history and audit row per finding.
import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { SeverityBadge, StatusBadge, useStatusLabel } from '@/components/common/status'
import { ApiError } from '@/lib/api'
import { FINDING_RESOLUTIONS } from '@/lib/statusCodes'
import { AcceptUntil } from './AcceptRisk'
import { untilOk } from './accept'
import { useHandle, type HandleInput } from './api'
import { MAX_HANDLE } from './contract'
import { errMsg } from './errors'
import type { CveSeverity, DeviceRef, Resolution, StatusCode } from './types'

/** A finding the dialog offers. */
export type HandleRow = { id: string; cve: string; severity?: CveSeverity | null; status?: StatusCode; software?: string | null }

/** What a note is required for (the API answers note_required otherwise). */
export const NOTE_NEEDED: readonly Resolution[] = ['accepted', 'not_relevant', 'false_positive']

/**
 * The dialog. `rows` are the findings offered, all ticked; the person may untick some. With `fix`, when every row is still ticked
 * and `complete` says the rows are every open finding of that fix on the device, the request names the device and the fix (the
 * box handles exactly that fix's open findings there); otherwise it names the ids. `resolutions` narrows the choices ("Not
 * affected…" offers Not relevant and False positive only).
 */
export function HandleDialog({ device, rows, fix, software, complete = false, resolutions = FINDING_RESOLUTIONS, title, onClose }: {
  device: DeviceRef; rows: HandleRow[]; fix?: string; software?: string | null; complete?: boolean; resolutions?: readonly Resolution[]; title?: string; onClose: () => void
}) {
  const { t } = useTranslation('findings')
  const handle = useHandle()
  const id = useId()
  const label = useStatusLabel()
  // nothing is chosen for the person: "Patched" ticked in advance on findings with no fix was a claim nobody made
  const [resolution, setResolution] = useState<Resolution | null>(resolutions.length === 1 ? resolutions[0]! : null)
  const [howError, setHowError] = useState<string | undefined>()
  const [picked, setPicked] = useState<ReadonlySet<string>>(() => new Set(rows.map((r) => r.id)))
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  const [pickError, setPickError] = useState<string | undefined>()
  // "patched" on a finding the device's latest reading still shows: the box says so once (409 still_reported) and the person keeps it
  const [still, setStill] = useState<string | undefined>()
  const accept = resolution === 'accepted'
  const needNote = !!resolution && NOTE_NEEDED.includes(resolution)
  const chosen = rows.filter((r) => picked.has(r.id))
  const cves = new Set(chosen.map((r) => r.cve)).size
  const all = chosen.length === rows.length
  const toggle = (rid: string, on: boolean) => { setPickError(undefined); setStill(undefined); setPicked((s) => { const n = new Set(s); if (on) n.add(rid); else n.delete(rid); return n }) }

  function submit(confirm = false) {
    const noPick = chosen.length === 0
    const tooMany = !(fix && complete && all) && chosen.length > MAX_HANDLE
    setPickError(noPick ? t('handle.pickOne') : tooMany ? t('handle.tooMany', { max: MAX_HANDLE }) : undefined)
    const badUntil = accept && !untilOk(until)
    setUntilError(badUntil ? t('accept.untilRequired') : undefined)
    const badNote = needNote && note.trim().length < 3
    setError(badNote ? t('handle.noteRequired') : undefined)
    setHowError(resolution ? undefined : t('handle.pickHow'))
    // The first field to fix gets the focus, so the reason is in view however long the dialog is (a Save that seems to do nothing
    // was a field error below the fold).
    const first = noPick || tooMany ? `${id}-${rows[0]!.id}` : !resolution ? `${id}-r-${resolutions[0]}` : badUntil ? `${id}-until` : badNote ? `${id}-note` : null
    if (first) document.getElementById(first)?.focus()
    if (first || !resolution) return
    const target = fix && complete && all ? { device: device.id, fix, ...(software ? { software } : {}) } : { ids: chosen.map((r) => r.id) }
    const body: HandleInput = { ...target, resolution, note: note.trim(), ...(accept ? { until } : {}), ...(confirm ? { confirm: true } : {}) }
    handle.mutate(body, {
      onSuccess: (r) => {
        // the status as its badge says it: "Risk accepted until 31 Dec 2026", not the option's "Accept the risk until…"
        const done = t('handle.done', { count: r.handled, status: label(resolution, { until: accept ? until : null }) })
        toast.success(r.skipped > 0 ? `${done} ${t('handle.skipped', { count: r.skipped })}` : done)
        onClose()
      },
      onError: (e) => { if (e instanceof ApiError && e.code === 'still_reported') setStill(e.message); else setError(errMsg(e)) },
    })
  }

  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={title ?? t('handle.title')} description={t('handle.scope', { count: chosen.length, cves, device: device.name })}>
        {rows.length > 1 ? (
          <fieldset className="grid gap-1.5">
            <legend className="mb-1 text-sm font-medium">{t('handle.which')}</legend>
            <ul className="grid max-h-56 gap-1 overflow-y-auto rounded-md border border-rule p-2">
              {rows.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <Checkbox id={`${id}-${r.id}`} checked={picked.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} />
                  <label htmlFor={`${id}-${r.id}`} className="text-sm font-medium">{r.cve}</label>
                  {r.software ? <span className="text-meta text-muted">{r.software}</span> : null}
                  {r.severity !== undefined ? <SeverityBadge severity={r.severity} compact /> : null}
                  {r.status ? <StatusBadge code={r.status} /> : null}
                </li>
              ))}
            </ul>
            {pickError ? <p role="alert" className="text-meta text-danger">{pickError}</p> : null}
          </fieldset>
        ) : null}
        <RadioGroup value={resolution ?? ''} aria-label={t('handle.how')} aria-invalid={!!howError}
          onValueChange={(v) => { setResolution(v as Resolution); setError(undefined); setUntilError(undefined); setHowError(undefined); setStill(undefined) }}>
          {resolutions.map((r) => (
            <div key={r} className="flex items-start gap-2.5">
              <RadioItem id={`${id}-r-${r}`} value={r} className="mt-1" />
              <label htmlFor={`${id}-r-${r}`} className="grid text-sm">
                <span className="font-medium">{t(`handle.option.${r}`)}</span>
                <span className="text-meta text-muted">{t(`handle.hint.${r}`)}</span>
              </label>
            </div>
          ))}
        </RadioGroup>
        {howError ? <p role="alert" className="text-meta text-danger">{howError}</p> : null}
        {accept ? <AcceptUntil id={`${id}-until`} value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor={`${id}-note`} label={needNote ? t('handle.noteRequiredLabel') : t('handle.noteLabel')} error={error}>
          <Textarea id={`${id}-note`} value={note} maxLength={500} onChange={(e) => { setNote(e.target.value); setError(undefined) }}
            aria-invalid={!!error} aria-describedby={error ? `${id}-note-error` : undefined} />
        </Field>
        {still ? (
          <Notice tone="warn" role="alert" className="mb-0" title={still}
            actions={<Button size="sm" busy={handle.isPending} busyLabel={t('common:busy.saving')} onClick={() => submit(true)}>{t('handle.patchedAnyway')}</Button>} />
        ) : null}
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant="primary" disabled={chosen.length === 0} busy={handle.isPending} busyLabel={t('common:busy.saving')} onClick={() => submit()}>{t('handle.submit', { count: chosen.length })}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
