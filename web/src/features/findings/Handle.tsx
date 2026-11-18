import { useRef, useState, type RefObject } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { MoreHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Field, Textarea } from '@/components/ui/input'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { useCan } from '@/lib/session'
import { AcceptUntil } from './AcceptRisk'
import { untilOk } from './accept'
import { useSetStatus, useUnconfirmFinding } from './api'
import { isOpen } from './basis'
import { canConfirm, canUndo, ConfirmDialog } from './Confirm'
import { errMsg } from './errors'
import { notAdded, useNotAddedActions } from './NotAdded'
import type { FindingAsset, FindingRow, StatusAction } from './types'

const RESOLVE: StatusAction[] = ['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk']

/** Mark one finding as handled: patched, mitigated, false positive, not relevant or accept the risk, with a note
 *  (POST /findings/{id}/status: its own history row and audit). The finding page, and every finding row of the lists. */
export function StatusDialog({ f, open, onOpenChange, opener }: { f: { id: string; cve: string }; open: boolean; onOpenChange: (v: boolean) => void; opener: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('findings')
  const set = useSetStatus(f.id)
  const [action, setAction] = useState<StatusAction>('patched')
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  // Every opening starts clean: Cancel or Esc drops the draft, and a saved status is not offered again the next time.
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { setWasOpen(open); if (open) { setAction('patched'); setNote(''); setUntil(''); setError(undefined); setUntilError(undefined) } }
  const accept = action === 'accept_risk'
  const needNote = action === 'false_positive' || action === 'not_relevant' || accept
  // one dialog per row on a list: the ids of its fields are its own
  const id = (s: string) => `st-${f.id}-${s}`
  function submit() {
    const badUntil = accept && !untilOk(until)
    setUntilError(badUntil ? t('accept.untilRequired') : undefined)
    if (needNote && note.trim().length < 3) { setError(t(accept ? 'accept.noteRequired' : 'status.noteRequired')); return }
    if (badUntil) return
    setError(undefined)
    set.mutate({ action, note: note.trim(), ...(accept ? { until } : {}) }, {
      onSuccess: () => { toast.success(t('status.done')); onOpenChange(false); setNote('') },
      onError: (e) => setError(errMsg(e)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('status.title')} description={t('status.description', { cve: f.cve })} info={t('status.descriptionInfo')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <RadioGroup value={action} onValueChange={(v) => { setAction(v as StatusAction); setError(undefined); setUntilError(undefined) }} aria-label={t('status.title')}>
          {RESOLVE.map((a) => (
            <div key={a} className="flex items-start gap-2.5">
              <RadioItem id={id(a)} value={a} className="mt-1" />
              <label htmlFor={id(a)} className="grid text-sm"><span className="font-medium">{t(`status.${a}`)}</span><span className="text-meta text-muted">{t(`status.${a}Hint`)}</span></label>
            </div>
          ))}
        </RadioGroup>
        {accept ? <AcceptUntil id={id('until')} value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor={id('note')} label={needNote ? t('status.noteLabelRequired') : t('status.noteLabel')} error={error}>
          <Textarea id={id('note')} value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? `${id('note')}-error` : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="primary" busy={set.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('status.submit')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A finding row; To fix's lines know only the id and the CVE of an open finding (no status: "Mark as handled…" only). */
type RowFinding = { id: string; cve: string; asset: FindingAsset | null } & (Pick<FindingRow, 'status' | 'basis'> | { status?: undefined; basis?: undefined })

/**
 * The actions of one finding row (All open, To fix, the device page), compact: at most one visible button, the most useful one for
 * the row (Confirm on a suspected finding, else "Mark as handled…" on an open one), and every other action in a "More actions"
 * menu: Mark as handled…, Undo confirm, and, where `device` is set and the device is not added yet, Add device and Ignore (a device
 * block that already offers them once leaves `device` false). The dialogs are the finding page's (StatusDialog, ConfirmDialog) and
 * the inventory's Ignore dialog. Every label names the CVE and the device. A click here never opens the row behind it.
 */
export function RowActions({ f, device = false }: { f: RowFinding; device?: boolean }) {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const admin = useCan('admin')
  const [handling, setHandling] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const primary = useRef<HTMLButtonElement>(null)
  const more = useRef<HTMLButtonElement>(null)
  const opener = useRef<HTMLButtonElement | null>(null)
  const undo = useUnconfirmFinding(f.id)
  const dev = useNotAddedActions(f.asset)
  const on = { cve: f.cve, device: f.asset?.name ?? t('removedDevice') }
  const st = f.status === undefined ? null : { id: f.id, cve: f.cve, status: f.status, basis: f.basis }
  const open = !st || isOpen(st.status)
  const confirmFirst = !!st && canConfirm(st)
  const undoable = !!st && canUndo(st)
  const deviceItems = device && notAdded(f.asset)
  const items = (confirmFirst ? 1 : 0) + (undoable ? 1 : 0) + (deviceItems ? 2 : 0)
  if (!open && !items) return null
  const needOperator = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const handle = (from: RefObject<HTMLButtonElement | null>) => { opener.current = from.current; setHandling(true) }
  return (
    <span onClick={(e) => e.stopPropagation()} className="inline-flex items-center gap-1">
      {confirmFirst ? (
        <Button ref={primary} size="sm" disabled={!admin} title={needAdmin} aria-label={t('confirm.buttonOn', on)}
          onClick={() => { opener.current = primary.current; setConfirming(true) }}>{t('confirm.button')}</Button>
      ) : open ? (
        <Button ref={primary} size="sm" disabled={!operator} title={needOperator} aria-label={t('status.markOf', on)} onClick={() => handle(primary)}>{t('status.markOne')}</Button>
      ) : null}
      {items ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button ref={more} size="sm" variant="ghost" aria-label={t('rowActions.more', on)} title={t('rowActions.moreShort')}><MoreHorizontal aria-hidden /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {confirmFirst ? <DropdownMenuItem disabled={!operator} title={needOperator} onSelect={() => handle(more)}>{t('status.markOne')}</DropdownMenuItem> : null}
            {undoable ? (
              <DropdownMenuItem disabled={!admin || undo.isPending} title={needAdmin}
                onSelect={() => undo.mutate(undefined, { onSuccess: () => toast.success(t('confirm.undone')), onError: (e) => toast.error(errMsg(e)) })}>{t('confirm.undo')}</DropdownMenuItem>
            ) : null}
            {deviceItems ? (
              <>
                <DropdownMenuItem disabled={!dev.can || dev.act.approve.isPending} title={dev.title} onSelect={dev.add}>{t('notAdded.add')}</DropdownMenuItem>
                <DropdownMenuItem disabled={!dev.can || dev.act.ignore.isPending} title={dev.title} onSelect={dev.ignore}>{t('notAdded.ignore')}</DropdownMenuItem>
              </>
            ) : null}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
      {handling ? <StatusDialog f={f} open={handling} onOpenChange={setHandling} opener={opener} /> : null}
      {confirming && st ? <ConfirmDialog f={st} onClose={() => setConfirming(false)} opener={opener} /> : null}
      {deviceItems ? dev.dialog : null}
    </span>
  )
}
