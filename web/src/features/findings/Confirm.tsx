import { useState, type ReactNode, type RefObject } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { useUnverify, useVerify } from './api'
import { errMsg } from './errors'
import type { FindingRow } from './types'

type Target = Pick<FindingRow, 'id' | 'cve' | 'status' | 'basis'>

/** The urgency layer of an update-recommended finding: it never asks for a confirmation (no sign of exploitation, only a version to
 *  update), so it offers no Confirm anywhere, as Needs your input lists only layers 1 to 4. */
export const UPDATE_RECOMMENDED_LAYER = 5

/** A suspected finding an admin can confirm on their own word, when its layer asks for one (1 to 4); a confirmation a person made can
 *  be undone. */
export const canConfirm = (f: Pick<FindingRow, 'status' | 'urgency'>) => f.status === 'suspected' && f.urgency < UPDATE_RECOMMENDED_LAYER
export const canUndo = (f: Pick<FindingRow, 'status' | 'basis'>) => f.status === 'confirmed' && f.basis === 'person'

/** The small dialog of Confirm: what the person checked, required, goes into the history next to their name. */
export function ConfirmDialog({ f, onClose, opener }: { f: Target; onClose: () => void; opener?: RefObject<HTMLElement | null> }) {
  const { t } = useTranslation('findings')
  const confirm = useVerify()
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | undefined>()
  function submit() {
    if (note.trim().length < 3) { setError(t('confirm.noteRequired')); return }
    setError(undefined)
    confirm.mutate({ id: f.id, note: note.trim() }, { onSuccess: () => { toast.success(t('confirm.done')); onClose() }, onError: (e) => setError(errMsg(e)) })
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
  const undo = useUnverify()
  return (
    <Button size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })} busy={undo.isPending} busyLabel={t('confirm.undoing')}
      aria-label={size ? t('confirm.undoFor', { cve: f.cve }) : undefined}
      onClick={() => undo.mutate({ id: f.id }, { onSuccess: () => toast.success(t('confirm.undone')), onError: (e) => toast.error(errMsg(e)) })}>{t('confirm.undo')}</Button>
  )
}

/**
 * The ways to confirm a suspected finding, in order (as Qualys confirms from an authenticated version check and keeps "potential" for
 * the rest): first the automatic ones, the device reporting its version itself (SNMP, or the agent: skipped when it already does) and a
 * safe vulnerability check (only when one exists for the CVE and the device can be scanned), last a person, shown only to an admin, the
 * one role that can confirm (children: Confirm on the finding page, the CVE links in Needs your input). The device page holds SNMP and "Run vulnerability checks now"; agents are set up
 * in Devices › Set up.
 */
export function ConfirmWays({ assetId, deviceStated, checkable, children, list = false }: { assetId: string; deviceStated: boolean; checkable: boolean; children?: ReactNode; list?: boolean }) {
  const { t } = useTranslation('findings')
  const admin = useCan('admin') // only an admin can confirm: the last way is not offered to anyone else
  const device = `/devices/${encodeURIComponent(assetId)}`
  const link = 'text-accent underline underline-offset-4'
  if (!admin && deviceStated && !checkable) return null // no way left that this person can take
  return (
    <div className="grid gap-1" data-testid="confirm-ways">
      <h3 className="text-sm font-semibold">{t('confirm.ways.title')}</h3>
      <ol className="grid list-decimal gap-2 pl-5 text-sm">
        {deviceStated ? null : (
          <li>
            {t('confirm.ways.device')}{' '}
            <span className="inline-flex flex-wrap gap-x-3">
              <Link to={device} className={link}>{t('confirm.ways.snmp')}</Link>
              <Link to="/devices/setup?tab=agents" className={link}>{t('confirm.ways.agent')}</Link>
            </span>
          </li>
        )}
        {checkable ? (
          <li>
            {t('confirm.ways.check')}{' '}
            <Link to={device} className={link}>{t('confirm.ways.runCheck')}</Link>
          </li>
        ) : null}
        {admin ? (
          <li>
            <span className="inline-flex flex-wrap items-center gap-2">{t(list ? 'confirm.ways.personList' : 'confirm.ways.person')}{children}</span>
          </li>
        ) : null}
      </ol>
    </div>
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
