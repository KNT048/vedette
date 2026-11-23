import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useToggleModule } from '@/features/core/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { errText, useActions, useBlocklist, usePlans } from './api'
import { undoable } from './state'
import type { ActionRequest, RequestItem } from './types'

// AI response is left out of v1. A box that has it on keeps seeing it (the pattern of a leaving module): no new action, every way back
// stays (frozen.ts), and turning the module off is offered with the list of what stays in force (CONTRACT "when a module is turned off").

/** Disables every form control inside: for the parts that only create or edit (catalog, never-touch list, settings form). */
export function Frozen({ on, children }: { on: boolean; children: ReactNode }) {
  if (!on) return <>{children}</>
  return <fieldset disabled className="m-0 min-w-0 border-0 p-0">{children}</fieldset>
}

const SHOWN = 8

type InForceItem = { a: ActionRequest; i: RequestItem }
/** What is in force, read from what the page already loads (GET /response/actions, the block list, the execution switch). Only reversible
 *  executed changes count (a sent message has nothing to undo). ponytail: GET /response/actions returns the newest 500 requests; an older
 *  change still in force is not listed, upgrade = a server-side "in force" filter. */
function useInForce() {
  const admin = useCan('admin')
  const actions = useActions()
  const block = useBlocklist(admin)
  const plans = usePlans()
  const loading = actions.isPending || (admin && block.isPending) || plans.isPending
  const failed = !!(actions.error || (admin && block.error) || plans.error)
  const items = actions.data?.items ?? []
  const live: InForceItem[] = items.flatMap((a) => a.items.filter((i) => undoable(i) && i.reversible).map((i) => ({ a, i })))
  return {
    loading, failed, live,
    device: live.filter(({ i }) => i.connector_id !== null),
    pending: items.filter((a) => a.status === 'pending').length,
    entries: block.data?.entries.length ?? 0,
    execution: plans.data?.execution === true,
  }
}

function ItemList({ list, execution }: { list: InForceItem[]; execution: boolean }) {
  const { t } = useTranslation('response')
  return (
    <ul className="grid list-disc gap-0.5 pl-5" aria-label={t('leaving.inForceList')}>
      {list.slice(0, SHOWN).map(({ a, i }) => (
        <li key={i.id}>{t('leaving.item', { title: i.title, device: a.asset_name })}{' '}
          <span className="text-muted">{i.connector_id !== null && !execution ? t('leaving.onDevice') : i.remove_at ? t('leaving.until', { time: fmtDateTime(i.remove_at) }) : t('leaving.byHand')}</span></li>
      ))}
      {list.length > SHOWN ? <li className="text-muted">{t('leaving.more', { count: list.length - SHOWN })}</li> : null}
    </ul>
  )
}

/** What stays in force once the module is off (CONTRACT "when a module is turned off"): executed changes are not undone, firewalls keep the block
 *  list they last pulled, waiting requests can no longer be approved. Never claims "nothing" before the data is there. */
export function InForce({ onRollBack }: { onRollBack?: () => void }) {
  const { t } = useTranslation('response')
  const f = useInForce()
  if (f.loading) return <p className="text-sm text-muted" role="status">{t('leaving.loading')}</p>
  if (f.failed) return <p className="text-sm text-danger" role="alert">{t('leaving.failed')}</p>
  if (!f.live.length && !f.pending && !f.entries) return <p className="text-sm text-muted">{t('leaving.nothing')}</p>
  // with execution off a device change cannot be rolled back from here (INV-7): it is listed as "undo on the device"
  const canRollBack = f.live.some(({ i }) => i.connector_id === null || f.execution)
  return (
    <div className="grid gap-2 text-sm">
      {f.live.length ? <><p className="font-medium">{t('leaving.inForce', { count: f.live.length })}</p><ItemList list={f.live} execution={f.execution} /></> : null}
      {f.entries ? <p>{t('leaving.blocklist', { count: f.entries })}</p> : null}
      {f.pending ? <p>{t('leaving.pending', { count: f.pending })}</p> : null}
      {canRollBack ? <p><Link to="/response?tab=requests&view=history" onClick={onRollBack} className="text-accent underline underline-offset-4">{t('leaving.rollBackFirst')}</Link></p> : null}
    </div>
  )
}

/** N-H1, option (b): turning execution off or pressing Emergency stop on a box where AI response is not offered is one-way for device
 *  changes (execution cannot be turned on again here, and rolling back a device change needs it, INV-7). Say so, list them, and offer to
 *  roll them back first, which still works at this moment because execution is on. */
export function ConfirmExecutionOff({ open, onOpenChange, title, confirmLabel, busy, busyLabel, onConfirm }: { open: boolean; onOpenChange: (v: boolean) => void; title: string; confirmLabel: string; busy: boolean; busyLabel: string; onConfirm: () => void }) {
  const { t } = useTranslation('response')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={title} description={t('leaving.offWarn')}>
        {open ? <DeviceInForce onRollBack={() => onOpenChange(false)} /> : null}
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="danger" busy={busy} busyLabel={busyLabel} onClick={onConfirm}>{confirmLabel}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DeviceInForce({ onRollBack }: { onRollBack: () => void }) {
  const { t } = useTranslation('response')
  const f = useInForce()
  if (f.loading) return <p className="text-sm text-muted" role="status">{t('leaving.loading')}</p>
  if (f.failed) return <p className="text-sm text-danger" role="alert">{t('leaving.failed')}</p>
  if (!f.device.length) return <p className="text-sm text-muted">{t('leaving.noDevice')}</p>
  return (
    <div className="grid gap-2 text-sm">
      <p className="font-medium">{t('leaving.deviceInForce', { count: f.device.length })}</p>
      <ItemList list={f.device} execution />
      <p><Link to="/response?tab=requests&view=history" onClick={onRollBack} className="text-accent underline underline-offset-4">{t('leaving.rollBackFirst')}</Link></p>
    </div>
  )
}

/** Slot `modules.disable` (Settings → Modules, turn-off dialog): the same list for AI response. */
export function ModulesDisableNote({ module, onClose }: Record<string, unknown>) {
  return module === 'response' ? <InForce onRollBack={onClose as (() => void) | undefined} /> : null
}

/** The way out: PATCH /modules/response off, after listing what stays in force. */
export function TurnOffResponse() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const [ask, setAsk] = useState(false)
  async function off() {
    try {
      await toggle.mutateAsync({ id: 'response', enabled: false })
      setAsk(false)
      toast.success(t('leaving.done'))
    } catch (e) { setAsk(false); toast.error(errText(e)) }
  }
  return (
    <>
      <Button disabled={!admin} busy={toggle.isPending} busyLabel={t('common:busy.turningOff')} title={admin ? undefined : t('leaving.needAdmin')} onClick={() => setAsk(true)}>{t('leaving.turnOff')}</Button>
      <Dialog open={ask} onOpenChange={setAsk}>
        <DialogContent title={t('leaving.title')} description={t('leaving.body')}>
          {ask ? <InForce onRollBack={() => setAsk(false)} /> : null}
          <DialogFooter>
            <Button onClick={() => setAsk(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" busy={toggle.isPending} busyLabel={t('common:busy.turningOff')} onClick={() => void off()}>{t('leaving.turnOff')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
